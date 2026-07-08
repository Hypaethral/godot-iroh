use std::collections::{HashMap, hash_map::Entry};

use anyhow::{Context, bail};
use base64::prelude::*;
use bytes::{Buf, Bytes};
use godot::{classes::multiplayer_peer::TransferMode, global::godot_error, prelude::godot_warn};
use iroh::{
    Endpoint, EndpointId, SecretKey,
    endpoint::{Connection, presets, QuicTransportConfig, VarInt},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::{Receiver, UnboundedSender, channel, error::TryRecvError, unbounded_channel},
};

use crate::{ALPN, IrohRuntime};

pub(crate) async fn build_endpoint(secret_key: Option<SecretKey>) -> anyhow::Result<Endpoint> {
    let transport: QuicTransportConfig = QuicTransportConfig::default();
    let mut builder = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .transport_config(transport);
    // A stable secret key gives the endpoint a stable EndpointId across
    // rebuilds, which is how the server recognizes a reconnecting client
    // and reissues its original peer id. Server passes None (fresh identity
    // each session); client passes a persistent key.
    if let Some(secret_key) = secret_key {
        builder = builder.secret_key(secret_key);
    }
    let endpoint = builder.bind().await?;
    Ok(endpoint)
}

/// Base64 node-id string for an incoming raw connection, matching the format
/// produced by [IrohConnection::connection_string]. Used server-side to
/// recognize a reconnecting peer by its (authenticated) EndpointId.
pub(crate) fn connection_node_id_string(connection: &Connection) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(connection.remote_id().as_bytes())
}

pub struct IrohListener {
    pub(crate) endpoint: Endpoint,
    connection_receiver: Receiver<Connection>,
    closed: bool,
}

impl IrohListener {
    pub async fn new() -> anyhow::Result<Self> {
        let endpoint = build_endpoint(None).await?;

        // Accept connection loop
        let endpoint_clone = endpoint.clone();
        let (connection_sender, connection_receiver) = channel(32);
        tokio::spawn(async move {
            while let Some(incoming) = endpoint_clone.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                if connection_sender.send(connection).await.is_err() {
                    break;
                }
            }
        });

        // Return the listener
        Ok(Self {
            endpoint,
            connection_receiver,
            closed: false,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn close(&mut self) {
        let endpoint = self.endpoint.clone();
        IrohRuntime::spawn(async move { endpoint.close().await });
        self.closed = true;
    }

    pub fn connection_string(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.endpoint.id().as_bytes())
    }

    pub fn receive_connection(&mut self) -> Result<Connection, TryRecvError> {
        match self.connection_receiver.try_recv() {
            Ok(result) => Ok(result),
            Err(TryRecvError::Disconnected) => {
                self.close();
                Err(TryRecvError::Disconnected)
            }
            Err(TryRecvError::Empty) => Err(TryRecvError::Empty),
        }
    }
}

pub struct IrohConnection {
    connection: Connection,
    reliable_channels: HashMap<i32, UnboundedSender<Bytes>>,
    unreliable_sender: UnboundedSender<(i32, bool, Vec<u8>)>,
    packet_receiver: Receiver<(i32, TransferMode, Bytes)>,
}

impl IrohConnection {
    async fn new(connection: Connection) -> Self {
        let (unreliable_sender, mut unreliable_receiver) =
            unbounded_channel::<(i32, bool, Vec<u8>)>();
        let (packet_sender, packet_receiver) = channel(32);

        // Diagnostic: log establishment + why/when the QUIC connection closes.
        // The close reason is the authoritative signal for drops - it
        // distinguishes an idle timeout (TimedOut) from an application close,
        // a reset, or a transport/path error, which the Godot layer can't see.
        // (For direct-vs-relay, use the in-game ping RTT, or add a log over
        // connection.paths()/PathInfo::remote_addr per the iroh 0.96 API.)
        let connection_clone = connection.clone();
        godot_warn!("[iroh] connection established (remote {:?})", connection_clone.remote_id());
        tokio::spawn(async move {
            let reason = connection_clone.closed().await;
            godot_warn!("[iroh] connection closed (remote {:?}): {:?}", connection_clone.remote_id(), reason);
        });

        // Unreliable packet send loop
        let connection_clone = connection.clone();
        tokio::spawn(async move {
            let mut last_counts = HashMap::new();
            while let Some((channel, ordered, mut buffer)) = unreliable_receiver.recv().await {
                buffer.extend_from_slice(&channel.to_be_bytes());
                if ordered {
                    let count = last_counts.entry(channel).or_insert(0u32);
                    *count = count.wrapping_add(1);
                    if *count == 0 {
                        *count += 1;
                    }
                    buffer.extend_from_slice(&count.to_be_bytes());
                } else {
                    buffer.extend_from_slice(&0u32.to_be_bytes());
                }
                let max_datagram_size = connection_clone.max_datagram_size().unwrap_or(1024);
                if buffer.len() > max_datagram_size {
                    godot_warn!(
                        "Unreliable packet on channel {} (size: {}) exceeds {} bytes and will likely be discarded by the network",
                        channel,
                        buffer.len(),
                        max_datagram_size,
                    );
                }
                if connection_clone.send_datagram(buffer.into()).is_err() {
                    break;
                }
            }
        });

        // Unreliable packet receive loop
        let connection_clone = connection.clone();
        let packet_sender_clone = packet_sender.clone();
        tokio::spawn(async move {
            let mut last_counts = HashMap::new();
            while let Ok(mut packet) = connection_clone.read_datagram().await {
                if packet.len() < 8 {
                    break;
                }
                let count = packet.split_off(packet.len() - 4).get_u32();
                let channel = packet.split_off(packet.len() - 4).get_i32();
                let mode: TransferMode;

                // Ignore packets from the past if in ordered mode
                if count != 0 {
                    mode = TransferMode::UNRELIABLE_ORDERED;
                    let last_count = last_counts.entry(channel).or_insert(0u32);
                    if count < *last_count && *last_count - count < (u32::MAX / 4) {
                        continue;
                    }
                    *last_count = count;
                } else {
                    mode = TransferMode::UNRELIABLE;
                }

                // Send the packet to the main thread
                if packet_sender_clone
                    .send((channel, mode, packet))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // Reliable channel receive loop
        let connection_clone = connection.clone();
        tokio::spawn(async move {
            while let Ok(mut stream) = connection_clone.accept_uni().await {
                let packet_sender = packet_sender.clone();
                tokio::spawn(async move {
                    let channel = stream.read_i32().await?;
                    loop {
                        let packet_len = stream.read_u16().await?;
                        let mut packet = vec![0u8; packet_len as usize];
                        stream.read_exact(&mut packet).await?;
                        if packet_sender
                            .send((channel, TransferMode::RELIABLE, packet.into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                });
            }
        });

        // Return the connection
        Self {
            connection,
            reliable_channels: HashMap::new(),
            unreliable_sender,
            packet_receiver,
        }
    }

    pub async fn accept(connection: Connection, peer_id: i32) -> anyhow::Result<Self> {
        connection.open_uni().await?.write_i32(peer_id).await?;
        Ok(Self::new(connection).await)
    }

    pub async fn connect(
        endpoint: Endpoint,
        connection_string: String,
    ) -> anyhow::Result<(i32, Self)> {
        let node_id_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(connection_string)
            .context("invalid connection string")?;
        let node_id_bytes: [u8; 32] = match node_id_bytes.try_into() {
            Ok(bytes) => bytes,
            Err(_) => bail!("invalid connection string"),
        };
        let node_id =
            EndpointId::from_bytes(&node_id_bytes).context("invalid connection string")?;
        let connection = endpoint.connect(node_id, ALPN).await?;
        let peer_id = connection.accept_uni().await?.read_i32().await?;
        Ok((peer_id, Self::new(connection).await))
    }

    pub fn close(&self) {
        self.connection.close(VarInt::from_u32(0), b"");
    }

    pub fn send_packet(&mut self, channel: i32, mode: TransferMode, packet: Vec<u8>) {
        if mode == TransferMode::RELIABLE {
            let sender = match self.reliable_channels.entry(channel) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let connection = self.connection.clone();
                    let (sender, mut receiver) = unbounded_channel::<Bytes>();
                    IrohRuntime::spawn(async move {
                        let mut stream = connection.open_uni().await?;
                        stream.write_i32(channel).await?;
                        while let Some(packet) = receiver.recv().await {
                            if packet.len() > u16::MAX as usize {
                                godot_error!(
                                    "Reliable packet on channel {} (size: {}) exceeds the maximum allowed size of {} bytes and cannot be sent",
                                    channel,
                                    packet.len(),
                                    u16::MAX,
                                );
                            } else {
                                stream.write_u16(packet.len().try_into()?).await?;
                                stream.write_all(&packet).await?;
                            }
                        }

                        Ok::<(), anyhow::Error>(())
                    });
                    entry.insert(sender)
                }
            };
            let _ = sender.send(packet.into());
        } else {
            let _ = self.unreliable_sender.send((
                channel,
                mode == TransferMode::UNRELIABLE_ORDERED,
                packet,
            ));
        }
    }

    pub fn receive_packet(&mut self) -> Result<(i32, TransferMode, Bytes), TryRecvError> {
        self.packet_receiver.try_recv()
    }

    pub fn connection_string(&self) -> String {
        // If the connection is made the node id should be valid
        let node_id = self.connection.remote_id();
        BASE64_URL_SAFE_NO_PAD.encode(node_id.as_bytes())
    }
}

impl Drop for IrohConnection {
    fn drop(&mut self) {
        self.close();
    }
}
