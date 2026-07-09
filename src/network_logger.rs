use std::{
    fs::{create_dir_all, File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use chrono::Local;

pub struct NetworkLogger {
    file: Mutex<File>,
}

static LOGGER: OnceLock<NetworkLogger> = OnceLock::new();

impl NetworkLogger {
    pub fn init(log_path: PathBuf) -> std::io::Result<()> {
        if LOGGER.get().is_some() {
            return Ok(());
        }

        if let Some(parent) = log_path.parent() {
            create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

        LOGGER
            .set(NetworkLogger {
                file: Mutex::new(file),
            })
            .ok();

        Ok(())
    }

    pub fn debug(msg: impl AsRef<str>) {
        Self::log("DEBUG", msg.as_ref());
    }

    pub fn info(msg: impl AsRef<str>) {
        Self::log("INFO ", msg.as_ref());
    }

    pub fn warn(msg: impl AsRef<str>) {
        Self::log("WARN ", msg.as_ref());
    }

    pub fn error(msg: impl AsRef<str>) {
        Self::log("ERROR", msg.as_ref());
    }

    fn log(level: &str, msg: &str) {
        let Some(logger) = LOGGER.get() else {
            return;
        };

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");

        // Continue logging even if a previous log call panicked while holding the mutex.
        let mut file = logger.file.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(file, "[{timestamp}] [{level}] {msg}");
    }
}