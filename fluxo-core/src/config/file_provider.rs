//! File-based config provider — watches a TOML file for changes.
//!
//! Supports two trigger modes:
//! - **Unix:** Listens for `SIGHUP` signals (nginx-compatible)
//! - **All platforms:** Polls file modification time at a configurable interval

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{error, info};

use super::FluxoConfig;
use super::provider::ConfigProvider;

/// File-based configuration provider.
///
/// Watches a TOML config file for changes and pushes updated configs
/// into the shared channel. On Unix, also listens for SIGHUP.
pub struct FileProvider {
    path: PathBuf,
    /// How often to poll for file modification (fallback for non-signal systems).
    poll_interval: Duration,
}

impl FileProvider {
    /// Create a new file provider watching the given path.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            poll_interval: Duration::from_secs(5),
        }
    }

    /// Create a new file provider with a custom poll interval.
    pub fn with_poll_interval(path: PathBuf, poll_interval: Duration) -> Self {
        Self {
            path,
            poll_interval,
        }
    }

    /// Read and parse the config file.
    fn load_config(&self) -> Result<FluxoConfig, Box<dyn std::error::Error + Send + Sync>> {
        let config = super::load_from_file(&self.path)?;
        Ok(config)
    }
}

#[async_trait]
impl ConfigProvider for FileProvider {
    fn name(&self) -> &'static str {
        "file"
    }

    async fn watch(
        &self,
        tx: mpsc::Sender<(String, FluxoConfig)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Track last modification time for polling
        let mut last_modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();

        // On Unix: also listen for SIGHUP
        #[cfg(unix)]
        let mut sighup = {
            use tokio::signal::unix::{SignalKind, signal};
            signal(SignalKind::hangup()).ok()
        };

        loop {
            let should_reload;

            #[cfg(unix)]
            {
                tokio::select! {
                    () = tokio::time::sleep(self.poll_interval) => {
                        // Check if file was modified
                        let current_modified = std::fs::metadata(&self.path)
                            .and_then(|m| m.modified())
                            .ok();
                        should_reload = current_modified != last_modified;
                        if should_reload {
                            last_modified = current_modified;
                        }
                    }
                    () = async {
                        if let Some(ref mut s) = sighup {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        info!(path = %self.path.display(), "SIGHUP received — reloading config");
                        should_reload = true;
                        // Update last_modified so polling doesn't double-fire
                        last_modified = std::fs::metadata(&self.path)
                            .and_then(|m| m.modified())
                            .ok();
                    }
                }
            }

            #[cfg(not(unix))]
            {
                tokio::time::sleep(self.poll_interval).await;
                let current_modified = std::fs::metadata(&self.path)
                    .and_then(|m| m.modified())
                    .ok();
                should_reload = current_modified != last_modified;
                if should_reload {
                    last_modified = current_modified;
                }
            }

            if should_reload {
                match self.load_config() {
                    Ok(config) => {
                        info!(path = %self.path.display(), "config file changed — pushing update");
                        if tx.send((self.name().to_string(), config)).await.is_err() {
                            // Receiver dropped — shutdown
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        error!(
                            path = %self.path.display(),
                            error = %e,
                            "failed to load config file — skipping reload"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn file_provider_name() {
        let fp = FileProvider::new(PathBuf::from("/tmp/test.toml"));
        assert_eq!(fp.name(), "file");
    }

    #[test]
    fn custom_poll_interval() {
        let fp = FileProvider::with_poll_interval(
            PathBuf::from("/tmp/test.toml"),
            Duration::from_secs(10),
        );
        assert_eq!(fp.poll_interval, Duration::from_secs(10));
    }

    #[test]
    fn default_poll_interval() {
        let fp = FileProvider::new(PathBuf::from("/tmp/test.toml"));
        assert_eq!(fp.poll_interval, Duration::from_secs(5));
    }

    #[test]
    fn path_stored_correctly() {
        let fp = FileProvider::new(PathBuf::from("/etc/fluxo/fluxo.toml"));
        assert_eq!(fp.path, PathBuf::from("/etc/fluxo/fluxo.toml"));
    }

    #[test]
    fn load_config_missing_file() {
        let fp = FileProvider::new(PathBuf::from("/nonexistent/path/fluxo.toml"));
        assert!(fp.load_config().is_err());
    }

    #[test]
    fn load_config_valid_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("fluxo.toml");
        let mut file = std::fs::File::create(&config_path).unwrap();
        write!(
            file,
            r#"
[global]
admin = "127.0.0.1:2019"

[services.web]
listeners = [{{ address = "0.0.0.0:8080" }}]

[[services.web.routes]]
match_path = ["/*"]
upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#
        )
        .unwrap();
        drop(file);

        let fp = FileProvider::new(config_path);
        let result = fp.load_config();
        assert!(result.is_ok());
    }

    #[test]
    fn load_config_invalid_toml() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("bad.toml");
        let mut file = std::fs::File::create(&config_path).unwrap();
        write!(file, "this is not valid [[ toml {{}}").unwrap();
        drop(file);

        let fp = FileProvider::new(config_path);
        assert!(fp.load_config().is_err());
    }

    #[test]
    fn with_poll_interval_stores_path() {
        let fp = FileProvider::with_poll_interval(
            PathBuf::from("/custom/path.toml"),
            Duration::from_secs(30),
        );
        assert_eq!(fp.path, PathBuf::from("/custom/path.toml"));
        assert_eq!(fp.poll_interval, Duration::from_secs(30));
    }
}
