//! Simulator file bridge (`$CASHU_VAULT_SIM_DIR` or `~/.cashu-vault-sim`).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cashu_vault_protocol::ResponseEnvelope;

pub const ENV_DIR: &str = "CASHU_VAULT_SIM_DIR";
pub const DEFAULT_DIR_NAME: &str = ".cashu-vault-sim";

const MESSAGE_EXTENSION: &str = "cbor";
const STAGING_EXTENSION: &str = "part";
const CLAIMED_EXTENSION: &str = "taken";
const POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge {
    root: PathBuf,
}

impl Bridge {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn from_env() -> Self {
        if let Some(dir) = std::env::var_os(ENV_DIR) {
            return Self::new(dir);
        }
        let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
        Self::new(PathBuf::from(home).join(DEFAULT_DIR_NAME))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn inbox(&self) -> PathBuf {
        self.root.join("inbox")
    }

    pub fn outbox(&self) -> PathBuf {
        self.root.join("outbox")
    }

    pub fn seed_file(&self) -> PathBuf {
        self.root.join("app-seed.hex")
    }

    pub fn reset_file(&self) -> PathBuf {
        self.root.join("reset")
    }

    pub fn create(&self) -> io::Result<()> {
        fs::create_dir_all(self.inbox())?;
        fs::create_dir_all(self.outbox())
    }

    pub fn take_request(&self) -> io::Result<Option<Vec<u8>>> {
        let Some(path) = oldest_message(&self.inbox())? else {
            return Ok(None);
        };
        let claimed = path.with_extension(CLAIMED_EXTENSION);
        fs::rename(&path, &claimed)?;
        let bytes = fs::read(&claimed);
        let _ = fs::remove_file(&claimed);
        bytes.map(Some)
    }

    pub fn write_response(&self, response: &[u8]) -> io::Result<PathBuf> {
        let name = match ResponseEnvelope::from_cbor(response) {
            Ok(env) => format!("{:016x}", env.request_id),
            Err(_) => "unaddressed".to_owned(),
        };
        let target = self.outbox().join(format!("{name}.{MESSAGE_EXTENSION}"));
        write_atomic(&target, response)?;
        Ok(target)
    }

    pub fn pinned_app_seed(&self) -> Result<Option<[u8; 32]>, String> {
        let path = self.seed_file();
        match fs::read_to_string(&path) {
            Ok(text) => {
                let bytes = hex::decode(text.trim()).map_err(|e| format!("not hex: {e}"))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|v: Vec<u8>| format!("{} bytes, expected 32", v.len()))?;
                Ok(Some(arr))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    pub fn take_reset(&self) -> bool {
        fs::remove_file(self.reset_file()).is_ok()
    }

    pub fn submit(&self, request: &[u8]) -> io::Result<PathBuf> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|e| e.as_nanos())
            .unwrap_or_default();
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = self
            .inbox()
            .join(format!("{nanos:024}-{seq:08}.{MESSAGE_EXTENSION}"));
        write_atomic(&path, request)?;
        Ok(path)
    }

    pub fn take_response(&self, request_id: u64) -> io::Result<Option<Vec<u8>>> {
        let path = self
            .outbox()
            .join(format!("{request_id:016x}.{MESSAGE_EXTENSION}"));
        match fs::read(&path) {
            Ok(bytes) => {
                fs::remove_file(&path)?;
                Ok(Some(bytes))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn wait_response(
        &self,
        request_id: u64,
        timeout: Duration,
    ) -> io::Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(bytes) = self.take_response(request_id)? {
                return Ok(Some(bytes));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(POLL);
        }
    }

    pub fn request_reset(&self) -> io::Result<()> {
        fs::create_dir_all(&self.root)?;
        fs::write(self.reset_file(), b"")
    }

    pub fn pin_app_seed(&self, seed: &[u8; 32]) -> io::Result<()> {
        if let Some(parent) = self.seed_file().parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(self.seed_file());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(self.seed_file())?
            .write_all(hex::encode(seed).as_bytes())
    }

    pub fn clear_queues(&self) -> io::Result<()> {
        for dir in [self.inbox(), self.outbox()] {
            match fs::read_dir(&dir) {
                Ok(entries) => {
                    for entry in entries {
                        let path = entry?.path();
                        if path.is_file() {
                            fs::remove_file(path)?;
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

fn oldest_message(dir: &Path) -> io::Result<Option<PathBuf>> {
    let mut oldest: Option<PathBuf> = None;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let is_msg = path
            .extension()
            .is_some_and(|ext| ext == MESSAGE_EXTENSION);
        if is_msg && path.is_file() && oldest.as_ref().is_none_or(|first| path < *first) {
            oldest = Some(path);
        }
    }
    Ok(oldest)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let staged = path.with_extension(STAGING_EXTENSION);
    fs::write(&staged, bytes)?;
    fs::rename(&staged, path)
}
