//! KeyOS device integration: `GetAppSeed` (`os/security`), hardware TRNG (`getrandom`), and
//! durable storage (`os/fs` `AppData`).

use cashu_vault_service::{Platform, Storage};

security::use_api!();

const STATE_FILE: &str = "cashu-vault-state.cbor";

fn system_app_seed() -> Result<[u8; 32], String> {
    Security::default()
        .app_seed()
        .map(|seed| *seed.as_bytes())
        .map_err(|error| format!("the app seed is unavailable: {error:?}"))
}

#[cfg(keyos)]
pub fn app_seed() -> Result<[u8; 32], String> {
    system_app_seed()
}

#[cfg(not(keyos))]
pub fn app_seed() -> Result<[u8; 32], String> {
    match crate::bridge::pinned_app_seed()? {
        Some(seed) => {
            log::warn!("simulator: using the app seed pinned in the bridge directory");
            Ok(seed)
        }
        None => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).expect("the TRNG is always available");
            if let Err(err) = crate::bridge::pin_app_seed(&seed) {
                log::warn!("simulator: could not persist generated app seed: {err}");
                return system_app_seed();
            }
            log::info!("simulator: generated and pinned unique app seed in bridge directory");
            Ok(seed)
        }
    }
}

pub struct DevicePlatform;

impl Platform for DevicePlatform {
    fn random_32(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("the TRNG is always available");
        bytes
    }

    fn now_unix(&self) -> Option<u64> {
        #[cfg(keyos)]
        {
            None
        }
        #[cfg(not(keyos))]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|elapsed| elapsed.as_secs())
        }
    }
}

pub struct AppDataStorage;

impl AppDataStorage {
    #[cfg(not(keyos))]
    pub fn wipe(&self) -> Result<(), String> {
        let files = crate::FileSystem::default();
        for name in [
            STATE_FILE.to_owned(),
            format!("{STATE_FILE}.tmp"),
            format!("{STATE_FILE}.new"),
        ] {
            match files.remove(name, fs::Location::AppData) {
                Ok(()) | Err(fs::Error::FileNotFound) => {}
                Err(error) => return Err(format!("cannot remove vault state: {error:?}")),
            }
        }
        Ok(())
    }
}

impl Storage for AppDataStorage {
    fn load(&mut self) -> Result<Option<Vec<u8>>, String> {
        match crate::FileSystem::default().durable_file_read(STATE_FILE, fs::Location::AppData) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(fs::Error::FileNotFound) => Ok(None),
            Err(error) => Err(format!("reading vault state failed: {error:?}")),
        }
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(), String> {
        crate::FileSystem::default()
            .durable_file_write(STATE_FILE, fs::Location::AppData, bytes)
            .map_err(|error| format!("saving vault state failed: {error:?}"))
    }
}
