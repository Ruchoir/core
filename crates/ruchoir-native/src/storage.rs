//! Where the grants are kept: the system keychain, as the desktop gives it (the `keyring` crate, for
//! instance, wrapped in a blocking task). Only refresh tokens and what goes with them are stored;
//! access tokens stay in memory.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

/// A secure key-value store. Keys only use letters, digits, `.`, `-` and `_`. An error is a
/// message for the logs; it never holds a stored value.
pub trait Storage: Send + Sync {
    fn get(&self, key: &str) -> impl Future<Output = Result<Option<String>, String>> + Send;
    fn set(&self, key: &str, value: &str) -> impl Future<Output = Result<(), String>> + Send;
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), String>> + Send;
}

/// A store in memory, for tests and for a session that must not outlive the process.
#[derive(Default)]
pub struct MemoryStorage {
    values: Mutex<HashMap<String, String>>,
}

impl MemoryStorage {
    /// Every stored value, for a test to look at.
    pub fn values(&self) -> Vec<String> {
        self.values
            .lock()
            .map(|v| v.values().cloned().collect())
            .unwrap_or_default()
    }
}

impl Storage for MemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let values = self.values.lock().map_err(|e| e.to_string())?;
        Ok(values.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str) -> Result<(), String> {
        let mut values = self.values.lock().map_err(|e| e.to_string())?;
        values.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        let mut values = self.values.lock().map_err(|e| e.to_string())?;
        values.remove(key);
        Ok(())
    }
}
