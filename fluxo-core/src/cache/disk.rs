//! Filesystem-backed cache storage implementing Pingora's `Storage` trait.

use std::any::Any;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use pingora_cache::key::{CacheHashKey, CompactCacheKey};
use pingora_cache::meta::CacheMeta;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
use pingora_cache::CacheKey;
use pingora_cache::trace::SpanHandle;
use pingora_core::{Error, ErrorType, Result};
use sha2::{Digest, Sha256};

/// Disk-backed cache storage.
///
/// Stores cache entries as files on disk, organized by hash prefix for
/// filesystem-friendly distribution. Tracks total size for LRU eviction.
pub struct DiskCache {
    /// Root directory for cache files.
    root: PathBuf,
    /// Maximum total cache size in bytes.
    max_size: u64,
    /// Current total cache size (approximate, updated on write/evict).
    current_size: AtomicU64,
    /// LRU index: access_time -> hash (for eviction ordering).
    lru: RwLock<BTreeMap<u64, String>>,
    /// Monotonic counter for LRU ordering.
    lru_counter: AtomicU64,
}

impl DiskCache {
    /// Create a new disk cache rooted at the given directory with a max size budget.
    pub fn new(root: PathBuf, max_size: u64) -> Self {
        let cache = Self {
            root,
            max_size,
            current_size: AtomicU64::new(0),
            lru: RwLock::new(BTreeMap::new()),
            lru_counter: AtomicU64::new(0),
        };
        cache.scan_existing();
        cache
    }

    /// Parse a human-readable max size string into bytes. Falls back to 1 GB.
    pub fn parse_max_size(s: &str) -> u64 {
        parse_size(s).unwrap_or(1024 * 1024 * 1024)
    }

    /// Compute the hex-encoded SHA-256 hash for a cache key.
    fn hash_key(combined: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let result = hasher.finalize();
        hex_encode(&result)
    }

    /// Get the directory path for a given hash.
    fn entry_dir(&self, hash: &str) -> PathBuf {
        // Use first 2 chars as prefix directory for filesystem distribution
        let prefix = &hash[..2];
        self.root.join(prefix).join(hash)
    }

    /// Meta file path for a cache entry.
    fn meta_path(&self, hash: &str) -> PathBuf {
        self.entry_dir(hash).join("meta.bin")
    }

    /// Body file path for a cache entry.
    fn body_path(&self, hash: &str) -> PathBuf {
        self.entry_dir(hash).join("body.bin")
    }

    /// Scan existing cache directory to rebuild size and LRU state.
    fn scan_existing(&self) {
        let Ok(prefixes) = std::fs::read_dir(&self.root) else {
            return;
        };

        let mut total_size: u64 = 0;
        let mut lru = self.lru.write();
        let mut counter: u64 = 0;

        for prefix_entry in prefixes.flatten() {
            if !prefix_entry.path().is_dir() {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(prefix_entry.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let body_path = path.join("body.bin");
                let meta_path = path.join("meta.bin");
                if body_path.exists() && meta_path.exists() {
                    let body_size = std::fs::metadata(&body_path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    let meta_size = std::fs::metadata(&meta_path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    total_size += body_size + meta_size;

                    if let Some(hash) = path.file_name().and_then(|n| n.to_str()) {
                        lru.insert(counter, hash.to_string());
                        counter += 1;
                    }
                }
            }
        }

        drop(lru);
        self.current_size.store(total_size, Ordering::Relaxed);
        self.lru_counter.store(counter, Ordering::Relaxed);
    }

    /// Touch an entry in the LRU (move to most recent).
    fn touch_lru(&self, hash: &str) {
        let counter = self.lru_counter.fetch_add(1, Ordering::Relaxed);
        let mut lru = self.lru.write();
        // Remove old entry for this hash (if any)
        lru.retain(|_, v| v != hash);
        lru.insert(counter, hash.to_string());
    }

    /// Read meta from disk.
    fn read_meta(path: &Path) -> Result<CacheMeta> {
        let data = std::fs::read(path).map_err(|e| {
            Error::explain(ErrorType::ReadError, format!("cache meta read: {e}"))
        })?;
        if data.len() < 8 {
            return Error::e_explain(ErrorType::ReadError, "cache meta too short");
        }
        let meta0_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let meta1_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if data.len() < 8 + meta0_len + meta1_len {
            return Error::e_explain(ErrorType::ReadError, "cache meta truncated");
        }
        let meta0 = data[8..8 + meta0_len].to_vec();
        let meta1 = data[8 + meta0_len..8 + meta0_len + meta1_len].to_vec();
        CacheMeta::deserialize(&meta0, &meta1)
    }

    /// Write meta to disk.
    fn write_meta(path: &Path, meta: &CacheMeta) -> Result<()> {
        let (meta0, meta1) = meta.serialize()?;
        let meta0_len = (meta0.len() as u32).to_le_bytes();
        let meta1_len = (meta1.len() as u32).to_le_bytes();
        let mut buf = Vec::with_capacity(8 + meta0.len() + meta1.len());
        buf.extend_from_slice(&meta0_len);
        buf.extend_from_slice(&meta1_len);
        buf.extend_from_slice(&meta0);
        buf.extend_from_slice(&meta1);
        std::fs::write(path, &buf).map_err(|e| {
            Error::explain(ErrorType::WriteError, format!("cache meta write: {e}"))
        })?;
        Ok(())
    }
}

/// Hex-encode a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Calculate total size of files in a directory (non-recursive into subdirs).
fn dir_size(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// Parse a human-readable size string (e.g., `"1gb"`, `"500mb"`, `"100kb"`) into bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    if let Some(val) = s.strip_suffix("gb") {
        val.trim().parse::<u64>().ok().map(|v| v * 1024 * 1024 * 1024)
    } else if let Some(val) = s.strip_suffix("mb") {
        val.trim().parse::<u64>().ok().map(|v| v * 1024 * 1024)
    } else if let Some(val) = s.strip_suffix("kb") {
        val.trim().parse::<u64>().ok().map(|v| v * 1024)
    } else {
        s.parse::<u64>().ok()
    }
}

// --- Hit handler (reads body from disk) ---

struct DiskHitHandler {
    body: Vec<u8>,
    done: bool,
    range_start: usize,
    range_end: usize,
}

#[async_trait]
impl HandleHit for DiskHitHandler {
    async fn read_body(&mut self) -> Result<Option<Bytes>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        Ok(Some(Bytes::copy_from_slice(
            &self.body[self.range_start..self.range_end],
        )))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<()> {
        Ok(())
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        if start >= self.body.len() {
            return Error::e_explain(
                ErrorType::InternalError,
                format!("seek start out of range {start} >= {}", self.body.len()),
            );
        }
        self.range_start = start;
        if let Some(end) = end {
            self.range_end = std::cmp::min(self.body.len(), end);
        }
        self.done = false;
        Ok(())
    }

    fn should_count_access(&self) -> bool {
        true
    }

    fn get_eviction_weight(&self) -> usize {
        self.body.len()
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

// --- Miss handler (writes body to disk) ---

struct DiskMissHandler {
    body: Vec<u8>,
    /// Pre-serialized meta bytes (length-prefixed pair).
    meta_bytes: Vec<u8>,
    hash: String,
    root: PathBuf,
    max_size: u64,
    current_size: &'static AtomicU64,
    lru: &'static RwLock<BTreeMap<u64, String>>,
    lru_counter: &'static AtomicU64,
}

#[async_trait]
impl HandleMiss for DiskMissHandler {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> Result<()> {
        self.body.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<MissFinishType> {
        let prefix = &self.hash[..2];
        let dir = self.root.join(prefix).join(&self.hash);
        std::fs::create_dir_all(&dir).map_err(|e| {
            Error::explain(ErrorType::WriteError, format!("cache dir create: {e}"))
        })?;

        // Write body
        let body_path = dir.join("body.bin");
        std::fs::write(&body_path, &self.body).map_err(|e| {
            Error::explain(ErrorType::WriteError, format!("cache body write: {e}"))
        })?;

        // Write meta (pre-serialized)
        let meta_path = dir.join("meta.bin");
        std::fs::write(&meta_path, &self.meta_bytes).map_err(|e| {
            Error::explain(ErrorType::WriteError, format!("cache meta write: {e}"))
        })?;

        let body_size = self.body.len();
        let meta_size = std::fs::metadata(&meta_path).map(|m| m.len()).unwrap_or(0);
        let entry_size = body_size as u64 + meta_size;

        // Update size tracking
        self.current_size.fetch_add(entry_size, Ordering::Relaxed);

        // Update LRU
        let counter = self.lru_counter.fetch_add(1, Ordering::Relaxed);
        {
            let mut lru = self.lru.write();
            lru.retain(|_, v| v.as_str() != self.hash);
            lru.insert(counter, self.hash.clone());
        }

        // Evict if over budget (inline to avoid needing &'static self)
        let mut current = self.current_size.load(Ordering::Relaxed);
        if current > self.max_size {
            let mut lru = self.lru.write();
            while current > self.max_size {
                let Some((&oldest_key, oldest_hash)) = lru.iter().next() else {
                    break;
                };
                // Don't evict the entry we just wrote
                if oldest_hash == &self.hash {
                    break;
                }
                let oldest_hash = oldest_hash.clone();
                lru.remove(&oldest_key);
                let old_prefix = &oldest_hash[..2];
                let old_dir = self.root.join(old_prefix).join(&oldest_hash);
                let freed = dir_size(&old_dir);
                let _ = std::fs::remove_dir_all(&old_dir);
                current = current.saturating_sub(freed);
            }
            self.current_size.store(current, Ordering::Relaxed);
        }

        Ok(MissFinishType::Created(body_size))
    }
}

// --- Storage trait implementation ---

#[async_trait]
impl Storage for DiskCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let hash = Self::hash_key(&key.combined());
        let meta_path = self.meta_path(&hash);
        let body_path = self.body_path(&hash);

        if !meta_path.exists() || !body_path.exists() {
            return Ok(None);
        }

        let meta = Self::read_meta(&meta_path)?;
        let body = std::fs::read(&body_path).map_err(|e| {
            Error::explain(ErrorType::ReadError, format!("cache body read: {e}"))
        })?;

        self.touch_lru(&hash);

        let body_len = body.len();
        let hit_handler = DiskHitHandler {
            body,
            done: false,
            range_start: 0,
            range_end: body_len,
        };

        Ok(Some((meta, Box::new(hit_handler))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<MissHandler> {
        let hash = Self::hash_key(&key.combined());

        // Pre-serialize meta so we don't need to hold CacheMeta (not Clone)
        let (meta0, meta1) = meta.serialize()?;
        let meta0_len = (meta0.len() as u32).to_le_bytes();
        let meta1_len = (meta1.len() as u32).to_le_bytes();
        let mut meta_bytes = Vec::with_capacity(8 + meta0.len() + meta1.len());
        meta_bytes.extend_from_slice(&meta0_len);
        meta_bytes.extend_from_slice(&meta1_len);
        meta_bytes.extend_from_slice(&meta0);
        meta_bytes.extend_from_slice(&meta1);

        let miss_handler = DiskMissHandler {
            body: Vec::new(),
            meta_bytes,
            hash,
            root: self.root.clone(),
            max_size: self.max_size,
            current_size: &self.current_size,
            lru: &self.lru,
            lru_counter: &self.lru_counter,
        };
        Ok(Box::new(miss_handler))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let hash = Self::hash_key(&key.combined());
        let dir = self.entry_dir(&hash);
        if dir.exists() {
            let freed = dir_size(&dir);
            let _ = std::fs::remove_dir_all(&dir);
            self.current_size.fetch_sub(freed, Ordering::Relaxed);

            let mut lru = self.lru.write();
            lru.retain(|_, v| v.as_str() != hash);

            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let hash = Self::hash_key(&key.combined());
        let meta_path = self.meta_path(&hash);
        if meta_path.exists() {
            Self::write_meta(&meta_path, meta)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn parse_size_works() {
        assert_eq!(parse_size("1gb"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("500mb"), Some(500 * 1024 * 1024));
        assert_eq!(parse_size("100kb"), Some(100 * 1024));
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("bad"), None);
    }

    #[test]
    fn hash_key_deterministic() {
        let h1 = DiskCache::hash_key("GETlocalhost/foo");
        let h2 = DiskCache::hash_key("GETlocalhost/foo");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn entry_dir_uses_prefix() {
        let cache = DiskCache::new(PathBuf::from("/tmp/cache"), 1024 * 1024);
        let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let dir = cache.entry_dir(hash);
        assert!(dir.to_string_lossy().contains("ab"));
        assert!(dir.to_string_lossy().contains(hash));
    }

    #[test]
    fn disk_cache_write_read_meta_roundtrip() {
        use std::time::SystemTime;

        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("meta.bin");

        // Build a CacheMeta via the public constructor
        let header =
            pingora_http::ResponseHeader::build(200, None).unwrap();
        let now = SystemTime::now();
        let meta = CacheMeta::new(now, now, 0, 0, header);

        DiskCache::write_meta(&meta_path, &meta).unwrap();
        let restored = DiskCache::read_meta(&meta_path).unwrap();

        // Verify the meta survived the roundtrip (deserialize didn't error)
        // CacheMeta doesn't expose status directly; verify fresh_until survived
        assert!(restored.is_fresh(now));
    }
}
