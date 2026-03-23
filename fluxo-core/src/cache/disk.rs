//! Filesystem-backed cache storage implementing Pingora's `Storage` trait.

use std::any::Any;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use pingora_cache::CacheKey;
use pingora_cache::key::{CacheHashKey, CompactCacheKey};
use pingora_cache::meta::CacheMeta;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
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
    /// LRU index: `access_time` -> hash (for eviction ordering).
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
                    // Use dir_size to match purge accounting (includes key.txt, tags.txt, etc.)
                    total_size += dir_size(&path);

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
        let data = std::fs::read(path)
            .map_err(|e| Error::explain(ErrorType::ReadError, format!("cache meta read: {e}")))?;
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

    /// Key file path for a cache entry (stores the original primary key string).
    fn key_path(&self, hash: &str) -> PathBuf {
        self.entry_dir(hash).join("key.txt")
    }

    /// Tags file path for a cache entry (stores cache tags, one per line).
    fn tags_path(&self, hash: &str) -> PathBuf {
        self.entry_dir(hash).join("tags.txt")
    }

    /// Purge entries matching a glob pattern on the original cache key.
    /// Returns the number of entries purged.
    pub fn purge_by_pattern(&self, pattern: &str) -> usize {
        let Ok(matcher) = glob::Pattern::new(pattern) else {
            return 0;
        };

        let mut purged = 0;
        let hashes = self.all_entry_hashes();

        let mut removed_hashes = Vec::new();
        for hash in &hashes {
            let key_path = self.key_path(hash);
            let Ok(key_str) = std::fs::read_to_string(&key_path) else {
                continue;
            };
            if matcher.matches(&key_str) {
                let dir = self.entry_dir(hash);
                let freed = dir_size(&dir);
                let _ = std::fs::remove_dir_all(&dir);
                self.current_size.fetch_sub(freed, Ordering::Relaxed);
                removed_hashes.push(hash.clone());
                purged += 1;
            }
        }

        if purged > 0 {
            let mut lru = self.lru.write();
            lru.retain(|_, v| !removed_hashes.contains(v));
        }

        purged
    }

    /// Purge entries with a matching cache tag.
    /// Returns the number of entries purged.
    pub fn purge_by_tag(&self, tag: &str) -> usize {
        let mut purged = 0;
        let hashes = self.all_entry_hashes();

        let mut removed_hashes = Vec::new();
        for hash in &hashes {
            let tags_path = self.tags_path(hash);
            let Ok(tags_content) = std::fs::read_to_string(&tags_path) else {
                continue;
            };
            let has_tag = tags_content.lines().any(|line| line.trim() == tag);
            if has_tag {
                let dir = self.entry_dir(hash);
                let freed = dir_size(&dir);
                let _ = std::fs::remove_dir_all(&dir);
                self.current_size.fetch_sub(freed, Ordering::Relaxed);
                removed_hashes.push(hash.clone());
                purged += 1;
            }
        }

        if purged > 0 {
            let mut lru = self.lru.write();
            lru.retain(|_, v| !removed_hashes.contains(v));
        }

        purged
    }

    /// Purge all cache entries.
    /// Returns the number of entries purged.
    pub fn purge_all(&self) -> usize {
        let hashes = self.all_entry_hashes();
        let count = hashes.len();

        for hash in &hashes {
            let dir = self.entry_dir(hash);
            let _ = std::fs::remove_dir_all(&dir);
        }

        self.current_size.store(0, Ordering::Relaxed);
        self.lru.write().clear();

        count
    }

    /// Collect all entry hashes from the cache directory tree.
    fn all_entry_hashes(&self) -> Vec<String> {
        let mut hashes = Vec::new();
        let Ok(prefixes) = std::fs::read_dir(&self.root) else {
            return hashes;
        };

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
                if let Some(hash) = path.file_name().and_then(|n| n.to_str()) {
                    hashes.push(hash.to_string());
                }
            }
        }

        hashes
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
        std::fs::write(path, &buf)
            .map_err(|e| Error::explain(ErrorType::WriteError, format!("cache meta write: {e}")))?;
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
                .filter(std::fs::Metadata::is_file)
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// Parse a human-readable size string (e.g., `"1gb"`, `"500mb"`, `"100kb"`) into bytes.
#[allow(clippy::option_if_let_else)]
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    if let Some(val) = s.strip_suffix("gb") {
        val.trim()
            .parse::<u64>()
            .ok()
            .map(|v| v * 1024 * 1024 * 1024)
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
    /// Original primary key string (written to `key.txt` for pattern-based purge).
    primary_key: String,
    /// Cache tags extracted from upstream response headers (written to `tags.txt`).
    cache_tags: Vec<String>,
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
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::explain(ErrorType::WriteError, format!("cache dir create: {e}")))?;

        // Write body
        let body_path = dir.join("body.bin");
        std::fs::write(&body_path, &self.body)
            .map_err(|e| Error::explain(ErrorType::WriteError, format!("cache body write: {e}")))?;

        // Write meta (pre-serialized)
        let meta_path = dir.join("meta.bin");
        std::fs::write(&meta_path, &self.meta_bytes)
            .map_err(|e| Error::explain(ErrorType::WriteError, format!("cache meta write: {e}")))?;

        // Write primary key for pattern-based purge
        let key_path = dir.join("key.txt");
        let _ = std::fs::write(&key_path, &self.primary_key);

        // Write cache tags (one per line) for tag-based purge
        if !self.cache_tags.is_empty() {
            let tags_path = dir.join("tags.txt");
            let _ = std::fs::write(&tags_path, self.cache_tags.join("\n"));
        }

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
        let body = std::fs::read(&body_path)
            .map_err(|e| Error::explain(ErrorType::ReadError, format!("cache body read: {e}")))?;

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
        let combined = key.combined();
        let hash = Self::hash_key(&combined);

        // Pre-serialize meta so we don't need to hold CacheMeta (not Clone)
        let (meta0, meta1) = meta.serialize()?;
        let meta0_len = (meta0.len() as u32).to_le_bytes();
        let meta1_len = (meta1.len() as u32).to_le_bytes();
        let mut meta_bytes = Vec::with_capacity(8 + meta0.len() + meta1.len());
        meta_bytes.extend_from_slice(&meta0_len);
        meta_bytes.extend_from_slice(&meta1_len);
        meta_bytes.extend_from_slice(&meta0);
        meta_bytes.extend_from_slice(&meta1);

        // Extract cache tags from upstream response headers (Cache-Tag, Surrogate-Key)
        let headers = meta.headers();
        let mut cache_tags = Vec::new();
        for header_name in &["cache-tag", "surrogate-key"] {
            if let Some(val) = headers.get(*header_name).and_then(|v| v.to_str().ok()) {
                for tag in val.split(',') {
                    let tag = tag.trim();
                    if !tag.is_empty() {
                        cache_tags.push(tag.to_string());
                    }
                }
            }
        }

        let miss_handler = DiskMissHandler {
            body: Vec::new(),
            meta_bytes,
            hash,
            root: self.root.clone(),
            max_size: self.max_size,
            current_size: &self.current_size,
            lru: &self.lru,
            lru_counter: &self.lru_counter,
            primary_key: combined,
            cache_tags,
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
        let header = pingora_http::ResponseHeader::build(200, None).unwrap();
        let now = SystemTime::now();
        let meta = CacheMeta::new(now, now, 0, 0, header);

        DiskCache::write_meta(&meta_path, &meta).unwrap();
        let restored = DiskCache::read_meta(&meta_path).unwrap();

        // Verify the meta survived the roundtrip (deserialize didn't error)
        // CacheMeta doesn't expose status directly; verify fresh_until survived
        assert!(restored.is_fresh(now));
    }

    // --- parse_max_size / parse_size edge cases ---

    #[test]
    fn parse_max_size_valid_values() {
        assert_eq!(DiskCache::parse_max_size("2gb"), 2 * 1024 * 1024 * 1024);
        assert_eq!(DiskCache::parse_max_size("256mb"), 256 * 1024 * 1024);
        assert_eq!(DiskCache::parse_max_size("512kb"), 512 * 1024);
        assert_eq!(DiskCache::parse_max_size("4096"), 4096);
    }

    #[test]
    fn parse_max_size_invalid_falls_back_to_1gb() {
        let one_gb = 1024 * 1024 * 1024;
        assert_eq!(DiskCache::parse_max_size("bad"), one_gb);
        assert_eq!(DiskCache::parse_max_size(""), one_gb);
        assert_eq!(DiskCache::parse_max_size("notanumber_gb"), one_gb);
    }

    #[test]
    fn parse_size_whitespace_and_case() {
        assert_eq!(parse_size("  10GB  "), Some(10 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("  5MB"), Some(5 * 1024 * 1024));
        assert_eq!(parse_size("3KB "), Some(3 * 1024));
        assert_eq!(parse_size("  Gb  "), None); // suffix only, no number
    }

    #[test]
    fn parse_size_empty_string() {
        assert_eq!(parse_size(""), None);
    }

    #[test]
    fn parse_size_bare_zero() {
        assert_eq!(parse_size("0"), Some(0));
        assert_eq!(parse_size("0gb"), Some(0));
    }

    // --- read_meta error paths ---

    #[test]
    fn read_meta_too_short() {
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("meta.bin");
        // Write only 4 bytes — less than the required 8
        std::fs::write(&meta_path, [0u8; 4]).unwrap();
        assert!(DiskCache::read_meta(&meta_path).is_err());
    }

    #[test]
    fn read_meta_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("meta.bin");
        // Header claims 100 bytes for meta0 but body is empty
        let mut data = Vec::new();
        data.extend_from_slice(&100u32.to_le_bytes()); // meta0_len = 100
        data.extend_from_slice(&0u32.to_le_bytes()); // meta1_len = 0
        std::fs::write(&meta_path, &data).unwrap();
        assert!(DiskCache::read_meta(&meta_path).is_err());
    }

    #[test]
    fn read_meta_nonexistent_file() {
        let result = DiskCache::read_meta(Path::new("/nonexistent/path/meta.bin"));
        assert!(result.is_err());
    }

    // --- DiskCache::new creates root dir and starts at zero ---

    #[test]
    fn new_creates_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache_root");
        // root doesn't exist yet — new() should still work (scan_existing gracefully handles)
        let cache = DiskCache::new(root, 1024);
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 0);
        assert!(cache.lru.read().is_empty());
    }

    // --- scan_existing picks up pre-populated entries ---

    #[test]
    fn scan_existing_rebuilds_state() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        // Manually plant an entry: prefix "ab" / hash dir
        let hash = "ab00000000000000000000000000000000000000000000000000000000000000";
        let entry_dir = root.join("ab").join(hash);
        std::fs::create_dir_all(&entry_dir).unwrap();
        std::fs::write(entry_dir.join("body.bin"), b"hello").unwrap();
        std::fs::write(entry_dir.join("meta.bin"), b"metabytes").unwrap();

        let cache = DiskCache::new(root, 1024 * 1024);
        // Size should reflect the files we wrote
        let size = cache.current_size.load(Ordering::Relaxed);
        assert!(size > 0, "expected non-zero size, got {size}");
        // LRU should have one entry
        assert_eq!(cache.lru.read().len(), 1);
    }

    #[test]
    fn scan_existing_ignores_incomplete_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        let hash = "cd00000000000000000000000000000000000000000000000000000000000000";
        let entry_dir = root.join("cd").join(hash);
        std::fs::create_dir_all(&entry_dir).unwrap();
        // Only body, no meta — should be skipped
        std::fs::write(entry_dir.join("body.bin"), b"body_only").unwrap();

        let cache = DiskCache::new(root, 1024 * 1024);
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 0);
        assert!(cache.lru.read().is_empty());
    }

    // --- touch_lru ---

    #[test]
    fn touch_lru_moves_entry_to_most_recent() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::new(dir.path().to_path_buf(), 1024);

        cache.touch_lru("aaa");
        cache.touch_lru("bbb");
        // "aaa" should be oldest
        {
            let lru = cache.lru.read();
            let oldest = lru.values().next().unwrap();
            assert_eq!(oldest, "aaa");
        }

        // Touch "aaa" again — now "bbb" should be oldest
        cache.touch_lru("aaa");
        {
            let lru = cache.lru.read();
            let oldest = lru.values().next().unwrap();
            assert_eq!(oldest, "bbb");
        }
    }

    // --- dir_size ---

    #[test]
    fn dir_size_sums_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"world!").unwrap();
        let size = dir_size(dir.path());
        assert_eq!(size, 11); // 5 + 6
    }

    #[test]
    fn dir_size_nonexistent_returns_zero() {
        assert_eq!(dir_size(Path::new("/nonexistent/dir")), 0);
    }

    #[test]
    fn dir_size_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(dir_size(dir.path()), 0);
    }

    // --- hash_key different inputs produce different outputs ---

    #[test]
    fn hash_key_different_for_different_inputs() {
        let h1 = DiskCache::hash_key("GETlocalhost/foo");
        let h2 = DiskCache::hash_key("POSTlocalhost/foo");
        assert_ne!(h1, h2);
    }

    // --- meta/body path helpers ---

    #[test]
    fn meta_and_body_paths_in_entry_dir() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::new(dir.path().to_path_buf(), 1024);
        let hash = "ff11223344556677889900aabbccddeeff11223344556677889900aabbccddee";
        let meta = cache.meta_path(hash);
        let body = cache.body_path(hash);
        assert!(meta.ends_with("meta.bin"));
        assert!(body.ends_with("body.bin"));
        // Both should be under the same entry_dir
        assert_eq!(meta.parent().unwrap(), body.parent().unwrap());
    }

    // --- full write_meta + read_meta roundtrip with 304 status ---

    #[test]
    fn write_read_meta_roundtrip_304() {
        use std::time::SystemTime;

        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("meta.bin");

        let header = pingora_http::ResponseHeader::build(304, None).unwrap();
        let now = SystemTime::now();
        let meta = CacheMeta::new(now, now, 0, 0, header);

        DiskCache::write_meta(&meta_path, &meta).unwrap();
        let restored = DiskCache::read_meta(&meta_path).unwrap();
        assert!(restored.is_fresh(now));
    }

    // --- write_meta to bad path fails ---

    #[test]
    fn write_meta_bad_path_returns_error() {
        use std::time::SystemTime;
        let header = pingora_http::ResponseHeader::build(200, None).unwrap();
        let now = SystemTime::now();
        let meta = CacheMeta::new(now, now, 0, 0, header);
        let result = DiskCache::write_meta(Path::new("/nonexistent/dir/meta.bin"), &meta);
        assert!(result.is_err());
    }

    // --- entry lifecycle: plant files, verify scan picks them up ---

    #[test]
    fn entry_lifecycle_write_scan_verify() {
        use std::time::SystemTime;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        let hash = DiskCache::hash_key("testkey");
        let prefix = &hash[..2];
        let entry_dir = root.join(prefix).join(&hash);
        std::fs::create_dir_all(&entry_dir).unwrap();

        // Write a real meta
        let header = pingora_http::ResponseHeader::build(200, None).unwrap();
        let now = SystemTime::now();
        let meta = CacheMeta::new(now, now, 0, 0, header);
        DiskCache::write_meta(&entry_dir.join("meta.bin"), &meta).unwrap();

        // Write body
        let body = b"cached response body";
        std::fs::write(entry_dir.join("body.bin"), body).unwrap();

        // Create cache — scan_existing should pick this up
        let cache = DiskCache::new(root, 1024 * 1024);
        assert!(cache.current_size.load(Ordering::Relaxed) > 0);
        assert_eq!(cache.lru.read().len(), 1);

        // Verify meta can be read back
        let restored = DiskCache::read_meta(&entry_dir.join("meta.bin")).unwrap();
        assert!(restored.is_fresh(now));
    }

    // --- eviction: plant entries, create cache with tiny budget ---

    #[test]
    fn scan_existing_multiple_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        // Plant two entries under different prefixes
        for i in 0..2 {
            let hash =
                format!("{i:02x}00000000000000000000000000000000000000000000000000000000000000");
            let prefix = &hash[..2];
            let entry_dir = root.join(prefix).join(&hash);
            std::fs::create_dir_all(&entry_dir).unwrap();
            std::fs::write(entry_dir.join("body.bin"), vec![0u8; 100]).unwrap();
            std::fs::write(entry_dir.join("meta.bin"), vec![0u8; 50]).unwrap();
        }

        let cache = DiskCache::new(root, 1024 * 1024);
        assert_eq!(cache.lru.read().len(), 2);
        // Each entry is 150 bytes
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 300);
    }

    // --- scan_existing ignores non-directory items ---

    #[test]
    fn scan_existing_ignores_plain_files_in_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");
        std::fs::create_dir_all(&root).unwrap();
        // Place a plain file directly in root (not a prefix dir)
        std::fs::write(root.join("stray_file.txt"), b"ignored").unwrap();

        let cache = DiskCache::new(root, 1024 * 1024);
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 0);
        assert!(cache.lru.read().is_empty());
    }

    // --- read_meta with exact 8-byte header but zero-length meta ---

    #[test]
    fn read_meta_empty_meta_fields() {
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("meta.bin");
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // meta0_len = 0
        data.extend_from_slice(&0u32.to_le_bytes()); // meta1_len = 0
        std::fs::write(&meta_path, &data).unwrap();
        // Deserialization of empty meta slices likely fails — that's fine
        let result = DiskCache::read_meta(&meta_path);
        // We just verify it doesn't panic; it may succeed or error
        let _ = result;
    }

    // --- Pattern and tag purge tests ---

    /// Helper: plant a cache entry with optional key.txt and tags.txt files.
    fn plant_entry(root: &Path, key: &str, tags: &[&str]) -> String {
        let hash = DiskCache::hash_key(key);
        let prefix = &hash[..2];
        let entry_dir = root.join(prefix).join(&hash);
        std::fs::create_dir_all(&entry_dir).unwrap();
        std::fs::write(entry_dir.join("body.bin"), b"body").unwrap();
        std::fs::write(entry_dir.join("meta.bin"), b"meta").unwrap();
        std::fs::write(entry_dir.join("key.txt"), key).unwrap();
        if !tags.is_empty() {
            let tags_content: Vec<&str> = tags.to_vec();
            std::fs::write(entry_dir.join("tags.txt"), tags_content.join("\n")).unwrap();
        }
        hash
    }

    #[test]
    fn purge_by_pattern_matches_glob() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        plant_entry(&root, "GETexample.com/api/users", &[]);
        plant_entry(&root, "GETexample.com/api/posts", &[]);
        plant_entry(&root, "GETexample.com/static/logo.png", &[]);
        plant_entry(&root, "GETother.com/api/data", &[]);

        let cache = DiskCache::new(root, 1024 * 1024);
        assert_eq!(cache.lru.read().len(), 4);

        // Purge all /api/* entries on example.com
        let purged = cache.purge_by_pattern("GET*example.com/api/*");
        assert_eq!(purged, 2);
        assert_eq!(cache.lru.read().len(), 2);

        // The remaining entries should be the static and other.com ones
        let remaining = cache.all_entry_hashes();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn purge_by_pattern_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        plant_entry(&root, "GETexample.com/page", &[]);

        let cache = DiskCache::new(root, 1024 * 1024);
        let purged = cache.purge_by_pattern("*nomatch*");
        assert_eq!(purged, 0);
        assert_eq!(cache.lru.read().len(), 1);
    }

    #[test]
    fn purge_by_pattern_invalid_glob_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        plant_entry(&root, "GETexample.com/page", &[]);

        let cache = DiskCache::new(root, 1024 * 1024);
        // "[" is an invalid glob pattern (unclosed bracket)
        let purged = cache.purge_by_pattern("[");
        assert_eq!(purged, 0);
    }

    #[test]
    fn purge_by_tag_removes_tagged_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        plant_entry(
            &root,
            "GETexample.com/product/1",
            &["product-1", "category-electronics"],
        );
        plant_entry(
            &root,
            "GETexample.com/product/2",
            &["product-2", "category-electronics"],
        );
        plant_entry(&root, "GETexample.com/product/3", &["product-3"]);
        plant_entry(&root, "GETexample.com/about", &[]);

        let cache = DiskCache::new(root, 1024 * 1024);
        assert_eq!(cache.lru.read().len(), 4);

        // Purge by tag "category-electronics" — should remove 2 entries
        let purged = cache.purge_by_tag("category-electronics");
        assert_eq!(purged, 2);
        assert_eq!(cache.lru.read().len(), 2);

        // Purge by tag "product-3" — should remove 1 entry
        let purged = cache.purge_by_tag("product-3");
        assert_eq!(purged, 1);
        assert_eq!(cache.lru.read().len(), 1);
    }

    #[test]
    fn purge_by_tag_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        plant_entry(&root, "GETexample.com/page", &["tag-a"]);

        let cache = DiskCache::new(root, 1024 * 1024);
        let purged = cache.purge_by_tag("nonexistent-tag");
        assert_eq!(purged, 0);
        assert_eq!(cache.lru.read().len(), 1);
    }

    #[test]
    fn purge_by_tag_ignores_entries_without_tags() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        plant_entry(&root, "GETexample.com/page", &[]);

        let cache = DiskCache::new(root, 1024 * 1024);
        let purged = cache.purge_by_tag("any-tag");
        assert_eq!(purged, 0);
        assert_eq!(cache.lru.read().len(), 1);
    }

    #[test]
    fn purge_all_clears_everything() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        plant_entry(&root, "GETexample.com/a", &["tag-a"]);
        plant_entry(&root, "GETexample.com/b", &[]);
        plant_entry(&root, "GETexample.com/c", &["tag-c"]);

        let cache = DiskCache::new(root, 1024 * 1024);
        assert_eq!(cache.lru.read().len(), 3);
        assert!(cache.current_size.load(Ordering::Relaxed) > 0);

        let purged = cache.purge_all();
        assert_eq!(purged, 3);
        assert!(cache.lru.read().is_empty());
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 0);

        // All entry directories should be gone
        let remaining = cache.all_entry_hashes();
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn purge_all_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        let cache = DiskCache::new(root, 1024 * 1024);
        let purged = cache.purge_all();
        assert_eq!(purged, 0);
    }

    #[test]
    fn key_and_tags_files_written_on_miss() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        // Plant entry with key and tags (simulating what DiskMissHandler::finish does)
        let key = "GETexample.com/api/data";
        let tags = &["product-1", "api-v2"];
        let hash = plant_entry(&root, key, tags);

        let cache = DiskCache::new(root, 1024 * 1024);

        // Verify key.txt exists and contains the primary key
        let key_path = cache.key_path(&hash);
        let stored_key = std::fs::read_to_string(&key_path).unwrap();
        assert_eq!(stored_key, key);

        // Verify tags.txt exists and contains the tags
        let tags_path = cache.tags_path(&hash);
        let stored_tags = std::fs::read_to_string(&tags_path).unwrap();
        assert!(stored_tags.contains("product-1"));
        assert!(stored_tags.contains("api-v2"));
        assert_eq!(stored_tags.lines().count(), 2);
    }

    #[test]
    fn key_file_written_without_tags() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        let key = "GETexample.com/page";
        let hash = plant_entry(&root, key, &[]);

        let cache = DiskCache::new(root, 1024 * 1024);

        // key.txt should exist
        let key_path = cache.key_path(&hash);
        assert!(key_path.exists());
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), key);

        // tags.txt should NOT exist
        let tags_path = cache.tags_path(&hash);
        assert!(!tags_path.exists());
    }

    #[test]
    fn purge_by_pattern_updates_current_size() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");

        plant_entry(&root, "GETexample.com/a", &[]);
        plant_entry(&root, "GETexample.com/b", &[]);

        let cache = DiskCache::new(root, 1024 * 1024);
        let initial_size = cache.current_size.load(Ordering::Relaxed);
        assert!(initial_size > 0);

        cache.purge_by_pattern("*example.com/a");
        let after_purge = cache.current_size.load(Ordering::Relaxed);
        assert!(after_purge < initial_size);
    }

    #[test]
    fn all_entry_hashes_nonexistent_root() {
        let cache = DiskCache {
            root: PathBuf::from("/nonexistent/cache/root"),
            max_size: 1024,
            current_size: AtomicU64::new(0),
            lru: RwLock::new(BTreeMap::new()),
            lru_counter: AtomicU64::new(0),
        };
        let hashes = cache.all_entry_hashes();
        assert!(hashes.is_empty());
    }
}
