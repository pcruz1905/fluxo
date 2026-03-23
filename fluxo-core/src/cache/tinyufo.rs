//! TinyUFO-based in-memory cache storage implementing Pingora's `Storage` trait.
//!
//! Uses `TinyLFU` admission + S3-FIFO eviction for better hit rates on
//! frequency-skewed workloads compared to pure LRU.

use std::any::Any;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_cache::CacheKey;
use pingora_cache::key::{CacheHashKey, CompactCacheKey};
use pingora_cache::meta::CacheMeta;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
use pingora_cache::trace::SpanHandle;
use pingora_core::{Error, ErrorType, Result};
use sha2::{Digest, Sha256};

/// In-memory cache backed by `TinyUfo` (`TinyLFU` + S3-FIFO eviction).
///
/// Unlike `DiskCache`, entries do not survive restarts but have lower latency
/// and better hit rates for skewed access patterns.
pub struct TinyUfoCache {
    inner: tinyufo::TinyUfo<u64, CacheEntry>,
}

/// A cached entry holding serialized metadata and the response body.
#[derive(Clone)]
struct CacheEntry {
    /// Serialized `CacheMeta` (length-prefixed meta0 + meta1 pair).
    meta_bytes: Vec<u8>,
    /// Response body bytes.
    body: Bytes,
}

impl TinyUfoCache {
    /// Create a new `TinyUfoCache` with the given capacity (max entries).
    ///
    /// `capacity` is both the weight limit and estimated size hint for the
    /// internal data structures.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: tinyufo::TinyUfo::new(capacity, capacity),
        }
    }

    /// Hash a combined cache key string into a `u64` for `TinyUFO` lookup.
    fn hash_key(combined: &str) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let result = hasher.finalize();
        // Take the first 8 bytes of the SHA-256 as a u64
        u64::from_le_bytes([
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
        ])
    }

    /// Deserialize `CacheMeta` from the length-prefixed binary format.
    fn deserialize_meta(data: &[u8]) -> Result<CacheMeta> {
        if data.len() < 8 {
            return Error::e_explain(ErrorType::ReadError, "tinyufo meta too short");
        }
        let meta0_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let meta1_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if data.len() < 8 + meta0_len + meta1_len {
            return Error::e_explain(ErrorType::ReadError, "tinyufo meta truncated");
        }
        let meta0 = data[8..8 + meta0_len].to_vec();
        let meta1 = data[8 + meta0_len..8 + meta0_len + meta1_len].to_vec();
        CacheMeta::deserialize(&meta0, &meta1)
    }

    /// Serialize `CacheMeta` into the length-prefixed binary format.
    fn serialize_meta(meta: &CacheMeta) -> Result<Vec<u8>> {
        let (meta0, meta1) = meta.serialize()?;
        let meta0_len = (meta0.len() as u32).to_le_bytes();
        let meta1_len = (meta1.len() as u32).to_le_bytes();
        let mut buf = Vec::with_capacity(8 + meta0.len() + meta1.len());
        buf.extend_from_slice(&meta0_len);
        buf.extend_from_slice(&meta1_len);
        buf.extend_from_slice(&meta0);
        buf.extend_from_slice(&meta1);
        Ok(buf)
    }
}

// --- Hit handler (reads body from in-memory entry) ---

struct TinyUfoHitHandler {
    body: Bytes,
    done: bool,
    range_start: usize,
    range_end: usize,
}

#[async_trait]
impl HandleHit for TinyUfoHitHandler {
    async fn read_body(&mut self) -> Result<Option<Bytes>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        Ok(Some(self.body.slice(self.range_start..self.range_end)))
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

// --- Miss handler (writes body into TinyUFO) ---

struct TinyUfoMissHandler {
    body: Vec<u8>,
    meta_bytes: Vec<u8>,
    key: u64,
    cache: &'static tinyufo::TinyUfo<u64, CacheEntry>,
}

#[async_trait]
impl HandleMiss for TinyUfoMissHandler {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> Result<()> {
        self.body.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<MissFinishType> {
        let body_size = self.body.len();
        let entry = CacheEntry {
            meta_bytes: self.meta_bytes,
            body: Bytes::from(self.body),
        };
        // Weight = 1 per entry (capacity counts entries, not bytes).
        let _evicted = self.cache.put(self.key, entry, 1);
        Ok(MissFinishType::Created(body_size))
    }
}

// --- Storage trait implementation ---

#[async_trait]
impl Storage for TinyUfoCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let hash = Self::hash_key(&key.combined());
        let Some(entry) = self.inner.get(&hash) else {
            return Ok(None);
        };

        let meta = Self::deserialize_meta(&entry.meta_bytes)?;
        let body_len = entry.body.len();
        let hit_handler = TinyUfoHitHandler {
            body: entry.body,
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
        let meta_bytes = Self::serialize_meta(meta)?;

        let miss_handler = TinyUfoMissHandler {
            body: Vec::new(),
            meta_bytes,
            key: hash,
            cache: &self.inner,
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
        Ok(self.inner.remove(&hash).is_some())
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let hash = Self::hash_key(&key.combined());
        let Some(mut entry) = self.inner.get(&hash) else {
            return Ok(false);
        };
        entry.meta_bytes = Self::serialize_meta(meta)?;
        // Re-insert with updated meta (weight 1).
        let _evicted = self.inner.put(hash, entry, 1);
        Ok(true)
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
    fn hash_key_deterministic() {
        let h1 = TinyUfoCache::hash_key("GETlocalhost/foo");
        let h2 = TinyUfoCache::hash_key("GETlocalhost/foo");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_key_different_for_different_inputs() {
        let h1 = TinyUfoCache::hash_key("GETlocalhost/foo");
        let h2 = TinyUfoCache::hash_key("POSTlocalhost/foo");
        assert_ne!(h1, h2);
    }

    #[test]
    fn new_creates_cache() {
        let cache = TinyUfoCache::new(100);
        // Verify basic get returns None for missing key
        assert!(cache.inner.get(&42).is_none());
    }

    #[test]
    fn put_and_get_entry() {
        let cache = TinyUfoCache::new(100);
        let entry = CacheEntry {
            meta_bytes: vec![0, 0, 0, 0, 0, 0, 0, 0],
            body: Bytes::from_static(b"hello"),
        };
        let _evicted = cache.inner.put(42, entry, 1);
        let retrieved = cache.inner.get(&42);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().body, Bytes::from_static(b"hello"));
    }

    #[test]
    fn get_miss_returns_none() {
        let cache = TinyUfoCache::new(100);
        assert!(cache.inner.get(&999).is_none());
    }

    #[test]
    fn remove_entry() {
        let cache = TinyUfoCache::new(100);
        let entry = CacheEntry {
            meta_bytes: vec![0, 0, 0, 0, 0, 0, 0, 0],
            body: Bytes::from_static(b"data"),
        };
        let _evicted = cache.inner.put(7, entry, 1);
        assert!(cache.inner.get(&7).is_some());
        let removed = cache.inner.remove(&7);
        assert!(removed.is_some());
        assert!(cache.inner.get(&7).is_none());
    }

    #[test]
    fn serialize_deserialize_meta_roundtrip() {
        use std::time::SystemTime;

        let header = pingora_http::ResponseHeader::build(200, None).unwrap();
        let now = SystemTime::now();
        let meta = CacheMeta::new(now, now, 0, 0, header);

        let serialized = TinyUfoCache::serialize_meta(&meta).unwrap();
        let restored = TinyUfoCache::deserialize_meta(&serialized).unwrap();
        assert!(restored.is_fresh(now));
    }

    #[test]
    fn deserialize_meta_too_short() {
        let result = TinyUfoCache::deserialize_meta(&[0u8; 4]);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_meta_truncated() {
        let mut data = Vec::new();
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let result = TinyUfoCache::deserialize_meta(&data);
        assert!(result.is_err());
    }
}
