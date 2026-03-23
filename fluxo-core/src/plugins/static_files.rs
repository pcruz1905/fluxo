//! Static file serving plugin — serves files from a directory on disk.
//!
//! Features: content-type detection, ETag, byte-range, directory listing, index files.

use serde::Deserialize;

use crate::context::RequestContext;
use crate::plugins::PluginAction;

/// Static file serving configuration.
#[derive(Debug, Deserialize)]
pub struct StaticFilesConfig {
    /// Root directory to serve files from.
    pub root: String,

    /// Index file name. Default: "index.html".
    #[serde(default = "default_index")]
    pub index: String,

    /// Enable directory listing. Default: false.
    #[serde(default)]
    pub directory_listing: bool,

    /// Custom headers to add to all static file responses.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

fn default_index() -> String {
    "index.html".to_string()
}

/// Static file serving plugin.
#[derive(Debug)]
pub struct StaticFilesPlugin {
    root: std::path::PathBuf,
    index: String,
    directory_listing: bool,
    headers: Vec<(String, String)>,
}

impl StaticFilesPlugin {
    pub fn try_new(cfg: StaticFilesConfig) -> Result<Self, String> {
        let root = std::path::PathBuf::from(&cfg.root);
        if !root.is_absolute() {
            return Err(format!(
                "static_files.root must be an absolute path, got: {}",
                cfg.root
            ));
        }
        Ok(Self {
            root,
            index: cfg.index,
            directory_listing: cfg.directory_listing,
            headers: cfg.headers.into_iter().collect(),
        })
    }

    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let path = req.uri.path();

        // Resolve the file path, preventing directory traversal
        let resolved = match self.resolve_path(path) {
            Some(p) => p,
            None => {
                ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
                return PluginAction::Handled(403);
            }
        };

        // Check if it's a directory
        if resolved.is_dir() {
            // Try index file
            let index_path = resolved.join(&self.index);
            if index_path.is_file() {
                return self.serve_file(&index_path, req, ctx);
            }
            // Directory listing
            if self.directory_listing {
                return self.serve_directory_listing(&resolved, path, ctx);
            }
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
            return PluginAction::Handled(403);
        }

        if resolved.is_file() {
            return self.serve_file(&resolved, req, ctx);
        }

        // File not found — let the request continue to upstream
        PluginAction::Continue
    }

    fn resolve_path(&self, request_path: &str) -> Option<std::path::PathBuf> {
        // Decode percent-encoding
        let decoded = percent_encoding::percent_decode_str(request_path)
            .decode_utf8_lossy()
            .into_owned();

        // Remove leading slash and join with root
        let relative = decoded.trim_start_matches('/');
        let resolved = self.root.join(relative);

        // Canonicalize to prevent traversal attacks (.. components)
        // If the file doesn't exist yet, at least check the parent
        let canonical = if resolved.exists() {
            resolved.canonicalize().ok()?
        } else {
            // Check parent exists and is within root
            let parent = resolved.parent()?;
            if parent.exists() {
                let canonical_parent = parent.canonicalize().ok()?;
                let canonical_root = self.root.canonicalize().ok()?;
                if !canonical_parent.starts_with(&canonical_root) {
                    return None;
                }
                return None; // File doesn't exist
            }
            return None;
        };

        let canonical_root = self.root.canonicalize().ok()?;
        if canonical.starts_with(&canonical_root) {
            Some(canonical)
        } else {
            None // Traversal attempt
        }
    }

    fn serve_file(
        &self,
        path: &std::path::Path,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => {
                return PluginAction::Continue; // Fall through
            }
        };

        let size = metadata.len();

        // ETag from modification time + size
        let etag = if let Ok(modified) = metadata.modified() {
            let dur = modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            format!("\"{:x}-{:x}\"", dur.as_secs(), size)
        } else {
            format!("\"{:x}\"", size)
        };

        // Check If-None-Match for 304
        if let Some(inm) = req
            .headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok())
        {
            if inm == etag || inm == "*" {
                ctx.plugin_response = Some(crate::context::PluginResponse::Static {
                    status: 304,
                    body: None,
                    content_type: None,
                });
                return PluginAction::Handled(304);
            }
        }

        // Read the file
        let body = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => {
                ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 500 });
                return PluginAction::Handled(500);
            }
        };

        // Content-Type detection
        let content_type = guess_content_type(path);

        // Check for byte-range request
        if let Some(range_header) = req.headers.get("range").and_then(|v| v.to_str().ok()) {
            if let Some((start, end)) = parse_byte_range(range_header, size) {
                let slice = &body[start as usize..=end as usize];
                let range_body = String::from_utf8_lossy(slice).into_owned();
                // Store range info in extensions for response phase
                ctx.set_extension("static_file_etag", serde_json::json!(etag));
                ctx.set_extension(
                    "static_file_range",
                    serde_json::json!(format!("bytes {start}-{end}/{size}")),
                );
                ctx.plugin_response = Some(crate::context::PluginResponse::Static {
                    status: 206,
                    body: Some(range_body),
                    content_type: Some(content_type),
                });
                return PluginAction::Handled(206);
            }
        }

        ctx.set_extension("static_file_etag", serde_json::json!(etag));
        ctx.plugin_response = Some(crate::context::PluginResponse::Static {
            status: 200,
            body: Some(String::from_utf8_lossy(&body).into_owned()),
            content_type: Some(content_type),
        });
        PluginAction::Handled(200)
    }

    fn serve_directory_listing(
        &self,
        dir: &std::path::Path,
        request_path: &str,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let mut entries = Vec::new();
        let read_dir = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => {
                ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 500 });
                return PluginAction::Handled(500);
            }
        };

        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
            let display_name = if is_dir {
                format!("{name}/")
            } else {
                name.clone()
            };
            let href = if request_path.ends_with('/') {
                format!("{request_path}{name}")
            } else {
                format!("{request_path}/{name}")
            };
            entries.push(format!("<li><a href=\"{href}\">{display_name}</a></li>"));
        }

        entries.sort();
        let body = format!(
            "<!DOCTYPE html><html><head><title>Index of {request_path}</title></head><body><h1>Index of {request_path}</h1><ul>{}</ul></body></html>",
            entries.join("")
        );

        ctx.plugin_response = Some(crate::context::PluginResponse::Static {
            status: 200,
            body: Some(body),
            content_type: Some("text/html; charset=utf-8".to_string()),
        });
        PluginAction::Handled(200)
    }
}

/// Guess content type from file extension.
fn guess_content_type(path: &std::path::Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Parse a simple byte range header: "bytes=start-end" or "bytes=start-".
fn parse_byte_range(header: &str, total_size: u64) -> Option<(u64, u64)> {
    let range = header.strip_prefix("bytes=")?;
    let (start_str, end_str) = range.split_once('-')?;
    let start: u64 = if start_str.is_empty() {
        0
    } else {
        start_str.parse().ok()?
    };
    let end: u64 = if end_str.is_empty() {
        total_size.checked_sub(1)?
    } else {
        end_str.parse().ok()?
    };
    if start <= end && end < total_size {
        Some((start, end))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn guess_content_type_html() {
        let path = std::path::Path::new("/var/www/index.html");
        assert!(guess_content_type(path).contains("text/html"));
    }

    #[test]
    fn guess_content_type_unknown() {
        let path = std::path::Path::new("/var/www/file.xyz");
        assert_eq!(guess_content_type(path), "application/octet-stream");
    }

    #[test]
    fn parse_byte_range_full() {
        assert_eq!(parse_byte_range("bytes=0-499", 1000), Some((0, 499)));
    }

    #[test]
    fn parse_byte_range_open_end() {
        assert_eq!(parse_byte_range("bytes=500-", 1000), Some((500, 999)));
    }

    #[test]
    fn parse_byte_range_invalid() {
        assert_eq!(parse_byte_range("bytes=500-1500", 1000), None);
    }

    #[test]
    fn relative_root_rejected() {
        let result = StaticFilesPlugin::try_new(StaticFilesConfig {
            root: "relative/path".to_string(),
            index: "index.html".to_string(),
            directory_listing: false,
            headers: std::collections::HashMap::new(),
        });
        assert!(result.is_err());
    }
}
