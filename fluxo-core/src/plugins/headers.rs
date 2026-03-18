//! Headers plugin — add, set, and remove request/response headers.

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct HeadersConfig {
    /// Headers to set on upstream requests.
    #[serde(default)]
    pub request_set: HashMap<String, String>,
    /// Headers to remove from upstream requests.
    #[serde(default)]
    pub request_remove: Vec<String>,
    /// Headers to set on downstream responses.
    #[serde(default)]
    pub response_set: HashMap<String, String>,
    /// Headers to remove from downstream responses.
    #[serde(default)]
    pub response_remove: Vec<String>,
}

#[derive(Debug)]
pub struct HeadersPlugin {
    pub config: HeadersConfig,
}

impl HeadersPlugin {
    pub fn new(config: HeadersConfig) -> Self {
        Self { config }
    }

    pub fn on_upstream_request(
        &self,
        req: &mut pingora_http::RequestHeader,
        _ctx: &crate::context::RequestContext,
    ) {
        for (name, value) in &self.config.request_set {
            let _ = req.insert_header(name.clone(), value.clone());
        }
        for name in &self.config.request_remove {
            let _ = req.remove_header(name.as_str());
        }
    }

    pub fn on_response(
        &self,
        resp: &mut pingora_http::ResponseHeader,
        _ctx: &mut crate::context::RequestContext,
    ) {
        for (name, value) in &self.config.response_set {
            let _ = resp.insert_header(name.clone(), value.clone());
        }
        for name in &self.config.response_remove {
            let _ = resp.remove_header(name.as_str());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_response_header() {
        let config = HeadersConfig {
            response_set: HashMap::from([("X-Powered-By".into(), "fluxo".into())]),
            ..Default::default()
        };
        let plugin = HeadersPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        assert_eq!(
            resp.headers.get("X-Powered-By").unwrap().to_str().unwrap(),
            "fluxo"
        );
    }

    #[test]
    fn remove_response_header() {
        let config = HeadersConfig {
            response_remove: vec!["Server".into()],
            ..Default::default()
        };
        let plugin = HeadersPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Server", "nginx").unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        assert!(resp.headers.get("Server").is_none());
    }

    #[test]
    fn set_request_header() {
        let config = HeadersConfig {
            request_set: HashMap::from([("X-Proxy".into(), "fluxo".into())]),
            ..Default::default()
        };
        let plugin = HeadersPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(
            req.headers.get("X-Proxy").unwrap().to_str().unwrap(),
            "fluxo"
        );
    }

    #[test]
    fn remove_request_header() {
        let config = HeadersConfig {
            request_remove: vec!["Cookie".into()],
            ..Default::default()
        };
        let plugin = HeadersPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Cookie", "session=abc").unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        assert!(req.headers.get("Cookie").is_none());
    }
}
