//! Phase 02 Spike E — request body inspected, and still forwarded?
//!
//! Decision gate blocking Phase 04. The red-team review concluded from source
//! reading that draining the body inside a `PluginStep::Request` plugin
//! forwards an EMPTY body upstream on every allowed request, because
//! `enable_retry_buffering()` runs at `pingora-proxy-0.8.1/src/proxy_h1.rs:103`
//! — inside `proxy_to_upstream` (`lib.rs:873`), strictly after `request_filter`
//! (`lib.rs:782`) has returned. This spike converts that argument into evidence.
//!
//! Three modes, one question each:
//!
//!   drain-request-filter  drain in `request_filter`, return Continue, proxy.
//!                         Expected: upstream receives 0 body bytes.
//!   drain-with-buffering  same, but call `enable_retry_buffering()` first.
//!                         Expected: works up to BODY_BUF_LIMIT (64 KiB), then
//!                         `truncated` is set and the body is lost again.
//!   body-filter           inspect in `request_body_filter`, forward untouched.
//!                         Expected: upstream receives every byte.
//!
//! The upstream is an echo server that reports the byte count it actually read,
//! so the answer comes from the far side of the proxy rather than from a log
//! line on this side.

use async_trait::async_trait;
use bytes::Bytes;
use clap::Parser;
use pingora::prelude::*;
use pingora_proxy::{ProxyHttp, Session};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    DrainRequestFilter,
    DrainWithBuffering,
    BodyFilter,
}

impl std::str::FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "drain-request-filter" => Ok(Mode::DrainRequestFilter),
            "drain-with-buffering" => Ok(Mode::DrainWithBuffering),
            "body-filter" => Ok(Mode::BodyFilter),
            other => Err(format!(
                "unknown mode {other:?}; expected drain-request-filter, \
                 drain-with-buffering, or body-filter"
            )),
        }
    }
}

#[derive(Parser)]
struct Args {
    /// Which inspection strategy to exercise.
    #[arg(long)]
    mode: Mode,
    /// Address this proxy listens on.
    #[arg(long)]
    listen: String,
    /// Echo upstream that reports the byte count it read.
    #[arg(long)]
    upstream: String,
}

struct SpikeProxy {
    mode: Mode,
    upstream: String,
}

#[async_trait]
impl ProxyHttp for SpikeProxy {
    type CTX = usize;

    fn new_ctx(&self) -> Self::CTX {
        0
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        match self.mode {
            Mode::DrainRequestFilter | Mode::DrainWithBuffering => {
                if self.mode == Mode::DrainWithBuffering {
                    // The rejected fallback: ask pingora to mirror body bytes
                    // into a replayable buffer *before* reading them, since
                    // `read_body_bytes` only fills a buffer that already exists.
                    session.as_mut().enable_retry_buffering();
                }
                let mut drained = 0usize;
                while let Some(chunk) = session.read_request_body().await? {
                    drained += chunk.len();
                }
                let replay = session
                    .as_mut()
                    .get_retry_buffer()
                    .map(|b| b.len())
                    .unwrap_or(0);
                println!(
                    "[spike] request_filter drained={drained} replay_buffer={replay} \
                     truncated={}",
                    session.as_ref().retry_buffer_truncated()
                );
                // Continue to the upstream. This is the whole point: a WAF must
                // drain, decide *pass*, and forward.
                Ok(false)
            },
            Mode::BodyFilter => Ok(false),
        }
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        if self.mode == Mode::BodyFilter {
            if let Some(chunk) = body {
                // Inspect in place. A real detector scans here; the body is
                // left untouched so pingora forwards it verbatim.
                *ctx += chunk.len();
            }
            if end_of_stream {
                println!("[spike] request_body_filter inspected={ctx} (end_of_stream)");
            }
        }
        Ok(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            self.upstream.as_str(),
            false,
            String::new(),
        )))
    }
}

fn main() {
    let args = Args::parse();
    let mut server = Server::new(None).expect("spike: server init");
    server.bootstrap();

    let mut proxy = pingora_proxy::http_proxy_service(
        &server.configuration,
        SpikeProxy {
            mode: args.mode,
            upstream: args.upstream.clone(),
        },
    );
    proxy.add_tcp(&args.listen);

    println!(
        "[spike] mode={:?} listen={} upstream={}",
        args.mode, args.listen, args.upstream
    );
    server.add_service(proxy);
    server.run_forever();
}
