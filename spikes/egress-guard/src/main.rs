//! Spike: can a custom `reqwest::dns::Resolve` implementation enforce an egress
//! guard at connection time, including across redirect hops and against IP-literal
//! targets?

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Every hostname the resolver is asked about, in order.
type Seen = Arc<Mutex<Vec<String>>>;

struct Guard {
    seen: Seen,
}

fn is_refused(ip: IpAddr) -> bool {
    match ip {
        // Link-local / cloud metadata only, so the spike can still reach 127.0.0.1.
        IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        IpAddr::V6(_) => false,
    }
}

impl Resolve for Guard {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let seen = Arc::clone(&self.seen);
        Box::pin(async move {
            seen.lock().unwrap().push(host.clone());

            // Name-based refusal, so the refusal path is provable without depending on
            // what this machine's DNS happens to resolve.
            if host.starts_with("blocked.") {
                return Err(format!("refused {host}: policy").into());
            }

            // An IP literal may never reach a resolver at all; handle both cases.
            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_refused(ip) {
                    return Err(format!("refused {ip}: link-local/metadata").into());
                }
                let addr = SocketAddr::new(ip, 0);
                return Ok(Box::new(std::iter::once(addr)) as Addrs);
            }

            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| format!("resolve {host}: {e}"))?
                .collect();

            let allowed: Vec<SocketAddr> = resolved
                .into_iter()
                .filter(|a| !is_refused(a.ip()))
                .collect();

            if allowed.is_empty() {
                return Err(format!(
                    "refused {host}: every resolved address is link-local/metadata"
                )
                .into());
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

/// A server that answers one request per connection with a canned response.
async fn serve(listener: TcpListener, port: u16) {
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = if req.starts_with("GET /redirect-ip") {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else if req.starts_with("GET /redirect-local") {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/ok\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else if req.starts_with("GET /redirect-host-refused") {
                // Checked BEFORE /redirect-host: starts_with would otherwise match the
                // shorter prefix and serve the wrong redirect.
                "HTTP/1.1 302 Found\r\nLocation: http://blocked.test/latest/\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            } else if req.starts_with("GET /redirect-host") {
                // A hostname, not an IP literal. This is the case that decides whether a
                // custom Resolve impl is consulted at all, and whether it is consulted
                // again on a redirect hop rather than only on the first request.
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://localhost:{port}/ok\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
            };
            let _ = sock.write_all(body.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}

async fn attempt(
    label: &str,
    client: &reqwest::Client,
    url: &str,
) {
    let short = std::time::Duration::from_secs(4);
    let outcome = match tokio::time::timeout(short, client.get(url).send()).await {
        Err(_) => "TIMEOUT (4s)".to_string(),
        Ok(Err(e)) => {
            let chain: Vec<String> = {
                let mut v = Vec::new();
                let mut src: Option<&(dyn std::error::Error + 'static)> = Some(&e);
                while let Some(s) = src {
                    v.push(s.to_string());
                    src = s.source();
                }
                v
            };
            format!("ERROR: {}", chain.join(" | "))
        }
        Ok(Ok(resp)) => format!(
            "STATUS {} from {}",
            resp.status(),
            resp.url()
        ),
    };
    println!("  {label:<34} {outcome}");
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve(listener, port));
    let base = format!("http://127.0.0.1:{port}");

    println!("reqwest {}", env!("CARGO_PKG_VERSION"));
    println!("test server on {base}\n");

    // ---- A0. TRUE baseline: no guard, default redirect policy ----
    println!("A0. BASELINE — plain client, no guard, default policy");
    let plain = reqwest::Client::new();
    attempt("plain /ok", &plain, &format!("{base}/ok")).await;
    attempt("redirect -> 169.254.169.254", &plain, &format!("{base}/redirect-ip")).await;
    println!("   ^ TIMEOUT here means the client DID follow into the metadata address");

    // ---- A. default policy, resolver installed to observe names ----
    println!("\nA. DEFAULT POLICY + resolver installed (refuses 169.254/16)");
    let seen_a: Seen = Arc::new(Mutex::new(Vec::new()));
    let default = reqwest::Client::builder()
        .dns_resolver(Guard { seen: Arc::clone(&seen_a) })
        .build()
        .unwrap();
    attempt("plain /ok", &default, &format!("{base}/ok")).await;
    attempt("redirect -> 169.254.169.254", &default, &format!("{base}/redirect-ip")).await;
    println!("   names resolver saw: {:?}", seen_a.lock().unwrap());

    // ---- B. Policy::none() ----
    println!("\nB. Policy::none()");
    let none = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    attempt("redirect -> 169.254.169.254", &none, &format!("{base}/redirect-ip")).await;
    attempt("redirect -> 127.0.0.1 (local)", &none, &format!("{base}/redirect-local")).await;

    // ---- C. Policy::limited(5) + refusing resolver ----
    println!("\nC. Policy::limited(5) + refusing resolver");
    let seen_c: Seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .dns_resolver(Guard { seen: Arc::clone(&seen_c) })
        .build()
        .unwrap();
    attempt("plain /ok (must still work)", &guarded, &format!("{base}/ok")).await;
    // Does the resolver see HOSTNAMES at all? Without this the rest is uninterpretable.
    attempt("direct hostname localhost", &guarded, &format!("http://localhost:{port}/ok")).await;
    println!("   -- resolver names so far: {:?}", seen_c.lock().unwrap());

    attempt("direct refused hostname", &guarded, "http://blocked.test/latest/").await;
    attempt("redirect -> 127.0.0.1 (allowed)", &guarded, &format!("{base}/redirect-local")).await;
    attempt("redirect -> hostname localhost", &guarded, &format!("{base}/redirect-host")).await;
    attempt("redirect -> 169.254.169.254", &guarded, &format!("{base}/redirect-ip")).await;
    attempt("redirect -> refused hostname", &guarded, &format!("{base}/redirect-host-refused")).await;
    attempt("direct IP literal 169.254.169.254", &guarded, "http://169.254.169.254/").await;
    println!("   ALL names resolver saw: {:?}", seen_c.lock().unwrap());

    // ---- D. does ClientBuilder::resolve pin, and does the port note hold? ----
    println!("\nD. ClientBuilder::resolve pinning");
    let pinned = reqwest::Client::builder()
        .resolve("feed.example", SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))
        .build()
        .unwrap();
    attempt("http://feed.example/ok", &pinned, "http://feed.example/ok").await;

    let _ = Arc::clone(&seen_c);
}
