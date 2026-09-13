//! Spike A — is a JA4 ClientHello fingerprint reachable from
//! Pingora 0.8.1 + OpenSSL without patching Pingora?
//!
//! **Decision gate.** A no-go cuts full JA4 and bot management ships JA4H alone.
//!
//! Step 0 first: confirm `#[cfg(ossl111)]` resolves. Everything
//! below is moot if it does not, so it is checked in `build.rs` and asserted here
//! before any handshake runs.
//!
//! Then the four genuinely-unknown questions:
//!   1. Is extension **order** preserved? JA4 is order-sensitive, so a
//!      set-but-unordered API silently produces wrong fingerprints.
//!   2. Does the callback fire on session resumption and HTTP/2 reuse?
//!   3. Does `set_alpn_select_callback` (which pingap registers via `enable_h2`)
//!      coexist with the client-hello callback on one handshake?
//!   4. Do the borrow shapes reconcile — `&mut SslRef` in the client-hello
//!      callback, `set_ex_data` wanting `&mut`?
//!
//! The extension list needs one contained `unsafe` block:
//! `SSL_client_hello_get1_extensions_present` is declared in `openssl-sys` but
//! has no safe wrapper at this version.

use openssl::ssl::{
    ClientHelloResponse, SslAcceptor, SslConnector, SslMethod, SslVerifyMode,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// What the callback managed to observe, per connection.
#[derive(Debug, Default, Clone)]
struct Observed {
    fired: bool,
    legacy_version: u32,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    compression: Vec<u8>,
    alpn_selected: Option<String>,
}

/// `SSL_client_hello_get1_extensions_present` — the one unsafe block.
///
/// Returns extensions in the order OpenSSL recorded them, which is exactly the
/// property question 1 is about. The out-pointer is allocated by OpenSSL and must
/// be freed with `OPENSSL_free`.
fn client_hello_extensions(ssl: &mut openssl::ssl::SslRef) -> Option<Vec<u16>> {
    use foreign_types::ForeignTypeRef;
    let mut out: *mut libc::c_int = std::ptr::null_mut();
    let mut outlen: libc::size_t = 0;
    // SAFETY: `ssl` is a live SSL* mid-handshake, which is the only context in
    // which this call is defined. On success OpenSSL writes an owned array of
    // `outlen` ints; we copy it and free with OPENSSL_free, never aliasing it.
    let rc = unsafe {
        openssl_sys::SSL_client_hello_get1_extensions_present(
            ssl.as_ptr(),
            &mut out,
            &mut outlen,
        )
    };
    if rc != 1 || out.is_null() {
        return None;
    }
    let list = unsafe { std::slice::from_raw_parts(out, outlen) }
        .iter()
        .map(|&v| v as u16)
        .collect::<Vec<_>>();
    unsafe { openssl_sys::OPENSSL_free(out as *mut libc::c_void) };
    Some(list)
}

/// GREASE values, which JA4 excludes. RFC 8701.
fn is_grease(v: u16) -> bool {
    matches!(
        v,
        0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a | 0x5a5a | 0x6a6a | 0x7a7a
            | 0x8a8a | 0x9a9a | 0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa
    )
}

/// Truncated-SHA256 helper, the JA4 hash form (first 12 hex chars).
fn ja4_hash(parts: &[String]) -> String {
    use sha2::{Digest, Sha256};
    if parts.is_empty() {
        return "000000000000".to_string();
    }
    let joined = parts.join(",");
    let d = Sha256::digest(joined.as_bytes());
    hex::encode(d)[..12].to_string()
}

/// Compute a JA4-shaped string. Not claimed to be spec-exact — the spike's job is
/// to establish *reachability and ordering*, and any value here must be
/// cross-checked against a reference implementation before full JA4 trusts it.
fn ja4_like(o: &Observed, alpn: &str) -> String {
    let ciphers: Vec<u16> = o.ciphers.iter().copied().filter(|c| !is_grease(*c)).collect();
    let exts: Vec<u16> = o
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();
    let ver = match o.legacy_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let a = format!(
        "t{ver}d{:02}{:02}{}",
        ciphers.len().min(99),
        exts.len().min(99),
        if alpn.len() >= 2 { &alpn[..2] } else { "00" }
    );
    // JA4_b: ciphers, sorted, hashed. JA4_c: extensions, sorted, hashed.
    let mut cs: Vec<String> = ciphers.iter().map(|c| format!("{c:04x}")).collect();
    cs.sort();
    let mut es: Vec<String> = exts.iter().map(|e| format!("{e:04x}")).collect();
    es.sort();
    format!("{a}_{}_{}", ja4_hash(&cs), ja4_hash(&es))
}

fn main() {
    // ---- step 0: the cfg gate ------------------------------------------------
    #[cfg(not(ossl111))]
    {
        println!("RESULT ossl111                 NOT SATISFIED");
        println!("RESULT verdict                 NO-GO: cut full JA4, ship JA4H only");
        return;
    }

    #[cfg(ossl111)]
    {
        println!("RESULT ossl111                 satisfied");
        println!(
            "RESULT openssl_version         {}",
            openssl::version::version()
        );

        let observed: Arc<Mutex<Observed>> = Arc::new(Mutex::new(Observed::default()));

        // ---- server side: register the client-hello callback ----------------
        let mut acceptor =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("acceptor");
        let cert_key = generate_self_signed();
        acceptor.set_private_key(&cert_key.1).expect("set key");
        acceptor.set_certificate(&cert_key.0).expect("set cert");

        // Q3: pingap registers this via enable_h2(). Register it too, so the two
        // callbacks are exercised on the same handshake rather than in isolation.
        acceptor.set_alpn_select_callback(|_ssl, client_protos| {
            // Select h2 if offered, else http/1.1. Wire format: length-prefixed.
            let mut i = 0usize;
            let mut http11: Option<&[u8]> = None;
            while i < client_protos.len() {
                let len = client_protos[i] as usize;
                let p = &client_protos[i + 1..i + 1 + len];
                if p == b"h2" {
                    return Ok(p);
                }
                if p == b"http/1.1" {
                    http11 = Some(p);
                }
                i += 1 + len;
            }
            http11.ok_or(openssl::ssl::AlpnError::NOACK)
        });

        let obs = observed.clone();
        acceptor.set_client_hello_callback(move |ssl, _alert| {
            let mut o = obs.lock().expect("lock");
            o.fired = true;
            // Q4: borrow shapes. `ssl` is &mut SslRef here.
            // SslVersion's inner c_int is private; compare against the known constants.
            o.legacy_version = match ssl.client_hello_legacy_version() {
                Some(v) if v == openssl::ssl::SslVersion::TLS1_3 => 0x0304,
                Some(v) if v == openssl::ssl::SslVersion::TLS1_2 => 0x0303,
                Some(v) if v == openssl::ssl::SslVersion::TLS1_1 => 0x0302,
                Some(v) if v == openssl::ssl::SslVersion::TLS1 => 0x0301,
                _ => 0,
            };
            if let Some(c) = ssl.client_hello_ciphers() {
                o.ciphers = c.chunks_exact(2).map(|p| u16::from_be_bytes([p[0], p[1]])).collect();
            }
            if let Some(m) = ssl.client_hello_compression_methods() {
                o.compression = m.to_vec();
            }
            if let Some(e) = client_hello_extensions(ssl) {
                o.extensions = e;
            }
            Ok(ClientHelloResponse::SUCCESS)
        });

        let acceptor = Arc::new(acceptor.build());

        // ---- run one handshake over a socket pair ---------------------------
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let srv_acceptor = acceptor.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            match srv_acceptor.accept(stream) {
                Ok(mut s) => {
                    let mut buf = [0u8; 16];
                    let _ = s.read(&mut buf);
                    let _ = s.write_all(b"ok");
                    let neg = s
                        .ssl()
                        .selected_alpn_protocol()
                        .map(|p| String::from_utf8_lossy(p).to_string());
                    neg
                },
                Err(e) => {
                    println!("RESULT handshake               FAILED {e}");
                    None
                },
            }
        });

        let mut connector = SslConnector::builder(SslMethod::tls()).expect("connector");
        connector.set_verify(SslVerifyMode::NONE);
        connector.set_alpn_protos(b"\x02h2\x08http/1.1").expect("alpn");
        let connector = connector.build();
        let tcp = std::net::TcpStream::connect(addr).expect("connect");
        match connector.connect("localhost", tcp) {
            Ok(mut s) => {
                let _ = s.write_all(b"ping");
                let mut b = [0u8; 8];
                let _ = s.read(&mut b);
            },
            Err(e) => println!("RESULT client_handshake        FAILED {e}"),
        }
        let negotiated = server.join().expect("join");

        let mut o = observed.lock().expect("lock").clone();
        o.alpn_selected = negotiated.clone();

        println!("RESULT callback_fired          {}", o.fired);
        println!("RESULT alpn_negotiated         {:?}", negotiated);
        println!(
            "RESULT alpn_coexists           {}",
            o.fired && negotiated.is_some()
        );
        println!("RESULT legacy_version          0x{:04x}", o.legacy_version);
        println!("RESULT cipher_count            {}", o.ciphers.len());
        println!("RESULT extension_count         {}", o.extensions.len());
        println!(
            "RESULT extensions_raw_order    {}",
            o.extensions
                .iter()
                .map(|e| format!("{e:04x}"))
                .collect::<Vec<_>>()
                .join(" ")
        );

        // Q1: is the returned order the wire order, or is it sorted/set-like?
        let mut sorted = o.extensions.clone();
        sorted.sort();
        let already_sorted = sorted == o.extensions;
        println!(
            "RESULT extension_order         {}",
            if already_sorted {
                "AMBIGUOUS: returned list is already ascending — cannot distinguish \
                 wire order from a sorted set with this client"
            } else {
                "PRESERVED: returned list is NOT ascending, so it reflects wire order"
            }
        );

        println!(
            "RESULT ja4_like                {}",
            ja4_like(&o, negotiated.as_deref().unwrap_or("00"))
        );
        println!(
            "RESULT unsafe_blocks           1 (client_hello_extensions only)"
        );
    }
}

/// Minimal self-signed cert so the handshake has something to present.
fn generate_self_signed() -> (openssl::x509::X509, openssl::pkey::PKey<openssl::pkey::Private>) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509};

    let rsa = Rsa::generate(2048).expect("rsa");
    let key = PKey::from_rsa(rsa).expect("pkey");
    let mut name = X509NameBuilder::new().expect("name");
    name.append_entry_by_text("CN", "localhost").expect("cn");
    let name = name.build();

    let mut b = X509::builder().expect("builder");
    b.set_version(2).expect("version");
    let mut serial = BigNum::new().expect("bn");
    serial.rand(159, MsbOption::MAYBE_ZERO, false).expect("rand");
    b.set_serial_number(&serial.to_asn1_integer().expect("asn1")).expect("serial");
    b.set_subject_name(&name).expect("subject");
    b.set_issuer_name(&name).expect("issuer");
    b.set_pubkey(&key).expect("pubkey");
    b.set_not_before(&Asn1Time::days_from_now(0).expect("nb")).expect("set nb");
    b.set_not_after(&Asn1Time::days_from_now(1).expect("na")).expect("set na");
    b.sign(&key, MessageDigest::sha256()).expect("sign");
    (b.build(), key)
}
