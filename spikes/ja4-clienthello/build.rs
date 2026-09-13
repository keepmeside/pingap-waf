// Spike A — step 0 smoke check.
//
// The plan says to resolve `#[cfg(ossl111)]` in minutes, not days, because if it
// does not hold then every other question about JA4 is moot and full JA4 is cut
// immediately. `openssl-sys` emits the version cfgs as build-script output, so a
// build script is where the answer is cheapest to obtain.

fn main() {
    // Re-export the cfgs openssl-sys declared so the crate can use them.
    for (key, value) in std::env::vars() {
        if key.starts_with("DEP_OPENSSL_") {
            println!("cargo:warning=build-env {key}={value}");
        }
    }
    if let Ok(v) = std::env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let n = u64::from_str_radix(&v, 16).unwrap_or(0);
        // 1.1.1 == 0x1_01_01_00_0
        if n >= 0x1_01_01_00_0 {
            println!("cargo:rustc-cfg=ossl111");
            println!("cargo:warning=ossl111 SATISFIED (version_number=0x{v})");
        } else {
            println!("cargo:warning=ossl111 NOT satisfied (version_number=0x{v})");
        }
    } else {
        println!("cargo:warning=DEP_OPENSSL_VERSION_NUMBER absent");
    }
    println!("cargo::rustc-check-cfg=cfg(ossl111)");
}
