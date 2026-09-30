use sha2::{Digest, Sha256};

pub fn digest(salt: &str, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(nonce.to_string().as_bytes());
    hasher.finalize().into()
}

pub fn solved(salt: &str, nonce: u64, difficulty: u8) -> bool {
    let digest = digest(salt, nonce);
    let full = usize::from(difficulty / 8);
    let rem = difficulty % 8;
    digest[..full].iter().all(|byte| *byte == 0)
        && (rem == 0
            || digest.get(full).is_some_and(|byte| byte >> (8 - rem) == 0))
}

pub fn find_nonce(salt: &str, difficulty: u8, limit: u64) -> Option<u64> {
    (0..limit).find(|nonce| solved(salt, *nonce, difficulty))
}
