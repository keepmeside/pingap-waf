use pingap_challenge::pow::{find_nonce, solved};

#[test]
fn proof_of_work_accepts_a_solution_and_rejects_a_near_miss() {
    let nonce = find_nonce("salt", 8, 1_000_000)
        .expect("a low difficulty has a solution");
    assert!(solved("salt", nonce, 8));
    assert!(!solved("different", nonce, 8));
}
