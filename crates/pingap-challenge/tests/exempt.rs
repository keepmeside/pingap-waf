use pingap_challenge::exempt::Exemptions;

#[test]
fn exemptions_validate_every_entry_and_match_only_listed_addresses() {
    let exemptions =
        Exemptions::new(&["203.0.113.0/24".to_string()]).expect("valid");
    assert!(exemptions.contains("203.0.113.8"));
    assert!(!exemptions.contains("198.51.100.8"));
    assert!(Exemptions::new(&["not-an-ip".to_string()]).is_err());
}
