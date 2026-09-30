use pingap_util::IpRules;

#[derive(Debug, Clone)]
pub struct Exemptions {
    rules: IpRules,
}

impl Exemptions {
    pub fn new(entries: &[String]) -> Result<Self, String> {
        let rules = IpRules::new(entries);
        if rules.len() != entries.len() {
            let bad = entries
                .iter()
                .find(|entry| {
                    IpRules::new(std::slice::from_ref(*entry)).is_empty()
                })
                .cloned()
                .unwrap_or_default();
            return Err(format!(
                "exempt entry `{bad}` is not an IP address or CIDR range"
            ));
        }
        Ok(Self { rules })
    }
    pub fn contains(&self, identity: &str) -> bool {
        self.rules.is_match(identity).unwrap_or(false)
    }
}
