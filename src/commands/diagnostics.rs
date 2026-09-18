use kmux::agent::{UnixSocketAgent, UpstreamAgent};
use kmux::config::Config;
use std::collections::{BTreeMap, BTreeSet};

pub fn doctor(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut available = BTreeMap::new();
    for (name, definition) in config.agents() {
        let identities = UnixSocketAgent::new(definition.socket().to_owned()).identities()?;
        println!("ok\tagent\t{name}\t{} identities", identities.len());
        available.insert(
            name.clone(),
            identities
                .into_iter()
                .map(|identity| identity.fingerprint)
                .collect::<BTreeSet<_>>(),
        );
    }
    let missing = config
        .catalog()
        .entries()
        .filter(|entry| {
            !available
                .get(entry.agent())
                .is_some_and(|keys| keys.contains(entry.fingerprint()))
        })
        .map(|entry| format!("{} ({})", entry.alias(), entry.fingerprint()))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "configured fingerprints unavailable: {}",
            missing.join(", ")
        )
        .into());
    }
    println!("ok\tcatalog\tall configured fingerprints are available");
    Ok(())
}
