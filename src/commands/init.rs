use crate::cli::OutputFormat;
use kmux::config::{ConfigDocument, ConfigFormat, ConfigStore};
use std::path::Path;

pub fn initialize(
    explicit: Option<&Path>,
    requested_format: Option<OutputFormat>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let explicit_path = ConfigStore::explicit_path(explicit);
    let existing = match explicit_path {
        Some(path) if path.is_file() => Some(path),
        Some(path) => {
            let target_format = ConfigFormat::from_path(&path)?;
            if requested_format
                .map(format)
                .is_some_and(|requested| requested != target_format)
            {
                return Err(format!(
                    "--format does not match the target configuration path '{}'",
                    path.display()
                )
                .into());
            }
            ConfigStore::save(&path, &ConfigDocument::empty())?;
            println!("initialized kmux at {}", path.display());
            return Ok(());
        }
        None => match ConfigStore::discover(None) {
            Ok(path) => Some(path.as_path().to_owned()),
            Err(kmux::config::ConfigError::ConfigNotFound(_)) => None,
            Err(error) => return Err(error.into()),
        },
    };

    if let Some(path) = existing {
        let existing_format = ConfigFormat::from_path(&path)?;
        if let Some(requested) = requested_format.map(format)
            && requested != existing_format
        {
            return Err(format!(
                "refusing to replace '{}' as {}; it is an existing {} configuration",
                path.display(),
                requested.extension(),
                existing_format.extension()
            )
            .into());
        }
        if !force {
            println!("kmux already initialized at {}", path.display());
            return Ok(());
        }
        let document = ConfigStore::load(&path)?;
        ConfigStore::save(&path, &document)?;
        println!("reinitialized kmux at {}", path.display());
        return Ok(());
    }

    let format = requested_format.map(format).unwrap_or(ConfigFormat::Toml);
    let path = ConfigStore::default_path()?.with_extension(format.extension());
    ConfigStore::save(&path, &ConfigDocument::empty())?;
    println!("initialized kmux at {}", path.display());
    Ok(())
}

fn format(format: OutputFormat) -> ConfigFormat {
    match format {
        OutputFormat::Toml => ConfigFormat::Toml,
        OutputFormat::Yaml => ConfigFormat::Yaml,
        OutputFormat::Json => ConfigFormat::Json,
    }
}

#[cfg(test)]
mod tests {
    use super::initialize;
    use crate::cli::OutputFormat;
    use std::fs;

    fn path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kmux-init-command-{}-{name}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn initializes_an_explicit_path_and_is_idempotent() {
        let path = path("idempotent");
        initialize(Some(&path), None, false).unwrap();
        let original = fs::read_to_string(&path).unwrap();
        initialize(Some(&path), None, false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        initialize(Some(&path), None, true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_a_format_that_conflicts_with_the_target_path() {
        let path = path("format-conflict");
        assert!(initialize(Some(&path), Some(OutputFormat::Yaml), false).is_err());
    }
}
