use crate::cli::OutputFormat;
use kmux::config::{ConfigDocument, ConfigFormat, ConfigStore};
use std::path::Path;

pub fn initialize(
    explicit: Option<&Path>,
    requested_format: Option<OutputFormat>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    initialize_with_default_path(
        ConfigStore::explicit_path(explicit),
        requested_format,
        force,
        ConfigStore::default_path()?,
    )
}

fn initialize_with_default_path(
    explicit_path: Option<std::path::PathBuf>,
    requested_format: Option<OutputFormat>,
    force: bool,
    default_path: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
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
        None => match ConfigStore::discover_in(
            default_path
                .parent()
                .expect("default configuration path has a parent")
                .to_owned(),
        ) {
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
        ConfigStore::save(&path, &ConfigDocument::empty())?;
        println!("reinitialized kmux at {}", path.display());
        return Ok(());
    }

    let format = requested_format.map(format).unwrap_or(ConfigFormat::Toml);
    let path = default_path.with_extension(format.extension());
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
    use super::{initialize, initialize_with_default_path};
    use crate::cli::OutputFormat;
    use kmux::config::ConfigStore;
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
        fs::write(
            &path,
            "version = 1\n[agents.work]\ntype = \"unix\"\nsocket = \"/tmp/work.sock\"\n",
        )
        .unwrap();
        initialize(Some(&path), None, true).unwrap();
        let reset = ConfigStore::load(&path).unwrap().validate().unwrap();
        assert!(reset.agents().is_empty());
        assert!(reset.catalog().entries().next().is_none());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_a_format_that_conflicts_with_the_target_path() {
        let path = path("format-conflict");
        assert!(initialize(Some(&path), Some(OutputFormat::Yaml), false).is_err());
    }

    #[test]
    fn force_recovers_an_invalid_existing_configuration() {
        let path = path("recover-invalid");
        fs::write(&path, "this is not valid TOML = [").unwrap();
        initialize(Some(&path), None, true).unwrap();
        assert!(
            kmux::config::ConfigStore::load(&path)
                .unwrap()
                .validate()
                .is_ok()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn default_init_discovers_existing_formats_and_rejects_ambiguity() {
        let directory =
            std::env::temp_dir().join(format!("kmux-init-default-{}", std::process::id()));
        let default_path = directory.join("kmux").join("config.toml");
        initialize_with_default_path(None, None, false, default_path.clone()).unwrap();
        assert!(default_path.is_file());
        fs::remove_dir_all(&directory).unwrap();

        let yaml = directory.join("kmux").join("config.yaml");
        fs::create_dir_all(yaml.parent().unwrap()).unwrap();
        fs::write(&yaml, "version: 1\n").unwrap();
        initialize_with_default_path(None, None, false, default_path.clone()).unwrap();
        assert!(yaml.is_file());
        assert!(!default_path.exists());
        fs::write(&default_path, "version = 1\n").unwrap();
        assert!(initialize_with_default_path(None, None, false, default_path.clone()).is_err());
        assert_eq!(fs::read_to_string(&yaml).unwrap(), "version: 1\n");
        assert_eq!(fs::read_to_string(&default_path).unwrap(), "version = 1\n");
        fs::remove_dir_all(directory).unwrap();
    }
}
