use crate::cli::Cli;
use clap::CommandFactory;
use clap_complete::{Shell, generate as generate_completion};
use std::io::Write;

pub fn generate(shell: Shell) {
    generate_to(shell, &mut std::io::stdout().lock());
}

fn generate_to(shell: Shell, output: &mut impl Write) {
    let mut command = Cli::command();
    generate_completion(shell, &mut command, "kmux", output);
}

#[cfg(test)]
mod tests {
    use super::generate_to;
    use clap_complete::Shell;

    #[test]
    fn generates_non_empty_scripts_for_every_shell() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::Elvish,
            Shell::PowerShell,
        ] {
            let mut output = Vec::new();
            generate_to(shell, &mut output);

            assert!(!output.is_empty());
            assert!(String::from_utf8(output).unwrap().contains("kmux"));
        }
    }
}
