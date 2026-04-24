use anyhow::Result;
use clap::Parser;
use rex_cedar_auth::cedar_auth::CedarAuth;
use std::process;

#[derive(Parser)]
#[command(name = "cedar-policy-validator")]
#[command(about = "Validate Cedar policy against schema")]
struct Cli {
    /// Path to the Cedar policy file
    #[arg(short, long)]
    policy: String,

    /// Cedar schema file
    #[arg(short, long)]
    schema: String,

    /// Additional Cedar schema file
    #[arg(long)]
    additional_schema: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let (mut cedar_auth, _) = CedarAuth::new(&cli.policy, &cli.schema, "[]")?;

    if let Some(additional_schema_content) = cli.additional_schema {
        cedar_auth.additional_schema(&additional_schema_content)?;
    }

    match cedar_auth.validate_policy() {
        Ok(()) => {
            println!("Policy validation successful!: {}", cli.policy);
        }
        Err(e) => {
            eprintln!("Policy validation failed: {e:#}");
            process::exit(1);
        }
    }

    Ok(())
}
