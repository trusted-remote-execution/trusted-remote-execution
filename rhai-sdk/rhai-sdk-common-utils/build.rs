use std::env;
use std::path::Path;

fn main() {
    let manifest_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("Failed to get CARGO_MANIFEST_DIR: {e}");
            std::process::exit(1);
        }
    };

    let registry_file = Path::new(&manifest_dir).join("src/registry.rs");
    let tests_dir = Path::new(&manifest_dir).join("tests");

    let Some(registry_file_str) = registry_file.to_str() else {
        eprintln!(
            "Failed to convert registry file path to string: {}",
            registry_file.display()
        );
        std::process::exit(1);
    };

    let Some(tests_dir_str) = tests_dir.to_str() else {
        eprintln!(
            "Failed to convert tests directory path to string: {}",
            tests_dir.display()
        );
        std::process::exit(1);
    };

    rex_runner_registrar_utils::build_validation::validate_macro_tests(
        registry_file_str,
        tests_dir_str,
    );
}
