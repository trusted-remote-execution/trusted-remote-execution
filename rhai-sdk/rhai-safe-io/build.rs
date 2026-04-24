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

    let registry_dir = Path::new(&manifest_dir).join("src/registry");
    let tests_dir = Path::new(&manifest_dir).join("tests");

    let Some(tests_dir_str) = tests_dir.to_str() else {
        eprintln!(
            "Failed to convert tests directory path to string: {}",
            tests_dir.display()
        );
        std::process::exit(1);
    };

    // Validate each registry file
    let registry_files = ["common.rs", "unix.rs", "linux.rs", "non_apple.rs"];

    for file_name in registry_files {
        let registry_file = registry_dir.join(file_name);

        // Skip if file doesn't exist (platform-specific files may not be present)
        if !registry_file.exists() {
            continue;
        }

        let Some(registry_file_str) = registry_file.to_str() else {
            eprintln!(
                "Failed to convert registry file path to string: {}",
                registry_file.display()
            );
            std::process::exit(1);
        };

        println!("cargo:rerun-if-changed={registry_file_str}");

        rex_runner_registrar_utils::build_validation::validate_macro_tests(
            registry_file_str,
            tests_dir_str,
        );
    }

    println!("cargo:rerun-if-changed={tests_dir_str}");
}
