//! Tests for X.509 certificate chain verification
//!
//! These tests verify that our `verify_cert` and `verify_cert_chain` methods work correctly.
//! Test certificates are pre-generated and stored in fixtures/crypto/ with 100-year validity.

use rex_cedar_auth::test_utils::DEFAULT_TEST_CEDAR_AUTH;
use rex_test_utils::io::create_temp_dir_and_path;
use rstest::rstest;
use rust_safe_io::RcFileHandle;
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::OpenFileOptionsBuilder;
use std::fs;

use crate::test_common::open_test_dir_handle;

// =============================================================================
// Fixture paths for pre-generated test certificates
// =============================================================================

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/crypto");

fn root_ca_pem() -> String {
    fs::read_to_string(format!("{}/root-ca.pem", FIXTURES_DIR))
        .expect("Failed to read root-ca.pem fixture")
}

fn intermediate_ca_pem() -> String {
    fs::read_to_string(format!("{}/intermediate-ca.pem", FIXTURES_DIR))
        .expect("Failed to read intermediate-ca.pem fixture")
}

fn server_pem() -> String {
    fs::read_to_string(format!("{}/server.pem", FIXTURES_DIR))
        .expect("Failed to read server.pem fixture")
}

fn server_direct_pem() -> String {
    fs::read_to_string(format!("{}/server-direct.pem", FIXTURES_DIR))
        .expect("Failed to read server-direct.pem fixture")
}

fn self_signed_server_pem() -> String {
    fs::read_to_string(format!("{}/self-signed-server.pem", FIXTURES_DIR))
        .expect("Failed to read self-signed-server.pem fixture")
}

fn wrong_root_ca_pem() -> String {
    fs::read_to_string(format!("{}/wrong-root-ca.pem", FIXTURES_DIR))
        .expect("Failed to read wrong-root-ca.pem fixture")
}

fn server_bundled_pem() -> String {
    fs::read_to_string(format!("{}/server-bundled.pem", FIXTURES_DIR))
        .expect("Failed to read server-bundled.pem fixture")
}

fn malformed_der_pem() -> String {
    fs::read_to_string(format!("{}/malformed-der.pem", FIXTURES_DIR))
        .expect("Failed to read malformed-der.pem fixture")
}

// =============================================================================
// Test Helpers
// =============================================================================

fn create_temp_cert_file(
    temp_dir_path: &String,
    filename: &str,
    content: &str,
) -> anyhow::Result<RcFileHandle> {
    let file_path = format!("{}/{}", temp_dir_path, filename);
    fs::write(&file_path, content)?;

    let dir_handle = open_test_dir_handle(temp_dir_path);
    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    Ok(file_handle)
}

// =============================================================================
// Tests for verify_cert_chain (with intermediate CA)
// =============================================================================

/// Given: A valid certificate chain (root -> intermediate -> server)
/// When: Verifying the server certificate with verify_cert_chain
/// Then: Verification should succeed
#[test]
fn test_verify_cert_chain_valid_chain() -> anyhow::Result<()> {
    let (temp_dir, temp_path) = create_temp_dir_and_path()?;

    let root_fh = create_temp_cert_file(&temp_path, "root.pem", &root_ca_pem())?;
    let intermediate_fh =
        create_temp_cert_file(&temp_path, "intermediate.pem", &intermediate_ca_pem())?;
    let server_fh = create_temp_cert_file(&temp_path, "server.pem", &server_pem())?;

    let result = server_fh.verify_cert_chain(root_fh, vec![intermediate_fh]);

    assert!(result.is_ok(), "Valid chain should verify: {:?}", result);

    temp_dir.close()?;
    Ok(())
}

/// Given: Various invalid certificate chain combinations
/// When: Verifying with verify_cert_chain
/// Then: Verification should fail
#[rstest]
#[case::self_signed_server("self_signed")]
#[case::wrong_root_ca("wrong_root")]
fn test_verify_cert_chain_fails(#[case] scenario: &str) -> anyhow::Result<()> {
    let (temp_dir, temp_path) = create_temp_dir_and_path()?;

    let (root_to_use, server_pem_content) = match scenario {
        "self_signed" => (root_ca_pem(), self_signed_server_pem()),
        "wrong_root" => (wrong_root_ca_pem(), server_pem()),
        _ => unreachable!(),
    };

    let root_fh = create_temp_cert_file(&temp_path, "root.pem", &root_to_use)?;
    let intermediate_fh =
        create_temp_cert_file(&temp_path, "intermediate.pem", &intermediate_ca_pem())?;
    let server_fh = create_temp_cert_file(&temp_path, "server.pem", &server_pem_content)?;

    let result = server_fh.verify_cert_chain(root_fh, vec![intermediate_fh]);

    assert!(result.is_err(), "Verification should fail for {}", scenario);

    temp_dir.close()?;
    Ok(())
}

/// Given: Empty certificate files in chain verification
/// When: Attempting to verify
/// Then: Should return CertificateParseError with "No certificates found"
#[rstest]
#[case::empty_root("empty_root")]
#[case::empty_server("empty_server")]
fn test_verify_cert_chain_empty_file_error(#[case] scenario: &str) -> anyhow::Result<()> {
    let (temp_dir, temp_path) = create_temp_dir_and_path()?;

    let (root_content, server_content) = match scenario {
        "empty_root" => ("".to_string(), server_pem()),
        "empty_server" => (root_ca_pem(), "".to_string()),
        _ => unreachable!(),
    };

    let root_fh = create_temp_cert_file(&temp_path, "root.pem", &root_content)?;
    let intermediate_fh =
        create_temp_cert_file(&temp_path, "intermediate.pem", &intermediate_ca_pem())?;
    let server_fh = create_temp_cert_file(&temp_path, "server.pem", &server_content)?;

    let result = server_fh.verify_cert_chain(root_fh, vec![intermediate_fh]);

    assert!(result.is_err());
    match result.unwrap_err() {
        RustSafeIoError::CertificateParseError { reason } => {
            assert!(
                reason.contains("No certificates found"),
                "Expected 'No certificates found', got: {}",
                reason
            );
        }
        other => panic!("Expected CertificateParseError, got {:?}", other),
    }

    temp_dir.close()?;
    Ok(())
}

// =============================================================================
// Tests for verify_cert (direct root signing, no intermediate)
// =============================================================================

/// Given: A server certificate signed directly by root CA
/// When: Verifying with verify_cert (no intermediate)
/// Then: Verification should succeed
#[test]
fn test_verify_cert_direct_root_valid() -> anyhow::Result<()> {
    let (temp_dir, temp_path) = create_temp_dir_and_path()?;

    let root_fh = create_temp_cert_file(&temp_path, "root.pem", &root_ca_pem())?;
    let server_fh = create_temp_cert_file(&temp_path, "server.pem", &server_direct_pem())?;

    let result = server_fh.verify_cert(root_fh);

    assert!(
        result.is_ok(),
        "Direct root signing should verify: {:?}",
        result
    );

    temp_dir.close()?;
    Ok(())
}

/// Given: Various invalid certificate combinations
/// When: Verifying with verify_cert (no intermediate)
/// Then: Verification should fail
#[rstest]
#[case::self_signed_different_root("self_signed")]
#[case::missing_intermediate("missing_intermediate")]
fn test_verify_cert_fails(#[case] scenario: &str) -> anyhow::Result<()> {
    let (temp_dir, temp_path) = create_temp_dir_and_path()?;

    let server_pem_content = match scenario {
        "self_signed" => self_signed_server_pem(),
        "missing_intermediate" => {
            // Server signed by intermediate, but we only provide root
            server_pem()
        }
        _ => unreachable!(),
    };

    let root_fh = create_temp_cert_file(&temp_path, "root.pem", &root_ca_pem())?;
    let server_fh = create_temp_cert_file(&temp_path, "server.pem", &server_pem_content)?;

    let result = server_fh.verify_cert(root_fh);

    assert!(result.is_err(), "Verification should fail for {}", scenario);

    temp_dir.close()?;
    Ok(())
}

/// Given: Empty or invalid root certificate content
/// When: Calling verify_cert
/// Then: Should return CertificateParseError
#[rstest]
#[case::empty_root("")]
#[case::empty_server("empty_server")]
#[case::invalid_pem("invalid pem content\nnot a certificate")]
#[case::malformed_pem("-----BEGIN CERTIFICATE-----\nnot-valid-base64\n-----END CERTIFICATE-----")]
fn test_verify_cert_parse_error(#[case] scenario: &str) -> anyhow::Result<()> {
    let (temp_dir, temp_path) = create_temp_dir_and_path()?;

    let (root_content, server_content) = match scenario {
        "" => ("".to_string(), server_direct_pem()),
        "empty_server" => (root_ca_pem(), "".to_string()),
        _ => (scenario.to_string(), server_direct_pem()),
    };

    let root_fh = create_temp_cert_file(&temp_path, "root.pem", &root_content)?;
    let server_fh = create_temp_cert_file(&temp_path, "server.pem", &server_content)?;

    let result = server_fh.verify_cert(root_fh);

    assert!(result.is_err());
    match result.unwrap_err() {
        RustSafeIoError::CertificateParseError { reason } => {
            assert!(
                reason.contains("No certificates found") || reason.contains("Failed to parse"),
                "Expected parse error, got: {}",
                reason
            );
        }
        other => panic!("Expected CertificateParseError, got {:?}", other),
    }

    temp_dir.close()?;
    Ok(())
}

// =============================================================================
// Coverage tests for specific code paths
// =============================================================================

/// Given: A server certificate file containing multiple certificates (chain bundle)
/// When: Verifying with verify_cert_chain
/// Then: Should successfully verify using additional certs from the bundled file
#[test]
fn test_verify_cert_with_bundled_chain_in_server_file() -> anyhow::Result<()> {
    let (temp_dir, temp_path) = create_temp_dir_and_path()?;

    let root_fh = create_temp_cert_file(&temp_path, "root.pem", &root_ca_pem())?;
    let intermediate_fh =
        create_temp_cert_file(&temp_path, "intermediate.pem", &intermediate_ca_pem())?;
    // Use the bundled server cert (server + intermediate in one file)
    let server_fh = create_temp_cert_file(&temp_path, "server.pem", &server_bundled_pem())?;

    let result = server_fh.verify_cert_chain(root_fh, vec![intermediate_fh]);

    assert!(result.is_ok(), "Bundled chain should verify: {:?}", result);

    temp_dir.close()?;
    Ok(())
}

/// Given: Multiple intermediate CA files where the first is wrong but the second is correct
/// When: Verifying with verify_cert_chain using vec![wrong, correct]
/// Then: Verification should succeed because at least one intermediate matches the chain
#[test]
fn test_verify_cert_chain_multiple_intermediates_second_valid() -> anyhow::Result<()> {
    let (temp_dir, temp_path) = create_temp_dir_and_path()?;

    let root_fh = create_temp_cert_file(&temp_path, "root.pem", &root_ca_pem())?;
    // First intermediate is an unrelated CA (wrong_root_ca is a separate root CA, not an intermediate)
    let wrong_intermediate_fh =
        create_temp_cert_file(&temp_path, "wrong-int.pem", &wrong_root_ca_pem())?;
    // Second intermediate is the correct one
    let correct_intermediate_fh =
        create_temp_cert_file(&temp_path, "correct-int.pem", &intermediate_ca_pem())?;
    let server_fh = create_temp_cert_file(&temp_path, "server.pem", &server_pem())?;

    // Pass both intermediates - should succeed because the second one is valid
    let result = server_fh.verify_cert_chain(
        root_fh,
        vec![wrong_intermediate_fh, correct_intermediate_fh],
    );

    assert!(
        result.is_ok(),
        "Should succeed when at least one intermediate is valid: {:?}",
        result
    );

    temp_dir.close()?;
    Ok(())
}

/// Given: A root certificate file with valid PEM structure but malformed DER content
/// When: Calling verify_cert
/// Then: Should return CertificateParseError with "Failed to parse root certificate as trust anchor"
#[test]
fn test_verify_cert_malformed_der_in_valid_pem() -> anyhow::Result<()> {
    let (temp_dir, temp_path) = create_temp_dir_and_path()?;

    // malformed-der.pem has valid base64 encoding but invalid DER certificate data
    let root_fh = create_temp_cert_file(&temp_path, "root.pem", &malformed_der_pem())?;
    let server_fh = create_temp_cert_file(&temp_path, "server.pem", &server_direct_pem())?;

    let result = server_fh.verify_cert(root_fh);

    assert!(result.is_err());
    match result.unwrap_err() {
        RustSafeIoError::CertificateParseError { reason } => {
            assert!(
                reason.contains("Failed to parse root certificate as trust anchor"),
                "Expected 'Failed to parse root certificate as trust anchor', got: {}",
                reason
            );
        }
        other => panic!("Expected CertificateParseError, got {:?}", other),
    }

    temp_dir.close()?;
    Ok(())
}
