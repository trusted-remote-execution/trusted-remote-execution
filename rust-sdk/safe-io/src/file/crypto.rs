//! Cryptographic operations for file handles.
//!
//! This module provides X.509 certificate chain verification functionality
//! that replicates the behavior of OpenSSL's verify command.

#![allow(clippy::needless_pass_by_value)]
use crate::errors::RustSafeIoError;
use crate::file::RcFileHandle;

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls_pki_types::pem::PemObject;
use std::io::{BufReader, Read};
use std::time::SystemTime;
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage, anchor_from_trusted_cert};

fn read_certs_from_reader<R: Read>(
    reader: &mut R,
) -> Result<Vec<CertificateDer<'static>>, RustSafeIoError> {
    let mut contents = Vec::new();
    reader
        .read_to_end(&mut contents)
        .map_err(|e| RustSafeIoError::CertificateParseError {
            reason: format!("Failed to read certificate file: {e}"),
        })?;

    let mut buf_reader = BufReader::new(contents.as_slice());
    CertificateDer::pem_reader_iter(&mut buf_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| RustSafeIoError::CertificateParseError {
            reason: format!("Failed to parse PEM certificates: {e}"),
        })
}

fn parse_end_entity_cert<'a>(
    cert_der: &'a CertificateDer<'a>,
) -> Result<EndEntityCert<'a>, RustSafeIoError> {
    EndEntityCert::try_from(cert_der).map_err(|e| RustSafeIoError::CertificateParseError {
        reason: format!("Failed to parse end-entity certificate: {e}"),
    })
}

fn get_unix_time(time: SystemTime) -> Result<UnixTime, RustSafeIoError> {
    let duration = time.duration_since(SystemTime::UNIX_EPOCH).map_err(|e| {
        RustSafeIoError::CertificateVerificationError {
            reason: format!("Failed to get current time: {e}"),
        }
    })?;
    Ok(UnixTime::since_unix_epoch(duration))
}

impl RcFileHandle {
    /// Verifies this file as a server certificate against a certificate chain with intermediate CAs.
    ///
    /// This replicates the behavior of:
    /// ```bash
    /// openssl verify -CAfile root.pem -untrusted intermediate.pem server.pem
    /// ```
    ///
    /// # Example
    /// ```no_run
    /// use rust_safe_io::RcFileHandle;
    ///
    /// fn verify_with_intermediates(
    ///     server_cert_fh: &RcFileHandle,
    ///     root_ca_fh: RcFileHandle,
    ///     intermediate_ca_fhs: Vec<RcFileHandle>,
    /// ) -> Result<(), rust_safe_io::errors::RustSafeIoError> {
    ///     server_cert_fh.verify_cert_chain(root_ca_fh, intermediate_ca_fhs)
    /// }
    /// ```
    pub fn verify_cert_chain(
        &self,
        root_ca_fh: RcFileHandle,
        intermediate_ca_fhs: Vec<RcFileHandle>,
    ) -> Result<(), RustSafeIoError> {
        self.verify_cert_chain_impl(root_ca_fh, intermediate_ca_fhs)
    }

    /// Verifies this file as a server certificate directly signed by a root CA (no intermediate CA).
    ///
    /// This replicates the behavior of:
    /// ```bash
    /// openssl verify -CAfile root.pem server.pem
    /// ```
    ///
    /// # Example
    /// ```no_run
    /// use rust_safe_io::RcFileHandle;
    ///
    /// fn verify_server_cert(
    ///     server_cert_fh: &RcFileHandle,
    ///     root_ca_fh: RcFileHandle,
    /// ) -> Result<(), rust_safe_io::errors::RustSafeIoError> {
    ///     server_cert_fh.verify_cert(root_ca_fh)
    /// }
    /// ```
    pub fn verify_cert(&self, root_ca_fh: RcFileHandle) -> Result<(), RustSafeIoError> {
        self.verify_cert_chain_impl(root_ca_fh, vec![])
    }

    fn verify_cert_chain_impl(
        &self,
        root_ca_fh: RcFileHandle,
        intermediate_ca_fhs: Vec<RcFileHandle>,
    ) -> Result<(), RustSafeIoError> {
        let root_certs = root_ca_fh.read_certs()?;
        let server_certs = self.read_certs()?;

        let mut intermediate_certs = Vec::new();
        for fh in intermediate_ca_fhs {
            intermediate_certs.extend(fh.read_certs()?);
        }

        let root_cert = root_certs.into_iter().next().ok_or_else(|| {
            RustSafeIoError::CertificateParseError {
                reason: "No certificates found in root CA file".to_string(),
            }
        })?;
        let anchor = anchor_from_trusted_cert(&root_cert).map_err(|e| {
            RustSafeIoError::CertificateParseError {
                reason: format!("Failed to parse root certificate as trust anchor: {e}"),
            }
        })?;

        let mut server_certs_iter = server_certs.into_iter();
        let server_cert_der =
            server_certs_iter
                .next()
                .ok_or_else(|| RustSafeIoError::CertificateParseError {
                    reason: "No certificates found in server certificate file".to_string(),
                })?;
        let server_cert = parse_end_entity_cert(&server_cert_der)?;

        // Add remaining server certs to intermediates (for bundled chains)
        intermediate_certs.extend(server_certs_iter);

        let now = get_unix_time(SystemTime::now())?;

        server_cert
            .verify_for_usage(
                ALL_VERIFICATION_ALGS,
                &[anchor],
                &intermediate_certs,
                now,
                KeyUsage::server_auth(),
                None, // no revocation checking
                None, // no budget limit
            )
            .map_err(|e| RustSafeIoError::CertificateVerificationError {
                reason: format!("Certificate chain verification failed: {e}"),
            })?;

        Ok(())
    }

    fn read_certs(&self) -> Result<Vec<CertificateDer<'static>>, RustSafeIoError> {
        self.rewind()?;
        let file = &self.file_handle.file;
        let result = read_certs_from_reader(&mut &*file);
        self.rewind()?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{get_unix_time, parse_end_entity_cert, read_certs_from_reader};

    use rex_test_utils::assertions::assert_error_contains;
    use rstest::rstest;
    use rustls::pki_types::CertificateDer;
    use std::io::{self, Read};
    use std::time::{Duration, SystemTime};

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "simulated read error"))
        }
    }

    /// Given: A reader that always fails with an I/O error
    /// When: Reading certificates with read_certs_from_reader
    /// Then: Should return CertificateParseError with "Failed to read certificate file"
    #[test]
    fn test_read_certs_from_reader_io_error() {
        let mut reader = FailingReader;
        let result = read_certs_from_reader(&mut reader);

        assert_error_contains(
            result,
            "Certificate parse error: Failed to read certificate file: simulated read error",
        );
    }

    /// Given: Invalid DER bytes that do not form a valid certificate
    /// When: Parsing with parse_end_entity_cert
    /// Then: Should return CertificateParseError with "Failed to parse end-entity certificate"
    #[test]
    fn test_parse_end_entity_cert_invalid_der() {
        let invalid_der = CertificateDer::from(vec![0x00, 0x01, 0x02, 0x03]);
        let result = parse_end_entity_cert(&invalid_der);

        assert_error_contains(
            result,
            "Certificate parse error: Failed to parse end-entity certificate",
        );
    }

    /// Given: Various SystemTime values
    /// When: Converting to UnixTime with get_unix_time
    /// Then: Should succeed for valid times and fail for times before Unix epoch
    #[rstest]
    #[case::valid_current_time(SystemTime::now(), true)]
    #[case::before_unix_epoch(SystemTime::UNIX_EPOCH - Duration::from_secs(1), false)]
    fn test_get_unix_time(#[case] time: SystemTime, #[case] should_succeed: bool) {
        let result = get_unix_time(time);

        if should_succeed {
            assert!(result.is_ok(), "Time should convert successfully");
        } else {
            assert_error_contains(
                result,
                "Certificate verification error: Failed to get current time",
            );
        }
    }
}
