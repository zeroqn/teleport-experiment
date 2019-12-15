use derive_more::Display;
use rustls::{
    ClientCertVerified, ClientCertVerifier, DistinguishedNames, ServerCertVerified,
    ServerCertVerifier, TLSError,
};

use std::error::Error;

#[derive(Debug, Display)]
pub enum PeerCertificateVerifierError {
    #[display(fmt = "wrong number of certs in chain, expect 1, got {}", _0)]
    MoreThanOneCertificate(usize),
    #[display(fmt = "verify peer cert extension error: {}", _0)]
    ExtensionError(Box<dyn Error>),
}

impl PeerCertificateVerifierError {
    pub fn string(&self) -> String {
        format!("{}", self)
    }
}

// TODO: Normal TLS certificate verification processdure
struct PeerCertVerifier;

impl PeerCertVerifier {
    pub fn verify(certs: &[rustls::Certificate]) -> Result<(), TLSError> {
        use PeerCertificateVerifierError::*;
        use TLSError::*;

        if certs.len() != 1 {
            return Err(General(MoreThanOneCertificate(certs.len()).string()));
        }

        let root_cert = &certs[0];
        if let Err(err) = crate::cert::verify_cert_ext(root_cert.as_ref()) {
            return Err(General(ExtensionError(Box::new(err)).string()));
        }

        Ok(())
    }
}

pub struct ClientAuth;

impl ClientCertVerifier for ClientAuth {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> DistinguishedNames {
        DistinguishedNames::new()
    }

    fn verify_client_cert(
        &self,
        certs: &[rustls::Certificate],
    ) -> Result<ClientCertVerified, TLSError> {
        PeerCertVerifier::verify(certs)?;

        Ok(ClientCertVerified::assertion())
    }
}

pub struct ServerAuth;

impl ServerCertVerifier for ServerAuth {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef<'_>,
        _ocsp: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        PeerCertVerifier::verify(certs)?;

        Ok(ServerCertVerified::assertion())
    }
}
