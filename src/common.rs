//! Commonly used code in most examples.

use quinn::{
    Certificate, CertificateChain, ClientConfig, ClientConfigBuilder, Endpoint, EndpointDriver,
    Incoming, PrivateKey, ServerConfig, ServerConfigBuilder, TransportConfig,
};
use std::{error::Error, net::ToSocketAddrs, sync::Arc};

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
///
/// - UDP socket driver
/// - a sream of incoming QUIC connections
/// - server certificate serialized into DER format
#[allow(unused)]
pub fn make_server_endpoint<A: ToSocketAddrs>(
    bind_addr: A,
) -> Result<(EndpointDriver, Incoming, Vec<u8>), Box<dyn Error>> {
    let (server_config, server_cert) = configure_server()?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);
    let (driver, _endpoint, incoming) =
        endpoint_builder.bind(&bind_addr.to_socket_addrs().unwrap().next().unwrap())?;
    Ok((driver, incoming, server_cert))
}

/// Builds default quinn client config and trusts given certificates.
///
/// ## Args
///
/// - server_certs: a list of trusted certificates in DER format.
fn configure_client(server_certs: &[&[u8]]) -> Result<ClientConfig, Box<dyn Error>> {
    let mut cfg_builder = ClientConfigBuilder::default();
    for cert in server_certs {
        cfg_builder.add_certificate_authority(Certificate::from_der(&cert)?)?;
    }
    Ok(cfg_builder.build())
}

/// Returns default server configuration along with its certificate.
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Box<dyn Error>> {
    let mut buf = [0u8; 1000];
    let (_, cert) = crate::cert::generate_certificate(&mut buf)?;
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey::from_der(&priv_key)?;

    let mut tls_cfg = rustls::ServerConfig::new(Arc::new(crate::verifier::ClientAuth));
    tls_cfg.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    tls_cfg.max_early_data_size = u32::max_value();

    let server_config = ServerConfig {
        transport: Arc::new(TransportConfig {
            stream_window_uni: 0,
            ..Default::default()
        }),
        crypto: Arc::new(tls_cfg),
        ..Default::default()
    };

    let mut cfg_builder = ServerConfigBuilder::new(server_config);
    let cert = Certificate::from_der(&cert_der)?;
    cfg_builder.certificate(CertificateChain::from_certs(vec![cert]), priv_key)?;

    Ok((cfg_builder.build(), cert_der))
}

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-24"];
