use crate::verifier::{ClientAuth, ServerAuth};

use derive_more::Display;
use quinn::{
    ClientConfig, ClientConfigBuilder, Endpoint, EndpointDriver, Incoming, ServerConfig,
    ServerConfigBuilder, TransportConfig,
};

use std::{error::Error, net::ToSocketAddrs, sync::Arc};

#[derive(Debug, Display)]
pub enum EndpointError {
    #[display(fmt = "no connection")]
    NoConnection,
    #[display(fmt = "no peer certificates")]
    NoPeerCertificates,
    #[display(fmt = "no valid socket address")]
    NoSocketAddress,
}

impl Error for EndpointError {}

pub fn make_peer() -> Result<(rustls::Certificate, rustls::PrivateKey), Box<dyn Error>> {
    let mut buf = [0u8; 1000];
    let (_, cert) = crate::cert::generate_certificate(&mut buf)?;
    let priv_key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert = rustls::Certificate(cert.serialize_der()?);

    Ok((cert, priv_key))
}

pub fn make_server_config() -> Result<ServerConfig, Box<dyn Error>> {
    let (cert, priv_key) = make_peer()?;

    let mut tls_cfg = rustls::ServerConfig::new(Arc::new(ClientAuth));
    // Force tls 1.3, no fallback
    tls_cfg.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    // Allow early data
    tls_cfg.max_early_data_size = u32::max_value();
    tls_cfg.set_single_cert(vec![cert], priv_key)?;

    let server_config = ServerConfig {
        transport: Arc::new(TransportConfig {
            // No uni stream
            stream_window_uni: 0,
            ..Default::default()
        }),
        crypto: Arc::new(tls_cfg),
        ..Default::default()
    };

    Ok(ServerConfigBuilder::new(server_config).build())
}

pub fn make_server_endpoint<A: ToSocketAddrs>(
    bind_addr: A,
) -> Result<(EndpointDriver, Incoming), Box<dyn Error>> {
    use EndpointError::*;

    let sock_addr = bind_addr.to_socket_addrs()?.next().ok_or(NoSocketAddress)?;

    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(make_server_config()?);

    let (driver, _endpoint, incoming) = endpoint_builder.bind(&sock_addr)?;
    Ok((driver, incoming))
}

pub fn make_client_config() -> Result<ClientConfig, Box<dyn Error>> {
    let (cert, priv_key) = make_peer()?;

    let mut tls_cfg = rustls::ClientConfig::new();
    // Force tls 1.3, no fallback
    tls_cfg.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    tls_cfg.set_single_client_cert(vec![cert], priv_key);
    // Through rustls "dangerous_configuration" feature gate
    tls_cfg
        .dangerous()
        .set_certificate_verifier(Arc::new(ServerAuth));

    let client_config = ClientConfig {
        transport: Arc::new(TransportConfig {
            // No uni stream
            stream_window_uni: 0,
            ..Default::default()
        }),
        crypto: Arc::new(tls_cfg),
        ..Default::default()
    };

    Ok(ClientConfigBuilder::new(client_config).build())
}

pub fn make_client_endpoint<A: ToSocketAddrs>(
    bind_addr: A,
) -> Result<(EndpointDriver, Endpoint), Box<dyn Error>> {
    use EndpointError::*;

    let sock_addr = bind_addr.to_socket_addrs()?.next().ok_or(NoSocketAddress)?;

    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(make_client_config()?);

    let (driver, endpoint, _incoming) = endpoint_builder.bind(&sock_addr)?;
    Ok((driver, endpoint))
}
