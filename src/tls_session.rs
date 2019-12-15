use crate::verifier::{ClientAuth, ServerAuth};

use rustls::{
    ClientConfig, ClientSessionMemoryCache, ProtocolVersion, ServerConfig, ServerSessionMemoryCache,
};

use std::{error::Error as StdError, sync::Arc};

pub fn new_client_cfg(der_cert: &[u8], der_sk: &[u8]) -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::new();

    let persist = ClientSessionMemoryCache::new(32);
    cfg.set_persistence(persist);

    let certs = vec![rustls::Certificate(der_cert.to_owned())];
    let sk = rustls::PrivateKey(der_sk.to_owned());
    cfg.set_single_client_cert(certs, sk);

    cfg.dangerous()
        .set_certificate_verifier(Arc::new(ServerAuth {}));

    // IMORTANT: we only support tls 1.3, no tls 1.2
    cfg.versions.clear();
    cfg.versions.push(ProtocolVersion::TLSv1_3);

    Arc::new(cfg)
}

pub fn new_server_cfg(
    der_cert: &[u8],
    der_sk: &[u8],
) -> Result<Arc<rustls::ServerConfig>, Box<dyn StdError>> {
    let mut cfg = ServerConfig::new(Arc::new(ClientAuth));
    let persist = ServerSessionMemoryCache::new(32);
    cfg.set_persistence(persist);

    let certs = vec![rustls::Certificate(der_cert.to_owned())];
    let sk = rustls::PrivateKey(der_sk.to_owned());
    cfg.set_single_cert(certs, sk)?;

    // IMORTANT: we only support tls 1.3, no tls 1.2
    cfg.versions.clear();
    cfg.versions.push(ProtocolVersion::TLSv1_3);

    Ok(Arc::new(cfg))
}
