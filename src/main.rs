use multihash::Multihash;
use parity_multihash as multihash;
use rand::rngs::OsRng;
use rcgen::{CertificateParams, CustomExtension};
use secp256k1::Secp256k1;

use std::error::Error;

const CERT_EXT_P2P_KEY_PREFIX: &str = "libp2p-tls-handshake";
const CERT_LIBP2P_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 53594, 1, 1];

#[derive(Debug, Clone, PartialEq, Eq, prost::Enumeration)]
#[allow(dead_code)]
enum KeyType {
    RSA = 0,
    ED25519 = 1,
    Secp256k1 = 2,
    ECDSA = 3,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
struct PublicKey {
    #[prost(enumeration = "KeyType", tag = "1")]
    pub key_type: i32,
    #[prost(bytes, tag = "2")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SignedKey {
    #[prost(message, tag = "1")]
    pub public_key: Option<PublicKey>,
    #[prost(bytes, tag = "2")]
    pub signature: Vec<u8>,
}

struct PeerId(Multihash);

impl PeerId {
    pub fn from_slice(pk: &[u8]) -> Result<Self, multihash::EncodeError> {
        let hash = keccak256_hash(pk);
        let mhash = multihash::encode(multihash::Hash::Keccak256, &hash)?;

        Ok(PeerId(mhash))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn string(&self) -> String {
        use multibase::{encode, Base};

        encode(Base::Base58flickr, self.as_slice())
    }
}

fn keccak256_hash(obj: &[u8]) -> [u8; 32] {
    use tiny_keccak::Hasher;

    let mut hasher = tiny_keccak::Keccak::v256();
    let mut output = [0u8; 32];

    hasher.update(obj);
    hasher.finalize(&mut output);

    output
}

/*
 * Ok, we got a basic self-signed certificate now, according to libp2p tls 1.3
 * , we have to implant a OID with our host public key and a signature. We
 * should use our host private key to sign a string, which is "libp2p-tls-handshake"
 * concatenate with the certificate public key.
 */
pub fn main() -> Result<(), Box<dyn Error>> {
    let secp = Secp256k1::new();
    let mut os_rng = OsRng::new()?;
    let (host_sk, host_pk) = secp.generate_keypair(&mut os_rng);
    let host_pk_ref: &[u8] = &host_pk.serialize();
    let peer_id = PeerId::from_slice(host_pk_ref)?;

    let cert_kp = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P384_SHA384)?;
    let cert_pk = cert_kp.public_key_raw();

    // Now two keypairs are ready, we need to produce extension key message
    // and sign it.
    let cert_key_p_len = CERT_EXT_P2P_KEY_PREFIX.len();
    let cert_key_msg_len = cert_key_p_len + cert_pk.len();
    let mut cert_key_msg = [0u8; 1000];
    assert!(cert_key_msg_len < 1000, "too big certificate public key");

    cert_key_msg[..cert_key_p_len].copy_from_slice(CERT_EXT_P2P_KEY_PREFIX.as_bytes());
    cert_key_msg[cert_key_p_len..cert_key_msg_len].copy_from_slice(cert_pk);

    let msg = secp256k1::Message::from_slice(&keccak256_hash(&cert_key_msg[..cert_key_msg_len]))?;
    let sig = secp.sign(&msg, &host_sk);

    // Now we need to produce this extension blob
    let ext_pk = PublicKey {
        key_type: KeyType::Secp256k1 as i32,
        data: Vec::from(host_pk_ref),
    };
    let ext_blob = SignedKey {
        public_key: Some(ext_pk),
        signature: Vec::from(&sig.serialize_compact() as &[u8]),
    };

    let mut oid_blob = Vec::new();
    <SignedKey as prost::Message>::encode(&ext_blob, &mut oid_blob)?;
    let p2p_ext = CustomExtension::from_oid_content(CERT_LIBP2P_OID, oid_blob);

    // Now we're ready to produce our self-signed certificate
    let mut cert_params = CertificateParams::default();
    cert_params.subject_alt_names = vec![rcgen::SanType::DnsName(peer_id.string())];
    cert_params.custom_extensions = vec![p2p_ext];
    cert_params.is_ca = rcgen::IsCa::SelfSignedOnly;

    let cert = rcgen::Certificate::from_params(cert_params)?;

    println!("{}", cert.serialize_pem()?);
    println!("{}", cert.serialize_private_key_pem());

    // Now we're gnone try to use rustls to verify it

    Ok(())
}
