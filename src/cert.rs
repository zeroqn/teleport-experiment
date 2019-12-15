use derive_more::Display;
use lazy_static::lazy_static;
use multihash::Multihash;
use parity_multihash as multihash;
use rand::rngs::OsRng;
use rcgen::{CertificateParams, CustomExtension};
use secp256k1::Secp256k1;

use std::error::Error as StdError;

lazy_static! {
    static ref SECP256K1: Secp256k1<secp256k1::All> = Secp256k1::new();
}

const CERT_P2P_EXT_PK_PREFIX: &str = "libp2p-tls-handshake";
const CERT_P2P_EXT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 53594, 1, 1];

#[derive(Debug, Display)]
pub enum X509DerCertificateError {
    #[display(fmt = "parse error: {:?}", _0)]
    ParseError(nom::Err<x509_parser::error::X509Error>),
    #[display(fmt = "signed key decode error: {}", _0)]
    SignedKeyDecodeError(prost::DecodeError),
    #[display(fmt = "host public key not found")]
    NoneHostPublicKey,
    #[display(fmt = "unsupport host public key {}", _0)]
    UnsupportedHostPublicKey(i32),
    #[display(fmt = "invalid host public key {}", _0)]
    InvalidHostPublicKey(Box<dyn StdError>),
    #[display(fmt = "invalid proof {}", _0)]
    InvalidProof(Box<dyn StdError>),
    #[display(fmt = "unexpected internal error {}", _0)]
    UnexpectedError(Box<dyn StdError>),
    #[display(fmt = "no proof found in certificate")]
    NoneProof,
}

impl From<nom::Err<x509_parser::error::X509Error>> for X509DerCertificateError {
    fn from(err: nom::Err<x509_parser::error::X509Error>) -> Self {
        X509DerCertificateError::ParseError(err)
    }
}

impl From<prost::DecodeError> for X509DerCertificateError {
    fn from(err: prost::DecodeError) -> Self {
        X509DerCertificateError::SignedKeyDecodeError(err)
    }
}

impl From<secp256k1::Error> for X509DerCertificateError {
    fn from(err: secp256k1::Error) -> Self {
        use secp256k1::Error as SecpError;
        use X509DerCertificateError::*;

        match err {
            SecpError::InvalidPublicKey => InvalidHostPublicKey(Box::new(err)),
            SecpError::InvalidSignature | SecpError::IncorrectSignature => {
                InvalidProof(Box::new(err))
            }
            _ => UnexpectedError(Box::new(err)),
        }
    }
}

impl StdError for X509DerCertificateError {}

#[derive(Debug, Display, Clone, PartialEq, Eq, prost::Enumeration)]
#[allow(dead_code)]
enum KeyType {
    #[display(fmt = "rsa")]
    RSA = 0,
    #[display(fmt = "ed25519")]
    ED25519 = 1,
    #[display(fmt = "secp256k1")]
    Secp256k1 = 2,
    #[display(fmt = "ecdsa")]
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

impl SignedKey {
    pub fn new(host_pk: &[u8], cert_proof: &[u8]) -> Self {
        let pk = PublicKey {
            key_type: KeyType::Secp256k1 as i32,
            data: Vec::from(host_pk),
        };

        SignedKey {
            public_key: Some(pk),
            signature: Vec::from(cert_proof),
        }
    }
}

pub struct PeerId(Multihash);

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

struct P2pOid;

impl P2pOid {
    pub fn is_match(oid: std::slice::Iter<'_, u64>) -> bool {
        for (ln, rn) in oid.zip(CERT_P2P_EXT_OID) {
            if ln != rn {
                return false;
            }
        }

        true
    }
}

pub struct P2PSelfSignedCertificate {
    der_cert: rcgen::Certificate,
}

impl P2PSelfSignedCertificate {
    pub fn from_host(host_sk: &[u8], host_pk: &[u8]) -> Result<Self, Box<dyn StdError>> {
        // Generate random certificate keypair
        let cert_kp = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P384_SHA384)?;
        let cert_pk = cert_kp.public_key_raw();

        let mut buf = [0u8; 1000];
        let len = Self::gen_proof(cert_pk, host_sk, &mut buf)?;
        let cert_proof = &buf[..len];

        // TODO: Wait prost bytes 0.5 pr merged
        let mut encoded_key = Vec::new();

        // Now we need to produce this proof extension
        let signed_key = SignedKey::new(host_pk, cert_proof);
        <SignedKey as prost::Message>::encode(&signed_key, &mut encoded_key)?;
        let p2p_ext = CustomExtension::from_oid_content(CERT_P2P_EXT_OID, encoded_key);

        let peer_id = PeerId::from_slice(host_pk)?;

        // Now we're ready to produce our self-signed certificate
        let mut cert_params = CertificateParams::default();
        // Note: use peer id as dns name isn't defined in spec
        cert_params.subject_alt_names = vec![rcgen::SanType::DnsName(peer_id.string())];
        cert_params.custom_extensions = vec![p2p_ext];
        cert_params.is_ca = rcgen::IsCa::SelfSignedOnly;
        cert_params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
        cert_params.key_pair = Some(cert_kp);

        let cert = rcgen::Certificate::from_params(cert_params)?;

        Ok(P2PSelfSignedCertificate { der_cert: cert })
    }

    pub fn serialize_der(&self) -> Result<Vec<u8>, Box<dyn StdError>> {
        Ok(self.der_cert.serialize_der()?)
    }

    pub fn serialize_private_key_der(&self) -> Vec<u8> {
        self.der_cert.serialize_private_key_der()
    }

    pub fn verify_cert_ext(bytes: &[u8]) -> Result<Vec<u8>, X509DerCertificateError> {
        use prost::Message;
        use x509_parser::parse_x509_der;
        use X509DerCertificateError::*;

        let (_, cert) = parse_x509_der(bytes)?;

        let cert = cert.tbs_certificate;
        let exts = cert.extensions;

        let cert_pki = cert.subject_pki;
        let cert_pk = cert_pki.subject_public_key.data;

        for ext in exts.iter() {
            if P2pOid::is_match(ext.oid.iter()) {
                let signed_key = SignedKey::decode(ext.value)?;
                let ext_pk = signed_key.public_key.ok_or(NoneHostPublicKey)?;

                if ext_pk.key_type != KeyType::Secp256k1 as i32 {
                    return Err(UnsupportedHostPublicKey(ext_pk.key_type));
                }

                let host_pk = ext_pk.data;
                let sig = signed_key.signature.as_slice();

                P2PSelfSignedCertificate::verify_proof(sig, cert_pk, host_pk.as_slice())?;
                return Ok(host_pk);
            }
        }

        Err(NoneProof)
    }

    // TODO: remove assert!
    fn salt_pk(cert_pk: &[u8], buf: &mut [u8]) -> usize {
        let prefix = CERT_P2P_EXT_PK_PREFIX;
        let spk_len = prefix.len() + cert_pk.len();

        assert!(
            spk_len < buf.len(),
            "certificate public key size {} is bigger than {} bytes",
            spk_len,
            buf.len()
        );

        buf[..prefix.len()].copy_from_slice(prefix.as_bytes());
        buf[prefix.len()..spk_len].copy_from_slice(cert_pk);

        spk_len
    }

    fn gen_proof(
        cert_pk: &[u8],
        host_sk: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, X509DerCertificateError> {
        let len = P2PSelfSignedCertificate::salt_pk(cert_pk, buf);
        let salt_pk = &buf[..len];

        let host_sk = secp256k1::SecretKey::from_slice(host_sk)?;
        let msg = secp256k1::Message::from_slice(&keccak256_hash(salt_pk))?;

        let sig = SECP256K1.sign(&msg, &host_sk);
        let ser_sig = sig.serialize_compact();

        buf[..ser_sig.len()].copy_from_slice(&ser_sig);
        Ok(ser_sig.len())
    }

    fn verify_proof(
        proof: &[u8],
        cert_pk: &[u8],
        host_pk: &[u8],
    ) -> Result<(), X509DerCertificateError> {
        let mut buf = [0u8; 1000];

        let host_pk = secp256k1::PublicKey::from_slice(host_pk)?;
        let sig = secp256k1::Signature::from_compact(proof)?;

        let len = P2PSelfSignedCertificate::salt_pk(cert_pk, &mut buf);
        let salt_pk = &buf[..len];

        let msg = secp256k1::Message::from_slice(&keccak256_hash(salt_pk))?;

        SECP256K1.verify(&msg, &sig, &host_pk).map_err(From::from)
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

pub fn generate_certificate(
    buf: &mut [u8],
) -> Result<(usize, P2PSelfSignedCertificate), Box<dyn StdError>> {
    let mut os_rng = OsRng::new()?;
    let (host_sk, host_pk) = SECP256K1.generate_keypair(&mut os_rng);
    let host_pk_ref: &[u8] = &host_pk.serialize();

    let cert = P2PSelfSignedCertificate::from_host(&host_sk[..], host_pk_ref)?;
    buf[..host_pk_ref.len()].copy_from_slice(host_pk_ref);

    Ok((host_pk_ref.len(), cert))
}

pub fn verify_cert_ext(cert: &[u8]) -> Result<Vec<u8>, X509DerCertificateError> {
    P2PSelfSignedCertificate::verify_cert_ext(cert)
}
