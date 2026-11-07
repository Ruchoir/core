//! The signature of server-to-server events (ADR 0006 of `Ruchoir/.github`).
//!
//! # Why a signature, and why this one
//!
//! Services share no secret: each one is an OpenID Connect client of Propolis. A shared HMAC key
//! would let every consumer forge events in the name of every producer, so events are signed with
//! an asymmetric key instead. A producer signs with its private [`SigningKey`]; a consumer checks
//! with the producer's public key, from a [`PublicKeys`] set it fills from where the keys are
//! published (Propolis, once its design is written), and can never sign in the producer's name.
//!
//! The algorithm is Ed25519, through `ring`, which the products already ship as the rustls crypto
//! provider: small keys and signatures, no parameters to get wrong, and deterministic signing, so
//! no random source is needed to sign.
//!
//! # What is signed: the exact bytes sent
//!
//! The signature covers the exact bytes of the request body, as written by `serde_json::to_vec`
//! (see [`Event::sign`]). Those bytes are deterministic for a given build: `serde_json` without its
//! `preserve_order` feature keeps the keys of a `serde_json::Value` object in a sorted map, and a
//! struct is written with its fields in declaration order. They are still not a canonical form: a
//! crate that turns `preserve_order` on anywhere in a build changes the order of map keys, and two
//! JSON writers can format the same number differently. So nothing ever re-serializes to verify:
//!
//! - the producer signs the bytes it is about to send, and sends exactly those;
//! - the consumer verifies the bytes it received, *before* parsing them, and parses those same
//!   bytes only once they are known to come from the producer ([`verify_and_parse`]). Forged input
//!   never reaches the JSON parser or the product's handler.
//!
//! # The header
//!
//! The signature travels next to the body, in [`SIGNATURE_HEADER`]:
//!
//! ```text
//! Ruchoir-Signature: keyid=drive-2026-11, sig=<base64url of the 64-byte signature, no padding>
//! ```
//!
//! The key id says which public key to check with, so a producer can rotate its key: it publishes
//! the new public key, then signs with the new key, and the old public key stays published until no
//! event signed with it can still be in flight. A key id is 1 to [`MAX_KEY_ID_LEN`] ASCII letters,
//! digits, `.`, `_` or `-`, so it never needs quoting in the header. The parser is strict: both
//! parameters exactly once, in either order, nothing else. A new parameter is a new format, decided
//! deliberately, not something an old consumer silently ignores.
//!
//! # Whose key it is
//!
//! Every trusted key belongs to one service, its *owner*: Propolis publishes each service's event
//! keys with the service they belong to (ADR 0011 of `Ruchoir/.github`). A valid signature only
//! proves that the owner of the key wrote the bytes, so [`verify_and_parse`] also refuses an event
//! whose `source` is not that owner. Without this check, any producer could sign an event in
//! another service's name (the drive announcing that Propolis deleted an account).
//!
//! # What the signature does not do
//!
//! - It proves who wrote the event and that it was not changed, not that it is fresh. Replaying the
//!   same bytes replays the same event id, which the consumer's idempotency already absorbs; a
//!   consumer may also refuse an event whose `occurred_at` is too old for it.
//! - It hides nothing: events travel over TLS, like every other call between services.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _, UnparsedPublicKey, ED25519};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::event::Event;

/// The HTTP header that carries the signature of a request body.
pub const SIGNATURE_HEADER: &str = "Ruchoir-Signature";

/// The longest key id accepted, in bytes.
pub const MAX_KEY_ID_LEN: usize = 64;

/// The length of an Ed25519 signature, in bytes.
const SIGNATURE_LEN: usize = 64;

/// The length of an Ed25519 public key, in bytes.
const PUBLIC_KEY_LEN: usize = 32;

fn is_valid_key_id(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= MAX_KEY_ID_LEN
        && key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A producer's private Ed25519 key, with the id its public key is published under.
///
/// Its `Debug` output shows the key id and the public key only.
pub struct SigningKey {
    key_id: String,
    pair: Ed25519KeyPair,
}

impl SigningKey {
    /// Reads an unencrypted PKCS#8 Ed25519 private key.
    ///
    /// Both PKCS#8 versions are accepted. A v2 document (what [`SigningKey::generate`] and `ring`
    /// write) holds the public key, and it is checked against the private key. A v1 document (what
    /// `openssl genpkey -algorithm ed25519` writes) holds only the private key, and the public key
    /// is derived from it.
    pub fn from_pkcs8(key_id: impl Into<String>, pkcs8: &[u8]) -> Result<Self, KeyError> {
        let key_id = key_id.into();
        if !is_valid_key_id(&key_id) {
            return Err(KeyError::InvalidKeyId);
        }
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8)
            .map_err(|_| KeyError::InvalidPrivateKey)?;
        Ok(Self { key_id, pair })
    }

    /// A new random key, with its PKCS#8 v2 document so it can be stored and read back with
    /// [`SigningKey::from_pkcs8`]. For tests and development: a production key is made once, kept
    /// with the service's other secrets, and read at start-up.
    pub fn generate(key_id: impl Into<String>) -> Result<(Self, Vec<u8>), KeyError> {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| KeyError::Generation)?;
        let pkcs8 = document.as_ref().to_vec();
        Ok((Self::from_pkcs8(key_id, &pkcs8)?, pkcs8))
    }

    /// The id the public key is published under, written in every signature header.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The 32-byte public key, to publish under [`SigningKey::key_id`].
    pub fn public_key(&self) -> &[u8] {
        self.pair.public_key().as_ref()
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("key_id", &self.key_id)
            .field("public_key", &URL_SAFE_NO_PAD.encode(self.public_key()))
            .finish_non_exhaustive()
    }
}

/// The public keys a consumer trusts, by key id, each with the service that owns it.
///
/// A consumer fills it from the published keys of the producers it listens to. Holding several
/// keys at once is what lets a producer rotate: the outgoing and the incoming key are both here
/// while events signed with the outgoing one may still arrive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicKeys {
    keys: BTreeMap<String, TrustedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedKey {
    owner: String,
    key: [u8; PUBLIC_KEY_LEN],
}

impl PublicKeys {
    /// An empty set: nothing verifies against it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusts `public_key` (32 bytes) for signatures made under `key_id` by the service `owner`
    /// (the name its events carry in `source`), replacing what was trusted under that id before.
    pub fn insert(
        &mut self,
        key_id: impl Into<String>,
        owner: impl Into<String>,
        public_key: &[u8],
    ) -> Result<(), KeyError> {
        let key_id = key_id.into();
        if !is_valid_key_id(&key_id) {
            return Err(KeyError::InvalidKeyId);
        }
        let owner = owner.into();
        if owner.is_empty() {
            return Err(KeyError::InvalidOwner);
        }
        let key: [u8; PUBLIC_KEY_LEN] = public_key
            .try_into()
            .map_err(|_| KeyError::InvalidPublicKey)?;
        self.keys.insert(key_id, TrustedKey { owner, key });
        Ok(())
    }

    /// Stops trusting `key_id`. Says whether it was trusted.
    pub fn remove(&mut self, key_id: &str) -> bool {
        self.keys.remove(key_id).is_some()
    }

    /// Whether a key is trusted under `key_id`.
    pub fn contains(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    /// The public key trusted under `key_id`.
    pub fn get(&self, key_id: &str) -> Option<&[u8]> {
        self.keys.get(key_id).map(|trusted| trusted.key.as_slice())
    }

    /// The service that owns the key trusted under `key_id`.
    pub fn owner(&self, key_id: &str) -> Option<&str> {
        self.keys.get(key_id).map(|trusted| trusted.owner.as_str())
    }

    /// How many keys are trusted.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is trusted.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The parsed value of a [`SIGNATURE_HEADER`]: which key signed, and the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeader {
    key_id: String,
    signature: [u8; SIGNATURE_LEN],
}

impl SignatureHeader {
    /// The id of the key that made the signature.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The 64-byte Ed25519 signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The header value: `keyid=<id>, sig=<base64url, no padding>`.
    pub fn to_header_value(&self) -> String {
        format!(
            "keyid={}, sig={}",
            self.key_id,
            URL_SAFE_NO_PAD.encode(self.signature)
        )
    }

    /// Reads a header value written by [`SignatureHeader::to_header_value`].
    ///
    /// Parameters are separated by commas, with optional spaces or tabs around them; `keyid` and
    /// `sig` must each appear exactly once, in either order, and nothing else may. The signature
    /// must be canonical unpadded base64url of exactly 64 bytes.
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        let mut key_id = None;
        let mut signature = None;
        for parameter in value.split(',') {
            let parameter = parameter.trim_matches([' ', '\t']);
            let (name, value) = parameter
                .split_once('=')
                .ok_or(HeaderError::MalformedParameter)?;
            let slot = match name {
                "keyid" => &mut key_id,
                "sig" => &mut signature,
                _ => return Err(HeaderError::UnknownParameter),
            };
            if slot.replace(value).is_some() {
                return Err(HeaderError::DuplicateParameter);
            }
        }
        let key_id = key_id.ok_or(HeaderError::MissingKeyId)?;
        let signature = signature.ok_or(HeaderError::MissingSignature)?;
        if !is_valid_key_id(key_id) {
            return Err(HeaderError::InvalidKeyId);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| HeaderError::InvalidSignatureEncoding)?
            .try_into()
            .map_err(|_| HeaderError::InvalidSignatureLength)?;
        Ok(Self {
            key_id: key_id.to_owned(),
            signature,
        })
    }
}

impl fmt::Display for SignatureHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_header_value())
    }
}

impl FromStr for SignatureHeader {
    type Err = HeaderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Signs `bytes`, the exact body about to be sent, with `key`.
pub fn sign(bytes: &[u8], key: &SigningKey) -> SignatureHeader {
    let signature = key
        .pair
        .sign(bytes)
        .as_ref()
        .try_into()
        .expect("an Ed25519 signature is 64 bytes");
    SignatureHeader {
        key_id: key.key_id.clone(),
        signature,
    }
}

/// Checks that `bytes`, the exact body received, were signed by the key `header` names, and that
/// this key is one of `keys`. Returns the service that owns the key.
///
/// It does not read the body, so it cannot check the event's `source` against that owner:
/// [`verify_and_parse`] does both, and is what a consumer of events calls.
pub fn verify<'k>(
    bytes: &[u8],
    header: &SignatureHeader,
    keys: &'k PublicKeys,
) -> Result<&'k str, VerifyError> {
    let trusted = keys
        .keys
        .get(header.key_id())
        .ok_or_else(|| VerifyError::UnknownKey(header.key_id().to_owned()))?;
    UnparsedPublicKey::new(&ED25519, &trusted.key)
        .verify(bytes, header.signature())
        .map_err(|_| VerifyError::BadSignature)?;
    Ok(&trusted.owner)
}

/// What a consumer does with a request: reads the [`SIGNATURE_HEADER`] value, verifies the body
/// against it, only then parses the body as an [`Event`], and refuses it unless its `source` is the
/// service that owns the signing key.
pub fn verify_and_parse<T: DeserializeOwned>(
    bytes: &[u8],
    header: &str,
    keys: &PublicKeys,
) -> Result<Event<T>, VerifyError> {
    let header = SignatureHeader::parse(header).map_err(VerifyError::Header)?;
    let owner = verify(bytes, &header, keys)?;
    let event: Event<T> = serde_json::from_slice(bytes).map_err(VerifyError::InvalidEvent)?;
    if event.source != owner {
        return Err(VerifyError::WrongSource {
            key_owner: owner.to_owned(),
            source: event.source,
        });
    }
    Ok(event)
}

/// An event ready to send: the body to send as is, and the header that goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEvent {
    /// The JSON body, exactly the bytes that were signed. Send it unchanged.
    pub body: Vec<u8>,
    /// The signature of `body`, for the [`SIGNATURE_HEADER`].
    pub header: SignatureHeader,
}

impl<T: Serialize> Event<T> {
    /// Serializes the event once with `serde_json::to_vec` and signs those bytes.
    ///
    /// Fails only when the payload cannot be represented as JSON.
    pub fn sign(&self, key: &SigningKey) -> Result<SignedEvent, serde_json::Error> {
        let body = serde_json::to_vec(self)?;
        let header = sign(&body, key);
        Ok(SignedEvent { body, header })
    }
}

/// Why a key could not be built or trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The key id is empty, too long, or holds something other than ASCII letters, digits, `.`,
    /// `_` and `-`.
    InvalidKeyId,
    /// The bytes are not an unencrypted PKCS#8 Ed25519 private key, or its public key does not
    /// match it.
    InvalidPrivateKey,
    /// The bytes are not a 32-byte Ed25519 public key.
    InvalidPublicKey,
    /// The owner of a trusted key is empty.
    InvalidOwner,
    /// The system random source failed while generating a key.
    Generation,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidKeyId => "invalid key id",
            Self::InvalidPrivateKey => "not an unencrypted PKCS#8 Ed25519 private key",
            Self::InvalidPublicKey => "not a 32-byte Ed25519 public key",
            Self::InvalidOwner => "a trusted key needs the name of the service that owns it",
            Self::Generation => "could not generate an Ed25519 key",
        })
    }
}

impl std::error::Error for KeyError {}

/// Why a signature header value could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// A parameter is not of the form `name=value` (an empty header included).
    MalformedParameter,
    /// A parameter other than `keyid` and `sig`.
    UnknownParameter,
    /// `keyid` or `sig` appears more than once.
    DuplicateParameter,
    /// No `keyid` parameter.
    MissingKeyId,
    /// No `sig` parameter.
    MissingSignature,
    /// The key id is empty, too long, or holds a character outside the allowed set.
    InvalidKeyId,
    /// The signature is not canonical unpadded base64url.
    InvalidSignatureEncoding,
    /// The signature does not decode to 64 bytes.
    InvalidSignatureLength,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MalformedParameter => "signature header parameter is not name=value",
            Self::UnknownParameter => "unknown signature header parameter",
            Self::DuplicateParameter => "repeated signature header parameter",
            Self::MissingKeyId => "signature header has no keyid",
            Self::MissingSignature => "signature header has no sig",
            Self::InvalidKeyId => "invalid key id in signature header",
            Self::InvalidSignatureEncoding => "signature is not unpadded base64url",
            Self::InvalidSignatureLength => "signature is not 64 bytes",
        })
    }
}

impl std::error::Error for HeaderError {}

/// Why a signed body was refused.
#[derive(Debug)]
pub enum VerifyError {
    /// The signature header could not be read.
    Header(HeaderError),
    /// No trusted public key has the key id the header names (an unknown producer, or a key not
    /// published yet or already withdrawn).
    UnknownKey(String),
    /// The signature does not match the body under the named key: the body was changed, or it was
    /// signed by another key.
    BadSignature,
    /// The body is authentic but is not an event with the expected payload.
    InvalidEvent(serde_json::Error),
    /// The event is authentic, but names as its `source` another service than the one that owns
    /// the key that signed it.
    WrongSource {
        /// The service that owns the signing key.
        key_owner: String,
        /// The service the event claims to come from.
        source: String,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(error) => write!(f, "malformed signature header: {error}"),
            Self::UnknownKey(key_id) => write!(f, "no trusted public key under key id {key_id:?}"),
            Self::BadSignature => f.write_str("signature does not match the body"),
            Self::InvalidEvent(error) => write!(f, "signed body is not a valid event: {error}"),
            Self::WrongSource { key_owner, source } => write!(
                f,
                "event claims to come from {source:?} but is signed by a key of {key_owner:?}"
            ),
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header(error) => Some(error),
            Self::InvalidEvent(error) => Some(error),
            Self::UnknownKey(_) | Self::BadSignature | Self::WrongSource { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Kind;
    use serde::Deserialize;
    use uuid::Uuid;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct FileDeleted {
        file_id: Uuid,
    }

    fn key(key_id: &str) -> SigningKey {
        SigningKey::generate(key_id).unwrap().0
    }

    /// Trusts each key for the service its id starts with (`drive-1` belongs to `drive`).
    fn trusting(keys: &[&SigningKey]) -> PublicKeys {
        let mut trusted = PublicKeys::new();
        for key in keys {
            let owner = key.key_id().split('-').next().unwrap();
            trusted
                .insert(key.key_id(), owner, key.public_key())
                .unwrap();
        }
        trusted
    }

    fn event() -> Event<FileDeleted> {
        Event::new(
            Kind::new("drive.file.deleted").unwrap(),
            1,
            "drive",
            Some(Uuid::new_v4()),
            FileDeleted {
                file_id: Uuid::new_v4(),
            },
        )
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn a_signed_body_verifies() {
        let drive = key("drive-1");
        let signed = event().sign(&drive).unwrap();
        assert_eq!(signed.header.key_id(), "drive-1");
        verify(&signed.body, &signed.header, &trusting(&[&drive])).unwrap();
    }

    #[test]
    fn the_header_value_has_the_documented_form_and_reads_back() {
        let drive = key("drive-2026.11_a");
        let header = sign(b"{}", &drive);
        let value = header.to_header_value();
        let sig = value.strip_prefix("keyid=drive-2026.11_a, sig=").unwrap();
        assert_eq!(sig.len(), 86, "64 bytes in unpadded base64url");
        assert!(sig
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_eq!(SignatureHeader::parse(&value).unwrap(), header);
        assert_eq!(value.parse::<SignatureHeader>().unwrap(), header);
        assert_eq!(header.to_string(), value);
    }

    #[test]
    fn parameters_read_in_either_order_with_spaces_or_tabs() {
        let header = sign(b"{}", &key("k1"));
        let sig = URL_SAFE_NO_PAD.encode(header.signature());
        for value in [
            format!("sig={sig}, keyid=k1"),
            format!("keyid=k1,sig={sig}"),
            format!(" keyid=k1 ,\tsig={sig} "),
        ] {
            assert_eq!(SignatureHeader::parse(&value).unwrap(), header, "{value}");
        }
    }

    #[test]
    fn a_tampered_body_is_refused() {
        let drive = key("drive-1");
        let keys = trusting(&[&drive]);
        let signed = event().sign(&drive).unwrap();

        let mut flipped = signed.body.clone();
        let last = flipped.len() - 2;
        flipped[last] ^= 0x01;
        let mut padded = signed.body.clone();
        padded.push(b' ');
        let reserialized = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&signed.body).unwrap(),
        )
        .unwrap();

        for body in [flipped, padded, reserialized, Vec::new()] {
            assert!(matches!(
                verify(&body, &signed.header, &keys),
                Err(VerifyError::BadSignature)
            ));
        }
    }

    #[test]
    fn an_unknown_key_id_is_refused() {
        let drive = key("drive-1");
        let signed = event().sign(&drive).unwrap();
        let error =
            verify(&signed.body, &signed.header, &trusting(&[&key("drive-2")])).unwrap_err();
        assert!(matches!(error, VerifyError::UnknownKey(ref id) if id == "drive-1"));
        assert!(matches!(
            verify(&signed.body, &signed.header, &PublicKeys::new()),
            Err(VerifyError::UnknownKey(_))
        ));
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let drive = key("drive-1");
        let impostor = key("drive-1");
        let signed = event().sign(&impostor).unwrap();
        assert!(matches!(
            verify(&signed.body, &signed.header, &trusting(&[&drive])),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn a_signature_moved_under_another_trusted_key_id_is_refused() {
        let drive = key("drive-1");
        let chat = key("chat-1");
        let signed = event().sign(&chat).unwrap();
        let relabelled = SignatureHeader::parse(
            &signed
                .header
                .to_header_value()
                .replace("keyid=chat-1", "keyid=drive-1"),
        )
        .unwrap();
        assert!(matches!(
            verify(&signed.body, &relabelled, &trusting(&[&drive, &chat])),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn malformed_headers_are_refused_with_the_reason() {
        let sig = URL_SAFE_NO_PAD.encode(sign(b"{}", &key("k1")).signature());
        let standard = base64::engine::general_purpose::STANDARD.encode([0xfb; 64]);
        let cases = [
            (String::new(), HeaderError::MalformedParameter),
            ("keyid=k1".to_owned(), HeaderError::MissingSignature),
            (format!("sig={sig}"), HeaderError::MissingKeyId),
            // A semicolon is not a separator: this is a single `keyid` parameter, and no `sig`.
            (
                format!("keyid=k1; sig={sig}"),
                HeaderError::MissingSignature,
            ),
            (
                format!("keyid=k1, sig={sig},"),
                HeaderError::MalformedParameter,
            ),
            (
                format!("keyid k1, sig={sig}"),
                HeaderError::MalformedParameter,
            ),
            (
                format!("keyid=k1, sig={sig}, alg=ed25519"),
                HeaderError::UnknownParameter,
            ),
            (
                format!("KEYID=k1, sig={sig}"),
                HeaderError::UnknownParameter,
            ),
            (
                format!("keyid=k1, keyid=k1, sig={sig}"),
                HeaderError::DuplicateParameter,
            ),
            (
                format!("keyid=k1, sig={sig}, sig={sig}"),
                HeaderError::DuplicateParameter,
            ),
            (format!("keyid=, sig={sig}"), HeaderError::InvalidKeyId),
            (format!("keyid=k 1, sig={sig}"), HeaderError::InvalidKeyId),
            (
                format!("keyid=\"k1\", sig={sig}"),
                HeaderError::InvalidKeyId,
            ),
            (
                format!("keyid={}, sig={sig}", "k".repeat(MAX_KEY_ID_LEN + 1)),
                HeaderError::InvalidKeyId,
            ),
            (
                format!("keyid=k1, sig={sig}=="),
                HeaderError::InvalidSignatureEncoding,
            ),
            (
                format!("keyid=k1, sig={standard}"),
                HeaderError::InvalidSignatureEncoding,
            ),
            (
                "keyid=k1, sig=not*base64".to_owned(),
                HeaderError::InvalidSignatureEncoding,
            ),
            (
                "keyid=k1, sig=".to_owned(),
                HeaderError::InvalidSignatureLength,
            ),
            (
                "keyid=k1, sig=AAAA".to_owned(),
                HeaderError::InvalidSignatureLength,
            ),
            (
                format!("keyid=k1, sig={}", URL_SAFE_NO_PAD.encode([0; 65])),
                HeaderError::InvalidSignatureLength,
            ),
        ];
        for (value, reason) in cases {
            assert_eq!(SignatureHeader::parse(&value), Err(reason), "{value:?}");
        }
    }

    #[test]
    fn non_canonical_trailing_bits_are_refused() {
        let mut sig = URL_SAFE_NO_PAD.encode(sign(b"{}", &key("k1")).signature());
        // 64 bytes leave four unused low bits in the last character: setting one gives another
        // spelling of the same bytes, which a strict decoder refuses.
        let last = sig.pop().unwrap();
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let index = alphabet.find(last).unwrap();
        sig.push(alphabet.as_bytes()[index ^ 0b01] as char);
        assert_eq!(
            SignatureHeader::parse(&format!("keyid=k1, sig={sig}")),
            Err(HeaderError::InvalidSignatureEncoding)
        );
    }

    #[test]
    fn verify_and_parse_returns_the_event_sent() {
        let drive = key("drive-1");
        let sent = event();
        let signed = sent.sign(&drive).unwrap();
        let received: Event<FileDeleted> = verify_and_parse(
            &signed.body,
            &signed.header.to_header_value(),
            &trusting(&[&drive]),
        )
        .unwrap();
        assert_eq!(received, sent);
    }

    #[test]
    fn verify_names_the_owner_of_the_key() {
        let drive = key("drive-1");
        let keys = trusting(&[&drive]);
        assert_eq!(keys.owner("drive-1"), Some("drive"));
        assert_eq!(
            verify(b"body", &sign(b"body", &drive), &keys).unwrap(),
            "drive"
        );
    }

    #[test]
    fn an_event_signed_by_another_service_than_its_source_is_refused() {
        // The drive's key is trusted, but only for the drive: an event it signs in Propolis's
        // name is authentic bytes with a forged origin.
        let drive = key("drive-1");
        let forged = Event::new(
            Kind::new("propolis.account.deleted").unwrap(),
            1,
            "propolis",
            None,
            FileDeleted {
                file_id: Uuid::new_v4(),
            },
        );
        let signed = forged.sign(&drive).unwrap();
        let error = verify_and_parse::<FileDeleted>(
            &signed.body,
            &signed.header.to_header_value(),
            &trusting(&[&drive]),
        )
        .unwrap_err();
        match error {
            VerifyError::WrongSource { key_owner, source } => {
                assert_eq!(key_owner, "drive");
                assert_eq!(source, "propolis");
            }
            other => panic!("expected WrongSource, got {other:?}"),
        }
    }

    #[test]
    fn verify_and_parse_refuses_before_parsing() {
        let drive = key("drive-1");
        let keys = trusting(&[&drive]);
        let header = sign(b"not json", &drive).to_header_value();

        // Authentic but not an event: refused by the parser.
        assert!(matches!(
            verify_and_parse::<FileDeleted>(b"not json", &header, &keys),
            Err(VerifyError::InvalidEvent(_))
        ));
        // Not authentic: refused by the signature, the parser never runs.
        assert!(matches!(
            verify_and_parse::<FileDeleted>(b"not json!", &header, &keys),
            Err(VerifyError::BadSignature)
        ));
        assert!(matches!(
            verify_and_parse::<FileDeleted>(b"not json", "keyid=drive-1", &keys),
            Err(VerifyError::Header(HeaderError::MissingSignature))
        ));
    }

    #[test]
    fn verify_and_parse_refuses_an_authentic_body_of_another_shape() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Other {
            calendar_id: Uuid,
        }
        let drive = key("drive-1");
        let signed = event().sign(&drive).unwrap();
        let error = verify_and_parse::<Other>(
            &signed.body,
            &signed.header.to_header_value(),
            &trusting(&[&drive]),
        )
        .unwrap_err();
        assert!(matches!(error, VerifyError::InvalidEvent(_)));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn a_generated_key_reads_back_from_its_pkcs8_document() {
        let (key, pkcs8) = SigningKey::generate("drive-1").unwrap();
        let again = SigningKey::from_pkcs8("drive-1", &pkcs8).unwrap();
        assert_eq!(again.public_key(), key.public_key());
        assert_eq!(key.public_key().len(), 32);
        verify(b"body", &sign(b"body", &again), &trusting(&[&key])).unwrap();
    }

    #[test]
    fn an_openssl_style_pkcs8_v1_key_signs_as_rfc_8032_says() {
        // RFC 8032, section 7.1, test 1, wrapped in the PKCS#8 v1 document of RFC 8410.
        let mut pkcs8 = hex("302e020100300506032b657004220420");
        pkcs8.extend(hex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let key = SigningKey::from_pkcs8("rfc-8032", &pkcs8).unwrap();
        assert_eq!(
            key.public_key(),
            hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        assert_eq!(
            sign(b"", &key).signature(),
            hex(concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ))
        );
    }

    #[test]
    fn invalid_keys_and_key_ids_are_refused() {
        assert_eq!(
            SigningKey::from_pkcs8("k1", b"not a key").unwrap_err(),
            KeyError::InvalidPrivateKey
        );
        for key_id in ["", "k 1", "k,1", "k=1", "clé"] {
            assert_eq!(
                SigningKey::generate(key_id).unwrap_err(),
                KeyError::InvalidKeyId,
                "{key_id:?}"
            );
        }
        let mut keys = PublicKeys::new();
        assert_eq!(
            keys.insert("k1", "drive", &[0; 31]),
            Err(KeyError::InvalidPublicKey)
        );
        assert_eq!(
            keys.insert("k=1", "drive", &[0; 32]),
            Err(KeyError::InvalidKeyId)
        );
        assert_eq!(keys.insert("k1", "", &[0; 32]), Err(KeyError::InvalidOwner));
        assert!(keys.is_empty());
    }

    #[test]
    fn public_keys_rotate() {
        let old = key("drive-1");
        let new = key("drive-2");
        let mut keys = trusting(&[&old, &new]);
        assert_eq!(keys.len(), 2);
        let from_old = sign(b"body", &old);
        verify(b"body", &from_old, &keys).unwrap();
        verify(b"body", &sign(b"body", &new), &keys).unwrap();

        assert!(keys.remove("drive-1"));
        assert!(!keys.contains("drive-1"));
        assert!(matches!(
            verify(b"body", &from_old, &keys),
            Err(VerifyError::UnknownKey(_))
        ));
    }

    #[test]
    fn the_debug_output_of_a_signing_key_holds_no_private_key() {
        let (key, pkcs8) = SigningKey::generate("drive-1").unwrap();
        let shown = format!("{key:?}");
        assert!(shown.contains("drive-1"));
        assert!(shown.contains(&URL_SAFE_NO_PAD.encode(key.public_key())));
        // The seed sits at the start of the PKCS#8 v2 document's private key octet string.
        let seed = URL_SAFE_NO_PAD.encode(&pkcs8[16..48]);
        assert!(!shown.contains(&seed));
    }
}
