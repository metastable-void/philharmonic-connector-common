use std::collections::{HashMap, hash_map::Entry};

use serde::{Deserialize, Serialize};

pub use coset::{CoseEncrypt0, CoseSign1};
pub use philharmonic_types::{Sha256, UnixMillis, Uuid};

/// Fixed ML-KEM-768 public-key length in bytes.
pub const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;

/// Verified claims carried in the connector authorization token payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorTokenClaims {
    /// Issuer identifier (the lowerer / deployment minting authority).
    pub iss: String,
    /// Expiry timestamp in Unix milliseconds.
    pub exp: UnixMillis,
    /// Signing key identifier used for token verification.
    pub kid: String,
    /// Target connector realm identifier.
    pub realm: String,
    /// Tenant UUID (plain UUID to keep this crate independent from policy IDs).
    pub tenant: Uuid,
    /// Workflow instance UUID.
    pub inst: Uuid,
    /// Step sequence number within the workflow instance.
    pub step: u64,
    /// Tenant endpoint-config UUID used for audit correlation.
    pub config_uuid: Uuid,
    /// SHA-256 digest of the encrypted payload bytes.
    pub payload_hash: Sha256,
}

/// Verified call metadata passed to connector implementations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorCallContext {
    /// Tenant UUID.
    pub tenant_id: Uuid,
    /// Workflow instance UUID.
    pub instance_id: Uuid,
    /// Step sequence number within the workflow instance.
    pub step_seq: u64,
    /// Tenant endpoint-config UUID.
    pub config_uuid: Uuid,
    /// Token issuance timestamp in Unix milliseconds.
    pub issued_at: UnixMillis,
    /// Token expiry timestamp in Unix milliseconds.
    pub expires_at: UnixMillis,
}

/// Realm identifier used by connector routing and key selection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RealmId(String);

impl RealmId {
    /// Construct a realm identifier from owned string data.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying realm string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RealmId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for RealmId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for RealmId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Public hybrid KEM key material for one connector realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmPublicKey {
    /// Stable key identifier used in COSE headers.
    pub kid: String,
    /// Realm that owns this key.
    pub realm: RealmId,
    /// ML-KEM-768 public key bytes (fixed-length 1184 bytes).
    #[serde(deserialize_with = "deserialize_mlkem_public")]
    pub mlkem_public: Vec<u8>,
    /// X25519 public key bytes.
    pub x25519_public: [u8; 32],
    /// Key validity lower bound.
    pub not_before: UnixMillis,
    /// Key validity upper bound.
    pub not_after: UnixMillis,
}

impl RealmPublicKey {
    /// Construct a realm public key while enforcing ML-KEM-768 key length.
    pub fn new(
        kid: impl Into<String>,
        realm: RealmId,
        mlkem_public: Vec<u8>,
        x25519_public: [u8; 32],
        not_before: UnixMillis,
        not_after: UnixMillis,
    ) -> Result<Self, RealmPublicKeyError> {
        validate_mlkem_public(&mlkem_public)?;
        Ok(Self {
            kid: kid.into(),
            realm,
            mlkem_public,
            x25519_public,
            not_before,
            not_after,
        })
    }

    /// Validate field-level invariants on an existing key value.
    pub fn validate(&self) -> Result<(), RealmPublicKeyError> {
        validate_mlkem_public(&self.mlkem_public)
    }
}

/// Validation failures for `RealmPublicKey`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RealmPublicKeyError {
    #[error("invalid ML-KEM-768 public-key length: expected {expected} bytes, got {actual}")]
    InvalidMlkemPublicKeyLength { expected: usize, actual: usize },
}

/// In-memory registry of realm public keys, indexed by `kid`.
#[derive(Clone, Debug, Default)]
pub struct RealmRegistry {
    by_kid: HashMap<String, RealmPublicKey>,
}

impl RealmRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a registry from keys, rejecting duplicate `kid` values.
    pub fn with_keys(
        keys: impl IntoIterator<Item = RealmPublicKey>,
    ) -> Result<Self, RealmRegistryInsertError> {
        let mut registry = Self::new();
        for key in keys {
            registry.insert(key)?;
        }
        Ok(registry)
    }

    /// Insert a key if `kid` is not already present.
    pub fn insert(&mut self, key: RealmPublicKey) -> Result<(), RealmRegistryInsertError> {
        key.validate()?;

        match self.by_kid.entry(key.kid.clone()) {
            Entry::Occupied(_) => Err(RealmRegistryInsertError::DuplicateKid { kid: key.kid }),
            Entry::Vacant(slot) => {
                slot.insert(key);
                Ok(())
            }
        }
    }

    /// Look up a key by its `kid`.
    pub fn lookup(&self, kid: &str) -> Option<&RealmPublicKey> {
        self.by_kid.get(kid)
    }

    /// Number of keys currently registered.
    pub fn len(&self) -> usize {
        self.by_kid.len()
    }

    /// Whether the registry contains zero keys.
    pub fn is_empty(&self) -> bool {
        self.by_kid.is_empty()
    }
}

/// Insertion failures for `RealmRegistry`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RealmRegistryInsertError {
    #[error("realm key with kid '{kid}' is already registered")]
    DuplicateKid { kid: String },

    #[error("invalid realm public key: {0}")]
    InvalidKey(#[from] RealmPublicKeyError),
}

/// Type-safe wrapper for connector authorization tokens (`COSE_Sign1`).
#[derive(Clone, Debug)]
pub struct ConnectorSignedToken(CoseSign1);

impl ConnectorSignedToken {
    /// Wrap a COSE_Sign1 value as a connector authorization token.
    pub fn new(inner: CoseSign1) -> Self {
        Self(inner)
    }

    /// Borrow the wrapped COSE_Sign1 value.
    pub fn as_inner(&self) -> &CoseSign1 {
        &self.0
    }

    /// Consume the wrapper and return the raw COSE_Sign1 value.
    pub fn into_inner(self) -> CoseSign1 {
        self.0
    }
}

impl AsRef<CoseSign1> for ConnectorSignedToken {
    fn as_ref(&self) -> &CoseSign1 {
        self.as_inner()
    }
}

impl From<CoseSign1> for ConnectorSignedToken {
    fn from(value: CoseSign1) -> Self {
        Self::new(value)
    }
}

impl From<ConnectorSignedToken> for CoseSign1 {
    fn from(value: ConnectorSignedToken) -> Self {
        value.into_inner()
    }
}

/// Type-safe wrapper for encrypted connector payloads (`COSE_Encrypt0`).
#[derive(Clone, Debug)]
pub struct ConnectorEncryptedPayload(CoseEncrypt0);

impl ConnectorEncryptedPayload {
    /// Wrap a COSE_Encrypt0 value as an encrypted connector payload.
    pub fn new(inner: CoseEncrypt0) -> Self {
        Self(inner)
    }

    /// Borrow the wrapped COSE_Encrypt0 value.
    pub fn as_inner(&self) -> &CoseEncrypt0 {
        &self.0
    }

    /// Consume the wrapper and return the raw COSE_Encrypt0 value.
    pub fn into_inner(self) -> CoseEncrypt0 {
        self.0
    }
}

impl AsRef<CoseEncrypt0> for ConnectorEncryptedPayload {
    fn as_ref(&self) -> &CoseEncrypt0 {
        self.as_inner()
    }
}

impl From<CoseEncrypt0> for ConnectorEncryptedPayload {
    fn from(value: CoseEncrypt0) -> Self {
        Self::new(value)
    }
}

impl From<ConnectorEncryptedPayload> for CoseEncrypt0 {
    fn from(value: ConnectorEncryptedPayload) -> Self {
        value.into_inner()
    }
}

/// Common failure model for connector implementations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImplementationError {
    #[error("invalid config: {detail}")]
    InvalidConfig { detail: String },

    #[error("upstream returned non-success status {status}: {body}")]
    UpstreamError { status: u16, body: String },

    #[error("upstream unreachable: {detail}")]
    UpstreamUnreachable { detail: String },

    #[error("upstream timeout")]
    UpstreamTimeout,

    #[error("schema validation failed: {detail}")]
    SchemaValidationFailed { detail: String },

    #[error("response too large: limit {limit} bytes, got {actual} bytes")]
    ResponseTooLarge { limit: usize, actual: usize },

    #[error("invalid request: {detail}")]
    InvalidRequest { detail: String },

    #[error("internal implementation error: {detail}")]
    Internal { detail: String },
}

impl ImplementationError {
    /// Whether retrying the operation may succeed without changing inputs.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::UpstreamUnreachable { .. } | Self::UpstreamTimeout | Self::Internal { .. }
        )
    }
}

fn validate_mlkem_public(bytes: &[u8]) -> Result<(), RealmPublicKeyError> {
    if bytes.len() != MLKEM768_PUBLIC_KEY_LEN {
        return Err(RealmPublicKeyError::InvalidMlkemPublicKeyLength {
            expected: MLKEM768_PUBLIC_KEY_LEN,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn deserialize_mlkem_public<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    validate_mlkem_public(&bytes).map_err(serde::de::Error::custom)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{CoseEncrypt0Builder, CoseSign1Builder};

    fn uuid(value: &str) -> Uuid {
        Uuid::parse_str(value).expect("test UUID must be valid")
    }

    fn sample_claims() -> ConnectorTokenClaims {
        ConnectorTokenClaims {
            iss: "lowerer.main".to_owned(),
            exp: UnixMillis(1_800_000_000_000),
            kid: "lowerer-signing-key-2026-04".to_owned(),
            realm: "llm".to_owned(),
            tenant: uuid("11111111-1111-4111-8111-111111111111"),
            inst: uuid("22222222-2222-4222-8222-222222222222"),
            step: 42,
            config_uuid: uuid("33333333-3333-4333-8333-333333333333"),
            payload_hash: Sha256::from_bytes_unchecked([0xAB; 32]),
        }
    }

    fn sample_realm_key(kid: &str) -> RealmPublicKey {
        RealmPublicKey::new(
            kid,
            RealmId::from("llm"),
            vec![0x11; MLKEM768_PUBLIC_KEY_LEN],
            [0x22; 32],
            UnixMillis(1_700_000_000_000),
            UnixMillis(1_900_000_000_000),
        )
        .expect("sample key must satisfy invariants")
    }

    #[test]
    fn connector_token_claims_serde_round_trip() {
        let claims = sample_claims();
        let json = serde_json::to_string(&claims).unwrap();
        let back: ConnectorTokenClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(back, claims);
    }

    #[test]
    fn connector_token_claims_serde_round_trip_allows_edge_values() {
        let claims = ConnectorTokenClaims {
            iss: String::new(),
            exp: UnixMillis(0),
            kid: String::new(),
            realm: String::new(),
            tenant: Uuid::nil(),
            inst: Uuid::nil(),
            step: 0,
            config_uuid: Uuid::nil(),
            payload_hash: Sha256::from_bytes_unchecked([0_u8; 32]),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let back: ConnectorTokenClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(back, claims);
    }

    #[test]
    fn connector_call_context_serde_round_trip() {
        let context = ConnectorCallContext {
            tenant_id: uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            instance_id: uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            step_seq: 9,
            config_uuid: uuid("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            issued_at: UnixMillis(1_700_100_000_000),
            expires_at: UnixMillis(1_700_100_030_000),
        };

        let json = serde_json::to_string(&context).unwrap();
        let back: ConnectorCallContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back, context);
    }

    #[test]
    fn realm_registry_lookup_returns_key_for_present_kid() {
        let key = sample_realm_key("kid-main");
        let mut registry = RealmRegistry::new();
        registry.insert(key.clone()).unwrap();

        let found = registry.lookup("kid-main");
        assert_eq!(found, Some(&key));
    }

    #[test]
    fn realm_registry_lookup_returns_none_for_missing_kid() {
        let mut registry = RealmRegistry::new();
        registry.insert(sample_realm_key("kid-main")).unwrap();

        assert!(registry.lookup("missing-kid").is_none());
    }

    #[test]
    fn realm_registry_duplicate_kid_is_rejected() {
        let mut registry = RealmRegistry::new();
        registry.insert(sample_realm_key("dup-kid")).unwrap();

        let err = registry.insert(sample_realm_key("dup-kid")).unwrap_err();
        assert_eq!(
            err,
            RealmRegistryInsertError::DuplicateKid {
                kid: "dup-kid".to_owned(),
            }
        );
    }

    #[test]
    fn realm_public_key_new_accepts_exact_mlkem_length() {
        let key = RealmPublicKey::new(
            "kid-valid",
            RealmId::from("sql"),
            vec![0x55; MLKEM768_PUBLIC_KEY_LEN],
            [0x66; 32],
            UnixMillis(1),
            UnixMillis(2),
        );

        assert!(key.is_ok());
    }

    #[test]
    fn realm_public_key_new_rejects_wrong_mlkem_length() {
        let err = RealmPublicKey::new(
            "kid-invalid",
            RealmId::from("sql"),
            vec![0x55; 64],
            [0x66; 32],
            UnixMillis(1),
            UnixMillis(2),
        )
        .unwrap_err();

        assert_eq!(
            err,
            RealmPublicKeyError::InvalidMlkemPublicKeyLength {
                expected: MLKEM768_PUBLIC_KEY_LEN,
                actual: 64,
            }
        );
    }

    #[test]
    fn implementation_error_serde_round_trip() {
        let original = ImplementationError::ResponseTooLarge {
            limit: 65_536,
            actual: 70_001,
        };

        let json = serde_json::to_string(&original).unwrap();
        let back: ImplementationError = serde_json::from_str(&json).unwrap();

        assert_eq!(back, original);
    }

    #[test]
    fn wrapper_types_can_wrap_sample_cose_values() {
        let signed = ConnectorSignedToken::new(CoseSign1Builder::new().build());
        let encrypted = ConnectorEncryptedPayload::new(CoseEncrypt0Builder::new().build());

        let _: CoseSign1 = signed.into_inner();
        let _: CoseEncrypt0 = encrypted.into_inner();
    }
}
