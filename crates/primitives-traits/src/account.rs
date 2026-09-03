use crate::{InMemorySize, MaybeCompact, MaybeSerde};
use alloc::vec::Vec;
use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_genesis::GenesisAccount;
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_trie::{TrieAccount, TrieAccountExtension};
use core::fmt::Debug;
use derive_more::Deref;
use revm_bytecode::{Bytecode as RevmBytecode, BytecodeDecodeError};
use revm_state::AccountInfo;

#[cfg(feature = "reth-codec")]
/// Identifiers used in [`Compact`](reth_codecs::Compact) encoding of [`Bytecode`].
pub mod compact_ids {
    /// Identifier for legacy raw bytecode.
    pub const LEGACY_RAW_BYTECODE_ID: u8 = 0;

    /// Identifier for removed bytecode variant.
    pub const REMOVED_BYTECODE_ID: u8 = 1;

    /// Identifier for legacy analyzed bytecode.
    pub const LEGACY_ANALYZED_BYTECODE_ID: u8 = 2;

    /// Identifier for EIP-7702 bytecode.
    pub const EIP7702_BYTECODE_ID: u8 = 4;
}

/// Default account extension that has no state and emits no encoded bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EmptyAccountExtension;

impl TrieAccountExtension for EmptyAccountExtension {
    fn payload_length(&self) -> usize {
        0
    }

    fn encode_payload(&self, _out: &mut dyn alloy_rlp::BufMut) {}

    fn decode_payload(_payload: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self)
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for EmptyAccountExtension {
    fn to_compact<B>(&self, _buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        0
    }

    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        (Self, buf)
    }
}

impl InMemorySize for EmptyAccountExtension {
    fn size(&self) -> usize {
        0
    }
}

/// Requirements for chain-specific account data.
pub trait AccountExtension:
    Clone
    + Debug
    + Default
    + Eq
    + InMemorySize
    + MaybeCompact
    + MaybeSerde
    + Send
    + Sync
    + TrieAccountExtension
    + Unpin
    + 'static
{
}

impl<T> AccountExtension for T where
    T: Clone
        + Debug
        + Default
        + Eq
        + InMemorySize
        + MaybeCompact
        + MaybeSerde
        + Send
        + Sync
        + TrieAccountExtension
        + Unpin
        + 'static
{
}

/// An Ethereum account with chain-specific extension data.
#[cfg_attr(any(test, feature = "serde"), derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Account<E = EmptyAccountExtension> {
    /// Account nonce.
    pub nonce: u64,
    /// Account balance.
    pub balance: U256,
    /// Hash of the account's bytecode.
    pub bytecode_hash: Option<B256>,
    /// Chain-specific account data committed to the account trie leaf.
    pub extension: E,
}

#[cfg(feature = "reth-codec")]
#[derive(reth_codecs::Compact)]
struct LegacyAccount {
    nonce: u64,
    balance: U256,
    bytecode_hash: Option<B256>,
}

#[cfg(feature = "reth-codec")]
impl Account<EmptyAccountExtension> {
    /// Number of bytes used by the backwards-compatible account Compact flags.
    pub const fn bitflag_encoded_bytes() -> usize {
        LegacyAccount::bitflag_encoded_bytes()
    }

    /// Number of unused bits in the backwards-compatible account Compact flags.
    pub const fn bitflag_unused_bits() -> usize {
        LegacyAccount::bitflag_unused_bits()
    }
}

#[cfg(feature = "reth-codec")]
impl<E: reth_codecs::Compact> reth_codecs::Compact for Account<E> {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let legacy = LegacyAccount {
            nonce: self.nonce,
            balance: self.balance,
            bytecode_hash: self.bytecode_hash,
        };
        legacy.to_compact(buf) + self.extension.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (legacy, buf) = LegacyAccount::from_compact(buf, len);
        let (extension, buf) = E::from_compact(buf, buf.len());
        (
            Self {
                nonce: legacy.nonce,
                balance: legacy.balance,
                bytecode_hash: legacy.bytecode_hash,
                extension,
            },
            buf,
        )
    }
}

#[cfg(feature = "reth-codec")]
reth_codecs::impl_compression_for_compact!(Account<E>);

fn encode_extension<E: TrieAccountExtension>(extension: &E) -> Bytes {
    let mut bytes = Vec::with_capacity(extension.payload_length());
    extension.encode_payload(&mut bytes);
    bytes.into()
}

fn decode_extension<E: TrieAccountExtension>(bytes: &[u8]) -> E {
    let mut payload = bytes;
    let extension = E::decode_payload(&mut payload).expect("invalid account extension");
    assert!(payload.is_empty(), "account extension decoder left trailing bytes");
    extension
}

impl<E: AccountExtension> Account<E> {
    /// Whether the account has bytecode.
    #[inline]
    pub const fn has_bytecode(&self) -> bool {
        self.bytecode_hash.is_some()
    }

    /// After `SpuriousDragon` empty account is defined as account with nonce == 0 && balance == 0
    /// && bytecode = None (or hash is [`KECCAK_EMPTY`]).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 &&
            self.balance.is_zero() &&
            self.bytecode_hash.is_none_or(|hash| hash == KECCAK_EMPTY) &&
            self.extension == E::default()
    }

    /// Returns an account bytecode's hash.
    /// In case of no bytecode, returns [`KECCAK_EMPTY`].
    #[inline]
    pub fn get_bytecode_hash(&self) -> B256 {
        self.bytecode_hash.unwrap_or(KECCAK_EMPTY)
    }

    /// Converts the account into a trie account with the given storage root.
    #[inline]
    pub fn into_trie_account(self, storage_root: B256) -> TrieAccount<E> {
        let Self { nonce, balance, bytecode_hash, extension } = self;
        TrieAccount {
            nonce,
            balance,
            storage_root,
            code_hash: bytecode_hash.unwrap_or(KECCAK_EMPTY),
            extension,
        }
    }

    /// Extracts the account information from a [`revm_state::Account`]
    pub fn from_revm_account(revm_account: &revm_state::Account) -> Self {
        Self {
            balance: revm_account.info.balance,
            nonce: revm_account.info.nonce,
            bytecode_hash: if revm_account.info.code_hash == revm_primitives::KECCAK_EMPTY {
                None
            } else {
                Some(revm_account.info.code_hash)
            },
            extension: decode_extension(&revm_account.info.extension),
        }
    }
}

impl<E: AccountExtension> From<revm_state::Account> for Account<E> {
    #[inline]
    fn from(value: revm_state::Account) -> Self {
        Self::from_revm_account(&value)
    }
}

impl<E: AccountExtension> From<TrieAccount<E>> for Account<E> {
    fn from(value: TrieAccount<E>) -> Self {
        Self {
            balance: value.balance,
            nonce: value.nonce,
            bytecode_hash: (value.code_hash != KECCAK_EMPTY).then_some(value.code_hash),
            extension: value.extension,
        }
    }
}

impl<E: AccountExtension> InMemorySize for Account<E> {
    #[inline]
    fn size(&self) -> usize {
        size_of::<u64>() + size_of::<U256>() + size_of::<Option<B256>>() + self.extension.size()
    }
}

/// Bytecode for an account.
///
/// A wrapper around [`revm::primitives::Bytecode`][RevmBytecode] with encoding/decoding support.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deref)]
pub struct Bytecode(pub RevmBytecode);

impl Bytecode {
    /// Create new bytecode from raw bytes.
    ///
    /// No analysis will be performed.
    ///
    /// # Panics
    ///
    /// Panics if bytecode is EOF and has incorrect format.
    #[inline]
    pub fn new_raw(bytes: Bytes) -> Self {
        Self(RevmBytecode::new_raw(bytes))
    }

    /// Creates a new raw [`revm_bytecode::Bytecode`].
    ///
    /// Returns an error on incorrect Bytecode format.
    #[inline]
    pub fn new_raw_checked(bytecode: Bytes) -> Result<Self, BytecodeDecodeError> {
        RevmBytecode::new_raw_checked(bytecode).map(Self)
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for Bytecode {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        use compact_ids::{EIP7702_BYTECODE_ID, LEGACY_ANALYZED_BYTECODE_ID};

        let bytecode = self.0.bytes_ref();
        buf.put_u32(bytecode.len() as u32);
        buf.put_slice(bytecode.as_ref());
        let len = if self.0.is_legacy() {
            // [`REMOVED_BYTECODE_ID`] has been removed.
            if let Some(jump_table) = self.0.legacy_jump_table() {
                buf.put_u8(LEGACY_ANALYZED_BYTECODE_ID);
                buf.put_u64(self.0.len() as u64);
                let map = jump_table.as_slice();
                buf.put_slice(map);
                1 + 8 + map.len()
            } else {
                unreachable!("legacy bytecode must contain a jump table")
            }
        } else {
            buf.put_u8(EIP7702_BYTECODE_ID);
            1
        };
        len + bytecode.len() + 4
    }

    // # Panics
    //
    // A panic will be triggered if a bytecode variant of 1 or greater than 2 is passed from the
    // database.
    fn from_compact(mut buf: &[u8], _: usize) -> (Self, &[u8]) {
        use byteorder::ReadBytesExt;
        use bytes::Buf;

        use compact_ids::*;

        let len = buf.read_u32::<byteorder::BigEndian>().expect("could not read bytecode length")
            as usize;
        let bytes = Bytes::from(buf.copy_to_bytes(len));
        let variant = buf.read_u8().expect("could not read bytecode variant");
        let decoded = match variant {
            LEGACY_RAW_BYTECODE_ID => Self(RevmBytecode::new_raw(bytes)),
            REMOVED_BYTECODE_ID => {
                unreachable!("Junk data in database: checked Bytecode variant was removed")
            }
            LEGACY_ANALYZED_BYTECODE_ID => {
                let original_len = buf.read_u64::<byteorder::BigEndian>().unwrap() as usize;
                // When saving jumptable, its length is getting aligned to u8 boundary. Thus, we
                // need to re-calculate the internal length of bitvec and truncate it when loading
                // jumptables to avoid inconsistencies during `Compact` roundtrip.
                let jump_table_len = if buf.len() * 8 >= bytes.len() {
                    // Use length of padded bytecode if we can fit it
                    bytes.len()
                } else {
                    // Otherwise, use original_len
                    original_len
                };
                // SAFETY: jump table is constructed from the persisted bitvec and the bytecode
                // length matches; this is the inverse of the original `to_compact` encoding.
                Self(unsafe {
                    RevmBytecode::new_analyzed(
                        bytes,
                        original_len,
                        revm_bytecode::JumpTable::from_slice(buf, jump_table_len),
                    )
                })
            }
            EIP7702_BYTECODE_ID => {
                // EIP-7702 bytecode objects will be decoded from the raw bytecode
                Self(RevmBytecode::new_raw(bytes))
            }
            _ => unreachable!("Junk data in database: unknown Bytecode variant"),
        };
        (decoded, &[])
    }
}

#[cfg(feature = "reth-codec")]
reth_codecs::impl_compression_for_compact!(Bytecode);

impl From<&GenesisAccount> for Account {
    fn from(value: &GenesisAccount) -> Self {
        Self {
            nonce: value.nonce.unwrap_or_default(),
            balance: value.balance,
            bytecode_hash: value.code.as_ref().map(keccak256),
            extension: EmptyAccountExtension,
        }
    }
}

impl<E: AccountExtension> From<AccountInfo> for Account<E> {
    fn from(revm_acc: AccountInfo) -> Self {
        Self {
            balance: revm_acc.balance,
            nonce: revm_acc.nonce,
            bytecode_hash: (!revm_acc.is_empty_code_hash()).then_some(revm_acc.code_hash),
            extension: decode_extension(&revm_acc.extension),
        }
    }
}

impl<E: AccountExtension> From<&AccountInfo> for Account<E> {
    fn from(revm_acc: &AccountInfo) -> Self {
        Self {
            balance: revm_acc.balance,
            nonce: revm_acc.nonce,
            bytecode_hash: (!revm_acc.is_empty_code_hash()).then_some(revm_acc.code_hash),
            extension: decode_extension(&revm_acc.extension),
        }
    }
}

impl<E: AccountExtension> From<Account<E>> for AccountInfo {
    fn from(reth_acc: Account<E>) -> Self {
        Self {
            balance: reth_acc.balance,
            nonce: reth_acc.nonce,
            code_hash: reth_acc.bytecode_hash.unwrap_or(KECCAK_EMPTY),
            code: None,
            account_id: None,
            extension: encode_extension(&reth_acc.extension),
        }
    }
}

#[cfg(all(test, feature = "std", feature = "reth-codec"))]
mod tests {
    use super::*;
    use alloy_primitives::{hex_literal::hex, B256, U256};
    use reth_codecs::Compact;
    use revm_bytecode::JumpTable;

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    struct TestExtension(u64);

    impl InMemorySize for TestExtension {
        fn size(&self) -> usize {
            size_of::<Self>()
        }
    }

    impl TrieAccountExtension for TestExtension {
        fn payload_length(&self) -> usize {
            alloy_rlp::Encodable::length(&self.0)
        }

        fn encode_payload(&self, out: &mut dyn alloy_rlp::BufMut) {
            alloy_rlp::Encodable::encode(&self.0, out);
        }

        fn decode_payload(payload: &mut &[u8]) -> alloy_rlp::Result<Self> {
            alloy_rlp::Decodable::decode(payload).map(Self)
        }
    }

    impl Compact for TestExtension {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: bytes::BufMut + AsMut<[u8]>,
        {
            self.0.to_compact(buf)
        }

        fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
            let (value, buf) = u64::from_compact(buf, len);
            (Self(value), buf)
        }
    }

    #[test]
    fn test_account() {
        let mut buf = vec![];
        let mut acc: Account = Account::default();
        let len = acc.to_compact(&mut buf);
        assert_eq!(len, 2);

        acc.balance = U256::from(2);
        let len = acc.to_compact(&mut buf);
        assert_eq!(len, 3);

        acc.nonce = 2;
        let len = acc.to_compact(&mut buf);
        assert_eq!(len, 4);
    }

    #[test]
    fn empty_extension_preserves_compact_encoding() {
        let account: Account = Account {
            nonce: 1,
            balance: U256::from(2),
            bytecode_hash: Some(B256::repeat_byte(3)),
            extension: EmptyAccountExtension,
        };
        let legacy = LegacyAccount {
            nonce: account.nonce,
            balance: account.balance,
            bytecode_hash: account.bytecode_hash,
        };
        let mut account_buf = Vec::new();
        let mut legacy_buf = Vec::new();
        account.to_compact(&mut account_buf);
        legacy.to_compact(&mut legacy_buf);

        assert_eq!(account_buf, legacy_buf);
    }

    #[test]
    fn custom_extension_roundtrips_all_representations() {
        let account = Account {
            nonce: 1,
            balance: U256::from(2),
            bytecode_hash: None,
            extension: TestExtension(42),
        };
        let mut compact = Vec::new();
        let len = account.to_compact(&mut compact);
        assert_eq!(Account::<TestExtension>::from_compact(&compact, len).0, account);

        let trie_account = account.into_trie_account(B256::repeat_byte(4));
        let rlp = alloy_rlp::encode(trie_account);
        assert_eq!(
            <TrieAccount<TestExtension> as alloy_rlp::Decodable>::decode(&mut rlp.as_slice(),)
                .unwrap(),
            trie_account
        );

        let revm_account: AccountInfo = account.into();
        assert_eq!(Account::<TestExtension>::from(revm_account), account);
    }

    #[test]
    fn test_empty_account() {
        let mut acc: Account =
            Account { nonce: 0, balance: U256::ZERO, bytecode_hash: None, ..Default::default() };
        // Nonce 0, balance 0, and bytecode hash set to None is considered empty.
        assert!(acc.is_empty());

        acc.bytecode_hash = Some(KECCAK_EMPTY);
        // Nonce 0, balance 0, and bytecode hash set to KECCAK_EMPTY is considered empty.
        assert!(acc.is_empty());

        acc.balance = U256::from(2);
        // Non-zero balance makes it non-empty.
        assert!(!acc.is_empty());

        acc.balance = U256::ZERO;
        acc.nonce = 10;
        // Non-zero nonce makes it non-empty.
        assert!(!acc.is_empty());

        acc.nonce = 0;
        acc.bytecode_hash = Some(B256::from(U256::ZERO));
        // Non-empty bytecode hash makes it non-empty.
        assert!(!acc.is_empty());
    }

    #[test]
    #[ignore]
    fn test_bytecode() {
        let mut buf = vec![];
        let bytecode = Bytecode::new_raw(Bytes::default());
        let len = bytecode.to_compact(&mut buf);
        assert_eq!(len, 14);

        let mut buf = vec![];
        let bytecode = Bytecode::new_raw(Bytes::from(&hex!("ffff")));
        let len = bytecode.to_compact(&mut buf);
        assert_eq!(len, 17);

        let mut buf = vec![];
        // SAFETY: hand-crafted analyzed bytecode used purely for round-trip testing.
        let bytecode = Bytecode(unsafe {
            RevmBytecode::new_analyzed(
                Bytes::from(&hex!("ff00")),
                2,
                JumpTable::from_slice(&[0], 2),
            )
        });
        let len = bytecode.to_compact(&mut buf);
        assert_eq!(len, 16);

        let (decoded, remainder) = Bytecode::from_compact(&buf, len);
        assert_eq!(decoded, bytecode);
        assert!(remainder.is_empty());
    }

    #[test]
    fn test_account_has_bytecode() {
        // Account with no bytecode (None)
        let acc_no_bytecode: Account =
            Account { nonce: 1, balance: U256::from(1000), ..Default::default() };
        assert!(!acc_no_bytecode.has_bytecode(), "Account should not have bytecode");

        // Account with bytecode hash set to KECCAK_EMPTY (should have bytecode)
        let acc_empty_bytecode: Account = Account {
            nonce: 1,
            balance: U256::from(1000),
            bytecode_hash: Some(KECCAK_EMPTY),
            ..Default::default()
        };
        assert!(acc_empty_bytecode.has_bytecode(), "Account should have bytecode");

        // Account with a non-empty bytecode hash
        let acc_with_bytecode: Account = Account {
            nonce: 1,
            balance: U256::from(1000),
            bytecode_hash: Some(B256::from_slice(&[0x11u8; 32])),
            ..Default::default()
        };
        assert!(acc_with_bytecode.has_bytecode(), "Account should have bytecode");
    }

    #[test]
    fn test_account_get_bytecode_hash() {
        // Account with no bytecode (should return KECCAK_EMPTY)
        let acc_no_bytecode: Account = Default::default();
        assert_eq!(acc_no_bytecode.get_bytecode_hash(), KECCAK_EMPTY, "Should return KECCAK_EMPTY");

        // Account with bytecode hash set to KECCAK_EMPTY
        let acc_empty_bytecode: Account = Account {
            nonce: 1,
            balance: U256::from(1000),
            bytecode_hash: Some(KECCAK_EMPTY),
            ..Default::default()
        };
        assert_eq!(
            acc_empty_bytecode.get_bytecode_hash(),
            KECCAK_EMPTY,
            "Should return KECCAK_EMPTY"
        );

        // Account with a valid bytecode hash
        let bytecode_hash = B256::from_slice(&[0x11u8; 32]);
        let acc_with_bytecode: Account = Account {
            nonce: 1,
            balance: U256::from(1000),
            bytecode_hash: Some(bytecode_hash),
            ..Default::default()
        };
        assert_eq!(
            acc_with_bytecode.get_bytecode_hash(),
            bytecode_hash,
            "Should return the bytecode hash"
        );
    }
}
