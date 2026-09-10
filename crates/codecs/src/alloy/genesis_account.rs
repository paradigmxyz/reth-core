//! Compact implementation for [`AlloyGenesisAccount`]

use crate::Compact;
use alloc::vec::Vec;
use alloy_genesis::GenesisAccount as AlloyGenesisAccount;
use alloy_primitives::{Bytes, B256, U256};
use reth_codecs_derive::add_arbitrary_tests;

/// `GenesisAccount` acts as bridge which simplifies Compact implementation for
/// `AlloyGenesisAccount`.
///
/// Notice: Make sure this struct is 1:1 with `alloy_genesis::GenesisAccount`
#[derive(Debug, Clone, PartialEq, Eq, Compact)]
#[reth_codecs(crate = "crate")]
pub(crate) struct GenesisAccountRef<'a> {
    /// The nonce of the account at genesis.
    nonce: Option<u64>,
    /// The balance of the account at genesis.
    balance: &'a U256,
    /// The account's bytecode at genesis.
    code: Option<&'a Bytes>,
    /// The account's storage at genesis.
    storage: Option<StorageEntries>,
    /// The account's private key. Should only be used for testing.
    private_key: Option<&'a B256>,
}

/// Acts as bridge which simplifies Compact implementation for
/// `AlloyGenesisAccount`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Compact)]
#[reth_codecs(crate = "crate")]
#[cfg_attr(
    any(test, feature = "test-utils"),
    derive(arbitrary::Arbitrary, serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "test-utils", allow(unreachable_pub), visibility::make(pub))]
#[add_arbitrary_tests(crate, compact)]
pub(crate) struct GenesisAccount {
    /// The nonce of the account at genesis.
    nonce: Option<u64>,
    /// The balance of the account at genesis.
    balance: U256,
    /// The account's bytecode at genesis.
    code: Option<Bytes>,
    /// The account's storage at genesis.
    storage: Option<StorageEntries>,
    /// The account's private key. Should only be used for testing.
    private_key: Option<B256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Compact)]
#[reth_codecs(crate = "crate")]
#[cfg_attr(
    any(test, feature = "test-utils"),
    derive(arbitrary::Arbitrary, serde::Serialize, serde::Deserialize)
)]
#[add_arbitrary_tests(crate, compact)]
pub(crate) struct StorageEntries {
    entries: Vec<StorageEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Compact)]
#[reth_codecs(crate = "crate")]
#[cfg_attr(
    any(test, feature = "test-utils"),
    derive(arbitrary::Arbitrary, serde::Serialize, serde::Deserialize)
)]
#[add_arbitrary_tests(crate, compact)]
pub(crate) struct StorageEntry {
    key: B256,
    value: B256,
}

impl Compact for AlloyGenesisAccount {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let account = GenesisAccountRef {
            nonce: self.nonce,
            balance: &self.balance,
            code: self.code.as_ref(),
            storage: self.storage.as_ref().map(|s| StorageEntries {
                entries: s
                    .iter()
                    .map(|(key, value)| StorageEntry { key: *key, value: *value })
                    .collect(),
            }),
            private_key: self.private_key.as_ref(),
        };
        let len = account.to_compact(buf);
        #[cfg(feature = "account-ext")]
        {
            if self.extension.is_empty() {
                return len;
            }
            let extension_len = u16::try_from(self.extension.len())
                .expect("account extension exceeds compact encoding limit");
            buf.put_u16(extension_len);
            buf.put_slice(&self.extension);
            len + 2 + self.extension.len()
        }
        #[cfg(not(feature = "account-ext"))]
        len
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (account_buf, rest) = buf.split_at(len);
        let (account, extension) = GenesisAccount::from_compact(account_buf, len);
        #[cfg(not(feature = "account-ext"))]
        assert!(extension.is_empty(), "account extensions require account-ext");
        let alloy_account = Self {
            nonce: account.nonce,
            balance: account.balance,
            code: account.code,
            storage: account
                .storage
                .map(|s| s.entries.into_iter().map(|entry| (entry.key, entry.value)).collect()),
            private_key: account.private_key,
            #[cfg(feature = "account-ext")]
            extension: if extension.is_empty() {
                Default::default()
            } else {
                let (length, bytes) = extension.split_at(2);
                let extension_len = usize::from(u16::from_be_bytes(length.try_into().unwrap()));
                assert_eq!(bytes.len(), extension_len, "invalid account extension length");
                alloy_genesis::AccountExtension::copy_from_slice(bytes)
            },
        };
        (alloy_account, rest)
    }
}

#[cfg(all(test, feature = "account-ext"))]
mod extension_tests {
    use super::*;

    #[test]
    fn raw_extension_compact_roundtrip() {
        for payload in [&[][..], &[0x82, 0xaa][..], &[42; 2048][..]] {
            let account = AlloyGenesisAccount {
                extension: alloy_genesis::AccountExtension::copy_from_slice(payload),
                ..Default::default()
            };
            let mut encoded = Vec::new();
            let len = account.to_compact(&mut encoded);
            if !payload.is_empty() {
                let mut suffix = (payload.len() as u16).to_be_bytes().to_vec();
                suffix.extend_from_slice(payload);
                assert!(encoded.ends_with(&suffix));
            }
            encoded.extend_from_slice(&[99]);
            let (decoded, rest) = AlloyGenesisAccount::from_compact(&encoded, len);
            assert_eq!(decoded, account);
            assert_eq!(rest, &[99]);
        }
    }
}
