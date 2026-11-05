//! Compact codec.
//!
//! *Warning*: The `Compact` encoding format and its implementations are
//! designed for storing and retrieving data internally. They are not hardened
//! to safely read potentially malicious data.
//!
//! ## Feature Flags
//!
//! - `alloy`: [Compact] implementation for various alloy types.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use reth_codecs_derive::*;
use serde as _;

use alloy_primitives::{Address, Bloom, Bytes, FixedBytes, U256};
use bytes::{Buf, BufMut};

use alloc::{
    borrow::{Cow, ToOwned},
    vec::Vec,
};
use core::num::NonZeroU64;

#[cfg(feature = "alloy")]
pub mod alloy;

pub mod compress;
pub use compress::{Compress, Decompress, DecompressError};

pub mod txtype;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Used by generated code and doc tests. Not public API.
#[doc(hidden)]
#[path = "private.rs"]
pub mod __private;

/// Trait that implements the `Compact` codec.
///
/// When deriving the trait for custom structs, be aware of certain limitations/recommendations:
/// * Works best with structs that only have native types (eg. u64, B256, U256).
/// * Fixed array types (B256, Address, Bloom) are not compacted.
/// * Max size of `T` in `Option<T>` or `Vec<T>` shouldn't exceed `0xffff`.
/// * Any `Bytes` field **should be placed last**.
/// * Any other type which is not known to the derive module **should be placed last** in they
///   contain a `Bytes` field.
///
/// The last two points make it easier to decode the data without saving the length on the
/// `StructFlags`. It will fail compilation if it's not respected. If they're alias to known types,
/// add their definitions to `get_bit_size()` or `known_types` in `generator.rs`.
///
/// Regarding the `specialized_to/from_compact` methods: Mainly used as a workaround for not being
/// able to specialize an impl over certain types like `Vec<T>`/`Option<T>` where `T` is a fixed
/// size array like `Vec<B256>`.
///
/// ## Caution
///
/// Due to the bitfields, every type change on the rust type (e.g. `U256` to `u64`) is a breaking
/// change and will lead to a new, incompatible [`Compact`] implementation. Implementers must take
/// special care when changing or rearranging fields.
pub trait Compact: Sized {
    /// Internal opt-in for stack buffering by the derive macro.
    ///
    /// `Some(n)` guarantees that both encoding methods write at most `n` bytes and that
    /// their bytes and return values do not depend on the destination buffer's type,
    /// contents, or capacity. Existing/custom implementations retain the heap-buffered
    /// path by default. This is an upper bound on bytes written, not on the return value
    /// (for example, `bool` writes no bytes but returns a flag).
    #[doc(hidden)]
    const __COMPACT_MAX_SIZE: Option<usize> = None;

    /// Takes a buffer which can be written to. *Ideally*, it returns the length written to.
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>;

    /// Takes a buffer which can be read from. Returns the object and `buf` with its internal cursor
    /// advanced (eg.`.advance(len)`).
    ///
    /// `len` can either be the `buf` remaining length, or the length of the compacted type.
    ///
    /// It will panic, if `len` is smaller than `buf.len()`.
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]);

    /// "Optional": If there's no good reason to use it, don't.
    #[inline]
    fn specialized_to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        self.to_compact(buf)
    }

    /// "Optional": If there's no good reason to use it, don't.
    #[inline]
    fn specialized_from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        Self::from_compact(buf, len)
    }
}

impl Compact for alloc::string::String {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        self.as_bytes().to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (vec, buf) = Vec::<u8>::from_compact(buf, len);
        let string = Self::from_utf8(vec).unwrap(); // Safe conversion
        (string, buf)
    }
}

impl<T: Compact> Compact for &T {
    const __COMPACT_MAX_SIZE: Option<usize> = T::__COMPACT_MAX_SIZE;

    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        (*self).to_compact(buf)
    }

    fn from_compact(_: &[u8], _: usize) -> (Self, &[u8]) {
        unimplemented!()
    }
}

/// To be used with `Option<CompactPlaceholder>` to place or replace one bit on the bitflag struct.
pub type CompactPlaceholder = ();

impl Compact for CompactPlaceholder {
    const __COMPACT_MAX_SIZE: Option<usize> = Some(0);

    #[inline]
    fn to_compact<B>(&self, _: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        0
    }

    #[inline]
    fn from_compact(buf: &[u8], _: usize) -> (Self, &[u8]) {
        ((), buf)
    }
}

macro_rules! impl_uint_compact {
    ($($name:tt),+) => {
        $(
            impl Compact for $name {
                const __COMPACT_MAX_SIZE: Option<usize> = Some(core::mem::size_of::<$name>());

                #[inline]
                fn to_compact<B>(&self, buf: &mut B) -> usize
                    where B: bytes::BufMut + AsMut<[u8]>
                {
                    let leading = self.leading_zeros() as usize / 8;
                    buf.put_slice(&self.to_be_bytes()[leading..]);
                    core::mem::size_of::<$name>() - leading
                }

                #[inline]
                fn from_compact(mut buf: &[u8], len: usize) -> (Self, &[u8]) {
                    if len == 0 {
                        return (0, buf);
                    }

                    let mut arr = [0; core::mem::size_of::<$name>()];
                    arr[core::mem::size_of::<$name>() - len..].copy_from_slice(&buf[..len]);
                    buf.advance(len);
                    ($name::from_be_bytes(arr), buf)
                }
            }
        )+
    };
}

impl_uint_compact!(u8, u64, u128);

/// `usize` is encoded as an unsigned LEB128 varint, the same encoding used for the length
/// prefixes of `Vec` and `Option` values.
///
/// The encoding is self-delimiting: `to_compact` returns the number of bytes written and
/// `from_compact` ignores `len`.
impl Compact for usize {
    const __COMPACT_MAX_SIZE: Option<Self> = Some((Self::BITS as Self).div_ceil(7));

    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        encode_varuint(*self, buf)
    }

    #[inline]
    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        decode_varuint(buf)
    }
}

impl Compact for NonZeroU64 {
    const __COMPACT_MAX_SIZE: Option<usize> = Some(8);

    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        self.get().to_compact(buf)
    }

    #[inline]
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (value, buf) = u64::from_compact(buf, len);
        (Self::new(value).expect("compact non-zero integer cannot decode zero"), buf)
    }
}

impl<T> Compact for Vec<T>
where
    T: Compact,
{
    /// Returns 0 since we won't include it in the `StructFlags`.
    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        self.as_slice().to_compact(buf)
    }

    #[inline]
    fn from_compact(buf: &[u8], _: usize) -> (Self, &[u8]) {
        let (length, mut buf) = decode_varuint(buf);
        let mut list = Self::with_capacity(length);
        for _ in 0..length {
            let len;
            (len, buf) = decode_varuint(buf);

            let (element, _) = T::from_compact(&buf[..len], len);
            buf.advance(len);

            list.push(element);
        }

        (list, buf)
    }

    /// To be used by fixed sized types like `Vec<B256>`.
    #[inline]
    fn specialized_to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        self.as_slice().specialized_to_compact(buf)
    }

    /// To be used by fixed sized types like `Vec<B256>`.
    #[inline]
    fn specialized_from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (length, mut buf) = decode_varuint(buf);
        let mut list = Self::with_capacity(length);

        for _ in 0..length {
            let element;
            (element, buf) = T::from_compact(buf, len);
            list.push(element);
        }

        (list, buf)
    }
}

impl<T> Compact for &[T]
where
    T: Compact,
{
    /// Returns 0 since we won't include it in the `StructFlags`.
    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        encode_varuint(self.len(), buf);

        let mut tmp: Vec<u8> = Vec::with_capacity(64);

        for element in *self {
            tmp.clear();

            // We don't know the length until we compact it
            let length = element.to_compact(&mut tmp);
            encode_varuint(length, buf);

            buf.put_slice(&tmp);
        }

        0
    }

    #[inline]
    fn from_compact(_: &[u8], _: usize) -> (Self, &[u8]) {
        unimplemented!()
    }

    /// To be used by fixed sized types like `&[B256]`.
    #[inline]
    fn specialized_to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        encode_varuint(self.len(), buf);
        for element in *self {
            element.to_compact(buf);
        }
        0
    }

    #[inline]
    fn specialized_from_compact(_: &[u8], _: usize) -> (Self, &[u8]) {
        unimplemented!()
    }
}

impl<T> Compact for Option<T>
where
    T: Compact,
{
    // A full-width varint bounds the prefix even when T returns a flag rather than a size.
    // This bound also covers specialized_to_compact, which omits the prefix.
    const __COMPACT_MAX_SIZE: Option<usize> = match T::__COMPACT_MAX_SIZE {
        Some(size) => size.checked_add((usize::BITS as usize).div_ceil(7)),
        None => None,
    };

    /// Returns 0 for `None` and 1 for `Some(_)`.
    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let Some(element) = self else { return 0 };

        // We don't know the length of the element until we compact it.
        let mut tmp = Vec::with_capacity(64);
        let length = element.to_compact(&mut tmp);

        encode_varuint(length, buf);

        buf.put_slice(&tmp);

        1
    }

    #[inline]
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        if len == 0 {
            return (None, buf);
        }

        let (len, buf) = decode_varuint(buf);

        let (element, buf) = T::from_compact(buf, len);

        (Some(element), buf)
    }

    /// To be used by fixed sized types like `Option<B256>`.
    #[inline]
    fn specialized_to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        if let Some(element) = self {
            element.to_compact(buf);
            1
        } else {
            0
        }
    }

    /// To be used by fixed sized types like `Option<B256>`.
    #[inline]
    fn specialized_from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        if len == 0 {
            return (None, buf);
        }

        let (element, buf) = T::from_compact(buf, len);
        (Some(element), buf)
    }
}

impl<T: Compact + ToOwned<Owned = T>> Compact for Cow<'_, T> {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        self.as_ref().to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (element, buf) = T::from_compact(buf, len);
        (Cow::Owned(element), buf)
    }

    fn specialized_to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        self.as_ref().specialized_to_compact(buf)
    }

    fn specialized_from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (element, buf) = T::specialized_from_compact(buf, len);
        (Cow::Owned(element), buf)
    }
}

impl Compact for U256 {
    const __COMPACT_MAX_SIZE: Option<usize> = Some(32);

    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let inner = self.to_be_bytes::<32>();
        let size = 32 - (self.leading_zeros() / 8);
        buf.put_slice(&inner[32 - size..]);
        size
    }

    #[inline]
    fn from_compact(mut buf: &[u8], len: usize) -> (Self, &[u8]) {
        if len == 0 {
            return (Self::ZERO, buf);
        }

        let mut arr = [0; 32];
        arr[(32 - len)..].copy_from_slice(&buf[..len]);
        buf.advance(len);
        (Self::from_be_bytes(arr), buf)
    }
}

impl Compact for Bytes {
    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let len = self.len();
        buf.put_slice(&self.0);
        len
    }

    #[inline]
    fn from_compact(mut buf: &[u8], len: usize) -> (Self, &[u8]) {
        (buf.copy_to_bytes(len).into(), buf)
    }
}

impl<const N: usize> Compact for [u8; N] {
    const __COMPACT_MAX_SIZE: Option<usize> = Some(N);

    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        buf.put_slice(&self[..]);
        N
    }

    #[inline]
    fn from_compact(mut buf: &[u8], len: usize) -> (Self, &[u8]) {
        if len == 0 {
            return ([0; N], buf);
        }

        let v = buf[..N].try_into().unwrap();
        buf.advance(N);
        (v, buf)
    }
}

/// Implements the [`Compact`] trait for wrappers over fixed size byte array types.
#[macro_export]
macro_rules! impl_compact_for_wrapped_bytes {
    ($($name:tt),+) => {
        $(
            impl Compact for $name {
                #[inline]
                fn to_compact<B>(&self, buf: &mut B) -> usize
                where
                    B: bytes::BufMut + AsMut<[u8]>
                {
                    self.0.to_compact(buf)
                }

                #[inline]
                fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
                    let (v, buf) = <[u8; core::mem::size_of::<$name>()]>::from_compact(buf, len);
                    (Self::from(v), buf)
                }
            }
        )+
    };
}
impl_compact_for_wrapped_bytes!(Address, Bloom);

impl<const N: usize> Compact for FixedBytes<N> {
    const __COMPACT_MAX_SIZE: Option<usize> = Some(N);

    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        self.0.to_compact(buf)
    }

    #[inline]
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (v, buf) = <[u8; N]>::from_compact(buf, len);
        (Self::from(v), buf)
    }
}

impl Compact for bool {
    const __COMPACT_MAX_SIZE: Option<usize> = Some(0);

    /// `bool` vars go directly to the `StructFlags` and are not written to the buffer.
    #[inline]
    fn to_compact<B>(&self, _: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        *self as usize
    }

    /// `bool` expects the real value to come in `len`, and does not advance the cursor.
    #[inline]
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        (len != 0, buf)
    }
}

/// Writes `n` as an unsigned LEB128 varint and returns the number of bytes written.
fn encode_varuint<B>(mut n: usize, buf: &mut B) -> usize
where
    B: bytes::BufMut + AsMut<[u8]>,
{
    let mut written = 1;
    while n >= 0x80 {
        buf.put_u8((n as u8) | 0x80);
        n >>= 7;
        written += 1;
    }
    buf.put_u8(n as u8);
    written
}

fn decode_varuint(buf: &[u8]) -> (usize, &[u8]) {
    let mut value = 0;

    for i in 0..33 {
        let byte = buf[i];
        value |= usize::from(byte & 0x7F) << (i * 7);
        if byte < 0x80 {
            return (value, &buf[i + 1..]);
        }
    }

    decode_varuint_panic();
}

#[inline(never)]
#[cold]
const fn decode_varuint_panic() -> ! {
    panic!("could not decode varuint");
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{hex, B256};
    use bytes::BytesMut;
    use serde::{Deserialize, Serialize};

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test value must be non-zero")
    }

    #[test]
    fn compact_bytes() {
        let arr = [1, 2, 3, 4, 5];
        let list = Bytes::copy_from_slice(&arr);
        let mut buf = Vec::with_capacity(list.len() + 1);
        assert_eq!(list.to_compact(&mut buf), list.len());

        // Add some noise data.
        buf.push(1);

        assert_eq!(&buf[..arr.len()], &arr);
        assert_eq!(Bytes::from_compact(&buf, list.len()), (list, vec![1].as_slice()));
    }

    #[test]
    fn compact_address() {
        let mut buf = Vec::with_capacity(21);
        assert_eq!(Address::ZERO.to_compact(&mut buf), 20);
        assert_eq!(buf, vec![0; 20]);

        // Add some noise data.
        buf.push(1);

        // Address shouldn't care about the len passed, since it's not actually compacted.
        assert_eq!(Address::from_compact(&buf, 1000), (Address::ZERO, vec![1u8].as_slice()));
    }

    #[test]
    fn compact_b256() {
        let mut buf = Vec::with_capacity(32 + 1);
        assert_eq!(B256::ZERO.to_compact(&mut buf), 32);
        assert_eq!(buf, vec![0; 32]);

        // Add some noise data.
        buf.push(1);

        // B256 shouldn't care about the len passed, since it's not actually compacted.
        assert_eq!(B256::from_compact(&buf, 1000), (B256::ZERO, vec![1u8].as_slice()));
    }

    #[test]
    fn compact_usize() {
        fn check(value: usize, expected: &[u8]) {
            let mut buf = vec![];
            assert_eq!(value.to_compact(&mut buf), expected.len());
            assert_eq!(buf, expected);

            // Add some noise data.
            buf.push(1);

            // usize is self-delimiting, so the len passed is ignored.
            assert_eq!(usize::from_compact(&buf, 1000), (value, vec![1u8].as_slice()));
        }

        check(0, &[0x00]);
        check(127, &[0x7f]);
        check(128, &[0x80, 0x01]);
        check(300, &[0xac, 0x02]);
        #[cfg(target_pointer_width = "64")]
        check(usize::MAX, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
    }

    #[test]
    fn compress_b512() {
        use alloy_primitives::B512;

        let value = B512::repeat_byte(0xab);
        assert_eq!(value.uncompressable_ref(), Some(value.as_slice()));
        assert_eq!(value.compress(), value.to_vec());
        assert_eq!(B512::decompress(&value.compress()).unwrap(), value);
    }

    #[test]
    fn compact_bool() {
        let _vtrue = true;
        let mut buf = vec![];

        assert_eq!(true.to_compact(&mut buf), 1);
        // Bool vars go directly to the `StructFlags` and not written to the buf.
        assert_eq!(buf.len(), 0);

        assert_eq!(false.to_compact(&mut buf), 0);
        assert_eq!(buf.len(), 0);

        let buf = vec![100u8];

        // Bool expects the real value to come in `len`, and does not advance the cursor.
        assert_eq!(bool::from_compact(&buf, 1), (true, buf.as_slice()));
        assert_eq!(bool::from_compact(&buf, 0), (false, buf.as_slice()));
    }

    #[test]
    fn compact_nonzero_u64() {
        let value = nz(0x12_34);
        let mut buf = vec![];

        assert_eq!(value.to_compact(&mut buf), 2);
        assert_eq!(buf, vec![0x12, 0x34]);

        buf.push(0xaa);
        assert_eq!(NonZeroU64::from_compact(&buf, 2), (value, vec![0xaa].as_slice()));
    }

    #[test]
    fn compact_option() {
        let opt = Some(B256::ZERO);
        let mut buf = Vec::with_capacity(1 + 32);

        assert_eq!(None::<B256>.to_compact(&mut buf), 0);
        assert_eq!(opt.to_compact(&mut buf), 1);
        assert_eq!(buf.len(), 1 + 32);

        assert_eq!(Option::<B256>::from_compact(&buf, 1), (opt, vec![].as_slice()));

        // If `None`, it returns the slice at the same cursor position.
        assert_eq!(Option::<B256>::from_compact(&buf, 0), (None, buf.as_slice()));

        let mut buf = Vec::with_capacity(32);
        assert_eq!(opt.specialized_to_compact(&mut buf), 1);
        assert_eq!(buf.len(), 32);
        assert_eq!(Option::<B256>::specialized_from_compact(&buf, 1), (opt, vec![].as_slice()));
    }

    #[test]
    fn compact_option_nonzero_u64() {
        let value = Some(nz(0x12_34));
        let mut buf = vec![];

        assert_eq!(value.to_compact(&mut buf), 1);
        assert_eq!(buf, vec![2, 0x12, 0x34]);
        assert_eq!(Option::<NonZeroU64>::from_compact(&buf, 1), (value, vec![].as_slice()));
    }

    #[test]
    fn compact_vec() {
        let list = vec![B256::ZERO, B256::ZERO];
        let mut buf = vec![];

        // Vec doesn't return a total length
        assert_eq!(list.to_compact(&mut buf), 0);

        // Add some noise data in the end that should be returned by `from_compact`.
        buf.extend([1u8, 2]);

        let mut remaining_buf = buf.as_slice();
        remaining_buf.advance(1 + 1 + 32 + 1 + 32);

        assert_eq!(Vec::<B256>::from_compact(&buf, 0), (list, remaining_buf));
        assert_eq!(remaining_buf, &[1u8, 2]);
    }

    #[test]
    fn compact_u256() {
        let mut buf = vec![];

        assert_eq!(U256::ZERO.to_compact(&mut buf), 0);
        assert!(buf.is_empty());
        assert_eq!(U256::from_compact(&buf, 0), (U256::ZERO, vec![].as_slice()));

        assert_eq!(U256::from(2).to_compact(&mut buf), 1);
        assert_eq!(buf, vec![2u8]);
        assert_eq!(U256::from_compact(&buf, 1), (U256::from(2), vec![].as_slice()));
    }

    #[test]
    fn compact_u64() {
        let mut buf = vec![];

        assert_eq!(0u64.to_compact(&mut buf), 0);
        assert!(buf.is_empty());
        assert_eq!(u64::from_compact(&buf, 0), (0u64, vec![].as_slice()));

        assert_eq!(2u64.to_compact(&mut buf), 1);
        assert_eq!(buf, vec![2u8]);
        assert_eq!(u64::from_compact(&buf, 1), (2u64, vec![].as_slice()));

        let mut buf = Vec::with_capacity(8);

        assert_eq!(0xffffffffffffffffu64.to_compact(&mut buf), 8);
        assert_eq!(&buf, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(u64::from_compact(&buf, 8), (0xffffffffffffffffu64, vec![].as_slice()));
    }

    #[test]
    fn variable_uint() {
        proptest::proptest!(|(val: usize)| {
            let mut buf = vec![];
            encode_varuint(val, &mut buf);
            let (decoded, read_buf) = decode_varuint(&buf);
            assert_eq!(val, decoded);
            assert!(!read_buf.has_remaining());
        });
    }

    #[test]
    fn compact_slice() {
        let vec_list = vec![B256::ZERO, B256::random(), B256::random(), B256::ZERO];

        // to_compact
        {
            let mut vec_buf = vec![];
            assert_eq!(vec_list.to_compact(&mut vec_buf), 0);

            let mut slice_buf = vec![];
            assert_eq!(vec_list.as_slice().to_compact(&mut slice_buf), 0);

            assert_eq!(vec_buf, slice_buf);
        }

        // specialized_to_compact
        {
            let mut vec_buf = vec![];
            assert_eq!(vec_list.specialized_to_compact(&mut vec_buf), 0);

            let mut slice_buf = vec![];
            assert_eq!(vec_list.as_slice().specialized_to_compact(&mut slice_buf), 0);

            assert_eq!(vec_buf, slice_buf);
        }
    }

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Compact, arbitrary::Arbitrary)]
    #[add_arbitrary_tests(crate, compact)]
    #[reth_codecs(crate = "crate")]
    struct TestStruct {
        f_u64: u64,
        f_u256: U256,
        f_bool_t: bool,
        f_bool_f: bool,
        f_option_none: Option<B256>,
        f_option_some: Option<B256>,
        f_option_some_u64: Option<u64>,
        f_vec_empty: Vec<Address>,
        f_vec_some: Vec<Address>,
    }

    impl Default for TestStruct {
        fn default() -> Self {
            Self {
                f_u64: 1u64,                                    // 4 bits | 1 byte
                f_u256: U256::from(1u64),                       // 6 bits | 1 byte
                f_bool_f: false,                                // 1 bit  | 0 bytes
                f_bool_t: true,                                 // 1 bit  | 0 bytes
                f_option_none: None,                            // 1 bit  | 0 bytes
                f_option_some: Some(B256::ZERO),                // 1 bit  | 32 bytes
                f_option_some_u64: Some(0xffffu64),             // 1 bit  | 1 + 2 bytes
                f_vec_empty: vec![],                            // 0 bits | 1 bytes
                f_vec_some: vec![Address::ZERO, Address::ZERO], // 0 bits | 1 + 20*2 bytes
            }
        }
    }

    #[test]
    fn compact_test_struct() {
        let test = TestStruct::default();
        const EXPECTED_SIZE: usize = 2 + // TestStructFlags
            1 +
            1 +
            // 0 + 0 + 0 +
            32 +
            1 + 2 +
            1 +
            1 + 20 * 2;
        let mut buf = Vec::with_capacity(EXPECTED_SIZE);
        assert_eq!(test.to_compact(&mut buf), EXPECTED_SIZE);

        assert_eq!(
            TestStruct::from_compact(&buf, buf.len()),
            (TestStruct::default(), vec![].as_slice())
        );
    }

    #[test]
    fn compact_stack_buffers() {
        #[derive(Debug, PartialEq, Compact)]
        #[reth_codecs(crate = "crate")]
        struct Value {
            nonce: u64,
            balance: U256,
            bytecode_hash: Option<B256>,
        }

        let value = Value {
            nonce: 0x1234,
            balance: U256::from(1),
            bytecode_hash: Some(B256::repeat_byte(0xab)),
        };
        let expected = [hex!("1204123401").as_slice(), &[0xab; 32]].concat();
        let mut vec = vec![0xff; 3];
        assert_eq!(value.to_compact(&mut vec), expected.len());
        assert_eq!(&vec[..3], &[0xff; 3]);
        assert_eq!(&vec[3..], expected);

        let mut bytes = BytesMut::from(&vec[..3]);
        assert_eq!(value.to_compact(&mut bytes), expected.len());
        assert_eq!(&bytes[..], vec);

        let mut storage = [0xa5; 40];
        let mut slice = storage.as_mut_slice();
        assert_eq!(value.to_compact(&mut slice), expected.len());
        assert_eq!(slice, &[0xa5; 3]);
        assert_eq!(&storage[..expected.len()], expected);
        let (decoded, remaining) = Value::from_compact(&storage, expected.len());
        assert_eq!(decoded, value);
        assert_eq!(remaining, &[0xa5; 3]);

        // As before, a short destination receives the flags before the payload write panics.
        let mut short = [0xa5; 3];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            value.to_compact(&mut short.as_mut_slice())
        }));
        assert!(result.is_err());
        assert_eq!(short, [0x12, 0x04, 0xa5]);
    }

    #[derive(
        Debug, PartialEq, Clone, Default, Serialize, Deserialize, Compact, arbitrary::Arbitrary,
    )]
    #[add_arbitrary_tests(crate, compact)]
    #[reth_codecs(crate = "crate")]
    enum TestEnum {
        #[default]
        Var0,
        Var1(TestStruct),
        Var2(u64),
    }

    #[cfg(test)]
    #[test_fuzz::test_fuzz]
    fn compact_test_enum_all_variants(var0: TestEnum, var1: TestEnum, var2: TestEnum) {
        let mut buf = vec![];
        var0.to_compact(&mut buf);
        assert_eq!(TestEnum::from_compact(&buf, buf.len()).0, var0);

        let mut buf = vec![];
        var1.to_compact(&mut buf);
        assert_eq!(TestEnum::from_compact(&buf, buf.len()).0, var1);

        let mut buf = vec![];
        var2.to_compact(&mut buf);
        assert_eq!(TestEnum::from_compact(&buf, buf.len()).0, var2);
    }

    #[test]
    fn compact_test_enum() {
        let var0 = TestEnum::Var0;
        let var1 = TestEnum::Var1(TestStruct::default());
        let var2 = TestEnum::Var2(1u64);

        compact_test_enum_all_variants(var0, var1, var2);
    }
}
