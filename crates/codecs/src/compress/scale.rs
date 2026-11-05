//! The SCALE encodings used by database values: fixed-width integers and byte vectors.
//!
//! Keep these encodings compatible with `parity-scale-codec`, including canonical compact vector
//! lengths and acceptance of trailing bytes when decoding a value.

use crate::{Compress, Decompress, DecompressError};
use alloc::vec::Vec;
use bytes::BufMut;
use core::fmt;

/// Implements the fixed-width, little-endian SCALE integer encoding.
macro_rules! impl_compression_for_scale {
    ($($name:ty),+) => {
        $(
            impl Compress for $name {
                type Compressed = Vec<u8>;

                fn compress(self) -> Self::Compressed {
                    self.to_le_bytes().to_vec()
                }

                fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
                    buf.put_slice(&self.to_le_bytes());
                }
            }

            impl Decompress for $name {
                fn decompress(mut value: &[u8]) -> Result<Self, DecompressError> {
                    read_array(&mut value).map(Self::from_le_bytes).map_err(DecompressError::new)
                }
            }
        )+
    };
}

impl_compression_for_scale!(u8, u16, u32, u64);

impl Compress for Vec<u8> {
    type Compressed = Self;

    fn compress(self) -> Self::Compressed {
        let mut buf = Self::with_capacity(self.len() + MAX_LENGTH_PREFIX_SIZE);
        self.compress_to_buf(&mut buf);
        buf
    }

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        encode_length(self.len(), buf);
        buf.put_slice(self);
    }
}

impl Decompress for Vec<u8> {
    fn decompress(mut value: &[u8]) -> Result<Self, DecompressError> {
        let len = decode_length(&mut value).map_err(DecompressError::new)? as usize;
        // Validate the length before allocating, just as SCALE does for slice inputs.
        value
            .get(..len)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| DecompressError::new(ScaleError::TruncatedVector))
    }
}

const TWO_BYTE_MIN: u32 = 1 << 6;
const FOUR_BYTE_MIN: u32 = 1 << 14;
const FIVE_BYTE_MIN: u32 = 1 << 30;
const MAX_LENGTH_PREFIX_SIZE: usize = 1 + size_of::<u32>();

#[derive(Debug)]
enum ScaleError {
    TruncatedInput,
    TruncatedVector,
    InvalidLength,
}

impl fmt::Display for ScaleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TruncatedInput => "Not enough data to fill buffer",
            Self::TruncatedVector => "Not enough data to decode vector",
            Self::InvalidLength => "out of range decoding Compact<u32>",
        })
    }
}

impl core::error::Error for ScaleError {}

fn read_array<const N: usize>(value: &mut &[u8]) -> Result<[u8; N], ScaleError> {
    let Some((bytes, rest)) = value.split_first_chunk() else {
        return Err(ScaleError::TruncatedInput)
    };
    *value = rest;
    Ok(*bytes)
}

fn encode_length<B: BufMut>(len: usize, buf: &mut B) {
    // SCALE collection lengths are limited to u32, even on 64-bit platforms.
    assert!(len <= u32::MAX as usize, "SCALE vector length exceeds u32::MAX");
    let len = len as u32;
    match len {
        0..TWO_BYTE_MIN => buf.put_u8((len << 2) as u8),
        TWO_BYTE_MIN..FOUR_BYTE_MIN => buf.put_u16_le(((len << 2) | 1) as u16),
        FOUR_BYTE_MIN..FIVE_BYTE_MIN => buf.put_u32_le((len << 2) | 2),
        _ => {
            buf.put_u8(3);
            buf.put_u32_le(len);
        }
    }
}

fn decode_length(value: &mut &[u8]) -> Result<u32, ScaleError> {
    let Some(&first) = value.first() else { return Err(ScaleError::TruncatedInput) };
    let (len, min) = match first & 3 {
        0 => {
            *value = &value[1..];
            return Ok(u32::from(first >> 2))
        }
        1 => (u32::from(u16::from_le_bytes(read_array(value)?) >> 2), TWO_BYTE_MIN),
        2 => (u32::from_le_bytes(read_array(value)?) >> 2, FOUR_BYTE_MIN),
        _ if first == 3 => {
            *value = &value[1..];
            (u32::from_le_bytes(read_array(value)?), FIVE_BYTE_MIN)
        }
        // Other mode-3 prefixes describe more than four bytes, which cannot encode a u32.
        _ => return Err(ScaleError::InvalidLength),
    };
    if len < min {
        return Err(ScaleError::InvalidLength)
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use parity_scale_codec::{Compact, Decode, Encode};
    use proptest::{collection::vec, prelude::*};

    fn assert_encoding<T: Compress + Decompress + Encode + Clone + PartialEq>(value: T) {
        let encoded = value.encode();
        assert_eq!(value.clone().compress().as_ref(), encoded);

        let mut appended = vec![0xaa, 0xbb];
        value.compress_to_buf(&mut appended);
        assert_eq!(&appended[..2], &[0xaa, 0xbb]);
        assert_eq!(&appended[2..], encoded);

        let mut buf = BytesMut::new();
        value.compress_to_buf(&mut buf);
        assert_eq!(buf.as_ref(), encoded);

        let mut storage = vec![0; encoded.len()];
        value.compress_to_buf(&mut storage.as_mut_slice());
        assert_eq!(storage, encoded);

        assert_eq!(T::decompress(&encoded).unwrap(), value);
        let mut trailing = encoded;
        trailing.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(T::decompress(&trailing).unwrap(), value);
    }

    fn assert_decoding<T: Decompress + Decode + PartialEq>(encoded: &[u8]) {
        assert_eq!(
            T::decompress(encoded).map_err(|err| err.to_string()),
            T::decode(&mut &*encoded).map_err(|err| err.to_string()),
            "input: {encoded:?}"
        );
    }

    fn assert_length(len: u32) {
        let mut encoded = Vec::new();
        encode_length(len as usize, &mut encoded);
        assert_eq!(encoded, Compact(len).encode());
        encoded.extend_from_slice(&[0xaa, 0xbb]);
        let mut input = encoded.as_slice();
        assert_eq!(decode_length(&mut input).unwrap(), len);
        assert_eq!(input, &[0xaa, 0xbb]);
    }

    #[test]
    fn integer_boundaries() {
        for value in [0, 1, u8::MAX] {
            assert_encoding(value);
        }
        for value in [0, 1, u16::MAX] {
            assert_encoding(value);
        }
        for value in [0, 1, u32::MAX] {
            assert_encoding(value);
        }
        for value in [0, 1, u64::MAX] {
            assert_encoding(value);
        }
    }

    #[test]
    fn vector_boundaries() {
        for len in [0, 1, 63, 64, 65, 16383, 16384, 16385] {
            assert_encoding(vec![0x5a; len]);
        }
        // Exercise large prefixes without allocating their payloads.
        for len in [0, 1, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, u32::MAX] {
            assert_length(len);
            if len != 0 {
                let encoded = Compact(len).encode();
                assert_decoding::<Vec<u8>>(&encoded);
                assert_eq!(
                    Vec::<u8>::decompress(&encoded).unwrap_err().to_string(),
                    "Not enough data to decode vector"
                );
            }
        }
    }

    #[test]
    fn truncated_values() {
        for len in 0..size_of::<u64>() {
            let encoded = vec![0xff; len];
            assert_decoding::<u8>(&encoded);
            assert_decoding::<u16>(&encoded);
            assert_decoding::<u32>(&encoded);
            assert_decoding::<u64>(&encoded);
        }
        for len in [0u32, 64, 16384, 1 << 30] {
            let encoded = Compact(len).encode();
            for end in 0..encoded.len() {
                assert_decoding::<Vec<u8>>(&encoded[..end]);
                assert_eq!(
                    Vec::<u8>::decompress(&encoded[..end]).unwrap_err().to_string(),
                    "Not enough data to fill buffer"
                );
            }
        }
        let encoded = vec![1u8, 2, 3].encode();
        for end in 1..encoded.len() {
            assert_decoding::<Vec<u8>>(&encoded[..end]);
            assert_eq!(
                Vec::<u8>::decompress(&encoded[..end]).unwrap_err().to_string(),
                "Not enough data to decode vector"
            );
        }
    }

    #[test]
    fn noncanonical_lengths() {
        for encoded in [
            &[1, 0][..],
            &[0xfd, 0],
            &[2, 0, 0, 0],
            &[0xfe, 0xff, 0, 0],
            &[3, 0, 0, 0, 0],
            &[3, 0xff, 0xff, 0xff, 0x3f],
        ] {
            assert_decoding::<Vec<u8>>(encoded);
            assert_eq!(
                Vec::<u8>::decompress(encoded).unwrap_err().to_string(),
                "out of range decoding Compact<u32>"
            );
        }
        // Reject unsupported length widths immediately, even with a truncated body.
        for first in (7..=u8::MAX).step_by(4) {
            assert_decoding::<Vec<u8>>(&[first]);
            assert_eq!(
                Vec::<u8>::decompress(&[first]).unwrap_err().to_string(),
                "out of range decoding Compact<u32>"
            );
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    #[should_panic(expected = "SCALE vector length exceeds u32::MAX")]
    fn oversized_length() {
        encode_length(u32::MAX as usize + 1, &mut Vec::new());
    }

    proptest! {
        #[test]
        fn integer_encodings(a: u8, b: u16, c: u32, d: u64) {
            assert_encoding(a);
            assert_encoding(b);
            assert_encoding(c);
            assert_encoding(d);
        }

        #[test]
        fn vector_encodings(value in vec(any::<u8>(), 0..=16385)) {
            assert_encoding(value);
        }

        #[test]
        fn length_encodings(len: u32) {
            assert_length(len);
        }

        #[test]
        fn arbitrary_inputs(encoded in vec(any::<u8>(), 0..512)) {
            scale_decoding(encoded);
        }
    }

    #[test_fuzz::test_fuzz]
    fn scale_decoding(encoded: Vec<u8>) {
        assert_decoding::<u8>(&encoded);
        assert_decoding::<u16>(&encoded);
        assert_decoding::<u32>(&encoded);
        assert_decoding::<u64>(&encoded);
        assert_decoding::<Vec<u8>>(&encoded);
    }
}
