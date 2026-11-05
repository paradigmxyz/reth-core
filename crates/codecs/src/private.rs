pub use modular_bitfield;

pub use bytes::{self, Buf};

// Bound per derived value, independent of its declared field sizes. Larger or unbounded
// encodings keep the original BytesMut path.
pub const COMPACT_STACK_CAPACITY: usize = 256;

// Autoref dispatch preserves support for fields with inherent codec methods but no
// Compact impl. They must retain the original BytesMut path as well.
#[derive(Debug)]
pub struct CompactMaxSize<'a, T>(pub &'a T);

pub trait GetCompactMaxSize {
    fn compact_max_size(self) -> Option<usize>;
    fn compact_to_stack<B: bytes::BufMut + AsMut<[u8]>>(
        self,
        buf: &mut B,
        specialized: bool,
    ) -> usize;
}

impl<T: crate::Compact> GetCompactMaxSize for &CompactMaxSize<'_, T> {
    #[inline]
    fn compact_max_size(self) -> Option<usize> {
        T::__COMPACT_MAX_SIZE
    }

    #[inline]
    fn compact_to_stack<B: bytes::BufMut + AsMut<[u8]>>(
        self,
        buf: &mut B,
        specialized: bool,
    ) -> usize {
        if specialized {
            T::specialized_to_compact(self.0, buf)
        } else {
            T::to_compact(self.0, buf)
        }
    }
}

impl<T> GetCompactMaxSize for &&CompactMaxSize<'_, T> {
    #[inline]
    fn compact_max_size(self) -> Option<usize> {
        None
    }

    #[inline]
    fn compact_to_stack<B: bytes::BufMut + AsMut<[u8]>>(self, _: &mut B, _: bool) -> usize {
        unreachable!("fields without Compact never opt into stack buffering")
    }
}

#[inline]
pub const fn fits_on_stack(sizes: &[Option<usize>]) -> bool {
    let mut remaining = COMPACT_STACK_CAPACITY;
    let mut index = 0;
    while index < sizes.len() {
        match sizes[index] {
            Some(size) if size <= remaining => remaining -= size,
            _ => return false,
        }
        index += 1;
    }
    true
}
