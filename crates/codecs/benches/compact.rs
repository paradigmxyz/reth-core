//! Compare account encoding with the pre-optimization generated implementation.
use alloy_primitives::{B256, U256};
use bytes::{BufMut, BytesMut};
use reth_codecs::Compact;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

struct CountingAllocator;
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarded to the system allocator with the original layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded with the original pointer and layout.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarded with the caller's allocation and size.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[derive(Debug, Compact)]
struct Account {
    nonce: u64,
    balance: U256,
    bytecode_hash: Option<B256>,
}
impl Account {
    // The encoder generated before this optimization, kept for a direct comparison.
    fn legacy<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize {
        let mut flags = AccountFlags::default();
        let mut buffer = BytesMut::new();
        flags.set_nonce_len(self.nonce.to_compact(&mut buffer) as u8);
        flags.set_balance_len(self.balance.to_compact(&mut buffer) as u8);
        flags.set_bytecode_hash_len(self.bytecode_hash.specialized_to_compact(&mut buffer) as u8);
        let flags = flags.into_bytes();
        let len = flags.len() + buffer.len();
        buf.put_slice(&flags);
        buf.put(buffer);
        len
    }
}

fn measure(label: &str, accounts: &[Account], legacy: bool) {
    const ITERATIONS: usize = 1_000_000;
    let mut buf = Vec::with_capacity(128);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let start = Instant::now();
    for i in 0..ITERATIONS {
        buf.clear();
        let value = black_box(&accounts[i % accounts.len()]);
        let len = if legacy { value.legacy(&mut buf) } else { value.to_compact(&mut buf) };
        black_box((len, &buf));
    }
    let elapsed = start.elapsed();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - allocations;
    println!(
        "{label}: {:.2} ns/value, {allocations} allocations/reallocations for {ITERATIONS} values",
        elapsed.as_nanos() as f64 / ITERATIONS as f64
    );
    if !legacy {
        assert_eq!(allocations, 0, "bounded account encoding should not allocate scratch storage");
    }
}

fn main() {
    let accounts = [
        Account { nonce: 0, balance: U256::ZERO, bytecode_hash: None },
        Account { nonce: 1, balance: U256::from(1_000_000_000u64), bytecode_hash: None },
        Account {
            nonce: 256,
            balance: U256::from(1_000_000_000u64),
            bytecode_hash: Some(B256::repeat_byte(0xab)),
        },
        Account {
            nonce: u64::MAX,
            balance: U256::MAX,
            bytecode_hash: Some(B256::repeat_byte(0xcd)),
        },
    ];
    for value in &accounts {
        let (mut old, mut new) = (vec![], vec![]);
        assert_eq!(value.legacy(&mut old), value.to_compact(&mut new));
        assert_eq!(old, new);
    }
    for _ in 0..3 {
        measure("legacy", &accounts, true);
        measure("stack", &accounts, false);
    }
}
