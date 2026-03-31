# reth-core

Core traits and libraries extracted from [Reth](https://github.com/paradigmxyz/reth), published as crates so they can be depended on without git references.

## Crates

- [`reth-codecs`] - `Compact` codec trait, implementations for primitive and alloy types, and the derive macro
- [`reth-codecs-derive`] - Procedural macro for deriving `Compact` on custom types
- [`reth-primitives-traits`] - Common types in reth
- [`reth-rpc-traits`] - Conversion and signing traits for Ethereum RPC types
- [`reth-zstd-compressors`] - Pre-trained zstd dictionaries for compressing Ethereum data (transactions, headers, receipts)

[`reth-codecs`]: https://github.com/paradigmxyz/reth-core/tree/main/crates/codecs
[`reth-codecs-derive`]: https://github.com/paradigmxyz/reth-core/tree/main/crates/codecs-derive
[`reth-primitives-traits`]: https://github.com/paradigmxyz/reth-core/tree/main/crates/primitives-traits
[`reth-rpc-traits`]: https://github.com/paradigmxyz/reth-core/tree/main/crates/rpc-traits
[`reth-zstd-compressors`]: https://github.com/paradigmxyz/reth-core/tree/main/crates/zstd-compressors

## Supported Rust Versions (MSRV)

The current MSRV (minimum supported rust version) is 1.93.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

## Warning

The `Compact` encoding format and its implementations are designed for storing and retrieving data internally. They are not hardened to safely read potentially malicious data.

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
</sub>
