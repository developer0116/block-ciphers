# RustCrypto: block ciphers [![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link]

Collection of [block ciphers] written in pure Rust.

## Warnings

Currently only the `aes` crate provides constant-time implementation.
If you do not really know what you are doing, it's generally recommended not to
use other cipher implementations in this repository.

Additionally, crates in this repository have not yet received any formal
cryptographic and security reviews.

**USE AT YOUR OWN RISK.**

## Supported algorithms

| Name | Crate name | crates.io | Docs | MSRV |
|------|------------|-----------|------|------|
| [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (Rijndael) | `aes` | [![crates.io](https://img.shields.io/crates/v/aes.svg)](https://crates.io/crates/aes) | [![Documentation](https://docs.rs/aes/badge.svg)](https://docs.rs/aes) | ![Minimum Supported Rust Version][msrv-1.49]* |
| [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)) | `blowfish` | [![crates.io](https://img.shields.io/crates/v/blowfish.svg)](https://crates.io/crates/blowfish) | [![Documentation](https://docs.rs/blowfish/badge.svg)](https://docs.rs/blowfish) | ![Minimum Supported Rust Version][msrv-1.41] |
| [CAST5](https://en.wikipedia.org/wiki/CAST-128) (CAST-128) | `cast5` | [![crates.io](https://img.shields.io/crates/v/cast5.svg)](https://crates.io/crates/cast5) | [![Documentation](https://docs.rs/cast5/badge.svg)](https://docs.rs/cast5) | ![Minimum Supported Rust Version][msrv-1.41] |
| [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) + [3DES](https://en.wikipedia.org/wiki/Triple_DES) (DEA, 3DEA) | `des` | [![crates.io](https://img.shields.io/crates/v/des.svg)](https://crates.io/crates/des) | [![Documentation](https://docs.rs/des/badge.svg)](https://docs.rs/des) | ![Minimum Supported Rust Version][msrv-1.41] |
| [IDEA](https://simple.wikipedia.org/wiki/International_Data_Encryption_Algorithm) | `idea` | [![crates.io](https://img.shields.io/crates/v/idea.svg)](https://crates.io/crates/idea) | [![Documentation](https://docs.rs/idea/badge.svg)](https://docs.rs/idea) | ![Minimum Supported Rust Version][msrv-1.41] |
| [Kuznyechik](https://en.wikipedia.org/wiki/Kuznyechik) (GOST R 34.12-2015)  | `kuznyechik` | [![crates.io](https://img.shields.io/crates/v/kuznyechik.svg)](https://crates.io/crates/kuznyechik) | [![Documentation](https://docs.rs/kuznyechik/badge.svg)](https://docs.rs/kuznyechik) | ![Minimum Supported Rust Version][msrv-1.41] |
| [Magma](https://en.wikipedia.org/wiki/GOST_(block_cipher)) (GOST R 34.12-2015) | `magma` | [![crates.io](https://img.shields.io/crates/v/magma.svg)](https://crates.io/crates/magma) | [![Documentation](https://docs.rs/magma/badge.svg)](https://docs.rs/magma) | ![Minimum Supported Rust Version][msrv-1.41] |
| [RC2](https://en.wikipedia.org/wiki/RC2) (ARC2) | `rc2` | [![crates.io](https://img.shields.io/crates/v/rc2.svg)](https://crates.io/crates/rc2) | [![Documentation](https://docs.rs/rc2/badge.svg)](https://docs.rs/rc2) | ![Minimum Supported Rust Version][msrv-1.41] |
| [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher)) | `serpent` | [![crates.io](https://img.shields.io/crates/v/serpent.svg)](https://crates.io/crates/serpent) | [![Documentation](https://docs.rs/serpent/badge.svg)](https://docs.rs/serpent) | ![Minimum Supported Rust Version][msrv-1.41] |
| [SM4](https://en.wikipedia.org/wiki/SM4_(cipher)) | `sm4` | [![crates.io](https://img.shields.io/crates/v/sm4.svg)](https://crates.io/crates/sm4) | [![Documentation](https://docs.rs/sm4/badge.svg)](https://docs.rs/sm4) | ![Minimum Supported Rust Version][msrv-1.41] |
| [Twofish](https://en.wikipedia.org/wiki/Twofish) | `twofish` | [![crates.io](https://img.shields.io/crates/v/twofish.svg)](https://crates.io/crates/twofish) | [![Documentation](https://docs.rs/twofish/badge.svg)](https://docs.rs/twofish) | ![Minimum Supported Rust Version][msrv-1.41] |
| [Threefish](https://en.wikipedia.org/wiki/Threefish) | `threefish` | [![crates.io](https://img.shields.io/crates/v/threefish.svg)](https://crates.io/crates/threefish) | [![Documentation](https://docs.rs/threefish/badge.svg)](https://docs.rs/threefish) | ![Minimum Supported Rust Version][msrv-1.41] |

\* The `aes` crate supports MSRV 1.41 with enabled `force-soft` feature.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260039-block-ciphers
[deps-image]: https://deps.rs/repo/github/RustCrypto/block-ciphers/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/block-ciphers
[msrv-1.49]: https://img.shields.io/badge/rustc-1.49.0+-blue.svg
[msrv-1.41]: https://img.shields.io/badge/rustc-1.41.0+-blue.svg

[//]: # (links)

[block ciphers]: https://en.wikipedia.org/wiki/Block_cipher
