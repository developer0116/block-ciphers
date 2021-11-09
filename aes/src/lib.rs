//! Pure Rust implementation of the Advanced Encryption Standard
//! (a.k.a. Rijndael)
//!
//! # Supported backends
//! This crate provides multiple backends including a portable pure Rust
//! backend as well as ones based on CPU intrinsics.
//!
//! By default, it performs runtime detection of CPU intrinsics and uses them
//! if they are available.
//!
//! ## "soft" portable backend
//! As a baseline implementation, this crate provides a constant-time pure Rust
//! implementation based on [fixslicing], a more advanced form of bitslicing
//! implemented entirely in terms of bitwise arithmetic with no use of any
//! lookup tables or data-dependent branches.
//!
//! Enabling the `compact` Cargo feature will reduce the code size of this
//! backend at the cost of decreased performance (using a modified form of
//! the fixslicing technique called "semi-fixslicing").
//!
//! ## ARMv8 intrinsics (nightly-only)
//! On `aarch64` targets including `aarch64-apple-darwin` (Apple M1) and Linux
//! targets such as `aarch64-unknown-linux-gnu` and `aarch64-unknown-linux-musl`,
//! support for using AES intrinsics provided by the ARMv8 Cryptography Extensions
//! is available when using the nightly compiler, and can be enabled using the
//! `armv8` crate feature.
//!
//! On Linux and macOS, when the `armv8` feature is enabled support for AES
//! intrinsics is autodetected at runtime. On other platforms the `aes`
//! target feature must be enabled via RUSTFLAGS.
//!
//! ## `x86`/`x86_64` intrinsics (AES-NI)
//! By default this crate uses runtime detection on `i686`/`x86_64` targets
//! in order to determine if AES-NI is available, and if it is not, it will
//! fallback to using a constant-time software implementation.
//!
//! Passing `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3` explicitly at compile-time
//! will override runtime detection and ensure that AES-NI is always used.
//! Programs built in this manner will crash with an illegal instruction on
//! CPUs which do not have AES-NI enabled.
//!
//! Note: runtime detection is not possible on SGX targets. Please use the
//! afforementioned `RUSTFLAGS` to leverage AES-NI on these targets.
//!
//! # Usage example
//! ```
//! use aes::{Aes128, Block};
//! use aes::cipher::{
//!     BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
//!     generic_array::GenericArray,
//! };
//!
//! let key = GenericArray::from_slice(&[0u8; 16]);
//! let mut block = Block::clone_from_slice(&[42u8; 16]);
//!
//! // Initialize cipher
//! let cipher = Aes128::new(&key);
//!
//! let block_copy = block.clone();
//!
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//!
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//!
//! // implementation supports parrallel block processing
//! // number of blocks processed in parallel depends in general
//! // on hardware capabilities
//! let mut blocks = [block; 100];
//! cipher.encrypt_blocks(
//!     &mut blocks,
//!     |chunk| {
//!         // you can process encrypted chunk here, e.g. for MAC
//!     },
//! );
//!
//! for block in blocks.iter_mut() {
//!     cipher.decrypt_block(block);
//!     assert_eq!(block, &block_copy);
//! }
//!
//! cipher.decrypt_blocks(
//!     &mut blocks,
//!     |chunk| {
//!         // you can process decrypted chunk here
//!     },
//! );
//!
//! for block in blocks.iter_mut() {
//!     cipher.encrypt_block(block);
//!     assert_eq!(block, &block_copy);
//! }
//! ```
//!
//! For implementations of block cipher modes of operation see
//! [`block-modes`] crate.
//!
//! [fixslicing]: https://eprint.iacr.org/2020/1123.pdf
//! [AES-NI]: https://en.wikipedia.org/wiki/AES_instruction_set
//! [`block-modes`]: https://docs.rs/block-modes

#![no_std]
#![cfg_attr(
    all(feature = "armv8", target_arch = "aarch64"),
    feature(stdsimd, aarch64_target_feature)
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "hazmat")]
pub mod hazmat;

mod soft;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", feature = "armv8", not(feature = "force-soft")))] {
        mod armv8;
        mod autodetect;
        pub use autodetect::{Aes128, Aes192, Aes256};
    } else if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(feature = "force-soft")
    ))] {
        mod autodetect;
        mod ni;
        pub use autodetect::{Aes128, Aes192, Aes256};
    } else {
        pub use soft::{Aes128, Aes192, Aes256};
    }
}

use cipher::generic_array::{
    typenum::{U16, U8},
    GenericArray,
};
pub use cipher::{self, BlockCipher, BlockDecrypt, BlockEncrypt, Key, KeyInit};

/// Size of an AES block (128-bits; 16-bytes)
pub const BLOCK_SIZE: usize = 16;

/// 128-bit AES block
pub type Block = GenericArray<u8, U16>;
/// Eight 128-bit AES blocks
pub type Block8 = GenericArray<Block, U8>;
