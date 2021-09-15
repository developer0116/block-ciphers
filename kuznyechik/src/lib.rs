//! Pure Rust implementation of the [Kuznyechik][1] (GOST R 34.12-2015) block cipher.
//!
//! [1]: https://en.wikipedia.org/wiki/Kuznyechik
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop, clippy::transmute_ptr_to_ptr)]

pub use cipher;
use core::fmt;
use cipher::{
    consts::{U16, U32},
    KeySizeUser, BlockSizeUser, BlockCipher,
};

#[macro_use]
mod macros;
mod consts;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    target_feature = "sse2",
    not(feature = "force-soft"),
))]
#[path = "sse2/mod.rs"]
mod imp;

#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    target_feature = "sse2",
    not(feature = "force-soft"),
)))]
#[path = "soft/mod.rs"]
mod imp;

pub use imp::Kuznyechik;

/// Block over which the Kuznyechik cipher operates.
pub type Block = cipher::Block<Kuznyechik>;
/// The Kuznyechik cipher initialization key.
pub type Key = cipher::Key<Kuznyechik>;

impl KeySizeUser for Kuznyechik {
    type KeySize = U32;
}

impl BlockSizeUser for Kuznyechik {
    type BlockSize = U16;
}

impl BlockCipher for Kuznyechik {}

impl fmt::Debug for Kuznyechik {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Kuznyechik {{ ... }}")
    }
}
