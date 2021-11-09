//! This crate contains generic implementation of [block cipher modes of
//! operation][1] defined in [GOST R 34.13-2015].
//!
//! CTR, CFB and OFB modes are implemented in terms of traits from the [`cipher`] crate.
//!
//! MAC function defined in the GOST is implemented in the [`cmac`] crate.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
//! [GOST R 34.13-2015]: https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf
//! [`cipher`]: https://docs.rs/cipher/
//! [`cmac`]: https://docs.rs/cmac/
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher::{self, consts, generic_array};

mod cbc;
mod cfb;
mod ctr128;
mod ctr64;
mod ofb;
mod utils;

/// Block padding procedure number 2 as defined in GOST R 34.13-2015
///
/// Fully equivalent to ISO 7816.
pub type Padding = cipher::block_buffer::block_padding::Iso7816;

pub use cbc::{CbcDecrypt, CbcEncrypt};
pub use cfb::Cfb;
pub use ctr128::{Ctr128, Ctr128Core};
pub use ctr64::{Ctr64, Ctr64Core};
pub use ofb::{Ofb, OfbCore};
