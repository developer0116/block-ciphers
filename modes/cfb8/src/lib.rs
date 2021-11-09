//! [Cipher Feedback with eight bit feedback][1] (CFB-8) mode.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB-1,_CFB-8,_CFB-64,_CFB-128,_etc.

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::typenum::U1,
    inout::InOut,
    AsyncStreamCipher, Block, BlockCipher, BlockDecryptMut, BlockEncryptMut,
    BlockSizeUser, InnerIvInit, Iv, IvState,
};

/// CFB-8 mode encryptor.
///
/// Since it works over one byte blocks, it implements both block-based
/// and slice-based traits.
#[derive(Clone)]
pub struct Cfb8<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> BlockEncryptMut for Cfb8<C> {
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        let mut t = self.iv.clone();
        self.cipher.encrypt_block_mut(&mut t);
        let r = block.get_in()[0] ^ t[0];
        block.get_out()[0] = r;
        let n = self.iv.len();
        for i in 0..n - 1 {
            self.iv[i] = self.iv[i + 1];
        }
        self.iv[n - 1] = r;
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockDecryptMut for Cfb8<C> {
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        let mut t = self.iv.clone();
        self.cipher.encrypt_block_mut(&mut t);
        let r = block.get_in()[0];
        block.get_out()[0] = r ^ t[0];
        let n = self.iv.len();
        for i in 0..n - 1 {
            self.iv[i] = self.iv[i + 1];
        }
        self.iv[n - 1] = r;
    }
}

impl<C: BlockEncryptMut + BlockCipher> AsyncStreamCipher for Cfb8<C> {}

impl<C: BlockEncryptMut + BlockCipher> BlockSizeUser for Cfb8<C> {
    type BlockSize = U1;
}

impl<C: BlockEncryptMut + BlockCipher> InnerUser for Cfb8<C> {
    type Inner = C;
}

impl<C: BlockEncryptMut + BlockCipher> IvSizeUser for Cfb8<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for Cfb8<C> {
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> IvState for Cfb8<C> {
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}
