//! [Output feedback][1] (OFB) mode.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{ArrayLength, GenericArray},
    inout::{InOut, InOutBuf},
    Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv, IvState,
    StreamCipherCore,
};
use core::slice::from_ref;

/// Output feedback (OFB) mode.
#[derive(Clone)]
pub struct Ofb<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> StreamCipherCore for Ofb<C> {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn apply_keystream_blocks(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        mut pre_fn: impl FnMut(&[Block<Self>]),
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) {
        for mut block in blocks {
            pre_fn(from_ref(block.get_in()));
            self.cipher.encrypt_block_mut(&mut self.iv);
            xor_set(&self.iv, block.reborrow());
            post_fn(from_ref(block.get_out()));
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockSizeUser for Ofb<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> InnerUser for Ofb<C> {
    type Inner = C;
}

impl<C: BlockEncryptMut + BlockCipher> IvSizeUser for Ofb<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for Ofb<C> {
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> IvState for Ofb<C> {
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockEncryptMut for Ofb<C> {
    #[inline]
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.cipher.encrypt_block_mut(&mut self.iv);
        xor_set(&self.iv, block);
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockDecryptMut for Ofb<C> {
    #[inline]
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.cipher.encrypt_block_mut(&mut self.iv);
        xor_set(&self.iv, block);
    }
}

#[inline(always)]
fn xor_set<N: ArrayLength<u8>>(a: &GenericArray<u8, N>, b: InOut<'_, GenericArray<u8, N>>) {
    let input = b.get_in().clone();
    let output = b.get_out();
    for i in 0..N::USIZE {
        output[i] = a[i] ^ input[i];
    }
}
