//! AES block cipher constant-time implementation.
//!
//! The implementation uses a technique called [fixslicing][1], an improved
//! form of bitslicing which represents ciphers in a way which enables
//! very efficient constant-time implementations in software.
//!
//! [1]: https://eprint.iacr.org/2020/1123.pdf

#![deny(unsafe_code)]

#[cfg_attr(not(target_pointer_width = "64"), path = "soft/fixslice32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "soft/fixslice64.rs")]
pub(crate) mod fixslice;

use crate::Block;
use cipher::{
    consts::{U16, U24, U32},
    generic_array::GenericArray,
    inout::{InOut, InOutBuf, InSrc, InTmpOutBuf},
    BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
};
use core::fmt;
use fixslice::{BatchBlocks, FixsliceBlocks, FixsliceKeys128, FixsliceKeys192, FixsliceKeys256};

macro_rules! define_aes_impl {
    (
        $name:ident,
        $key_size:ty,
        $fixslice_keys:ty,
        $fixslice_key_schedule:path,
        $fixslice_decrypt:path,
        $fixslice_encrypt:path,
        $doc:expr
    ) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $name {
            keys: $fixslice_keys,
        }

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                Self {
                    keys: $fixslice_key_schedule(key),
                }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }

        impl BlockCipher for $name {}

        impl BlockEncrypt for $name {
            #[inline]
            fn encrypt_block_inout(&self, block: InOut<'_, Block>) {
                let mut blocks = BatchBlocks::default();
                blocks[0] = *block.get_in();
                *(block.get_out()) = $fixslice_encrypt(&self.keys, &blocks)[0];
            }

            fn encrypt_blocks_with_pre(
                &self,
                blocks: InOutBuf<'_, Block>,
                pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
            ) {
                blocks.process_chunks::<FixsliceBlocks, _, _, _, _, _>(
                    &self.keys,
                    pre_fn,
                    post_fn,
                    |keys, chunk| *chunk.get_out() = $fixslice_encrypt(keys, chunk.get_in()),
                    |keys, chunk| {
                        let n = chunk.len();
                        let mut blocks = BatchBlocks::default();
                        blocks[..n].copy_from_slice(chunk.get_in());
                        let res = $fixslice_encrypt(keys, &blocks);
                        chunk.get_out().copy_from_slice(&res[..n]);
                    },
                )
            }
        }

        impl BlockDecrypt for $name {
            #[inline]
            fn decrypt_block_inout(&self, block: InOut<'_, Block>) {
                let mut blocks = BatchBlocks::default();
                blocks[0] = *block.get_in();
                *(block.get_out()) = $fixslice_decrypt(&self.keys, &blocks)[0];
            }

            #[inline]
            fn decrypt_blocks_with_pre(
                &self,
                blocks: InOutBuf<'_, Block>,
                pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
            ) {
                blocks.process_chunks::<FixsliceBlocks, _, _, _, _, _>(
                    &self.keys,
                    pre_fn,
                    post_fn,
                    |keys, chunk| *chunk.get_out() = $fixslice_decrypt(keys, chunk.get_in()),
                    |keys, chunk| {
                        let n = chunk.len();
                        let mut blocks = BatchBlocks::default();
                        blocks[..n].copy_from_slice(chunk.get_in());
                        let res = $fixslice_decrypt(keys, &blocks);
                        chunk.get_out().copy_from_slice(&res[..n]);
                    },
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

define_aes_impl!(
    Aes128,
    U16,
    FixsliceKeys128,
    fixslice::aes128_key_schedule,
    fixslice::aes128_decrypt,
    fixslice::aes128_encrypt,
    "AES-128 block cipher instance"
);

define_aes_impl!(
    Aes192,
    U24,
    FixsliceKeys192,
    fixslice::aes192_key_schedule,
    fixslice::aes192_decrypt,
    fixslice::aes192_encrypt,
    "AES-192 block cipher instance"
);

define_aes_impl!(
    Aes256,
    U32,
    FixsliceKeys256,
    fixslice::aes256_key_schedule,
    fixslice::aes256_decrypt,
    fixslice::aes256_encrypt,
    "AES-256 block cipher instance"
);
