//! AES block ciphers implementation using AES-NI instruction set.
//!
//! Ciphers functionality is accessed using `BlockCipher` trait from the
//! [`cipher`](https://docs.rs/cipher) crate.
//!
//! # Vulnerability
//! Lazy FP state restory vulnerability can allow local process to leak content
//! of the FPU register, in which round keys are stored. This vulnerability
//! can be mitigated at the operating system level by installing relevant
//! patches. (i.e. keep your OS updated!) More info:
//! - [Intel advisory](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00145.html)
//! - [Wikipedia](https://en.wikipedia.org/wiki/Lazy_FP_state_restore)
//!
//! # Related documents
//! - [Intel AES-NI whitepaper](https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf)
//! - [Use of the AES Instruction Set](https://www.cosic.esat.kuleuven.be/ecrypt/AESday/slides/Use_of_the_AES_Instruction_Set.pdf)

#[macro_use]
mod utils;

mod aes128;
mod aes192;
mod aes256;

#[cfg(test)]
mod test_expand;

#[cfg(feature = "hazmat")]
pub(crate) mod hazmat;

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use crate::Block;
use cipher::{
    consts::{U16, U24, U32, U8},
    generic_array::{typenum::Unsigned, GenericArray},
    inout::{InOut, InOutBuf, InSrc, InTmpOutBuf},
    BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
};
use core::fmt;

macro_rules! define_aes_impl {
    (
        $name: tt,
        $module: tt,
        $key_size: ty,
        $doc: expr$(,)?
    ) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $name {
            encrypt_keys: $module::RoundKeys,
            decrypt_keys: $module::RoundKeys,
        }

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            #[inline]
            fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
                // SAFETY: GenericArray<u8; KeySize> and [u8; KeySize::USIZE]
                // are equivalent to each other. we enforce that this code
                // is called only when target features required by `expand`
                // were properly checked.
                let (encrypt_keys, decrypt_keys) = unsafe {
                    let key = &*(key as *const _ as *const [u8; <$key_size>::USIZE]);
                    $module::expand(key)
                };

                Self {
                    encrypt_keys,
                    decrypt_keys,
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
                // SAFETY: we enforce that this code is called only when
                // required target features were properly checked.
                unsafe {
                    $module::encrypt1(&self.encrypt_keys, block);
                }
            }

            #[inline]
            fn encrypt_blocks_with_pre(
                &self,
                blocks: InOutBuf<'_, Block>,
                pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
            ) {
                #[target_feature(enable = "aes")]
                unsafe fn inner(
                    keys: &$module::RoundKeys,
                    blocks: InOutBuf<'_, Block>,
                    pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                    post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
                ) {
                    blocks.process_chunks::<U8, _, _, _, _, _>(
                        &keys,
                        pre_fn,
                        post_fn,
                        |keys, chunk| $module::encrypt8(keys, chunk),
                        |keys, chunk| {
                            for block in chunk {
                                $module::encrypt1(keys, block);
                            }
                        },
                    )
                }

                // SAFETY: we enforce that this code is called only when
                // required target features were properly checked.
                unsafe {
                    inner(&self.encrypt_keys, blocks, pre_fn, post_fn);
                }
            }
        }

        impl BlockDecrypt for $name {
            #[inline]
            fn decrypt_block_inout(&self, block: InOut<'_, Block>) {
                // SAFETY: we enforce that this code is called only when
                // required target features were properly checked.
                unsafe {
                    $module::decrypt1(&self.decrypt_keys, block);
                }
            }

            #[inline]
            fn decrypt_blocks_with_pre(
                &self,
                blocks: InOutBuf<'_, Block>,
                pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
            ) {
                #[target_feature(enable = "aes")]
                unsafe fn inner(
                    keys: &$module::RoundKeys,
                    blocks: InOutBuf<'_, Block>,
                    pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                    post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
                ) {
                    blocks.process_chunks::<U8, _, _, _, _, _>(
                        &keys,
                        pre_fn,
                        post_fn,
                        |keys, chunk| $module::decrypt8(keys, chunk),
                        |keys, chunk| {
                            for block in chunk {
                                $module::decrypt1(keys, block);
                            }
                        },
                    )
                }

                // SAFETY: we enforce that this code is called only when
                // required target features were properly checked.
                unsafe {
                    inner(&self.decrypt_keys, blocks, pre_fn, post_fn);
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

define_aes_impl!(Aes128, aes128, U16, "AES-128 block cipher instance");

define_aes_impl!(Aes192, aes192, U24, "AES-192 block cipher instance");

define_aes_impl!(Aes256, aes256, U32, "AES-256 block cipher instance");
