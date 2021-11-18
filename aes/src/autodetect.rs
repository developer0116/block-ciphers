//! Autodetection support for hardware accelerated AES backends with fallback
//! to the fixsliced "soft" implementation.

use crate::{soft, Block};
use cipher::{
    consts::{U16, U24, U32},
    crypto_common::AlgorithmName,
    generic_array::GenericArray,
    inout::{InOut, InOutBuf, InSrc, InTmpOutBuf},
    BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
};
use core::fmt;
use core::mem::ManuallyDrop;

#[cfg(all(target_arch = "aarch64", feature = "armv8"))]
use crate::armv8 as intrinsics;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use crate::ni as intrinsics;

cpufeatures::new!(aes_intrinsics, "aes");

macro_rules! define_aes_impl {
    (
        $name:tt,
        $module:tt,
        $key_size:ty,
        $doc:expr
    ) => {
        #[doc=$doc]
        pub struct $name {
            inner: $module::Inner,
            token: aes_intrinsics::InitToken,
        }

        mod $module {
            use super::{intrinsics, soft};
            use core::mem::ManuallyDrop;

            pub(super) union Inner {
                pub(super) intrinsics: ManuallyDrop<intrinsics::$name>,
                pub(super) soft: ManuallyDrop<soft::$name>,
            }
        }

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let (token, aesni_present) = aes_intrinsics::init_get();

                let inner = if aesni_present {
                    $module::Inner {
                        intrinsics: ManuallyDrop::new(intrinsics::$name::new(key)),
                    }
                } else {
                    $module::Inner {
                        soft: ManuallyDrop::new(soft::$name::new(key)),
                    }
                };

                Self { inner, token }
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                let inner = if self.token.get() {
                    $module::Inner {
                        intrinsics: unsafe { self.inner.intrinsics.clone() },
                    }
                } else {
                    $module::Inner {
                        soft: unsafe { self.inner.soft.clone() },
                    }
                };

                Self {
                    inner,
                    token: self.token,
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
                if self.token.get() {
                    unsafe { self.inner.intrinsics.encrypt_block_inout(block) }
                } else {
                    unsafe { self.inner.soft.encrypt_block_inout(block) }
                }
            }

            #[inline]
            fn encrypt_blocks_with_pre(
                &self,
                blocks: InOutBuf<'_, Block>,
                pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
            ) {
                if self.token.get() {
                    unsafe {
                        self.inner
                            .intrinsics
                            .encrypt_blocks_with_pre(blocks, pre_fn, post_fn)
                    }
                } else {
                    unsafe {
                        self.inner
                            .soft
                            .encrypt_blocks_with_pre(blocks, pre_fn, post_fn)
                    }
                }
            }
        }

        impl BlockDecrypt for $name {
            #[inline]
            fn decrypt_block_inout(&self, block: InOut<'_, Block>) {
                if self.token.get() {
                    unsafe { self.inner.intrinsics.decrypt_block_inout(block) }
                } else {
                    unsafe { self.inner.soft.decrypt_block_inout(block) }
                }
            }

            #[inline]
            fn decrypt_blocks_with_pre(
                &self,
                blocks: InOutBuf<'_, Block>,
                pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
            ) {
                if self.token.get() {
                    unsafe {
                        self.inner
                            .intrinsics
                            .decrypt_blocks_with_pre(blocks, pre_fn, post_fn)
                    }
                } else {
                    unsafe {
                        self.inner
                            .soft
                            .decrypt_blocks_with_pre(blocks, pre_fn, post_fn)
                    }
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

define_aes_impl!(Aes128, aes128, U16, "AES-128 block cipher instance");
define_aes_impl!(Aes192, aes192, U24, "AES-192 block cipher instance");
define_aes_impl!(Aes256, aes256, U32, "AES-256 block cipher instance");
