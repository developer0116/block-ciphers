//! Cipher feedback (CFB) mode.

use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{
        typenum::{
            marker_traits::NonZero,
            operator_aliases::{Gr, GrEq, LeEq},
            type_operators::{IsGreater, IsGreaterOrEqual, IsLessOrEqual},
            Unsigned, U0,
        },
        ArrayLength, GenericArray,
    },
    inout::InOut,
    AsyncStreamCipher, Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser,
    InnerIvInit, Iv, IvState,
};
use core::marker::PhantomData;

type BlockSize<C> = <C as BlockSizeUser>::BlockSize;

/// Cipher feedback (CFB) mode of operation as defined in GOST R 34.13-2015.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `M`: nonce length in bytes. Default: block size.
/// - `S`: number of block bytes used for message encryption. Default: block size.
///
/// With default parameters this mode is fully equivalent to the mode defined
/// in the [`cfb-mode`] crate.
///
/// [`cfb-mode`]: https://docs.rs/cfb-mode/
#[derive(Clone)]
pub struct Cfb<C, M = BlockSize<C>, S = BlockSize<C>>
where
    C: BlockCipher + BlockEncryptMut,
    M: ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    GrEq<M, C::BlockSize>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    cipher: C,
    iv: GenericArray<u8, M>,
    pd: PhantomData<S>,
}

impl<C, M, S> BlockSizeUser for Cfb<C, M, S>
where
    C: BlockCipher + BlockEncryptMut,
    M: ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    GrEq<M, C::BlockSize>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    type BlockSize = S;
}

impl<C, M, S> AsyncStreamCipher for Cfb<C, M, S>
where
    C: BlockCipher + BlockEncryptMut,
    M: ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    GrEq<M, C::BlockSize>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
}

impl<C, M, S> InnerUser for Cfb<C, M, S>
where
    C: BlockCipher + BlockEncryptMut,
    M: ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    GrEq<M, C::BlockSize>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    type Inner = C;
}

impl<C, M, S> IvSizeUser for Cfb<C, M, S>
where
    C: BlockCipher + BlockEncryptMut,
    M: ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    GrEq<M, C::BlockSize>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    type IvSize = M;
}

impl<C, M, S> InnerIvInit for Cfb<C, M, S>
where
    C: BlockCipher + BlockEncryptMut,
    M: ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    GrEq<M, C::BlockSize>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            pd: PhantomData,
        }
    }
}

impl<C, M, S> BlockEncryptMut for Cfb<C, M, S>
where
    C: BlockCipher + BlockEncryptMut,
    M: ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    GrEq<M, C::BlockSize>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    #[inline]
    fn encrypt_block_inout_mut(&mut self, mut block: InOut<'_, Block<Self>>) {
        let bs = C::BlockSize::USIZE;
        let mut b = Block::<C>::clone_from_slice(&self.iv[..bs]);
        self.cipher.encrypt_block_mut(&mut b);
        block.xor(&b[..S::USIZE]);
        let mut new_iv = GenericArray::<u8, M>::default();
        let n = M::USIZE - S::USIZE;
        new_iv[..n].copy_from_slice(&self.iv[S::USIZE..]);
        new_iv[n..].copy_from_slice(block.get_out());
        self.iv = new_iv;
    }
}

impl<C, M, S> BlockDecryptMut for Cfb<C, M, S>
where
    C: BlockCipher + BlockEncryptMut,
    M: ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    GrEq<M, C::BlockSize>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    #[inline]
    fn decrypt_block_inout_mut(&mut self, mut block: InOut<'_, Block<Self>>) {
        let bs = C::BlockSize::USIZE;
        let mut b = Block::<C>::clone_from_slice(&self.iv[..bs]);
        self.cipher.encrypt_block_mut(&mut b);
        let mut new_iv = GenericArray::<u8, M>::default();
        let n = M::USIZE - S::USIZE;
        new_iv[..n].copy_from_slice(&self.iv[S::USIZE..]);
        new_iv[n..].copy_from_slice(block.get_in());
        self.iv = new_iv;
        block.xor(&b[..S::USIZE]);
    }
}

impl<C, M, S> IvState for Cfb<C, M, S>
where
    C: BlockCipher + BlockEncryptMut,
    M: ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    GrEq<M, C::BlockSize>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}
