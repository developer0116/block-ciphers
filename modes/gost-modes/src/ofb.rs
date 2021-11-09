use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{
        typenum::{
            marker_traits::NonZero,
            operator_aliases::{Gr, LeEq, Prod},
            type_operators::{IsGreater, IsLessOrEqual},
            Unsigned, U0, U1,
        },
        ArrayLength, GenericArray,
    },
    inout::{InOut, InOutBuf},
    Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv, IvState,
    StreamCipherCore, StreamCipherCoreWrapper,
};
use core::{marker::PhantomData, ops::Mul, slice::from_ref};

/// Wrapped OFB which handles block buffering and provides slice-based methods.
pub type Ofb<C, Z = U1, S = <C as BlockSizeUser>::BlockSize> =
    StreamCipherCoreWrapper<OfbCore<C, Z, S>>;

/// Output feedback (OFB) mode of operation as defined in GOST R 34.13-2015.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `Z`: nonce length in block sizes. Default: 1.
/// - `S`: number of block bytes used for message encryption. Default: block size.
///
/// With the default parameters this mode is fully equivalent to the mode defined
/// in the [`ofb`] crate.
///
/// [`ofb`]: https://docs.rs/ofb/
#[derive(Clone)]
pub struct OfbCore<C, Z = U1, S = <C as BlockSizeUser>::BlockSize>
where
    C: BlockCipher + BlockEncryptMut,
    Z: ArrayLength<Block<C>> + IsGreater<U0> + Mul<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    Gr<Z, U0>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    cipher: C,
    state: GenericArray<Block<C>, Z>,
    pos: usize,
    _pd: PhantomData<S>,
}

impl<C, Z, S> BlockSizeUser for OfbCore<C, Z, S>
where
    C: BlockCipher + BlockEncryptMut,
    Z: ArrayLength<Block<C>> + IsGreater<U0> + Mul<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    Gr<Z, U0>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    type BlockSize = S;
}

impl<C, Z, S> InnerUser for OfbCore<C, Z, S>
where
    C: BlockCipher + BlockEncryptMut,
    Z: ArrayLength<Block<C>> + IsGreater<U0> + Mul<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    Gr<Z, U0>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    type Inner = C;
}

impl<C, Z, S> IvSizeUser for OfbCore<C, Z, S>
where
    C: BlockCipher + BlockEncryptMut,
    Z: ArrayLength<Block<C>> + IsGreater<U0> + Mul<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    Gr<Z, U0>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    type IvSize = Prod<Z, C::BlockSize>;
}

impl<C, Z, S> InnerIvInit for OfbCore<C, Z, S>
where
    C: BlockCipher + BlockEncryptMut,
    Z: ArrayLength<Block<C>> + IsGreater<U0> + Mul<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    Gr<Z, U0>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let bs = C::BlockSize::USIZE;
        let mut state: GenericArray<Block<C>, Z> = Default::default();
        for (chunk, block) in iv.chunks_exact(bs).zip(state.iter_mut()) {
            block.copy_from_slice(chunk);
        }

        Self {
            cipher,
            state,
            pos: 0,
            _pd: PhantomData,
        }
    }
}

impl<C, Z, S> StreamCipherCore for OfbCore<C, Z, S>
where
    C: BlockCipher + BlockEncryptMut,
    Z: ArrayLength<Block<C>> + IsGreater<U0> + Mul<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    Gr<Z, U0>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
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
            let state_block = &mut self.state[self.pos];
            self.cipher.encrypt_block_mut(state_block);
            self.pos = self.pos.wrapping_add(1) % Z::USIZE;
            block.xor(&state_block[..S::USIZE]);
            post_fn(from_ref(block.get_out()));
        }
    }
}

impl<C, Z, S> IvState for OfbCore<C, Z, S>
where
    C: BlockCipher + BlockEncryptMut,
    Z: ArrayLength<Block<C>> + IsGreater<U0> + Mul<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    Gr<Z, U0>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        let bs = C::BlockSize::USIZE;
        let mut iv = Iv::<Self>::default();

        for i in 0..Z::USIZE {
            let n = self.pos.wrapping_add(i) % Z::USIZE;
            iv[bs * i..][..bs].copy_from_slice(&self.state[n]);
        }
        iv
    }
}

impl<C, Z, S> BlockEncryptMut for OfbCore<C, Z, S>
where
    C: BlockCipher + BlockEncryptMut,
    Z: ArrayLength<Block<C>> + IsGreater<U0> + Mul<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    Gr<Z, U0>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    #[inline]
    fn encrypt_block_inout_mut(&mut self, mut block: InOut<'_, Block<Self>>) {
        let state_block = &mut self.state[self.pos];
        self.cipher.encrypt_block_mut(state_block);
        self.pos = self.pos.wrapping_add(1) % Z::USIZE;
        block.xor(&state_block[..S::USIZE]);
    }
}

impl<C, Z, S> BlockDecryptMut for OfbCore<C, Z, S>
where
    C: BlockCipher + BlockEncryptMut,
    Z: ArrayLength<Block<C>> + IsGreater<U0> + Mul<C::BlockSize>,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    Gr<Z, U0>: NonZero,
    Gr<S, U0>: NonZero,
    LeEq<S, C::BlockSize>: NonZero,
{
    #[inline]
    fn decrypt_block_inout_mut(&mut self, mut block: InOut<'_, Block<Self>>) {
        let state_block = &mut self.state[self.pos];
        self.cipher.encrypt_block_mut(state_block);
        self.pos = self.pos.wrapping_add(1) % Z::USIZE;
        block.xor(&state_block[..S::USIZE]);
    }
}
