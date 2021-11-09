use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{
        typenum::{
            marker_traits::NonZero,
            operator_aliases::{Gr, LeEq},
            type_operators::{IsGreater, IsLessOrEqual},
            U0, U16, U8,
        },
        ArrayLength,
    },
    inout::{InOut, InOutBuf},
    Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv,
    StreamCipherCore, StreamCipherCoreWrapper, StreamCipherSeekCore,
};
use core::{convert::TryInto, marker::PhantomData, slice::from_ref};

/// Wrapped CTR which handles block buffering and provides slice-based methods.
pub type Ctr128<C, S = <C as BlockSizeUser>::BlockSize> = StreamCipherCoreWrapper<Ctr128Core<C, S>>;

/// Counter (CTR) mode of operation for 128-bit block ciphers as defined in
/// GOST R 34.13-2015.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `S`: number of block bytes used for message encryption. Default: block size.
#[derive(Clone)]
pub struct Ctr128Core<C, S = <C as BlockSizeUser>::BlockSize>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    cipher: C,
    nonce: u64,
    ctr: u64,
    _pd: PhantomData<S>,
}

impl<C, S> Ctr128Core<C, S>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    fn xor_block(&mut self, mut block: InOut<'_, Block<Self>>) {
        let mut b = Block::<C>::default();
        b[..8].copy_from_slice(&self.nonce.to_be_bytes());
        b[8..].copy_from_slice(&self.ctr.to_be_bytes());
        self.cipher.encrypt_block_mut(&mut b);
        self.ctr = self.ctr.wrapping_add(1);
        block.xor(&b[..S::USIZE]);
    }
}

impl<C, S> BlockSizeUser for Ctr128Core<C, S>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    type BlockSize = S;
}

impl<C, S> InnerUser for Ctr128Core<C, S>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    type Inner = C;
}

impl<C, S> IvSizeUser for Ctr128Core<C, S>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    type IvSize = U8;
}

impl<C, S> InnerIvInit for Ctr128Core<C, S>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            nonce: u64::from_be_bytes((*iv).into()),
            ctr: 0,
            _pd: PhantomData,
        }
    }
}

impl<C, S> StreamCipherCore for Ctr128Core<C, S>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    fn remaining_blocks(&self) -> Option<usize> {
        (u64::MAX - self.ctr).try_into().ok()
    }

    fn apply_keystream_blocks(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        mut pre_fn: impl FnMut(&[Block<Self>]),
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) {
        for mut block in blocks {
            pre_fn(from_ref(block.get_in()));
            self.xor_block(block.reborrow());
            post_fn(from_ref(block.get_out()));
        }
    }
}

impl<C, S> BlockEncryptMut for Ctr128Core<C, S>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    #[inline]
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.xor_block(block);
    }
}

impl<C, S> BlockDecryptMut for Ctr128Core<C, S>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    #[inline]
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.xor_block(block);
    }
}

impl<C, S> StreamCipherSeekCore for Ctr128Core<C, S>
where
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut,
    S: ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<U16>,
    Gr<S, U0>: NonZero,
    LeEq<S, U16>: NonZero,
{
    type Counter = u64;

    fn get_block_pos(&self) -> Self::Counter {
        self.ctr
    }

    fn set_block_pos(&mut self, pos: Self::Counter) {
        self.ctr = pos;
    }
}
