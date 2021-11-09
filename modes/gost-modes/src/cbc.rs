//! Cipher Block Chaining (CBC) mode.
use crate::utils::xor;
use cipher::{
    crypto_common::InnerUser,
    generic_array::{
        typenum::{
            type_operators::{IsGreater, IsLessOrEqual},
            Prod, Unsigned, U0, U1, U255,
        },
        ArrayLength, GenericArray,
    },
    inout::InOut,
    Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv,
    IvSizeUser,
};
use core::ops::Mul;

/// Cipher Block Chaining (CBC) mode encryptor as defined in GOST R 34.13-2015
///
/// Type parameters:
/// - `C`: block cipher.
/// - `Z`: nonce length in blocks. Default: 1.
///
/// With `Z = 1` this mode is fully equivalent to the encryptor defined
/// in the [`cbc`] crate.
///
/// [`cbc`]: https://docs.rs/cbc/
#[derive(Clone)]
pub struct CbcEncrypt<C, Z = U1>
where
    C: BlockCipher + BlockEncryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    cipher: C,
    state: GenericArray<Block<C>, Z>,
    pos: u8,
}

impl<C, Z> InnerUser for CbcEncrypt<C, Z>
where
    C: BlockCipher + BlockEncryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    type Inner = C;
}

impl<C, Z> IvSizeUser for CbcEncrypt<C, Z>
where
    C: BlockCipher + BlockEncryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    type IvSize = Prod<Z, C::BlockSize>;
}

impl<C, Z> BlockSizeUser for CbcEncrypt<C, Z>
where
    C: BlockCipher + BlockEncryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    type BlockSize = C::BlockSize;
}

impl<C, Z> InnerIvInit for CbcEncrypt<C, Z>
where
    C: BlockCipher + BlockEncryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let bs = C::BlockSize::USIZE;
        let mut state = GenericArray::<Block<C>, Z>::default();
        for (block, chunk) in state.iter_mut().zip(iv.chunks_exact(bs)) {
            *block = GenericArray::clone_from_slice(chunk);
        }
        Self {
            cipher,
            state,
            pos: 0,
        }
    }
}

impl<C, Z> BlockEncryptMut for CbcEncrypt<C, Z>
where
    C: BlockCipher + BlockEncryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        let sb = &mut self.state[self.pos as usize];
        let mut b = block.get_in().clone();
        xor(&mut b, sb);
        self.cipher.encrypt_block_mut(&mut b);
        *sb = b.clone();
        *block.get_out() = b;
        self.pos += 1;
        self.pos %= Z::U8;
    }
}

/// Cipher Block Chaining (CBC) mode decryptor as defined in GOST R 34.13-2015.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `Z`: nonce length in blocks. Default: 1.
///
/// With `Z = 1` this mode is fully equivalent to the decryptor defined
/// in the [`cbc`] crate.
///
/// [`cbc`]: https://docs.rs/cbc/
#[derive(Clone)]
pub struct CbcDecrypt<C, Z = U1>
where
    C: BlockCipher + BlockDecryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    cipher: C,
    state: GenericArray<Block<C>, Z>,
    pos: u8,
}

impl<C, Z> InnerUser for CbcDecrypt<C, Z>
where
    C: BlockCipher + BlockDecryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    type Inner = C;
}

impl<C, Z> IvSizeUser for CbcDecrypt<C, Z>
where
    C: BlockCipher + BlockDecryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    type IvSize = Prod<Z, C::BlockSize>;
}

impl<C, Z> BlockSizeUser for CbcDecrypt<C, Z>
where
    C: BlockCipher + BlockDecryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    type BlockSize = C::BlockSize;
}

impl<C, Z> InnerIvInit for CbcDecrypt<C, Z>
where
    C: BlockCipher + BlockDecryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let bs = C::BlockSize::USIZE;
        let mut state = GenericArray::<Block<C>, Z>::default();
        for (block, chunk) in state.iter_mut().zip(iv.chunks_exact(bs)) {
            *block = GenericArray::clone_from_slice(chunk);
        }
        Self {
            cipher,
            state,
            pos: 0,
        }
    }
}

impl<C, Z> BlockDecryptMut for CbcDecrypt<C, Z>
where
    C: BlockCipher + BlockDecryptMut,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        let pos = self.pos as usize;
        let b = self.state[pos].clone();
        let mut b2 = block.get_in().clone();
        self.state[pos] = b2.clone();
        self.cipher.decrypt_block_mut(&mut b2);
        xor(&mut b2, &b);
        *block.get_out() = b2;
        self.pos += 1;
        self.pos %= Z::U8;
    }
}

// TODO: impl IvState
