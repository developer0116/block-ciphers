//! Triple DES (3DES) block cipher.

use crate::des::{gen_keys, Des};
use cipher::{
    consts::{U16, U24, U8},
    inout::InOut,
    Block, BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, Key, KeyInit, KeySizeUser,
};
use core::{convert::TryInto, fmt};

/// Triple DES (3DES) block cipher.
#[derive(Copy, Clone)]
pub struct TdesEde3 {
    d1: Des,
    d2: Des,
    d3: Des,
}

impl KeySizeUser for TdesEde3 {
    type KeySize = U24;
}

impl BlockSizeUser for TdesEde3 {
    type BlockSize = U8;
}

impl KeyInit for TdesEde3 {
    fn new(key: &Key<Self>) -> Self {
        let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let k3 = u64::from_be_bytes(key[16..24].try_into().unwrap());
        let d1 = Des { keys: gen_keys(k1) };
        let d2 = Des { keys: gen_keys(k2) };
        let d3 = Des { keys: gen_keys(k3) };
        Self { d1, d2, d3 }
    }
}

impl BlockCipher for TdesEde3 {}

impl BlockEncrypt for TdesEde3 {
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.get_in().clone().into());

        data = self.d1.encrypt(data);
        data = self.d2.decrypt(data);
        data = self.d3.encrypt(data);

        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl BlockDecrypt for TdesEde3 {
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.get_in().clone().into());

        data = self.d3.decrypt(data);
        data = self.d2.encrypt(data);
        data = self.d1.decrypt(data);

        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl fmt::Debug for TdesEde3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEee3 { ... }")
    }
}

/// Triple DES (3DES) block cipher.
#[derive(Copy, Clone)]
pub struct TdesEee3 {
    d1: Des,
    d2: Des,
    d3: Des,
}

impl KeySizeUser for TdesEee3 {
    type KeySize = U24;
}

impl KeyInit for TdesEee3 {
    fn new(key: &Key<Self>) -> Self {
        let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let k3 = u64::from_be_bytes(key[16..24].try_into().unwrap());
        let d1 = Des { keys: gen_keys(k1) };
        let d2 = Des { keys: gen_keys(k2) };
        let d3 = Des { keys: gen_keys(k3) };
        Self { d1, d2, d3 }
    }
}

impl BlockSizeUser for TdesEee3 {
    type BlockSize = U8;
}

impl BlockCipher for TdesEee3 {}

impl BlockEncrypt for TdesEee3 {
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.get_in().clone().into());

        data = self.d1.encrypt(data);
        data = self.d2.encrypt(data);
        data = self.d3.encrypt(data);

        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl BlockDecrypt for TdesEee3 {
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.get_in().clone().into());

        data = self.d3.decrypt(data);
        data = self.d2.decrypt(data);
        data = self.d1.decrypt(data);

        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl fmt::Debug for TdesEee3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEee3 { ... }")
    }
}

/// Triple DES (3DES) block cipher.
#[derive(Copy, Clone)]
pub struct TdesEde2 {
    d1: Des,
    d2: Des,
}

impl KeySizeUser for TdesEde2 {
    type KeySize = U16;
}

impl KeyInit for TdesEde2 {
    fn new(key: &Key<Self>) -> Self {
        let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let d1 = Des { keys: gen_keys(k1) };
        let d2 = Des { keys: gen_keys(k2) };
        Self { d1, d2 }
    }
}

impl BlockSizeUser for TdesEde2 {
    type BlockSize = U8;
}

impl BlockCipher for TdesEde2 {}

impl BlockEncrypt for TdesEde2 {
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.get_in().clone().into());

        data = self.d1.encrypt(data);
        data = self.d2.decrypt(data);
        data = self.d1.encrypt(data);

        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl BlockDecrypt for TdesEde2 {
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.get_in().clone().into());

        data = self.d1.decrypt(data);
        data = self.d2.encrypt(data);
        data = self.d1.decrypt(data);

        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl fmt::Debug for TdesEde2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEde2 { ... }")
    }
}

/// Triple DES (3DES) block cipher.
#[derive(Copy, Clone)]
pub struct TdesEee2 {
    d1: Des,
    d2: Des,
}

impl KeySizeUser for TdesEee2 {
    type KeySize = U16;
}

impl KeyInit for TdesEee2 {
    fn new(key: &Key<Self>) -> Self {
        let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let d1 = Des { keys: gen_keys(k1) };
        let d2 = Des { keys: gen_keys(k2) };
        Self { d1, d2 }
    }
}

impl BlockSizeUser for TdesEee2 {
    type BlockSize = U8;
}

impl BlockCipher for TdesEee2 {}

impl BlockEncrypt for TdesEee2 {
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.get_in().clone().into());

        data = self.d1.encrypt(data);
        data = self.d2.encrypt(data);
        data = self.d1.encrypt(data);

        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl BlockDecrypt for TdesEee2 {
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.get_in().clone().into());

        data = self.d1.decrypt(data);
        data = self.d2.decrypt(data);
        data = self.d1.decrypt(data);

        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl fmt::Debug for TdesEee2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEee2 { ... }")
    }
}
