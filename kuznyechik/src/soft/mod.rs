pub use cipher;

use crate::consts::{P, P_INV};
use crate::{Block, Key};
use cipher::{inout::InOut, BlockDecrypt, BlockEncrypt, KeyInit};

mod consts;

/// Kuznyechik (GOST R 34.12-2015) block cipher
#[derive(Clone, Copy)]
pub struct Kuznyechik {
    keys: [Block; 10],
}

#[inline(always)]
fn x(a: &mut Block, b: &Block) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn l_step(msg: &mut Block, i: usize) {
    #[inline(always)]
    fn get_idx(b: usize, i: usize) -> usize {
        b.wrapping_sub(i) & 0x0F
    }
    #[inline(always)]
    fn get_m(msg: &Block, b: usize, i: usize) -> usize {
        msg[get_idx(b, i)] as usize
    }

    let mut x = msg[get_idx(15, i)];
    x ^= consts::GF[3][get_m(msg, 14, i)];
    x ^= consts::GF[1][get_m(msg, 13, i)];
    x ^= consts::GF[2][get_m(msg, 12, i)];
    x ^= consts::GF[0][get_m(msg, 11, i)];
    x ^= consts::GF[5][get_m(msg, 10, i)];
    x ^= consts::GF[4][get_m(msg, 9, i)];
    x ^= msg[get_idx(8, i)];
    x ^= consts::GF[6][get_m(msg, 7, i)];
    x ^= msg[get_idx(6, i)];
    x ^= consts::GF[4][get_m(msg, 5, i)];
    x ^= consts::GF[5][get_m(msg, 4, i)];
    x ^= consts::GF[0][get_m(msg, 3, i)];
    x ^= consts::GF[2][get_m(msg, 2, i)];
    x ^= consts::GF[1][get_m(msg, 1, i)];
    x ^= consts::GF[3][get_m(msg, 0, i)];
    msg[get_idx(15, i)] = x;
}

#[inline(always)]
fn lsx(block: &mut Block, key: &Block) {
    x(block, key);
    // s
    unroll16! {i, { block[i] = P[block[i] as usize]; }};
    // l
    unroll16! {i, { l_step(block, i) }};
}

#[inline(always)]
fn lsx_inv(block: &mut Block, key: &Block) {
    x(block, key);
    // l_inv
    unroll16! {i, { l_step(block, 15 - i) }};
    // s_inv
    unroll16! {i, { block[15 - i] = P_INV[block[15 - i] as usize]; }};
}

fn get_c(n: usize) -> Block {
    let mut v = Block::default();
    v[15] = n as u8;
    for i in 0..16 {
        l_step(&mut v, i);
    }
    v
}

fn f(k1: &mut Block, k2: &mut Block, n: usize) {
    for i in 0..4 {
        let mut k1_cpy = *k1;
        lsx(&mut k1_cpy, &get_c(8 * n + 2 * i + 1));
        x(k2, &k1_cpy);

        let mut k2_cpy = *k2;
        lsx(&mut k2_cpy, &get_c(8 * n + 2 * i + 2));
        x(k1, &k2_cpy);
    }
}

impl KeyInit for Kuznyechik {
    fn new(key: &Key) -> Self {
        let mut keys = [Block::default(); 10];

        let mut k1 = Block::default();
        let mut k2 = Block::default();

        k1.copy_from_slice(&key[..16]);
        k2.copy_from_slice(&key[16..]);

        keys[0] = k1;
        keys[1] = k2;

        for i in 1..5 {
            f(&mut k1, &mut k2, i - 1);
            keys[2 * i] = k1;
            keys[2 * i + 1] = k2;
        }

        Self { keys }
    }
}

impl BlockEncrypt for Kuznyechik {
    #[inline]
    fn encrypt_block_inout(&self, block: InOut<'_, Block>) {
        let mut b = block.get_in().clone();
        unroll9! {
            i, { lsx(&mut b, &self.keys[i]) ; }
        }
        x(&mut b, &self.keys[9]);
        *block.get_out() = b;
    }
}

impl BlockDecrypt for Kuznyechik {
    #[inline]
    fn decrypt_block_inout(&self, block: InOut<'_, Block>) {
        let mut b = block.get_in().clone();
        unroll9! {
            i, { lsx_inv(&mut b, &self.keys[9 - i]) ; }
        }
        x(&mut b, &self.keys[0]);
        *block.get_out() = b;
    }
}
