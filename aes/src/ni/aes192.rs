use core::{mem, ptr};
use super::{arch::*, utils::*};
use crate::{Block, Block8};
use cipher::inout::InOut;

/// AES-192 round keys
pub(super) type RoundKeys = [__m128i; 13];

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt1(keys: &RoundKeys, block: InOut<'_, Block>) {
    let (in_ptr, out_ptr) = block.into_raw();
    let mut b = _mm_loadu_si128(in_ptr as *const __m128i);
    b = _mm_xor_si128(b, keys[0]);
    b = _mm_aesenc_si128(b, keys[1]);
    b = _mm_aesenc_si128(b, keys[2]);
    b = _mm_aesenc_si128(b, keys[3]);
    b = _mm_aesenc_si128(b, keys[4]);
    b = _mm_aesenc_si128(b, keys[5]);
    b = _mm_aesenc_si128(b, keys[6]);
    b = _mm_aesenc_si128(b, keys[7]);
    b = _mm_aesenc_si128(b, keys[8]);
    b = _mm_aesenc_si128(b, keys[9]);
    b = _mm_aesenc_si128(b, keys[10]);
    b = _mm_aesenc_si128(b, keys[11]);
    b = _mm_aesenclast_si128(b, keys[12]);
    _mm_storeu_si128(out_ptr as *mut __m128i, b);
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt8(keys: &RoundKeys, blocks: InOut<'_, Block8>) {
    let (in_ptr, out_ptr) = blocks.into_raw();
    let mut b = load8(in_ptr);
    xor8(&mut b, keys[0]);
    aesenc8(&mut b, keys[1]);
    aesenc8(&mut b, keys[2]);
    aesenc8(&mut b, keys[3]);
    aesenc8(&mut b, keys[4]);
    aesenc8(&mut b, keys[5]);
    aesenc8(&mut b, keys[6]);
    aesenc8(&mut b, keys[7]);
    aesenc8(&mut b, keys[8]);
    aesenc8(&mut b, keys[9]);
    aesenc8(&mut b, keys[10]);
    aesenc8(&mut b, keys[11]);
    aesenclast8(&mut b, keys[12]);
    store8(out_ptr, b);
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt1(keys: &RoundKeys, block: InOut<'_, Block>) {
    let (in_ptr, out_ptr) = block.into_raw();
    let mut b = _mm_loadu_si128(in_ptr as *const __m128i);
    b = _mm_xor_si128(b, keys[12]);
    b = _mm_aesdec_si128(b, keys[11]);
    b = _mm_aesdec_si128(b, keys[10]);
    b = _mm_aesdec_si128(b, keys[9]);
    b = _mm_aesdec_si128(b, keys[8]);
    b = _mm_aesdec_si128(b, keys[7]);
    b = _mm_aesdec_si128(b, keys[6]);
    b = _mm_aesdec_si128(b, keys[5]);
    b = _mm_aesdec_si128(b, keys[4]);
    b = _mm_aesdec_si128(b, keys[3]);
    b = _mm_aesdec_si128(b, keys[2]);
    b = _mm_aesdec_si128(b, keys[1]);
    b = _mm_aesdeclast_si128(b, keys[0]);
    _mm_storeu_si128(out_ptr as *mut __m128i, b);
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt8(keys: &RoundKeys, blocks: InOut<'_, Block8>) {
    let (in_ptr, out_ptr) = blocks.into_raw();
    let mut b = load8(in_ptr);
    xor8(&mut b, keys[12]);
    aesdec8(&mut b, keys[11]);
    aesdec8(&mut b, keys[10]);
    aesdec8(&mut b, keys[9]);
    aesdec8(&mut b, keys[8]);
    aesdec8(&mut b, keys[7]);
    aesdec8(&mut b, keys[6]);
    aesdec8(&mut b, keys[5]);
    aesdec8(&mut b, keys[4]);
    aesdec8(&mut b, keys[3]);
    aesdec8(&mut b, keys[2]);
    aesdec8(&mut b, keys[1]);
    aesdeclast8(&mut b, keys[0]);
    store8(out_ptr, b);
}

macro_rules! expand_round {
    ($t1:expr, $t3:expr, $round:expr) => {{
        let mut t1 = $t1;
        let mut t2;
        let mut t3 = $t3;
        let mut t4;

        t2 = _mm_aeskeygenassist_si128(t3, $round);
        t2 = _mm_shuffle_epi32(t2, 0x55);
        t4 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t1 = _mm_xor_si128(t1, t2);
        t2 = _mm_shuffle_epi32(t1, 0xff);
        t4 = _mm_slli_si128(t3, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t3 = _mm_xor_si128(t3, t2);

        (t1, t3)
    }};
}

macro_rules! shuffle {
    ($a:expr, $b:expr, $imm:expr) => {
        mem::transmute::<_, __m128i>(_mm_shuffle_pd(mem::transmute($a), mem::transmute($b), $imm))
    };
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn expand(key: &[u8; 24]) -> (RoundKeys, RoundKeys) {
    // SAFETY: `RoundKeys` is a `[__m128i; 13]` which can be initialized
    // with all zeroes.
    let mut enc_keys: RoundKeys = mem::zeroed();
    let mut dec_keys: RoundKeys = mem::zeroed();

    macro_rules! store {
        ($i:expr, $k:expr) => {
            enc_keys[$i] = $k;
            dec_keys[$i] = _mm_aesimc_si128($k);
        };
    }

    // we are being extra pedantic here to remove out-of-bound access.
    // this should be optimized out into movups, movsd sequence
    // note that unaligned load MUST be used here, even though we read
    // from the array (compiler missoptimizes aligned load)
    let (k0, k1l) = {
        let mut t = [0u8; 32];
        ptr::write(t.as_mut_ptr() as *mut [u8; 24], *key);

        (
            _mm_loadu_si128(t.as_ptr() as *const __m128i),
            _mm_loadu_si128(t.as_ptr().offset(16) as *const __m128i),
        )
    };

    enc_keys[0] = k0;
    dec_keys[0] = k0;

    let (k1_2, k2r) = expand_round!(k0, k1l, 0x01);
    let k1 = shuffle!(k1l, k1_2, 0);
    let k2 = shuffle!(k1_2, k2r, 1);
    store!(1, k1);
    store!(2, k2);

    let (k3, k4l) = expand_round!(k1_2, k2r, 0x02);
    store!(3, k3);

    let (k4_5, k5r) = expand_round!(k3, k4l, 0x04);
    let k4 = shuffle!(k4l, k4_5, 0);
    let k5 = shuffle!(k4_5, k5r, 1);
    store!(4, k4);
    store!(5, k5);

    let (k6, k7l) = expand_round!(k4_5, k5r, 0x08);
    store!(6, k6);

    let (k7_8, k8r) = expand_round!(k6, k7l, 0x10);
    let k7 = shuffle!(k7l, k7_8, 0);
    let k8 = shuffle!(k7_8, k8r, 1);
    store!(7, k7);
    store!(8, k8);

    let (k9, k10l) = expand_round!(k7_8, k8r, 0x20);
    store!(9, k9);

    let (k10_11, k11r) = expand_round!(k9, k10l, 0x40);
    let k10 = shuffle!(k10l, k10_11, 0);
    let k11 = shuffle!(k10_11, k11r, 1);
    store!(10, k10);
    store!(11, k11);

    let (k12, _) = expand_round!(k10_11, k11r, 0x80);
    enc_keys[12] = k12;
    dec_keys[12] = k12;

    (enc_keys, dec_keys)
}
