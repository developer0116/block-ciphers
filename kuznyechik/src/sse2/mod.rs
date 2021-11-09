//! SSE2-based implementation based on https://github.com/aprelev/lg15

pub use cipher;

use crate::{
    consts::{P, P_INV},
    Block, Key,
};
use cipher::{
    generic_array::typenum::Unsigned,
    inout::{InOut, InOutBuf, InSrc, InTmpOutBuf},
    BlockDecrypt, BlockEncrypt, KeyInit,
};
use core::arch::x86_64::*;

type ParBlocks = cipher::consts::U4;

#[rustfmt::skip]
macro_rules! unroll_par {
    ($var:ident, $body:block) => {
        { let $var: usize = 0; $body; }
        { let $var: usize = 1; $body; }
        { let $var: usize = 2; $body; }
        { let $var: usize = 3; $body; }
    };
}

mod consts;

use consts::{Table, DEC_TABLE, ENC_TABLE};

/// Kuznyechik (GOST R 34.12-2015) block cipher
#[derive(Clone, Copy)]
#[repr(align(16))]
pub struct Kuznyechik {
    enc_keys: [__m128i; 10],
    dec_keys: [__m128i; 8],
}

#[inline(always)]
unsafe fn sub_bytes(block: __m128i, sbox: &[u8; 256]) -> __m128i {
    let t0 = _mm_extract_epi16(block, 0) as u16;
    let t1 = _mm_extract_epi16(block, 1) as u16;
    let t2 = _mm_extract_epi16(block, 2) as u16;
    let t3 = _mm_extract_epi16(block, 3) as u16;
    let t4 = _mm_extract_epi16(block, 4) as u16;
    let t5 = _mm_extract_epi16(block, 5) as u16;
    let t6 = _mm_extract_epi16(block, 6) as u16;
    let t7 = _mm_extract_epi16(block, 7) as u16;

    _mm_set_epi8(
        sbox[(t7 >> 8) as usize] as i8,
        sbox[(t7 & 0xFF) as usize] as i8,
        sbox[(t6 >> 8) as usize] as i8,
        sbox[(t6 & 0xFF) as usize] as i8,
        sbox[(t5 >> 8) as usize] as i8,
        sbox[(t5 & 0xFF) as usize] as i8,
        sbox[(t4 >> 8) as usize] as i8,
        sbox[(t4 & 0xFF) as usize] as i8,
        sbox[(t3 >> 8) as usize] as i8,
        sbox[(t3 & 0xFF) as usize] as i8,
        sbox[(t2 >> 8) as usize] as i8,
        sbox[(t2 & 0xFF) as usize] as i8,
        sbox[(t1 >> 8) as usize] as i8,
        sbox[(t1 & 0xFF) as usize] as i8,
        sbox[(t0 >> 8) as usize] as i8,
        sbox[(t0 & 0xFF) as usize] as i8,
    )
}

#[inline(always)]
unsafe fn transform(block: __m128i, table: &Table) -> __m128i {
    macro_rules! get {
        ($table:expr, $ind:expr, $i:expr) => {{
            let idx = _mm_extract_epi16($ind, $i) as u16 as usize;
            let p = &($table.0[idx]) as *const u8 as *const __m128i;
            // correct aligment of `p` is guaranteed since offset values
            // are shifted by 4 bits left and the table is aligned to 16 bytes
            debug_assert_eq!(p as usize % 16, 0);
            _mm_load_si128(p)
        }};
    }

    macro_rules! xor_get {
        ($val:expr, $table:expr, $ind:expr, $i:expr) => {
            $val = _mm_xor_si128($val, get!($table, $ind, $i));
        };
    }

    let ind = _mm_set_epi64x(0x0f0e0d0c0b0a0908, 0x0706050403020100);

    let lind = _mm_slli_epi16(_mm_unpacklo_epi8(block, ind), 4);

    let mut lt = get!(table, lind, 0);
    xor_get!(lt, table, lind, 1);
    xor_get!(lt, table, lind, 2);
    xor_get!(lt, table, lind, 3);
    xor_get!(lt, table, lind, 4);
    xor_get!(lt, table, lind, 5);
    xor_get!(lt, table, lind, 6);
    xor_get!(lt, table, lind, 7);

    let rind = _mm_slli_epi16(_mm_unpackhi_epi8(block, ind), 4);

    let mut rt = get!(table, rind, 0);
    xor_get!(rt, table, rind, 1);
    xor_get!(rt, table, rind, 2);
    xor_get!(rt, table, rind, 3);
    xor_get!(rt, table, rind, 4);
    xor_get!(rt, table, rind, 5);
    xor_get!(rt, table, rind, 6);
    xor_get!(rt, table, rind, 7);

    _mm_xor_si128(lt, rt)
}

impl KeyInit for Kuznyechik {
    fn new(key: &Key) -> Self {
        macro_rules! next_const {
            ($i:expr) => {{
                let p = consts::RKEY_GEN.0.as_ptr() as *const __m128i;
                // correct aligment of `p` is guaranteed since the table
                // is aligned to 16 bytes
                let p = p.add($i);
                debug_assert_eq!(p as usize % 16, 0);
                $i += 1;
                _mm_load_si128(p)
            }};
        }

        unsafe {
            let mut enc_keys = [_mm_setzero_si128(); 10];
            let mut dec_keys = [_mm_setzero_si128(); 8];

            let pk: *const __m128i = key.as_ptr() as *const __m128i;
            let mut k1 = _mm_loadu_si128(pk);
            let mut k2 = _mm_loadu_si128(pk.add(1));
            enc_keys[0] = k1;
            enc_keys[1] = k2;

            let mut cidx = 0;
            for i in 1..5 {
                for _ in 0..4 {
                    let mut t = _mm_xor_si128(k1, next_const!(cidx));
                    t = transform(t, &ENC_TABLE);
                    k2 = _mm_xor_si128(k2, t);

                    let mut t = _mm_xor_si128(k2, next_const!(cidx));
                    t = transform(t, &ENC_TABLE);
                    k1 = _mm_xor_si128(k1, t);
                }

                enc_keys[2 * i] = k1;
                enc_keys[2 * i + 1] = k2;
            }

            for i in 1..9 {
                let k = sub_bytes(enc_keys[i], &P);
                dec_keys[8 - i] = transform(k, &DEC_TABLE);
            }

            Self { enc_keys, dec_keys }
        }
    }
}

impl BlockEncrypt for Kuznyechik {
    #[inline]
    fn encrypt_block_inout(&self, block: InOut<'_, Block>) {
        let k = self.enc_keys;
        unsafe {
            let in_ptr = block.get_in() as *const Block as *const __m128i;
            let mut b = _mm_loadu_si128(in_ptr);

            unroll9! {
                i, {
                    b = _mm_xor_si128(b, k[i]);
                    b = transform(b, &ENC_TABLE);
                }
            };
            b = _mm_xor_si128(b, k[9]);
            let out_ptr = block.get_out() as *mut Block as *mut __m128i;
            _mm_storeu_si128(out_ptr, b);
        }
    }

    #[inline]
    fn encrypt_blocks_with_pre(
        &self,
        blocks: InOutBuf<'_, Block>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
    ) {
        blocks.process_chunks::<ParBlocks, _, _, _, _, _>(
            self,
            pre_fn,
            post_fn,
            |s, chunk| unsafe {
                let k = s.enc_keys;

                let (in_ptr, out_ptr) = chunk.into_raw();
                let in_ptr = in_ptr as *mut __m128i;
                let out_ptr = out_ptr as *mut __m128i;

                let mut blocks = [_mm_setzero_si128(); ParBlocks::USIZE];
                unroll_par! {
                    i, {
                        blocks[i] = _mm_loadu_si128(in_ptr.add(i));
                    }
                };

                unroll9! {
                    i, {
                        unroll_par!{
                            j, {
                                let t = _mm_xor_si128(blocks[j], k[i]);
                                blocks[j] = transform(t, &ENC_TABLE);
                            }
                        }
                    }
                }

                unroll_par! {
                    i, {
                        let t = _mm_xor_si128(blocks[i], k[9]);
                        _mm_storeu_si128(out_ptr.add(i), t);
                    }
                }
            },
            |s, chunk| {
                for block in chunk {
                    s.encrypt_block_inout(block);
                }
            },
        )
    }
}

impl BlockDecrypt for Kuznyechik {
    #[inline]
    fn decrypt_block_inout(&self, block: InOut<'_, Block>) {
        let ek = self.enc_keys;
        let dk = self.dec_keys;
        unsafe {
            let in_ptr = block.get_in() as *const Block as *const __m128i;
            let mut b = _mm_loadu_si128(in_ptr);

            b = _mm_xor_si128(b, ek[9]);

            b = sub_bytes(b, &P);
            b = transform(b, &DEC_TABLE);

            unroll8! {
                i, {
                    b = transform(b, &DEC_TABLE);
                    b = _mm_xor_si128(b, dk[i]);
                }
            }
            b = sub_bytes(b, &P_INV);
            b = _mm_xor_si128(b, ek[0]);

            let out_ptr = block.get_out() as *mut Block as *mut __m128i;
            _mm_storeu_si128(out_ptr, b)
        }
    }

    #[inline]
    fn decrypt_blocks_with_pre(
        &self,
        blocks: InOutBuf<'_, Block>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
    ) {
        blocks.process_chunks::<ParBlocks, _, _, _, _, _>(
            self,
            pre_fn,
            post_fn,
            |s, chunk| unsafe {
                let ek = s.enc_keys;
                let dk = s.dec_keys;

                let (in_ptr, out_ptr) = chunk.into_raw();
                let in_ptr = in_ptr as *mut __m128i;
                let out_ptr = out_ptr as *mut __m128i;

                let mut blocks = [_mm_setzero_si128(); ParBlocks::USIZE];
                unroll_par! {
                    i, {
                        blocks[i] = _mm_loadu_si128(in_ptr.add(i));
                    }
                };

                unroll_par! {
                    i, {
                        let t = _mm_xor_si128(blocks[i], ek[9]);
                        let t = sub_bytes(t, &P);
                        blocks[i] = transform(t, &DEC_TABLE);
                    }
                }

                unroll8! {
                    i, {
                        unroll_par!{
                            j, {
                                let t = transform(blocks[j], &DEC_TABLE);
                                blocks[j] = _mm_xor_si128(t, dk[i]);
                            }
                        }
                    }
                }

                unroll_par! {
                    i, {
                        let t = sub_bytes(blocks[i], &P_INV);
                        let t2 = _mm_xor_si128(t, ek[0]);
                        _mm_storeu_si128(out_ptr.add(i), t2)
                    }
                }
            },
            |s, chunk| {
                for block in chunk {
                    s.decrypt_block_inout(block);
                }
            },
        )
    }
}
