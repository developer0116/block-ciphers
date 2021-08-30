#![feature(test)]
extern crate test;

use cipher::{block_encryptor_bench, block_decryptor_bench, KeyInit};

block_encryptor_bench!(
    aes::Aes128,
    aes128_encrypt_block,
    aes128_encrypt_blocks,
);

block_decryptor_bench!(
    aes::Aes128,
    aes128_decrypt_block,
    aes128_decrypt_blocks,
);

block_encryptor_bench!(
    aes::Aes192,
    aes192_encrypt_block,
    aes192_encrypt_blocks,
);

block_decryptor_bench!(
    aes::Aes192,
    aes192_decrypt_block,
    aes192_decrypt_blocks,
);

block_encryptor_bench!(
    aes::Aes256,
    aes256_encrypt_block,
    aes256_encrypt_blocks,
);

block_decryptor_bench!(
    aes::Aes256,
    aes256_decrypt_block,
    aes256_decrypt_blocks,
);

#[bench]
pub fn aes128_new(bh: &mut test::Bencher) {
    bh.iter(|| {
        let key = test::black_box(Default::default());
        let cipher = aes::Aes128::new(&key);
        test::black_box(&cipher);
    });
}

#[bench]
pub fn aes192_new(bh: &mut test::Bencher) {
    bh.iter(|| {
        let key = test::black_box(Default::default());
        let cipher = aes::Aes192::new(&key);
        test::black_box(&cipher);
    });
}


#[bench]
pub fn aes256_new(bh: &mut test::Bencher) {
    bh.iter(|| {
        let key = test::black_box(Default::default());
        let cipher = aes::Aes256::new(&key);
        test::black_box(&cipher);
    });
}
