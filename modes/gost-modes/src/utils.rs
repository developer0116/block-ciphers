#[inline(always)]
pub(crate) fn xor(buf1: &mut [u8], buf2: &[u8]) {
    debug_assert_eq!(buf1.len(), buf2.len());
    for (a, b) in buf1.iter_mut().zip(buf2) {
        *a ^= *b;
    }
}
