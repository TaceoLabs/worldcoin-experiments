pub(crate) mod bit;
pub(crate) mod int_ring;
pub(crate) mod ring_element;
pub(crate) mod sharable;

use self::int_ring::IntRing2k;

// Euclid with inputs reversed, which is optimized for getting inverses
fn extended_euclid_rev<T: IntRing2k>(a: T, b: T) -> (T, T) {
    let mut r1 = a;
    let mut r0 = b;
    let mut s1 = T::one();
    let mut s0 = T::zero();
    // let mut t1 = T::zero();
    // let mut t0 = T::one();

    while !r1.is_zero() {
        let q = r0.floor_div(&r1);

        let tmp = r0.wrapping_sub(&q.wrapping_mul(&r1));
        r0 = r1;
        r1 = tmp;
        let tmp = s0.wrapping_sub(&q.wrapping_mul(&s1));
        s0 = s1;
        s1 = tmp;
        // let tmp = t0.wrapping_sub(&q.wrapping_mul(&t1));
        // t0 = t1;
        // t1 = tmp;
    }
    // (r0, s0, t0)
    (r0, s0)
}
