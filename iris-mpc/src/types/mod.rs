pub(crate) mod bit;
pub(crate) mod int_ring;
pub(crate) mod ring_element;
pub(crate) mod sharable;

use self::int_ring::IntRing2k;
use num_traits::{One, Zero};
use std::ops::{Mul, Sub};

trait DivRem {
    type Output;
    fn div_rem(self, other: &Self) -> (Self::Output, Self::Output);
}

impl<T: IntRing2k> DivRem for T {
    type Output = Self;

    fn div_rem(self, other: &Self) -> (Self::Output, Self::Output) {
        let q = self.to_owned().floor_div(other);
        let r = self - q.wrapping_mul(other);
        (q, r)
    }
}

// Euclid with inputs reversed, which is optimized for getting inverses
fn extended_euclid_rev<T>(a: T, b: T) -> (T, T, T)
where
    T: Clone + Zero + One + DivRem<Output = T> + Sub<Output = T> + for<'a> Mul<&'a T, Output = T>,
{
    let mut r1 = a;
    let mut r0 = b;
    let mut s1 = T::one();
    let mut s0 = T::zero();
    let mut t1 = T::zero();
    let mut t0 = T::one();

    while !r1.is_zero() {
        let (q, r) = r0.div_rem(&r1);
        r0 = r1;
        r1 = r;
        let tmp = s0 - q.to_owned() * &s1;
        s0 = s1;
        s1 = tmp;
        let tmp = t0 - q * &t1;
        t0 = t1;
        t1 = tmp;
    }
    (r0, s0, t0)
}
