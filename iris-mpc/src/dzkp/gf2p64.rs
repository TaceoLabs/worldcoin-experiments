use gf256::{gf2p64, p64};
use num_traits::{One, Zero};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct GF2p64(gf2p64);

impl GF2p64 {
    pub const MODULUS: [bool; 65] = [
        true, true, false, true, true, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, true,
    ];

    pub fn new(x: u64) -> Self {
        GF2p64(gf2p64::new(x))
    }

    pub unsafe fn new_unchecked(x: u64) -> Self {
        GF2p64(gf2p64::new_unchecked(x))
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }

    pub fn inverse(self) -> Self {
        Self(self.0.recip())
    }

    pub fn to_poly(self) -> p64 {
        p64(self.0.get())
    }

    pub fn from_poly(x: p64) -> Self {
        Self::new(x.get())
    }

    // Euclid with inputs reversed, which is optimized for getting inverses
    fn extended_euclid_rev(a: Self, b: Self) -> (Self, Self) {
        let zero = p64::new(0);
        let mut r1 = a.to_poly();
        let mut r0 = b.to_poly();
        let mut s1 = p64::new(1);
        let mut s0 = zero.to_owned();
        // let mut t1 = p64::new(1);
        // let mut t0 = zero.to_owned();

        while r1 != zero {
            let q = r0 / r1;

            let tmp = r0 - q * r1;
            r0 = r1;
            r1 = tmp;
            let tmp = s0 - q * s1;
            s0 = s1;
            s1 = tmp;
            // let tmp = t0 - &q * &t1;
            // t0 = t1;
            // t1 = tmp;
        }
        // (r0, s0, t0)
        (Self::from_poly(r0), Self::from_poly(s0))
    }

    pub fn inv_mod(self, modulus: Self) -> Self {
        Self::extended_euclid_rev(self, modulus).1
    }
}

impl Serialize for GF2p64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0.get())
    }
}

impl<'de> Deserialize<'de> for GF2p64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner: u64 = Deserialize::deserialize(deserializer)?;
        Ok(GF2p64::new(inner))
    }
}

impl Add for GF2p64 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        GF2p64(self.0 + rhs.0)
    }
}

impl Add<&Self> for GF2p64 {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        GF2p64(self.0 + rhs.0)
    }
}

impl Sub for GF2p64 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        GF2p64(self.0 - rhs.0)
    }
}

impl Sub<&Self> for GF2p64 {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        GF2p64(self.0 - rhs.0)
    }
}

impl AddAssign for GF2p64 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl AddAssign<&Self> for GF2p64 {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }
}

impl SubAssign for GF2p64 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl SubAssign<&Self> for GF2p64 {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0;
    }
}

impl Mul for GF2p64 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        GF2p64(self.0 * rhs.0)
    }
}

impl Mul<&Self> for GF2p64 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        GF2p64(self.0 * rhs.0)
    }
}

impl MulAssign for GF2p64 {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}
impl MulAssign<&Self> for GF2p64 {
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 *= rhs.0;
    }
}

impl Neg for GF2p64 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Zero for GF2p64 {
    fn zero() -> Self {
        // Safety: It is just a 0
        unsafe { Self::new_unchecked(0) }
    }

    fn is_zero(&self) -> bool {
        self.0.get().is_zero()
    }
}

impl One for GF2p64 {
    fn one() -> Self {
        // Safety: It is just a 1
        unsafe { Self::new_unchecked(1) }
    }

    fn is_one(&self) -> bool {
        self.0.get().is_one()
    }
}

impl Default for GF2p64 {
    fn default() -> Self {
        Self::zero()
    }
}
