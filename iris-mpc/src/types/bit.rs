use crate::error::Error;
use num_traits::{
    One, WrappingAdd, WrappingMul, WrappingNeg, WrappingShl, WrappingShr, WrappingSub, Zero,
};
use rand::{distributions::Standard, prelude::Distribution, Rng};
use serde::{Deserialize, Serialize};
use std::mem::ManuallyDrop;
use std::ops::{
    Add, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul, Neg, Not, Shl, Shr,
    Sub,
};

/// Bit is a sharable wrapper for a boolean value
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
/// This transparent is important due to some typecasts!
pub struct Bit(pub(super) bool);

impl std::fmt::Display for Bit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            true => write!(f, "1"),
            false => write!(f, "0"),
        }
    }
}

impl Bit {
    pub fn new(value: bool) -> Self {
        Self(value)
    }

    /// Safe because Bit has repr(transparent)
    pub fn convert_slice(vec: &[Self]) -> &[bool] {
        // SAFETY: Bit has repr(transparent)
        unsafe { &*(vec as *const [Self] as *const [bool]) }
    }

    /// Safe because Bit has repr(transparent)
    pub fn convert_vec(vec: Vec<Self>) -> Vec<bool> {
        let me = ManuallyDrop::new(vec);
        // SAFETY: Bit has repr(transparent)
        unsafe { Vec::from_raw_parts(me.as_ptr() as *mut bool, me.len(), me.capacity()) }
    }

    /// Safe because Bit has repr(transparent)
    pub fn convert_slice_rev(vec: &[bool]) -> &[Self] {
        // SAFETY: Bit has repr(transparent)
        unsafe { &*(vec as *const [bool] as *const [Self]) }
    }

    /// Safe because Bit has repr(transparent)
    pub fn convert_vec_rev(vec: Vec<bool>) -> Vec<Self> {
        let me = ManuallyDrop::new(vec);
        // SAFETY: Bit has repr(transparent)
        unsafe { Vec::from_raw_parts(me.as_ptr() as *mut Self, me.len(), me.capacity()) }
    }

    pub fn convert(self) -> bool {
        self.0
    }
}

impl TryFrom<u8> for Bit {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Bit(false)),
            1 => Ok(Bit(true)),
            _ => Err(Error::ConversionError),
        }
    }
}

impl TryFrom<usize> for Bit {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Bit(false)),
            1 => Ok(Bit(true)),
            _ => Err(Error::ConversionError),
        }
    }
}

impl Add for Bit {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        self ^ rhs
    }
}

impl Add<&Bit> for Bit {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn add(self, rhs: &Self) -> Self::Output {
        self ^ rhs
    }
}

impl WrappingAdd for Bit {
    #[inline(always)]
    fn wrapping_add(&self, rhs: &Self) -> Self::Output {
        *self ^ *rhs
    }
}

impl Sub for Bit {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        self ^ rhs
    }
}

impl Sub<&Bit> for Bit {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn sub(self, rhs: &Self) -> Self::Output {
        self ^ rhs
    }
}

impl WrappingSub for Bit {
    #[inline(always)]
    fn wrapping_sub(&self, rhs: &Self) -> Self::Output {
        *self ^ *rhs
    }
}

impl Neg for Bit {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self::Output {
        self
    }
}

impl WrappingNeg for Bit {
    #[inline(always)]
    fn wrapping_neg(&self) -> Self {
        -*self
    }
}

impl BitXor for Bit {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Bit(self.0 ^ rhs.0)
    }
}

impl BitXor<&Bit> for Bit {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: &Self) -> Self::Output {
        Bit(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Bit {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl BitXorAssign<&Bit> for Bit {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.0 ^= rhs.0;
    }
}

impl BitOr for Bit {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self::Output {
        Bit(self.0 | rhs.0)
    }
}

impl BitOr<&Bit> for Bit {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, rhs: &Self) -> Self::Output {
        Bit(self.0 | rhs.0)
    }
}

impl BitOrAssign for Bit {
    #[inline(always)]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitOrAssign<&Bit> for Bit {
    #[inline(always)]
    fn bitor_assign(&mut self, rhs: &Self) {
        self.0 |= rhs.0;
    }
}

impl Not for Bit {
    type Output = Self;

    #[inline(always)]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl BitAnd for Bit {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        Bit(self.0 & rhs.0)
    }
}

impl BitAnd<&Bit> for Bit {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: &Self) -> Self::Output {
        Bit(self.0 & rhs.0)
    }
}

impl BitAndAssign for Bit {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitAndAssign<&Bit> for Bit {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: &Self) {
        self.0 &= rhs.0;
    }
}

impl Mul for Bit {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        self & rhs
    }
}

impl Mul<&Bit> for Bit {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn mul(self, rhs: &Self) -> Self::Output {
        self & rhs
    }
}

impl WrappingMul for Bit {
    #[inline(always)]
    fn wrapping_mul(&self, rhs: &Self) -> Self::Output {
        *self & *rhs
    }
}

impl Zero for Bit {
    #[inline(always)]
    fn zero() -> Self {
        Self(false)
    }

    #[inline(always)]
    fn is_zero(&self) -> bool {
        !self.0
    }
}

impl One for Bit {
    #[inline(always)]
    fn one() -> Self {
        Self(true)
    }
}

impl From<Bit> for u8 {
    #[inline(always)]
    fn from(other: Bit) -> Self {
        other.0 as u8
    }
}

impl From<bool> for Bit {
    #[inline(always)]
    fn from(other: bool) -> Self {
        Bit(other)
    }
}

impl From<Bit> for bool {
    #[inline(always)]
    fn from(other: Bit) -> Self {
        other.0
    }
}

impl Shl<usize> for Bit {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self {
        if rhs == 0 {
            self
        } else {
            Self(false)
        }
    }
}

impl WrappingShl for Bit {
    #[inline(always)]
    fn wrapping_shl(&self, rhs: u32) -> Self {
        *self << rhs as usize
    }
}

impl Shr<usize> for Bit {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self {
        if rhs == 0 {
            self
        } else {
            Self(false)
        }
    }
}

impl WrappingShr for Bit {
    #[inline(always)]
    fn wrapping_shr(&self, rhs: u32) -> Self {
        *self >> rhs as usize
    }
}

impl Distribution<Bit> for Standard {
    #[inline(always)]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Bit {
        Bit(rng.gen())
    }
}

impl AsRef<Bit> for Bit {
    fn as_ref(&self) -> &Bit {
        self
    }
}

#[cfg(test)]
mod unsafe_test {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    const ELEMENTS: usize = 100;

    #[test]
    fn bit_conversion_test() {
        let mut rng = ChaCha12Rng::from_entropy();
        let bit_vec: Vec<Bit> = (0..ELEMENTS).map(|_| rng.gen()).collect();
        let bool_vec: Vec<bool> = (0..ELEMENTS).map(|_| rng.gen()).collect();

        // Convert vec<bool> to vec<Bit>
        let bit_conv = Bit::convert_vec_rev(bool_vec.to_owned());
        assert_eq!(bit_conv.len(), bool_vec.len());
        for (a, b) in bit_conv.iter().zip(bool_vec.iter()) {
            assert_eq!(a.0, *b)
        }

        // Convert slice vec<bool> to vec<Bit>
        let bit_conv = Bit::convert_slice_rev(&bool_vec);
        assert_eq!(bit_conv.len(), bool_vec.len());
        for (a, b) in bit_conv.iter().zip(bool_vec.iter()) {
            assert_eq!(a.0, *b)
        }

        // Convert vec<Bit> to vec<bool>
        let bool_conv = Bit::convert_vec(bit_vec.to_owned());
        assert_eq!(bool_conv.len(), bit_vec.len());
        for (a, b) in bool_conv.iter().zip(bit_vec.iter()) {
            assert_eq!(*a, b.0)
        }

        // Convert slice vec<Bit> to vec<bool>
        let bool_conv = Bit::convert_slice(&bit_vec);
        assert_eq!(bool_conv.len(), bit_vec.len());
        for (a, b) in bool_conv.iter().zip(bit_vec.iter()) {
            assert_eq!(*a, b.0)
        }
    }
}
