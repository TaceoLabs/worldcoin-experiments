use super::bit::Bit;
use super::int_ring::IntRing2k;
use crate::error::Error;
use bytes::{Bytes, BytesMut};
use num_traits::{One, Zero};
use rand::{distributions::Standard, prelude::Distribution, Rng};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt::{Debug, Display};
use std::mem::ManuallyDrop;
use std::num::TryFromIntError;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul, MulAssign,
    Neg, Not, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

pub trait RingImpl:
    Clone
    + Zero
    + One
    + Debug
    + PartialEq
    + Default
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign<Self>
    + for<'a> AddAssign<&'a Self>
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign<Self>
    + for<'a> SubAssign<&'a Self>
    + Mul<Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + Mul<Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + MulAssign<Self>
    + for<'a> MulAssign<&'a Self>
    + MulAssign<Self>
    + for<'a> MulAssign<&'a Self>
    + Neg<Output = Self>
    + BitXor<Self, Output = Self>
    + for<'a> BitXor<&'a Self, Output = Self>
    + BitXorAssign<Self>
    + for<'a> BitXorAssign<&'a Self>
    + BitAnd<Self, Output = Self>
    + for<'a> BitAnd<&'a Self, Output = Self>
    + BitAnd<Self, Output = Self>
    + for<'a> BitAnd<&'a Self, Output = Self>
    + BitAndAssign<Self>
    + for<'a> BitAndAssign<&'a Self>
    + BitAndAssign<Self>
    + for<'a> BitAndAssign<&'a Self>
    + BitOrAssign<Self>
    + Not<Output = Self>
    + Shl<u32, Output = Self>
    + ShlAssign<u32>
    + Shr<u32, Output = Self>
    + ShrAssign<u32>
    + Send
    + From<bool>
    + Display
    + Serialize
    + for<'a> Deserialize<'a>
{
    const K: usize;

    fn get_msb(&self) -> RingElement<Bit>;
    fn to_bits(&self) -> Vec<RingElement<Bit>>;
    fn from_bits(bits: &[RingElement<Bit>]) -> Result<Self, Error>;

    fn add_to_bytes(self, other: &mut BytesMut);
    fn from_bytes_mut(other: BytesMut) -> Result<Self, Error>;
    fn from_bytes(other: Bytes) -> Result<Self, Error>;
    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error>;
    fn to_bytes(self) -> Bytes;

    fn floor_div(self, other: &Self) -> Self;
    fn inverse(&self) -> Result<Self, Error>;
    fn add_to_hash<D: Digest>(&self, hasher: &mut D);
}

impl<T: IntRing2k> RingImpl for RingElement<T> {
    const K: usize = T::K;

    fn get_msb(&self) -> RingElement<Bit> {
        RingElement(Bit(self.0 >> (Self::K - 1) == T::one()))
    }

    fn to_bits(&self) -> Vec<RingElement<Bit>> {
        let k = Self::K;
        let mut res = Vec::with_capacity(k);
        for i in 0..k {
            let bit = ((self.0 >> i) & T::one()) == T::one();
            res.push(RingElement(Bit(bit)));
        }

        res
    }

    fn from_bits(bits: &[RingElement<Bit>]) -> Result<Self, Error> {
        if Self::K != bits.len() {
            return Err(Error::ConversionError);
        }
        let mut res = Self::zero();

        for (i, bit) in bits.iter().enumerate() {
            res.0 |= T::from(bit.0.convert()) << i;
        }

        Ok(res)
    }

    fn add_to_bytes(self, other: &mut BytesMut) {
        self.0.add_to_bytes(other)
    }

    fn from_bytes_mut(other: BytesMut) -> Result<Self, Error> {
        Ok(RingElement(T::from_bytes_mut(other)?))
    }

    fn from_bytes(other: Bytes) -> Result<Self, Error> {
        Ok(RingElement(T::from_bytes(other)?))
    }

    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error> {
        Ok(RingElement(T::take_from_bytes_mut(other)?))
    }

    fn to_bytes(self) -> Bytes {
        self.0.to_bytes()
    }

    fn floor_div(self, other: &Self) -> Self {
        RingElement(self.0.floor_div(&other.0))
    }

    fn inverse(&self) -> Result<Self, Error> {
        Ok(RingElement(self.0.inverse()?))
    }

    fn add_to_hash<D: Digest>(&self, hasher: &mut D) {
        self.0.add_to_hash(hasher)
    }
}

impl<T: IntRing2k> From<bool> for RingElement<T> {
    fn from(value: bool) -> Self {
        RingElement(T::from(value))
    }
}

impl<T: IntRing2k> TryFrom<RingElement<T>> for usize
where
    usize: TryFrom<T, Error = TryFromIntError>,
{
    type Error = TryFromIntError;

    fn try_from(value: RingElement<T>) -> Result<Self, Self::Error> {
        let test: usize = usize::try_from(value.0)?;
        Ok(test)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord)]
#[serde(bound = "")]
#[repr(transparent)]
/// This transparent is important due to some typecasts!
pub struct RingElement<T: IntRing2k + std::fmt::Display>(pub T);

impl<T: IntRing2k + std::fmt::Display> RingElement<T> {
    /// Safe because RingElement has repr(transparent)
    pub fn convert_slice(vec: &[Self]) -> &[T] {
        // SAFETY: RingElement has repr(transparent)
        unsafe { &*(vec as *const [Self] as *const [T]) }
    }

    /// Safe because RingElement has repr(transparent)
    pub fn convert_vec(vec: Vec<Self>) -> Vec<T> {
        let me = ManuallyDrop::new(vec);
        // SAFETY: RingElement has repr(transparent)
        unsafe { Vec::from_raw_parts(me.as_ptr() as *mut T, me.len(), me.capacity()) }
    }

    /// Safe because RingElement has repr(transparent)
    pub fn convert_slice_rev(vec: &[T]) -> &[Self] {
        // SAFETY: RingElement has repr(transparent)
        unsafe { &*(vec as *const [T] as *const [Self]) }
    }

    /// Safe because RingElement has repr(transparent)
    pub fn convert_vec_rev(vec: Vec<T>) -> Vec<Self> {
        let me = ManuallyDrop::new(vec);
        // SAFETY: RingElement has repr(transparent)
        unsafe { Vec::from_raw_parts(me.as_ptr() as *mut Self, me.len(), me.capacity()) }
    }

    pub fn convert(self) -> T {
        self.0
    }
}

impl<T: IntRing2k + std::fmt::Display> std::fmt::Display for RingElement<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl<T: IntRing2k> Add for RingElement<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(&rhs.0))
    }
}

impl<T: IntRing2k> Add<&Self> for RingElement<T> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.wrapping_add(&rhs.0))
    }
}

impl<T: IntRing2k> AddAssign for RingElement<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.0.wrapping_add_assign(&rhs.0)
    }
}

impl<T: IntRing2k> AddAssign<&Self> for RingElement<T> {
    fn add_assign(&mut self, rhs: &Self) {
        self.0.wrapping_add_assign(&rhs.0)
    }
}

impl<T: IntRing2k> Sub for RingElement<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_sub(&rhs.0))
    }
}

impl<T: IntRing2k> Sub<&Self> for RingElement<T> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.wrapping_sub(&rhs.0))
    }
}

impl<T: IntRing2k> SubAssign for RingElement<T> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.wrapping_sub_assign(&rhs.0)
    }
}

impl<T: IntRing2k> SubAssign<&Self> for RingElement<T> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0.wrapping_sub_assign(&rhs.0)
    }
}

impl<T: IntRing2k> Mul<T> for RingElement<T> {
    type Output = Self;

    fn mul(self, rhs: T) -> Self::Output {
        Self(self.0.wrapping_mul(&rhs))
    }
}

impl<T: IntRing2k> Mul<&T> for RingElement<T> {
    type Output = Self;

    fn mul(self, rhs: &T) -> Self::Output {
        Self(self.0.wrapping_mul(rhs))
    }
}

impl<T: IntRing2k> Mul for RingElement<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_mul(&rhs.0))
    }
}

impl<T: IntRing2k> Mul<&Self> for RingElement<T> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.wrapping_mul(&rhs.0))
    }
}

impl<T: IntRing2k> MulAssign for RingElement<T> {
    fn mul_assign(&mut self, rhs: Self) {
        self.0.wrapping_mul_assign(&rhs.0)
    }
}

impl<T: IntRing2k> MulAssign<&Self> for RingElement<T> {
    fn mul_assign(&mut self, rhs: &Self) {
        self.0.wrapping_mul_assign(&rhs.0)
    }
}

impl<T: IntRing2k> MulAssign<T> for RingElement<T> {
    fn mul_assign(&mut self, rhs: T) {
        self.0.wrapping_mul_assign(&rhs)
    }
}

impl<T: IntRing2k> MulAssign<&T> for RingElement<T> {
    fn mul_assign(&mut self, rhs: &T) {
        self.0.wrapping_mul_assign(rhs)
    }
}

impl<T: IntRing2k> Zero for RingElement<T> {
    fn zero() -> Self {
        Self(T::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl<T: IntRing2k> One for RingElement<T> {
    fn one() -> Self {
        Self(T::one())
    }
}

impl<T: IntRing2k> Neg for RingElement<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.wrapping_neg())
    }
}

impl<T: IntRing2k> Distribution<RingElement<T>> for Standard
where
    Standard: Distribution<T>,
{
    #[inline(always)]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RingElement<T> {
        RingElement(rng.gen())
    }
}

impl<T: IntRing2k> Not for RingElement<T> {
    type Output = Self;

    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl<T: IntRing2k> BitXor for RingElement<T> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        RingElement(self.0 ^ rhs.0)
    }
}

impl<T: IntRing2k> BitXor<&Self> for RingElement<T> {
    type Output = Self;

    fn bitxor(self, rhs: &Self) -> Self::Output {
        RingElement(self.0 ^ rhs.0)
    }
}

impl<T: IntRing2k> BitXorAssign for RingElement<T> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl<T: IntRing2k> BitXorAssign<&Self> for RingElement<T> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.0 ^= rhs.0;
    }
}

impl<T: IntRing2k> BitOr for RingElement<T> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        RingElement(self.0 | rhs.0)
    }
}

impl<T: IntRing2k> BitOr<&Self> for RingElement<T> {
    type Output = Self;

    fn bitor(self, rhs: &Self) -> Self::Output {
        RingElement(self.0 | rhs.0)
    }
}

impl<T: IntRing2k> BitOrAssign for RingElement<T> {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl<T: IntRing2k> BitOrAssign<&Self> for RingElement<T> {
    fn bitor_assign(&mut self, rhs: &Self) {
        self.0 |= rhs.0;
    }
}

impl<T: IntRing2k> BitAnd for RingElement<T> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        RingElement(self.0 & rhs.0)
    }
}

impl<T: IntRing2k> BitAnd<&Self> for RingElement<T> {
    type Output = Self;

    fn bitand(self, rhs: &Self) -> Self::Output {
        RingElement(self.0 & rhs.0)
    }
}

impl<T: IntRing2k> BitAndAssign for RingElement<T> {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl<T: IntRing2k> BitAndAssign<&Self> for RingElement<T> {
    fn bitand_assign(&mut self, rhs: &Self) {
        self.0 &= rhs.0;
    }
}

impl<T: IntRing2k> Shl<u32> for RingElement<T> {
    type Output = Self;

    fn shl(self, rhs: u32) -> Self::Output {
        RingElement(self.0.wrapping_shl(rhs))
    }
}

impl<T: IntRing2k> ShlAssign<u32> for RingElement<T> {
    fn shl_assign(&mut self, rhs: u32) {
        self.0.wrapping_shl_assign(rhs)
    }
}

impl<T: IntRing2k> Shr<u32> for RingElement<T> {
    type Output = Self;

    fn shr(self, rhs: u32) -> Self::Output {
        RingElement(self.0.wrapping_shr(rhs))
    }
}

impl<T: IntRing2k> ShrAssign<u32> for RingElement<T> {
    fn shr_assign(&mut self, rhs: u32) {
        self.0.wrapping_shr_assign(rhs)
    }
}

#[cfg(test)]
mod unsafe_test {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    const ELEMENTS: usize = 100;

    fn conversion_test<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = ChaCha12Rng::from_entropy();
        let t_vec: Vec<T> = (0..ELEMENTS).map(|_| rng.gen()).collect();
        let rt_vec: Vec<RingElement<T>> =
            (0..ELEMENTS).map(|_| rng.gen::<RingElement<T>>()).collect();

        // Convert vec<T> to vec<R<T>>
        let t_conv = RingElement::convert_vec_rev(t_vec.to_owned());
        assert_eq!(t_conv.len(), t_vec.len());
        for (a, b) in t_conv.iter().zip(t_vec.iter()) {
            assert_eq!(a.0, *b)
        }

        // Convert slice vec<T> to vec<R<T>>
        let t_conv = RingElement::convert_slice_rev(&t_vec);
        assert_eq!(t_conv.len(), t_vec.len());
        for (a, b) in t_conv.iter().zip(t_vec.iter()) {
            assert_eq!(a.0, *b)
        }

        // Convert vec<R<T>> to vec<T>
        let rt_conv = RingElement::convert_vec(rt_vec.to_owned());
        assert_eq!(rt_conv.len(), rt_vec.len());
        for (a, b) in rt_conv.iter().zip(rt_vec.iter()) {
            assert_eq!(*a, b.0)
        }

        // Convert slice vec<R<T>> to vec<T>
        let rt_conv = RingElement::convert_slice(&rt_vec);
        assert_eq!(rt_conv.len(), rt_vec.len());
        for (a, b) in rt_conv.iter().zip(rt_vec.iter()) {
            assert_eq!(*a, b.0)
        }
    }

    macro_rules! test_impl {
        ($([$ty:ty,$fn:ident]),*) => ($(
            #[test]
            fn $fn() {
                conversion_test::<$ty>();
            }
        )*)
    }

    test_impl! {
        [Bit, bit_test],
        [u8, u8_test],
        [u16, u16_test],
        [u32, u32_test],
        [u64, u64_test],
        [u128, u128_test]
    }
}
