use super::bit::Bit;
use super::ring_element::RingElement;
use super::{int_ring::IntRing2k, ring_element::RingImpl};
use num_traits::{
    One, WrappingAdd, WrappingMul, WrappingNeg, WrappingShl, WrappingShr, WrappingSub, Zero,
};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::mem::ManuallyDrop;
use std::{
    fmt::Debug,
    ops::{BitAnd, BitAndAssign, BitXor, BitXorAssign, Mul, MulAssign, Not},
};

/// The Sharable trait combines all functionalities required for the ABY3 framework. A type implementing the Sharable trait can be shared in the MPC protocols.
pub trait Sharable:
    Sized
    + Send
    + Sync
    + Clone
    + PartialEq
    + PartialOrd
    + Ord
    + Debug
    + WrappingAdd<Output = Self>
    + WrappingSub<Output = Self>
    + WrappingShl
    + WrappingShr
    + WrappingNeg
    + Not<Output = Self>
    + BitXor<Output = Self>
    + WrappingMul<Output = Self>
    + BitXorAssign
    + BitAnd<Output = Self>
    + BitAndAssign
    + Zero
    + One
    + From<bool>
    + Default
    + Serialize
    + TryFrom<usize>
    + for<'a> Deserialize<'a>
    + Display
    + 'static
{
    /// Each Sharable type has a corresponding internal ABY3 representation. In the easiest cases this is just the unsigned version of the type with the same size, i.e., u32 for i32 or u32 for u32.
    type Share: RingImpl + Send + Sync;

    /// The type used for verifying triples. Should be at least 40 bit larger than the Share type.
    type VerificationShare: Sharable + Send + Sync;

    /// Converts the Sharable type to its ABY3 internal representation.
    fn to_sharetype(self) -> Self::Share;

    /// Converts the ABY3 internal representation to the Sharable type.
    fn from_sharetype(rhs: Self::Share) -> Self;

    /// Converts a slice of the Sharable type to its ABY3 internal representation.
    fn slice_to_sharetype(rhs: &[Self]) -> &[Self::Share];

    /// Converts a slice of the ABY3 internal representation to the Sharable type.
    fn slice_from_sharetype(rhs: &[Self::Share]) -> &[Self];

    /// Converts a vector of the Sharable type to its ABY3 internal representation.
    fn vec_to_sharetype(rhs: Vec<Self>) -> Vec<Self::Share>;

    /// Converts a vector of the ABY3 internal representation to the Sharable type.
    fn vec_from_sharetype(rhs: Vec<Self::Share>) -> Vec<Self>;

    /// c = a >> b (arithmetic shift)
    fn arithmetic_shr(lhs: Self::Share, rhs: u32) -> Self::Share {
        Self::from_sharetype(lhs).wrapping_shr(rhs).to_sharetype()
    }

    /// Casts down from verificationtype
    fn from_verificationtype(a: <Self::VerificationShare as Sharable>::Share) -> Self::Share;

    /// Casts down from verificationtype
    fn from_verificationshare(a: Self::VerificationShare) -> Self;

    /// Casts up to verificationtype
    fn to_verificationtype(a: Self::Share) -> <Self::VerificationShare as Sharable>::Share;

    /// Casts up to verificationtype
    fn to_verificationshare(self) -> Self::VerificationShare;
}

impl Sharable for Bit {
    type Share = RingElement<Self>;
    type VerificationShare = u64;

    #[inline(always)]
    fn to_sharetype(self) -> Self::Share {
        RingElement(self)
    }

    #[inline(always)]
    fn from_sharetype(rhs: Self::Share) -> Self {
        rhs.0
    }

    fn slice_to_sharetype(rhs: &[Self]) -> &[Self::Share] {
        RingElement::convert_slice_rev(rhs)
    }

    fn slice_from_sharetype(rhs: &[Self::Share]) -> &[Self] {
        RingElement::convert_slice(rhs)
    }

    fn vec_to_sharetype(rhs: Vec<Self>) -> Vec<Self::Share> {
        RingElement::convert_vec_rev(rhs)
    }

    fn vec_from_sharetype(rhs: Vec<Self::Share>) -> Vec<Self> {
        RingElement::convert_vec(rhs)
    }

    fn from_verificationtype(a: <Self::VerificationShare as Sharable>::Share) -> Self::Share {
        RingElement(Bit(a.0 & 1 == 1))
    }

    fn from_verificationshare(a: Self::VerificationShare) -> Self {
        Bit(a & 1 == 1)
    }

    fn to_verificationtype(a: Self::Share) -> <Self::VerificationShare as Sharable>::Share {
        RingElement(a.0 .0 as Self::VerificationShare)
    }

    fn to_verificationshare(self) -> Self::VerificationShare {
        self.0 as Self::VerificationShare
    }
}

macro_rules! unsigned_sharable_impl {
    ($($s:ty=>($t:ty, $vs:ty)),*) => ($(
        impl Sharable for $t {
            type Share = RingElement<Self>;
            type VerificationShare = $vs;

            #[inline(always)]
            fn to_sharetype(self) -> Self::Share {
                RingElement(self)
            }

            #[inline(always)]
            fn from_sharetype(rhs: Self::Share) -> Self {
                rhs.0
            }

            fn slice_to_sharetype(rhs: &[Self]) -> &[Self::Share] {
                RingElement::convert_slice_rev(rhs)
            }

            fn slice_from_sharetype(rhs: &[Self::Share]) -> &[Self] {
                RingElement::convert_slice(rhs)
            }

            fn vec_to_sharetype(rhs: Vec<Self>) -> Vec<Self::Share> {
                RingElement::convert_vec_rev(rhs)
            }

            fn vec_from_sharetype(rhs: Vec<Self::Share>) -> Vec<Self> {
                RingElement::convert_vec(rhs)
            }

            fn from_verificationtype(a: <Self::VerificationShare as Sharable>::Share) -> Self::Share {
                RingElement(a.0 as $t)
            }

            fn from_verificationshare(a: Self::VerificationShare) -> Self {
                a as $t
            }

            fn to_verificationtype(a: Self::Share) -> <Self::VerificationShare as Sharable>::Share {
                RingElement(a.0 as Self::VerificationShare)
            }

            fn to_verificationshare(self) -> Self::VerificationShare {
                self as Self::VerificationShare
            }
        }

    )*)
}

unsigned_sharable_impl! {
    u8 => (u8, u64),
    u16 => (u16, u64),
    u32 => (u32, u64),
    u64 => (u64, u128),
    u128 => (u128, u128)
}

macro_rules! signed_sharable_impl {
    ($($s:ty=>($t:ty, $vs:ty)),*) => ($(

        impl Mul<$s> for RingElement<$t> {
            type Output = Self;

            fn mul(self, rhs: $s) -> Self::Output {
                Self {
                    0: self.0.wrapping_mul(rhs as $t),
                }
            }
        }

        impl Mul<RingElement<$t>> for $s {
            type Output = $s;

            fn mul(self, rhs: RingElement<$t>) -> Self::Output {
                self.wrapping_mul(rhs.0 as $s)
            }
        }

        impl Mul<RingElement<$t>> for $t {
            type Output = $t;

            fn mul(self, rhs: RingElement<$t>) -> Self::Output {
                self.wrapping_mul(rhs.0)
            }
        }

        impl Mul<&$s> for RingElement<$t> {
            type Output = Self;

            fn mul(self, rhs: &$s) -> Self::Output {
                Self {
                    0: self.0.wrapping_mul(*rhs as $t),
                }
            }
        }

        impl BitAnd<$s> for RingElement<$t> {
            type Output = Self;

            fn bitand(self, rhs: $s) -> Self::Output {
                Self {
                    0: self.0 & (rhs as $t),
                }
            }
        }

        impl BitAnd<RingElement<$t>> for $s {
            type Output = $s;

            fn bitand(self, rhs: RingElement<$t>) -> Self::Output {
                self & (rhs.0 as $s)
            }
        }

        impl BitAnd<RingElement<$t>> for $t {
            type Output = $t;

            fn bitand(self, rhs: RingElement<$t>) -> Self::Output {
                self & rhs.0
            }
        }

        impl BitAnd<&$s> for RingElement<$t> {
            type Output = Self;

            fn bitand(self, rhs: &$s) -> Self::Output {
                Self {
                    0: self.0 & (*rhs as $t),
                }
            }
        }

        impl MulAssign<$s> for RingElement<$t> {
            fn mul_assign(&mut self, rhs: $s)  {
               self.0.wrapping_mul_assign(&(rhs as $t));

            }
        }

        impl MulAssign<&$s> for RingElement<$t> {
            fn mul_assign(&mut self, rhs: &$s)  {
                self.0.wrapping_mul_assign(&(*rhs as $t));
            }
        }

        impl BitAndAssign<$s> for RingElement<$t> {
            fn bitand_assign(&mut self, rhs: $s)  {
               self.0 &= (&(rhs as $t));

            }
        }

        impl BitAndAssign<&$s> for RingElement<$t> {
            fn bitand_assign(&mut self, rhs: &$s)  {
                 self.0 &= (&(*rhs as $t));
            }
        }

        impl Sharable for $s {
            type Share = RingElement<$t>;
            type VerificationShare = $vs;

            #[inline(always)]
            fn to_sharetype(self) -> Self::Share {
                RingElement {0: self as $t }
            }

            #[inline(always)]
            fn from_sharetype(rhs: Self::Share) -> Self {
                rhs.0 as Self
            }

            /// Safe because RingElement has repr(transparent)
            fn slice_to_sharetype(rhs: &[Self]) -> &[Self::Share] {
                // SAFETY: RingElement has repr(transparent) and $s and $t have same size
                unsafe { &*(rhs as *const [Self] as *const [Self::Share]) }
            }

             /// Safe because RingElement has repr(transparent)
            fn slice_from_sharetype(rhs: &[Self::Share]) -> &[Self] {
                // SAFETY: RingElement has repr(transparent) and $s and $t have same size
                unsafe { &*(rhs as *const [Self::Share] as *const [Self]) }
            }

             /// Safe because RingElement has repr(transparent)
            fn vec_to_sharetype(rhs: Vec<Self>) -> Vec<Self::Share> {
                let me = ManuallyDrop::new(rhs);
                // SAFETY: RingElement has repr(transparent) and $s and $t have same size
                unsafe { Vec::from_raw_parts(me.as_ptr() as *mut Self::Share, me.len(), me.capacity()) }
            }

             /// Safe because RingElement has repr(transparent)
            fn vec_from_sharetype(rhs: Vec<Self::Share>) -> Vec<Self> {
                let me = ManuallyDrop::new(rhs);
                // SAFETY: RingElement has repr(transparent) and $s and $t have same size
                unsafe { Vec::from_raw_parts(me.as_ptr() as *mut Self, me.len(), me.capacity()) }
            }

            fn from_verificationtype(a:<Self::VerificationShare as Sharable>::Share) -> Self::Share {
                RingElement(a.0 as $t)
            }

            fn from_verificationshare(a: Self::VerificationShare) -> Self {
                a as $s
            }

            fn to_verificationtype(a: Self::Share) -> <Self::VerificationShare as Sharable>::Share {
                RingElement(a.0 as Self::VerificationShare)
            }

            fn to_verificationshare(self) -> Self::VerificationShare {
                self as Self::VerificationShare
            }
        }
    )*)
}

// SAFETY: the two unsigned + signed types are the same size
signed_sharable_impl! {
    i8 => (u8, u64),
    i16 => (u16, u64),
    i32 => (u32, u64),
    i64 => (u64, u128),
    i128 => (u128, u128)
}

#[cfg(test)]
mod unsafe_test {
    use super::*;
    use rand::{rngs::SmallRng, Rng, SeedableRng};

    const ELEMENTS: usize = 100;

    macro_rules! test_impl {
        ($([$ty:ty,$fn:ident]),*) => ($(
            #[test]
            fn $fn() {
                let mut rng = SmallRng::from_entropy();
                let t_vec: Vec<$ty> = (0..ELEMENTS).map(|_| rng.gen()).collect();
                let s_vec: Vec<<$ty as Sharable>::Share> = (0..ELEMENTS)
                    .map(|_| rng.gen::<<$ty as Sharable>::Share>())
                    .collect();

                // Convert vec<T> to vec<T::Share>
                let t_conv = <$ty>::vec_to_sharetype(t_vec.to_owned());
                assert_eq!(t_conv.len(), t_vec.len());
                for (a, b) in t_conv.iter().zip(t_vec.iter()) {
                    assert_eq!(a.0 as $ty, *b)
                }

                // Convert vec<T::Share> to vec<T>
                let s_conv = <$ty>::vec_from_sharetype(s_vec.to_owned());
                assert_eq!(s_conv.len(), s_vec.len());
                for (a, b) in s_conv.iter().zip(s_vec.iter()) {
                    assert_eq!(*a, b.0 as $ty)
                }

                // Convert slice vec<T> to vec<T::Share>
                let t_conv = <$ty>::slice_to_sharetype(&t_vec);
                assert_eq!(t_conv.len(), t_vec.len());
                for (a, b) in t_conv.iter().zip(t_vec.iter()) {
                    assert_eq!(a.0 as $ty, *b)
                }

                // Convert slice vec<T::Share> to vec<T>
                let s_conv = <$ty>::slice_from_sharetype(&s_vec);
                assert_eq!(s_conv.len(), s_vec.len());
                for (a, b) in s_conv.iter().zip(s_vec.iter()) {
                    assert_eq!(*a, b.0 as $ty)
                }
            }
        )*)
    }

    test_impl! {
        [i8, i8_test],
        [i16, i16_test],
        [i32, i32_test],
        [i64, i64_test],
        [i128, i128_test]
    }
}
