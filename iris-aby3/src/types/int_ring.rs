use super::{bit::Bit, ring_element::RingElement, sharable::Sharable};
use num_traits::{
    One, WrappingAdd, WrappingMul, WrappingNeg, WrappingShl, WrappingShr, WrappingSub, Zero,
};
use std::{
    fmt::Debug,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not},
};

pub trait IntRing2k:
    Sized
    + Send
    + Sync
    + Copy
    + PartialEq
    + Debug
    + std::fmt::Display
    + WrappingAdd<Output = Self>
    + WrappingSub<Output = Self>
    + WrappingShl
    + WrappingShr
    + WrappingNeg
    + Not<Output = Self>
    + BitXor<Output = Self>
    + BitOr<Output = Self>
    + BitOrAssign
    + WrappingMul<Output = Self>
    + BitXorAssign
    + BitAnd<Output = Self>
    + BitAndAssign
    + Zero
    + One
    + From<bool>
    + Default
    + PartialOrd
    + Ord
{
    type Signed: Sharable<Share = RingElement<Self>>;

    fn get_k() -> usize;
    fn to_signed(self) -> Self::Signed;

    /// a += b
    #[inline(always)]
    fn wrapping_add_assign(&mut self, rhs: &Self) {
        *self = self.wrapping_add(rhs);
    }

    /// a -= b
    #[inline(always)]
    fn wrapping_sub_assign(&mut self, rhs: &Self) {
        *self = self.wrapping_sub(rhs);
    }

    /// a = -a
    #[inline(always)]
    fn wrapping_neg_inplace(&mut self) {
        *self = self.wrapping_neg();
    }

    /// a*= b
    #[inline(always)]
    fn wrapping_mul_assign(&mut self, rhs: &Self) {
        *self = self.wrapping_mul(rhs);
    }

    /// a <<= b
    #[inline(always)]
    fn wrapping_shl_assign(&mut self, rhs: u32) {
        *self = self.wrapping_shl(rhs);
    }

    /// a >>= b
    #[inline(always)]
    fn wrapping_shr_assign(&mut self, rhs: u32) {
        *self = self.wrapping_shr(rhs);
    }
}

impl IntRing2k for Bit {
    type Signed = Self;

    #[inline(always)]
    fn get_k() -> usize {
        1
    }

    fn to_signed(self) -> Self::Signed {
        self
    }
}

impl IntRing2k for u8 {
    type Signed = i8;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }
}

impl IntRing2k for u16 {
    type Signed = i16;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }
}

impl IntRing2k for u32 {
    type Signed = i32;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }
}

impl IntRing2k for u64 {
    type Signed = i64;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }
}

impl IntRing2k for u128 {
    type Signed = i128;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }
}
