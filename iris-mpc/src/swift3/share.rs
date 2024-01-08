use crate::{
    prelude::{Bit, Error, Sharable},
    traits::share_trait::{ShareTrait, VecShareTrait},
    types::{
        int_ring::IntRing2k,
        ring_element::{RingElement, RingImpl},
    },
};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::{
    marker::PhantomData,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitXor, BitXorAssign, Mul, MulAssign, Neg, Not, Shl,
        ShlAssign, Sub, SubAssign,
    },
};

// A share of x is represented as
//   P_0: (a1, a3, b)
//   P_1: (a2, a1, b)
//   P_2: (a3, a2, b)
// where b = x + a1 + a2 + a3
#[derive(Clone, Debug, PartialEq, Default, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Share<T: Sharable> {
    pub(crate) a: T::Share,
    pub(crate) b: T::Share,
    pub(crate) c: T::Share,
    sharetype: PhantomData<T>,
}

impl<T: Sharable> ShareTrait for Share<T> {
    type VecShare = Vec<Self>;
}

impl<T: Sharable> VecShareTrait for Vec<Share<T>> {
    type Share = Share<T>;

    fn len(&self) -> usize {
        Vec::len(self)
    }

    // TODO update for other share
    fn filter_reduce_add_twice(
        a: &Self,
        b: &Self,
        mask: &plain_reference::IrisCodeArray,
    ) -> Result<(Self::Share, Self::Share), Error> {
        if a.is_empty() || a.len() != b.len() {
            return Err(Error::InvalidCodeSizeError);
        }

        let (sum_a, sum_b) = a
            .iter()
            .zip(b)
            .enumerate()
            .filter(|(i, _)| mask.get_bit(*i))
            .map(|(_, (a_, b_))| (a_.to_owned(), b_.to_owned()))
            .reduce(|(aa, ab), (ba, bb)| (aa + ba, ab + bb))
            .expect("Size is not zero");
        Ok((sum_a, sum_b))
    }

    fn with_capacity(capacity: usize) -> Self {
        Vec::with_capacity(capacity)
    }

    fn xor_many(self, b: Self) -> Result<Self, Error> {
        if self.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let res = self.into_iter().zip(b).map(|(a_, b_)| a_ ^ b_).collect();
        Ok(res)
    }

    fn xor_assign_many(&mut self, b: Self) -> Result<Self, Error> {
        if self.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        for (a_, b_) in self.iter_mut().zip(b) {
            *a_ ^= b_;
        }
        Ok(self.to_owned())
    }

    fn shl_assign_many(&mut self, shift: u32) -> Self {
        for a_ in self.iter_mut() {
            *a_ <<= shift;
        }
        self.to_owned()
    }

    fn reserve(&mut self, additional: usize) {
        Vec::reserve(self, additional);
    }

    fn push(&mut self, value: Self::Share) {
        Vec::push(self, value);
    }

    fn extend(&mut self, other: Self) {
        <Vec<_> as std::iter::Extend<_>>::extend(self, other);
    }

    fn split_at(&self, mid: usize) -> (Self, Self) {
        let (a, b) = self[..].split_at(mid);
        (a.to_owned(), b.to_owned())
    }

    fn chunks(self, chunk_size: usize) -> Vec<Self> {
        let capacity = self.len() / chunk_size + (self.len() % chunk_size != 0) as usize;

        let mut res = Vec::with_capacity(capacity);
        for chunk in self[..].chunks(chunk_size) {
            res.push(chunk.to_owned());
        }
        res
    }

    fn get_at(&self, index: usize) -> &Self::Share {
        &self[index]
    }

    fn set_at(&mut self, index: usize, value: Self::Share) {
        self[index] = value;
    }
}

impl<T: Sharable> Share<T> {
    pub fn new(a: T::Share, b: T::Share, c: T::Share) -> Self {
        Share {
            a,
            b,
            c,
            sharetype: PhantomData,
        }
    }

    pub fn get_a(self) -> T::Share {
        self.a
    }

    pub fn get_ac(self) -> (T::Share, T::Share) {
        (self.a, self.c)
    }

    pub fn get_abc(self) -> (T::Share, T::Share, T::Share) {
        (self.a, self.b, self.c)
    }

    pub fn get_msb(&self) -> Share<Bit> {
        Share {
            a: self.a.get_msb(),
            b: self.b.get_msb(),
            c: self.c.get_msb(),
            sharetype: PhantomData,
        }
    }

    pub(crate) fn add_const(mut self, other: &T::Share) -> Self {
        self.add_assign_const(other);
        self
    }

    pub(crate) fn add_assign_const(&mut self, other: &T::Share) {
        self.c += other;
    }

    pub(crate) fn sub_const(mut self, other: &T::Share) -> Self {
        self.sub_assign_const(other);
        self
    }

    pub(crate) fn sub_assign_const(&mut self, other: &T::Share) {
        self.c -= other;
    }
}

impl<T: Sharable> Add for Share<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Share {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
            c: self.c + rhs.c,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> Add<&Share<T>> for Share<T> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Share {
            a: self.a + &rhs.a,
            b: self.b + &rhs.b,
            c: self.c + &rhs.c,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> AddAssign for Share<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.a += &rhs.a;
        self.b += &rhs.b;
        self.c += &rhs.c;
    }
}

impl<T: Sharable> AddAssign<&Share<T>> for Share<T> {
    fn add_assign(&mut self, rhs: &Self) {
        self.a += &rhs.a;
        self.b += &rhs.b;
        self.c += &rhs.c;
    }
}

impl<T: Sharable> Sub for Share<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Share {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
            c: self.c - rhs.c,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> Sub<&Share<T>> for Share<T> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Share {
            a: self.a - &rhs.a,
            b: self.b - &rhs.b,
            c: self.c - &rhs.c,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> SubAssign for Share<T>
where
    for<'a> T::Share: SubAssign<&'a T::Share>,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.a -= &rhs.a;
        self.b -= &rhs.b;
        self.c -= &rhs.c;
    }
}

impl<T: Sharable> SubAssign<&Share<T>> for Share<T>
where
    for<'a> T::Share: SubAssign<&'a T::Share>,
{
    fn sub_assign(&mut self, rhs: &Self) {
        self.a -= &rhs.a;
        self.b -= &rhs.b;
        self.c -= &rhs.c;
    }
}

impl<T: Sharable, U: IntRing2k> Mul<RingElement<U>> for Share<T>
where
    for<'a> T::Share: Mul<&'a RingElement<U>, Output = T::Share>,
{
    type Output = Self;

    fn mul(self, rhs: RingElement<U>) -> Share<T> {
        Share {
            a: self.a * &rhs,
            b: self.b * &rhs,
            c: self.c * &rhs,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable, U: IntRing2k> Mul<&RingElement<U>> for Share<T>
where
    for<'a> T::Share: Mul<&'a RingElement<U>, Output = T::Share>,
{
    type Output = Self;

    fn mul(self, rhs: &RingElement<U>) -> Share<T> {
        Share {
            a: self.a * rhs,
            b: self.b * rhs,
            c: self.c * rhs,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable, U: IntRing2k> MulAssign<RingElement<U>> for Share<T>
where
    for<'a> T::Share: MulAssign<&'a RingElement<U>>,
{
    fn mul_assign(&mut self, rhs: RingElement<U>) {
        self.a *= &rhs;
        self.b *= &rhs;
        self.c *= &rhs;
    }
}

impl<T: Sharable, U: IntRing2k> MulAssign<&RingElement<U>> for Share<T>
where
    for<'a> T::Share: MulAssign<&'a RingElement<U>>,
{
    fn mul_assign(&mut self, rhs: &RingElement<U>) {
        self.a *= rhs;
        self.b *= rhs;
        self.c *= rhs;
    }
}

impl<T: Sharable, U: IntRing2k> Mul<Share<T>> for RingElement<U>
where
    for<'a> T::Share: Mul<&'a RingElement<U>, Output = T::Share>,
{
    type Output = Share<T>;

    fn mul(self, rhs: Share<T>) -> Share<T> {
        Share {
            a: rhs.a * &self,
            b: rhs.b * &self,
            c: rhs.c * &self,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable, U: IntRing2k> Mul<&Share<T>> for RingElement<U>
where
    for<'a> T::Share: Mul<&'a RingElement<U>, Output = T::Share>,
{
    type Output = Share<T>;

    fn mul(self, rhs: &Share<T>) -> Share<T> {
        Share {
            a: rhs.a.to_owned() * &self,
            b: rhs.b.to_owned() * &self,
            c: rhs.c.to_owned() * &self,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> Neg for Share<T> {
    type Output = Self;

    fn neg(self) -> Self {
        Share {
            a: self.a.neg(),
            b: self.b.neg(),
            c: self.c.neg(),
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> AsRef<Share<T>> for Share<T> {
    fn as_ref(&self) -> &Share<T> {
        self
    }
}

impl<T: Sharable> BitXor for Share<T> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Share {
            a: self.a ^ rhs.a,
            b: self.b ^ rhs.b,
            c: self.c ^ rhs.c,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> BitXor<&Self> for Share<T> {
    type Output = Self;

    fn bitxor(self, rhs: &Self) -> Self::Output {
        Share {
            a: self.a ^ &rhs.a,
            b: self.b ^ &rhs.b,
            c: self.c ^ &rhs.c,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> BitXorAssign for Share<T> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.a ^= rhs.a;
        self.b ^= rhs.b;
        self.c ^= rhs.c;
    }
}

impl<T: Sharable> BitXorAssign<&Self> for Share<T> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.a ^= &rhs.a;
        self.b ^= &rhs.b;
        self.c ^= &rhs.c;
    }
}

impl<T: Sharable, U: IntRing2k> BitAnd<RingElement<U>> for Share<T>
where
    for<'a> T::Share: BitAnd<&'a RingElement<U>, Output = T::Share>,
{
    type Output = Self;

    fn bitand(self, rhs: RingElement<U>) -> Share<T> {
        Share {
            a: self.a & &rhs,
            b: self.b & &rhs,
            c: self.c & &rhs,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable, U: IntRing2k> BitAnd<&RingElement<U>> for Share<T>
where
    for<'a> T::Share: BitAnd<&'a RingElement<U>, Output = T::Share>,
{
    type Output = Self;

    fn bitand(self, rhs: &RingElement<U>) -> Share<T> {
        Share {
            a: self.a & rhs,
            b: self.b & rhs,
            c: self.c & rhs,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable, U: IntRing2k> BitAndAssign<RingElement<U>> for Share<T>
where
    for<'a> T::Share: BitAndAssign<&'a RingElement<U>>,
{
    fn bitand_assign(&mut self, rhs: RingElement<U>) {
        self.a &= &rhs;
        self.b &= &rhs;
        self.c &= &rhs;
    }
}

impl<T: Sharable, U: IntRing2k> BitAndAssign<&RingElement<U>> for Share<T>
where
    for<'a> T::Share: BitAndAssign<&'a RingElement<U>>,
{
    fn bitand_assign(&mut self, rhs: &RingElement<U>) {
        self.a &= rhs;
        self.b &= rhs;
        self.c &= rhs;
    }
}

impl<T: Sharable, U: IntRing2k> BitAnd<Share<T>> for RingElement<U>
where
    for<'a> T::Share: BitAnd<&'a RingElement<U>, Output = T::Share>,
{
    type Output = Share<T>;

    fn bitand(self, rhs: Share<T>) -> Share<T> {
        Share {
            a: rhs.a & &self,
            b: rhs.b & &self,
            c: rhs.c & &self,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable, U: IntRing2k> BitAnd<&Share<T>> for RingElement<U>
where
    for<'a> T::Share: BitAnd<&'a RingElement<U>, Output = T::Share>,
{
    type Output = Share<T>;

    fn bitand(self, rhs: &Share<T>) -> Share<T> {
        Share {
            a: rhs.a.to_owned() & &self,
            b: rhs.b.to_owned() & &self,
            c: rhs.c.to_owned() & &self,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> Not for Share<T> {
    type Output = Self;

    fn not(self) -> Self {
        Share {
            a: !self.a,
            b: !self.b,
            c: !self.c,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> Shl<u32> for Share<T> {
    type Output = Self;

    fn shl(self, rhs: u32) -> Self::Output {
        Self {
            a: self.a << rhs,
            b: self.b << rhs,
            c: self.c << rhs,
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> ShlAssign<u32> for Share<T> {
    fn shl_assign(&mut self, rhs: u32) {
        self.a <<= rhs;
        self.b <<= rhs;
        self.c <<= rhs;
    }
}

impl<T: Sharable> Zero for Share<T> {
    fn zero() -> Self {
        Self {
            a: T::Share::zero(),
            b: T::Share::zero(),
            c: T::Share::zero(),
            sharetype: PhantomData,
        }
    }

    fn is_zero(&self) -> bool {
        self.a.is_zero() && self.b.is_zero() && self.c.is_zero()
    }
}
