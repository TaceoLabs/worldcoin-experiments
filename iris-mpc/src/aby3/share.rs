use crate::{
    traits::share_trait::ShareTrait,
    types::{
        bit::Bit,
        int_ring::IntRing2k,
        ring_element::{RingElement, RingImpl},
        sharable::Sharable,
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

use super::id::PartyID;

// share x = x1 + x2 + x3 where party i has (xi, x{i-1})
#[derive(Clone, Debug, PartialEq, Default, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Share<T: Sharable> {
    pub(crate) a: T::Share,
    pub(crate) b: T::Share,
    sharetype: PhantomData<T>,
}

impl<T: Sharable> ShareTrait for Share<T> {}

impl<T: Sharable> Share<T> {
    pub fn new(a: T::Share, b: T::Share) -> Self {
        Share {
            a,
            b,
            sharetype: PhantomData,
        }
    }

    pub fn from_verificationtype(a: Share<T::VerificationShare>) -> Self {
        let (a, b) = a.get_ab();
        Share {
            a: T::from_verificationtype(a),
            b: T::from_verificationtype(b),
            sharetype: PhantomData,
        }
    }

    pub fn to_verificationtype(self) -> Share<T::VerificationShare> {
        let (a, b) = self.get_ab();
        Share {
            a: T::to_verificationtype(a),
            b: T::to_verificationtype(b),
            sharetype: PhantomData,
        }
    }

    pub fn to_bits(self) -> Vec<Share<Bit>> {
        let (a, b) = self.get_ab();
        let a = a.to_bits();
        let b = b.to_bits();
        a.into_iter()
            .zip(b)
            .map(|(a, b)| Share::new(a, b))
            .collect()
    }

    pub fn get_a(self) -> T::Share {
        self.a
    }

    pub fn get_b(self) -> T::Share {
        self.b
    }

    pub fn get_ab(self) -> (T::Share, T::Share) {
        (self.a, self.b)
    }

    pub fn get_msb(&self) -> Share<Bit> {
        Share {
            a: self.a.get_msb(),
            b: self.b.get_msb(),
            sharetype: PhantomData,
        }
    }

    pub(crate) fn add_const(mut self, other: &T::Share, id: PartyID) -> Self {
        self.add_assign_const(other, id);
        self
    }

    pub(crate) fn add_assign_const(&mut self, other: &T::Share, id: PartyID) {
        match id {
            PartyID::ID0 => self.a += other,
            PartyID::ID1 => self.b += other,
            PartyID::ID2 => {}
        }
    }

    pub(crate) fn sub_const(mut self, other: &T::Share, id: PartyID) -> Self {
        self.sub_assign_const(other, id);
        self
    }

    pub(crate) fn sub_assign_const(&mut self, other: &T::Share, id: PartyID) {
        match id {
            PartyID::ID0 => self.a -= other,
            PartyID::ID1 => self.b -= other,
            PartyID::ID2 => {}
        }
    }

    pub(crate) fn xor_assign_const(&mut self, other: &T::Share, id: PartyID) {
        match id {
            PartyID::ID0 => self.a ^= other,
            PartyID::ID1 => self.b ^= other,
            PartyID::ID2 => {}
        }
    }
}

impl<T: Sharable> Add for Share<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Share {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
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
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> AddAssign for Share<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.a += &rhs.a;
        self.b += &rhs.b;
    }
}

impl<T: Sharable> AddAssign<&Share<T>> for Share<T> {
    fn add_assign(&mut self, rhs: &Self) {
        self.a += &rhs.a;
        self.b += &rhs.b;
    }
}

impl<T: Sharable> Sub for Share<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Share {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
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
    }
}

impl<T: Sharable> SubAssign<&Share<T>> for Share<T>
where
    for<'a> T::Share: SubAssign<&'a T::Share>,
{
    fn sub_assign(&mut self, rhs: &Self) {
        self.a -= &rhs.a;
        self.b -= &rhs.b;
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
    }
}

impl<T: Sharable, U: IntRing2k> MulAssign<&RingElement<U>> for Share<T>
where
    for<'a> T::Share: MulAssign<&'a RingElement<U>>,
{
    fn mul_assign(&mut self, rhs: &RingElement<U>) {
        self.a *= rhs;
        self.b *= rhs;
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
            sharetype: PhantomData,
        }
    }
}

/// This is only the local part of the multiplication (so without randomness and without communication)!
impl<T: Sharable> Mul for Share<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Share {
            a: (self.a.to_owned() * &rhs.a) + (self.a * &rhs.b) + (self.b * &rhs.a),
            b: T::Share::zero(),
            sharetype: PhantomData,
        }
    }
}

/// This is only the local part of the multiplication (so without randomness and without communication)!
impl<T: Sharable> Mul<&Share<T>> for Share<T> {
    type Output = Self;

    fn mul(self, rhs: &Share<T>) -> Self::Output {
        Share {
            a: (self.a.to_owned() * &rhs.a) + (self.a * &rhs.b) + (self.b * &rhs.a),
            b: T::Share::zero(),
            sharetype: PhantomData,
        }
    }
}

/// This is only the local part of the multiplication (so without randomness and without communication)!
impl<T: Sharable> MulAssign for Share<T> {
    fn mul_assign(&mut self, rhs: Self) {
        self.a = (self.a.to_owned() * &rhs.a)
            + (self.a.to_owned() * &rhs.b)
            + (self.b.to_owned() * &rhs.a);
        self.b = T::Share::zero();
    }
}

/// This is only the local part of the multiplication (so without randomness and without communication)!
impl<T: Sharable> MulAssign<&Share<T>> for Share<T> {
    fn mul_assign(&mut self, rhs: &Share<T>) {
        self.a = (self.a.to_owned() * &rhs.a)
            + (self.a.to_owned() * &rhs.b)
            + (self.b.to_owned() * &rhs.a);
        self.b = T::Share::zero();
    }
}

impl<T: Sharable> Neg for Share<T> {
    type Output = Self;

    fn neg(self) -> Self {
        Share {
            a: self.a.neg(),
            b: self.b.neg(),
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
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> BitXorAssign for Share<T> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.a ^= rhs.a;
        self.b ^= rhs.b;
    }
}

impl<T: Sharable> BitXorAssign<&Self> for Share<T> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.a ^= &rhs.a;
        self.b ^= &rhs.b;
    }
}

/// This is only the local part of the AND (so without randomness and without communication)!
impl<T: Sharable> BitAnd for Share<T> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Share {
            a: (self.a.to_owned() & &rhs.a) ^ (self.a & &rhs.b) ^ (self.b & &rhs.a),
            b: T::Share::zero(),
            sharetype: PhantomData,
        }
    }
}

/// This is only the local part of the AND (so without randomness and without communication)!
impl<T: Sharable> BitAnd<&Share<T>> for Share<T> {
    type Output = Self;

    fn bitand(self, rhs: &Share<T>) -> Self::Output {
        Share {
            a: (self.a.to_owned() & &rhs.a) ^ (self.a & &rhs.b) ^ (self.b & &rhs.a),
            b: T::Share::zero(),
            sharetype: PhantomData,
        }
    }
}

/// This is only the local part of the AND (so without randomness and without communication)!
impl<T: Sharable> BitAndAssign for Share<T> {
    fn bitand_assign(&mut self, rhs: Self) {
        self.a = (self.a.to_owned() & &rhs.a)
            ^ (self.a.to_owned() & &rhs.b)
            ^ (self.b.to_owned() & &rhs.a);
        self.b = T::Share::zero();
    }
}

/// This is only the local part of the AND (so without randomness and without communication)!
impl<T: Sharable> BitAndAssign<&Share<T>> for Share<T> {
    fn bitand_assign(&mut self, rhs: &Share<T>) {
        self.a = (self.a.to_owned() & &rhs.a)
            ^ (self.a.to_owned() & &rhs.b)
            ^ (self.b.to_owned() & &rhs.a);
        self.b = T::Share::zero();
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
    }
}

impl<T: Sharable, U: IntRing2k> BitAndAssign<&RingElement<U>> for Share<T>
where
    for<'a> T::Share: BitAndAssign<&'a RingElement<U>>,
{
    fn bitand_assign(&mut self, rhs: &RingElement<U>) {
        self.a &= rhs;
        self.b &= rhs;
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
            sharetype: PhantomData,
        }
    }
}

impl<T: Sharable> ShlAssign<u32> for Share<T> {
    fn shl_assign(&mut self, rhs: u32) {
        self.a <<= rhs;
        self.b <<= rhs;
    }
}

impl<T: Sharable> Zero for Share<T> {
    fn zero() -> Self {
        Self {
            a: T::Share::zero(),
            b: T::Share::zero(),
            sharetype: PhantomData,
        }
    }

    fn is_zero(&self) -> bool {
        self.a.is_zero() && self.b.is_zero()
    }
}
