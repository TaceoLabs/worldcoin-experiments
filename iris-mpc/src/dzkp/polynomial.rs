use super::gf2p64::GF2p64;
use crate::{prelude::Error, types::ring_element::RingImpl};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Mul, MulAssign, Rem, Sub, SubAssign};

pub(crate) trait PolyTrait:
    Clone
    + Serialize
    + for<'a> Deserialize<'a>
    + Default
    + AddAssign
    + for<'a> AddAssign<&'a Self>
    + SubAssign
    + for<'a> SubAssign<&'a Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> MulAssign<&'a Self>
    + Zero
    + One
    + PartialEq
{
}

impl<T: RingImpl> PolyTrait for T {}
impl<T: RingImpl> PolyTrait for Poly<T> {}
impl PolyTrait for GF2p64 {}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
pub(crate) struct Poly<T: PolyTrait> {
    pub coeffs: Vec<T>,
}

impl<T: PolyTrait> Poly<T> {
    pub fn from_vec(coeffs: Vec<T>) -> Self {
        Self { coeffs }
    }

    pub fn shrink(&mut self) {
        self.coeffs.resize(self.degree() + 1, T::default());
    }

    pub fn degree(&self) -> usize {
        for i in (0..self.coeffs.len()).rev() {
            if !self.coeffs[i].is_zero() {
                return i;
            }
        }
        0
    }

    pub fn leading_coeff(&self) -> &T {
        &self.coeffs[self.degree()]
    }
}

impl<T: RingImpl> Poly<T> {
    pub fn long_division(&self, other: &Self) -> Result<(Self, Self), Error> {
        let mut dividend = self.coeffs.clone();
        let degree = if dividend.len() >= other.coeffs.len() {
            dividend.len() - other.coeffs.len() + 1
        } else {
            1
        };
        let mut quotient = vec![T::default(); degree];

        let inv = other.leading_coeff().inverse()?;

        while dividend.len() >= other.coeffs.len() {
            let monomial = dividend.len() - other.coeffs.len();
            let coeff = dividend.pop().expect("size is not 0") * &inv;
            for (i, c) in other.coeffs.iter().enumerate().take(other.coeffs.len() - 1) {
                dividend[monomial + i] -= c.to_owned() * &coeff;
            }
            quotient[monomial] = coeff.to_owned();
        }

        Ok((Self::from_vec(quotient), Self::from_vec(dividend)))
    }

    // Mod 2 reduction
    fn to_gf2p64(&self) -> GF2p64 {
        assert!(T::K < 64);
        let mut u64 = 0;
        for coeff in self.coeffs.iter().rev() {
            u64 <<= 1;
            u64 |= (T::one() & coeff == T::one()) as u64;
        }
        GF2p64::new(u64)
    }

    fn from_u64(value: u64) -> Self {
        assert!(T::K < 64);
        let mut poly = Vec::with_capacity(T::K);

        for i in 0..64 {
            let coeff = (value >> i) & 1 == 1;
            poly.push(T::from(coeff));
        }
        let mut res = Self::from_vec(poly);
        res.shrink();
        res
    }

    fn mod_inverse_inner(&self, modulus: &Self, prime_power: usize) -> Self {
        if prime_power == 1 {
            let a_ = self.to_gf2p64();
            let mod_ = modulus.to_gf2p64();
            let inv = a_.inv_mod(mod_);
            Self::from_u64(inv.get())
        } else {
            let inv = Self::mod_inverse_inner(self, modulus, prime_power - 1);
            let r = (inv.to_owned() * self - T::one()) % modulus;
            let tmp = r * &inv;
            (inv - tmp) % modulus
        }
    }

    pub fn mod_inverse(&self, modulus: &Self) -> Self {
        self.mod_inverse_inner(modulus, T::K)
    }

    pub fn native_mod_inverse(&self) -> Self {
        let a_ = self.to_gf2p64();
        Self::from_u64(a_.inverse().get())
    }
}

impl<T: PolyTrait> Add for Poly<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let mut coeffs = vec![T::default(); len];
        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest = src;
        }

        for (src, dest) in rhs.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest += src;
        }

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> Add<&Self> for Poly<T> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let mut coeffs = vec![T::default(); len];
        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest = src;
        }

        for (src, dest) in rhs.coeffs.iter().zip(coeffs.iter_mut()) {
            *dest += src;
        }

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> Add<T> for Poly<T> {
    type Output = Self;

    fn add(self, rhs: T) -> Self::Output {
        let len = std::cmp::max(self.coeffs.len(), 1);
        let mut coeffs = vec![T::default(); len];
        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest = src;
        }
        coeffs[0] += rhs;

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> Add<&T> for Poly<T> {
    type Output = Self;

    fn add(self, rhs: &T) -> Self::Output {
        let len = std::cmp::max(self.coeffs.len(), 1);
        let mut coeffs = vec![T::default(); len];
        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest = src;
        }

        coeffs[0] += rhs;

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> AddAssign for Poly<T> {
    fn add_assign(&mut self, rhs: Self) {
        let len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        self.coeffs.resize(len, T::default());
        for (src, dest) in rhs.coeffs.into_iter().zip(self.coeffs.iter_mut()) {
            *dest += src;
        }
    }
}

impl<T: PolyTrait> AddAssign<&Self> for Poly<T> {
    fn add_assign(&mut self, rhs: &Self) {
        let len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        self.coeffs.resize(len, T::default());
        for (src, dest) in rhs.coeffs.iter().zip(self.coeffs.iter_mut()) {
            *dest += src;
        }
    }
}

impl<T: PolyTrait> AddAssign<T> for Poly<T> {
    fn add_assign(&mut self, rhs: T) {
        let len = std::cmp::max(self.coeffs.len(), 1);
        self.coeffs.resize(len, T::default());

        self.coeffs[0] += rhs;
    }
}

impl<T: PolyTrait> AddAssign<&T> for Poly<T> {
    fn add_assign(&mut self, rhs: &T) {
        let len = std::cmp::max(self.coeffs.len(), 1);
        self.coeffs.resize(len, T::default());

        self.coeffs[0] += rhs;
    }
}

impl<T: PolyTrait> Sub for Poly<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let mut coeffs = vec![T::default(); len];
        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest = src;
        }

        for (src, dest) in rhs.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest -= src;
        }

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> Sub<&Self> for Poly<T> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let mut coeffs = vec![T::default(); len];
        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest = src;
        }

        for (src, dest) in rhs.coeffs.iter().zip(coeffs.iter_mut()) {
            *dest -= src;
        }

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> Sub<T> for Poly<T> {
    type Output = Self;

    fn sub(self, rhs: T) -> Self::Output {
        let len = std::cmp::max(self.coeffs.len(), 1);
        let mut coeffs = vec![T::default(); len];
        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest = src;
        }
        coeffs[0] -= rhs;

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> Sub<&T> for Poly<T> {
    type Output = Self;

    fn sub(self, rhs: &T) -> Self::Output {
        let len = std::cmp::max(self.coeffs.len(), 1);
        let mut coeffs = vec![T::default(); len];
        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest = src;
        }

        coeffs[0] -= rhs;

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> SubAssign for Poly<T> {
    fn sub_assign(&mut self, rhs: Self) {
        let len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        self.coeffs.resize(len, T::default());
        for (src, dest) in rhs.coeffs.into_iter().zip(self.coeffs.iter_mut()) {
            *dest -= src;
        }
    }
}

impl<T: PolyTrait> SubAssign<&Self> for Poly<T> {
    fn sub_assign(&mut self, rhs: &Self) {
        let len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        self.coeffs.resize(len, T::default());
        for (src, dest) in rhs.coeffs.iter().zip(self.coeffs.iter_mut()) {
            *dest -= src;
        }
    }
}

impl<T: PolyTrait> SubAssign<T> for Poly<T> {
    fn sub_assign(&mut self, rhs: T) {
        let len = std::cmp::max(self.coeffs.len(), 1);
        self.coeffs.resize(len, T::default());

        self.coeffs[0] -= rhs;
    }
}

impl<T: PolyTrait> SubAssign<&T> for Poly<T> {
    fn sub_assign(&mut self, rhs: &T) {
        let len = std::cmp::max(self.coeffs.len(), 1);
        self.coeffs.resize(len, T::default());

        self.coeffs[0] -= rhs;
    }
}

impl<T: PolyTrait> Mul for Poly<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let len = self.coeffs.len() + rhs.coeffs.len() - 1;
        let mut coeffs = vec![T::default(); len];

        for (i, a) in self.coeffs.into_iter().enumerate() {
            for (j, b) in rhs.coeffs.iter().enumerate() {
                coeffs[i + j] += a.to_owned() * b;
            }
        }

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> Mul<&Self> for Poly<T> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        let len = self.coeffs.len() + rhs.coeffs.len() - 1;
        let mut coeffs = vec![T::default(); len];

        for (i, a) in self.coeffs.into_iter().enumerate() {
            for (j, b) in rhs.coeffs.iter().enumerate() {
                coeffs[i + j] += a.to_owned() * b;
            }
        }

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> Mul<T> for Poly<T> {
    type Output = Self;

    fn mul(self, rhs: T) -> Self::Output {
        let len = self.coeffs.len();
        let mut coeffs = vec![T::default(); len];

        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest += src * &rhs;
        }

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> Mul<&T> for Poly<T> {
    type Output = Self;

    fn mul(self, rhs: &T) -> Self::Output {
        let len = self.coeffs.len();
        let mut coeffs = vec![T::default(); len];

        for (src, dest) in self.coeffs.into_iter().zip(coeffs.iter_mut()) {
            *dest += src * rhs;
        }

        Self::from_vec(coeffs)
    }
}

impl<T: PolyTrait> MulAssign for Poly<T> {
    fn mul_assign(&mut self, rhs: Self) {
        let res = rhs * &*self;
        self.coeffs = res.coeffs;
    }
}

impl<T: PolyTrait> MulAssign<&Self> for Poly<T> {
    fn mul_assign(&mut self, rhs: &Self) {
        let res = self.to_owned() * rhs;
        self.coeffs = res.coeffs;
    }
}

impl<T: PolyTrait> MulAssign<T> for Poly<T> {
    fn mul_assign(&mut self, rhs: T) {
        for coeff in self.coeffs.iter_mut() {
            *coeff *= &rhs;
        }
    }
}

impl<T: PolyTrait> MulAssign<&T> for Poly<T> {
    fn mul_assign(&mut self, rhs: &T) {
        for coeff in self.coeffs.iter_mut() {
            *coeff *= rhs;
        }
    }
}

impl<T: RingImpl> Rem for Poly<T> {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        let (_, mut rem) = self.long_division(&rhs).expect("division should work");
        rem.shrink();
        rem
    }
}

impl<T: RingImpl> Rem<&Self> for Poly<T> {
    type Output = Self;

    fn rem(self, rhs: &Self) -> Self::Output {
        let (_, mut rem) = self.long_division(rhs).expect("division should work");
        rem.shrink();
        rem
    }
}

impl<T: PolyTrait> Zero for Poly<T> {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        self.coeffs.is_empty() || self.coeffs.iter().all(|c| c.is_zero())
    }
}

impl<T: PolyTrait> One for Poly<T> {
    fn one() -> Self {
        Self::from_vec(vec![T::one()])
    }

    fn is_one(&self) -> bool {
        self.degree() == 1 && self.leading_coeff().is_one()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::ring_element::RingElement;
    use rand::{rngs::SmallRng, Rng, SeedableRng};

    const TESTRUNS: usize = 100;

    #[test]
    fn test_long_division_u16() {
        let a = Poly::<RingElement<u16>>::from_vec(vec![
            RingElement(31322),
            RingElement(11328),
            RingElement(31819),
            RingElement(62992),
            RingElement(2073),
            RingElement(5459),
            RingElement(15884),
            RingElement(41216),
            RingElement(28781),
            RingElement(62039),
            RingElement(30213),
            RingElement(57012),
            RingElement(50078),
        ]);

        let b = Poly::<RingElement<u16>>::from_vec(vec![
            RingElement(1),
            RingElement(1),
            RingElement(0),
            RingElement(0),
            RingElement(0),
            RingElement(0),
            RingElement(0),
            RingElement(1),
        ]);

        let q = Poly::<RingElement<u16>>::from_vec(vec![
            RingElement(41216),
            RingElement(28781),
            RingElement(62039),
            RingElement(30213),
            RingElement(57012),
            RingElement(50078),
        ]);

        let r = Poly::<RingElement<u16>>::from_vec(vec![
            RingElement(55642),
            RingElement(6867),
            RingElement(6535),
            RingElement(36276),
            RingElement(45920),
            RingElement(29441),
            RingElement(31342),
        ]);

        let (q_, r_) = a.long_division(&b).expect("division should work");
        assert_eq!(q_, q);
        assert_eq!(r_, r);
    }

    #[test]
    fn modular_inverse_test_u16() {
        let a = Poly::<RingElement<u16>>::from_vec(vec![
            RingElement(10638),
            RingElement(59644),
            RingElement(21330),
            RingElement(13369),
            RingElement(19200),
            RingElement(51558),
            RingElement(55586),
        ]);

        let b = Poly::<RingElement<u16>>::from_vec(vec![
            RingElement(1),
            RingElement(1),
            RingElement(0),
            RingElement(0),
            RingElement(0),
            RingElement(0),
            RingElement(0),
            RingElement(1),
        ]);

        let r = Poly::<RingElement<u16>>::from_vec(vec![
            RingElement(34051),
            RingElement(37470),
            RingElement(16694),
            RingElement(45000),
            RingElement(21219),
            RingElement(47161),
            RingElement(17673),
        ]);

        assert_eq!(
            (a.to_owned() * &r) % &b,
            Poly::<RingElement<u16>>::from_vec(vec![RingElement(1)])
        );

        let r_ = a.mod_inverse(&b);

        assert_eq!(r_, r);
    }

    fn random_bits<R: Rng>(size: usize, rng: &mut R) -> Vec<RingElement<u16>> {
        (0..size)
            .map(|_| RingElement::from(rng.gen::<bool>()))
            .collect()
    }

    #[test]
    fn rand_modular_inverse_test_u16() {
        let mut modulus = Poly::<RingElement<u16>>::from_vec(vec![RingElement::zero(); 48]);
        modulus.coeffs[0] = RingElement::one();
        modulus.coeffs[5] = RingElement::one();
        modulus.coeffs[47] = RingElement::one();
        assert_eq!(modulus.degree(), 47);

        let mut rng = SmallRng::from_entropy();

        for _ in 0..TESTRUNS {
            let vec_a = random_bits(47, &mut rng);
            let mut vec_b = random_bits(47, &mut rng);
            while vec_a == vec_b {
                vec_b = random_bits(47, &mut rng);
            }

            let a = Poly::<RingElement<u16>>::from_vec(vec_a);
            let b = Poly::<RingElement<u16>>::from_vec(vec_b);
            let c = a - b;
            assert!(c.degree() < 47);

            let inv = c.mod_inverse(&modulus);

            assert_eq!(
                (c * &inv) % &modulus,
                Poly::from_vec(vec![RingElement::one()])
            );
        }
    }
}
