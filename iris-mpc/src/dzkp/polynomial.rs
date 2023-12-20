use super::gf2p64::GF2p64;
use crate::{prelude::Error, types::ring_element::RingImpl};
use num_traits::{One, Zero};
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Rem, Sub, SubAssign};

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
    + Neg<Output = Self>
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

    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Self
    where
        Standard: Distribution<T>,
    {
        let coeffs = (0..=degree).map(|_| rng.gen::<T>()).collect();
        Self::from_vec(coeffs)
    }

    pub fn shrink(&mut self) {
        self.coeffs.resize(self.degree() + 1, T::default());
    }

    pub fn lift(inp: T) -> Self {
        Self::from_vec(vec![inp])
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

    pub fn evaluate(self, x: &T) -> T {
        let mut res = T::zero();
        for coeff in self.coeffs.into_iter().rev() {
            res = res * x + coeff;
        }
        res
    }

    pub fn interpolate(ys: &[T], lagrange_polys: &[Poly<T>]) -> Self {
        assert_eq!(ys.len(), lagrange_polys.len());
        let mut res = Self::zero();
        for (poly, y) in lagrange_polys.iter().cloned().zip(ys.iter()) {
            res += poly * y;
        }
        res
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

    #[allow(dead_code)]
    fn native_mod_inverse_inner(&self, modulus: &Self, prime_power: usize) -> Self {
        if prime_power == 1 {
            let a_ = self.to_gf2p64();
            let inv = a_.inverse();
            Self::from_u64(inv.get())
        } else {
            let inv = Self::native_mod_inverse_inner(self, modulus, prime_power - 1);
            let r = (inv.to_owned() * self - T::one()) % modulus;
            let tmp = r * &inv;
            (inv - tmp) % modulus
        }
    }

    #[allow(dead_code)]
    pub fn native_mod_inverse(&self) -> Self {
        let modulus: Poly<T> = Self::get_native_mod();
        self.native_mod_inverse_inner(&modulus, T::K)
    }

    #[allow(dead_code)]
    pub fn get_native_mod() -> Poly<T> {
        Poly::<T>::from_vec(GF2p64::MODULUS.iter().map(|&x| T::from(x)).collect())
    }
}

impl<T: RingImpl> Poly<Poly<T>> {
    pub fn reduce_coeffs(&mut self, modulus: &Poly<T>) {
        for coeff in self.coeffs.iter_mut() {
            *coeff = coeff.to_owned() % modulus;
        }
    }

    pub fn lagrange_polys(xs: &[Poly<T>], modulus: &Poly<T>) -> Vec<Self> {
        let mut polys = Vec::with_capacity(xs.len());
        for j in 0..xs.len() {
            let mut poly = Self::one();
            for i in 0..xs.len() {
                if i != j {
                    let inv = xs[j].to_owned() - &xs[i];
                    poly *= Self::from_vec(vec![-xs[i].to_owned(), Poly::one()])
                        * &inv.mod_inverse(modulus);
                }
            }
            poly.reduce_coeffs(modulus);
            polys.push(poly);
        }
        polys
    }

    #[allow(dead_code)]
    pub fn native_lagrange_polys(xs: &[Poly<T>]) -> Vec<Self> {
        let mut polys = Vec::with_capacity(xs.len());
        for j in 0..xs.len() {
            let mut poly = Self::one();
            for i in 0..xs.len() {
                if i != j {
                    let inv = xs[j].to_owned() - &xs[i];
                    poly *= Self::from_vec(vec![-xs[i].to_owned(), Poly::one()])
                        * &inv.native_mod_inverse();
                }
            }
            polys.push(poly);
        }
        polys
    }
}

impl Poly<GF2p64> {
    pub fn lagrange_polys(xs: &[GF2p64]) -> Vec<Self> {
        let mut polys = Vec::with_capacity(xs.len());
        for j in 0..xs.len() {
            let mut poly = Self::one();
            for i in 0..xs.len() {
                if i != j {
                    let inv = xs[j].to_owned() - xs[i];
                    poly *= Self::from_vec(vec![-xs[i].to_owned(), GF2p64::one()]) * inv.inverse();
                }
            }
            polys.push(poly);
        }
        polys
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
        if self.is_zero() || rhs.is_zero() {
            return Self::zero();
        }
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
        if self.is_zero() || rhs.is_zero() {
            return Self::zero();
        }
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
            *dest = src * &rhs;
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
            *dest = src * rhs;
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

impl<T: PolyTrait> Neg for Poly<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut coeffs = Vec::with_capacity(self.coeffs.len());
        for coeff in self.coeffs.into_iter() {
            coeffs.push(-coeff);
        }
        Self::from_vec(coeffs)
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
    use crate::{aby3::utils, types::ring_element::RingElement};
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

    #[test]
    fn interpolate_test_u16() {
        let mut modulus = Poly::<RingElement<u16>>::from_vec(vec![RingElement::zero(); 48]);
        modulus.coeffs[0] = RingElement::one();
        modulus.coeffs[5] = RingElement::one();
        modulus.coeffs[47] = RingElement::one();
        assert_eq!(modulus.degree(), 47);

        const NUM_POINTS: usize = 10;

        let points: Vec<Poly<RingElement<u16>>> = (0..NUM_POINTS)
            .map(|x| Poly::from_vec(utils::to_bits(x)))
            .collect();
        let lagrange_polys = Poly::<Poly<RingElement<u16>>>::lagrange_polys(&points, &modulus);

        let mut rng = SmallRng::from_entropy();

        let ys = (0..NUM_POINTS)
            .map(|_| Poly::random(46, &mut rng))
            .collect::<Vec<_>>();

        let interpolated = Poly::interpolate(&ys, &lagrange_polys);

        for (point, y) in points.into_iter().zip(ys.into_iter()) {
            assert_eq!(interpolated.to_owned().evaluate(&point) % &modulus, y);
        }
    }

    #[test]
    fn interpolate_test_u16_native() {
        let modulus = Poly::<RingElement<u16>>::get_native_mod();
        assert_eq!(modulus.degree(), 64);

        const NUM_POINTS: usize = 10;

        let points: Vec<Poly<RingElement<u16>>> = (0..NUM_POINTS)
            .map(|x| Poly::from_vec(utils::to_bits(x)))
            .collect();
        let lagrange_polys = Poly::<Poly<RingElement<u16>>>::native_lagrange_polys(&points);

        let mut rng = SmallRng::from_entropy();

        let ys = (0..NUM_POINTS)
            .map(|_| Poly::random(63, &mut rng))
            .collect::<Vec<_>>();

        let mut interpolated = Poly::interpolate(&ys, &lagrange_polys);
        interpolated.reduce_coeffs(&modulus);

        for (point, y) in points.into_iter().zip(ys.into_iter()) {
            assert_eq!(interpolated.to_owned().evaluate(&point) % &modulus, y);
        }
    }

    #[test]
    fn interpolate_test_gf2() {
        const NUM_POINTS: usize = 10;

        let points: Vec<GF2p64> = (0..NUM_POINTS).map(|x| GF2p64::new(x as u64)).collect();
        let lagrange_polys = Poly::<GF2p64>::lagrange_polys(&points);

        let mut rng = SmallRng::from_entropy();

        let ys = (0..NUM_POINTS)
            .map(|_| GF2p64::random(&mut rng))
            .collect::<Vec<_>>();

        let interpolated = Poly::interpolate(&ys, &lagrange_polys);

        for (point, y) in points.into_iter().zip(ys.into_iter()) {
            assert_eq!(interpolated.to_owned().evaluate(&point), y);
        }
    }
}
