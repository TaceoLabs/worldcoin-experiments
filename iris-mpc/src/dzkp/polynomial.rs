use crate::{prelude::Error, types::ring_element::RingImpl};
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Mul, Rem, Sub, SubAssign};

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
{
    fn inverse(&self) -> Result<Self, Error>;
}

impl<T: RingImpl> PolyTrait for T {
    fn inverse(&self) -> Result<Self, Error> {
        self.inverse()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct Poly<T: PolyTrait> {
    pub coeffs: Vec<T>,
}

impl<T: PolyTrait> Poly<T> {
    pub fn from_vec(coeffs: Vec<T>) -> Self {
        Self { coeffs }
    }

    pub fn degree(&self) -> usize {
        self.coeffs.len() - 1
    }

    pub fn leading_coeff_ref(&self) -> &T {
        &self.coeffs[self.degree()]
    }

    pub fn long_division(&self, other: &Self) -> Result<(Self, Self), Error> {
        let mut dividend = self.coeffs.clone();
        let mut quotient = vec![T::default(); dividend.len() - other.coeffs.len() + 1];

        let inv = other.leading_coeff_ref().inverse()?;

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

impl<T: PolyTrait> Rem for Poly<T> {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        let (_, rem) = self.long_division(&rhs).expect("division should work");
        rem
    }
}
