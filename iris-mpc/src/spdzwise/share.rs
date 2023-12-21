use crate::prelude::{Aby3Share, Sharable};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::ops::Add;

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Share<T: Sharable> {
    value: Aby3Share<T>,
    mac: Aby3Share<T>,
}

impl<T: Sharable> Share<T> {
    pub fn new(value: Aby3Share<T>, mac: Aby3Share<T>) -> Self {
        Self { value, mac }
    }

    pub fn get(self) -> (Aby3Share<T>, Aby3Share<T>) {
        (self.value, self.mac)
    }

    pub fn get_value(self) -> Aby3Share<T> {
        self.value
    }
}

impl<T: Sharable> Add for Share<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value + rhs.value,
            mac: self.mac + rhs.mac,
        }
    }
}

impl<T: Sharable> Zero for Share<T> {
    fn zero() -> Self {
        Self {
            value: Aby3Share::zero(),
            mac: Aby3Share::zero(),
        }
    }

    // TODO is this corect?
    fn is_zero(&self) -> bool {
        self.value.is_zero() && self.mac.is_zero()
    }
}
