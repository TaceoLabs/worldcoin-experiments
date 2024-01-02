use crate::aby3::utils::ceil_log2;
use crate::prelude::{Error, Sharable};
use crate::types::ring_element::RingImpl;
use std::ops::{BitXor, BitXorAssign};

pub trait BinaryMpcTrait<T: Sharable, Bshare>
where
    Bshare: Clone
        + BitXorAssign
        + BitXor<Output = Bshare>
        + std::ops::ShlAssign<u32>
        + std::ops::Shl<u32, Output = Bshare>
        + Send
        + Sync
        + 'static,
{
    fn xor(a: Bshare, b: Bshare) -> Bshare {
        a ^ b
    }

    fn xor_many(a: Vec<Bshare>, b: Vec<Bshare>) -> Result<Vec<Bshare>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }
        let res = a
            .into_iter()
            .zip(b)
            .map(|(a_, b_)| Self::xor(a_, b_))
            .collect();
        Ok(res)
    }

    fn xor_assign(a: &mut Bshare, b: Bshare) {
        *a ^= b;
    }

    fn xor_assign_many(a: &mut Vec<Bshare>, b: Vec<Bshare>) -> Result<(), Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }
        for (a_, b_) in a.iter_mut().zip(b) {
            Self::xor_assign(a_, b_);
        }
        Ok(())
    }

    fn and(&mut self, a: Bshare, b: Bshare) -> Result<Bshare, Error>;

    fn and_many(&mut self, a: Vec<Bshare>, b: Vec<Bshare>) -> Result<Vec<Bshare>, Error>;

    fn or(&mut self, a: Bshare, b: Bshare) -> Result<Bshare, Error> {
        let x = Self::xor(a.to_owned(), b.to_owned());
        let y = self.and(a, b)?;
        Ok(Self::xor(x, y))
    }

    fn or_many(&mut self, a: Vec<Bshare>, b: Vec<Bshare>) -> Result<Vec<Bshare>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }
        let y = self.and_many(a.to_owned(), b.to_owned())?;
        let res = a
            .into_iter()
            .zip(b.into_iter())
            .zip(y.into_iter())
            .map(|((a_, b_), y_)| Self::xor(y_, Self::xor(a_, b_)))
            .collect();
        Ok(res)
    }

    fn binary_add_3(&mut self, x1: Bshare, x2: Bshare, x3: Bshare) -> Result<Bshare, Error> {
        let logk = ceil_log2(T::Share::K);

        // Full Adder
        let x2x3 = Self::xor(x2, x3.to_owned());
        let s = Self::xor(x1.to_owned(), x2x3.to_owned());
        let x1x3 = Self::xor(x1, x3.to_owned());
        let mut c = self.and(x1x3, x2x3)?;
        Self::xor_assign(&mut c, x3);

        // Add 2c + s via a packed Kogge-Stone adder
        c <<= 1;
        let mut p = Self::xor(s.to_owned(), c.to_owned());
        let mut g = self.and(s, c)?;
        let s_ = p.to_owned();
        for i in 0..logk {
            let p_ = p.to_owned() << (1 << i);
            let g_ = g.to_owned() << (1 << i);
            // TODO Maybe work with Bits in the inner loop to have less communication?
            let res = self.and_many(vec![p.to_owned(), p], vec![g_, p_])?;
            p = res[1].to_owned(); // p = p & p_
            Self::xor_assign(&mut g, res[0].to_owned()); // g = g ^ (p & g_)
        }
        g <<= 1;
        Ok(Self::xor(s_, g))
    }

    fn binary_add_3_many(
        &mut self,
        x1: Vec<Bshare>,
        x2: Vec<Bshare>,
        x3: Vec<Bshare>,
    ) -> Result<Vec<Bshare>, Error> {
        let len = x1.len();
        if len != x2.len() || len != x3.len() {
            return Err(Error::InvalidSizeError);
        }

        let logk = ceil_log2(T::Share::K);

        // Full Adder
        let x2x3 = Self::xor_many(x2, x3.to_owned()).expect("Same length");
        let s = Self::xor_many(x1.to_owned(), x2x3.to_owned()).expect("Same length");
        let x1x3 = Self::xor_many(x1, x3.to_owned()).expect("Same length");
        let mut c = self.and_many(x1x3, x2x3)?;
        c.iter_mut().zip(x3.into_iter()).for_each(|(c_, x3_)| {
            Self::xor_assign(c_, x3_);
            *c_ <<= 1 // c = 2*c
        });

        // Add 2c + s via a packed Kogge-Stone adder

        let mut p = Self::xor_many(s.to_owned(), c.to_owned()).expect("Same length");
        let mut g = self.and_many(s, c)?;
        let s_ = p.to_owned();
        for i in 0..logk {
            let p_: Vec<Bshare> = p.iter().cloned().map(|p_| p_ << (1 << i)).collect();
            let g_: Vec<Bshare> = g.iter().cloned().map(|g_| g_ << (1 << i)).collect();

            // TODO Maybe work with Bits in the inner loop to have less communication?

            // build inputs
            let mut a = p.to_owned();
            a.extend(p);
            let mut b = g_.to_owned();
            b.extend(p_);

            let res = self.and_many(a, b)?;
            p = res[len..].to_vec(); // p = p & p_
            g.iter_mut()
                .zip(res[0..len].to_vec())
                .for_each(|(g_, r_)| Self::xor_assign(g_, r_)); // g = g ^ (p & g_)
        }
        g.iter_mut().for_each(|g_| *g_ <<= 1);

        let res = s_
            .into_iter()
            .zip(g.into_iter())
            .map(|(s_, g_)| Self::xor(s_, g_))
            .collect();

        Ok(res)
    }

    fn arithmetic_to_binary(&mut self, x: Bshare) -> Result<Bshare, Error>;
    fn arithmetic_to_binary_many(&mut self, x: Vec<Bshare>) -> Result<Vec<Bshare>, Error>;
}
