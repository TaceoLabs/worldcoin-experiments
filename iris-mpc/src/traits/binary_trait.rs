use super::share_trait::{ShareTrait, VecShareTrait};
use crate::aby3::utils::ceil_log2;
use crate::prelude::{Error, Sharable};
use crate::types::ring_element::RingImpl;
use std::ops::{BitXor, BitXorAssign};

pub trait BinaryMpcTrait<T: Sharable, Bshare: ShareTrait>
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

    fn xor_many(a: Bshare::VecShare, b: Bshare::VecShare) -> Result<Bshare::VecShare, Error> {
        a.xor_many(b)
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

    async fn and(&mut self, a: Bshare, b: Bshare) -> Result<Bshare, Error>;

    async fn and_many(
        &mut self,
        a: Bshare::VecShare,
        b: Bshare::VecShare,
    ) -> Result<Bshare::VecShare, Error>;

    async fn or(&mut self, a: Bshare, b: Bshare) -> Result<Bshare, Error> {
        let x = Self::xor(a.to_owned(), b.to_owned());
        let y = self.and(a, b).await?;
        Ok(Self::xor(x, y))
    }

    async fn or_many(
        &mut self,
        a: Bshare::VecShare,
        b: Bshare::VecShare,
    ) -> Result<Bshare::VecShare, Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }
        let y = self.and_many(a.to_owned(), b.to_owned()).await?;
        y.xor_many(a.xor_many(b)?)
    }

    async fn binary_add_3(&mut self, x1: Bshare, x2: Bshare, x3: Bshare) -> Result<Bshare, Error> {
        let logk = ceil_log2(T::Share::K);

        // Full Adder
        let x2x3 = Self::xor(x2, x3.to_owned());
        let s = Self::xor(x1.to_owned(), x2x3.to_owned());
        let x1x3 = Self::xor(x1, x3.to_owned());
        let mut c = self.and(x1x3, x2x3).await?;
        Self::xor_assign(&mut c, x3);

        // Add 2c + s via a packed Kogge-Stone adder
        c <<= 1;
        let mut p = Self::xor(s.to_owned(), c.to_owned());
        let mut g = self.and(s, c).await?;
        let s_ = p.to_owned();
        for i in 0..logk {
            let p_ = p.to_owned() << (1 << i);
            let g_ = g.to_owned() << (1 << i);
            // TODO Maybe work with Bits in the inner loop to have less communication?
            let mut and_inp1 = Bshare::VecShare::with_capacity(2);
            let mut and_inp2 = Bshare::VecShare::with_capacity(2);
            and_inp1.push(p.to_owned());
            and_inp1.push(p);
            and_inp2.push(g_);
            and_inp2.push(p_);
            let res = self.and_many(and_inp1, and_inp2).await?;
            p = res.get_at(1).to_owned(); // p = p & p_
            Self::xor_assign(&mut g, res.get_at(0).to_owned()); // g = g ^ (p & g_)
        }
        g <<= 1;
        Ok(Self::xor(s_, g))
    }

    async fn binary_add_3_many(
        &mut self,
        x1: Bshare::VecShare,
        x2: Bshare::VecShare,
        x3: Bshare::VecShare,
    ) -> Result<Bshare::VecShare, Error> {
        let len = x1.len();
        if len != x2.len() || len != x3.len() {
            return Err(Error::InvalidSizeError);
        }

        let logk = ceil_log2(T::Share::K);

        // Full Adder
        let x2x3 = Self::xor_many(x2, x3.to_owned()).expect("Same length");
        let s = Self::xor_many(x1.to_owned(), x2x3.to_owned()).expect("Same length");
        let x1x3 = Self::xor_many(x1, x3.to_owned()).expect("Same length");

        let mut c = self.and_many(x1x3, x2x3).await?;
        c.xor_assign_many(x3).expect("Same length");
        c.shl_assign_many(1); // c= 2*c;

        // Add 2c + s via a packed Kogge-Stone adder

        let mut p = Self::xor_many(s.to_owned(), c.to_owned()).expect("Same length");
        let mut g = self.and_many(s, c).await?;
        let s_ = p.to_owned();
        for i in 0..logk {
            let mut p_ = p.to_owned();
            p_.shl_assign_many(1 << i);
            let mut g_ = g.to_owned();
            g_.shl_assign_many(1 << i);

            // TODO Maybe work with Bits in the inner loop to have less communication?

            // build inputs
            let mut a = p.to_owned();
            a.extend(p);
            let mut b = g_.to_owned();
            b.extend(p_);

            let res = self.and_many(a, b).await?;
            let (tmp_g, tmp_p) = res.split_at(len);
            p = tmp_p; // p = p & p_
            g.xor_assign_many(tmp_g).expect("Same length"); // g = g ^ (p & g_)
        }
        g.shl_assign_many(1);
        s_.xor_many(g)
    }

    async fn arithmetic_to_binary(&mut self, x: Bshare) -> Result<Bshare, Error>;
    async fn arithmetic_to_binary_many(
        &mut self,
        x: Vec<Bshare>,
    ) -> Result<Bshare::VecShare, Error>;
}
