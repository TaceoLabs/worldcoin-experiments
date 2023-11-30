use super::share::Share;
use super::utils::ceil_log2;
use crate::prelude::{Error, Sharable};
use crate::types::ring_element::RingImpl;

pub trait BinaryMpcTrait<T: Sharable> {
    fn xor(a: Share<T>, b: Share<T>) -> Share<T> {
        a ^ b
    }

    fn xor_assign(a: &mut Share<T>, b: Share<T>) {
        *a ^= b;
    }

    async fn and(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error>;

    async fn and_many(
        &mut self,
        a: Vec<Share<T>>,
        b: Vec<Share<T>>,
    ) -> Result<Vec<Share<T>>, Error>;

    async fn binary_add_3(
        &mut self,
        x1: Share<T>,
        x2: Share<T>,
        x3: Share<T>,
    ) -> Result<Share<T>, Error> {
        let k = T::Share::get_k();
        let logk = ceil_log2(k);

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
            let res = self.and_many(vec![p.to_owned(), p], vec![g_, p_]).await?;
            p = res[1].to_owned(); // p = p & p_
            Self::xor_assign(&mut g, res[0].to_owned()); // g = g ^ (p & g_)
        }
        g <<= 1;
        Ok(Self::xor(s_, g))
    }

    async fn arithmetic_to_binary(&mut self, x: Share<T>) -> Result<Share<T>, Error>;
}
