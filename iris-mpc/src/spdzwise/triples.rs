use crate::{
    prelude::{Aby3Share, Error, Sharable},
    types::ring_element::RingImpl,
};

#[derive(Clone, Debug, Default)]
pub struct Triples {
    a: Vec<Aby3Share<u128>>,
    b: Vec<Aby3Share<u128>>,
    c: Vec<Aby3Share<u128>>,
    bits_in_last: usize,
}

impl Triples {
    pub fn new(a: Vec<Aby3Share<u128>>, b: Vec<Aby3Share<u128>>, c: Vec<Aby3Share<u128>>) -> Self {
        let bits_in_last = if a.is_empty() { 0 } else { 128 };
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), c.len());
        Self {
            a,
            b,
            c,
            bits_in_last,
        }
    }

    pub fn len(&self) -> usize {
        debug_assert!(self.a.len() == self.b.len());
        debug_assert!(self.a.len() == self.c.len());
        self.a.len()
    }

    #[allow(clippy::type_complexity)]
    pub fn get_all(
        &mut self,
    ) -> (
        Vec<Aby3Share<u128>>,
        Vec<Aby3Share<u128>>,
        Vec<Aby3Share<u128>>,
    ) {
        let a = std::mem::take(&mut self.a);
        let b = std::mem::take(&mut self.b);
        let c = std::mem::take(&mut self.c);
        (a, b, c)
    }

    // Gets a multiple of 128 triples
    #[allow(clippy::type_complexity)]
    pub fn get(
        &mut self,
        amount: usize,
    ) -> Result<
        (
            Vec<Aby3Share<u128>>,
            Vec<Aby3Share<u128>>,
            Vec<Aby3Share<u128>>,
        ),
        Error,
    > {
        if amount > self.len() {
            return Err(Error::NotEnoughTriplesError);
        }

        let a = self.a.drain(0..amount).collect();
        let b = self.b.drain(0..amount).collect();
        let c = self.c.drain(0..amount).collect();
        Ok((a, b, c))
    }

    pub fn extend(&mut self, other: Self) {
        assert_eq!(other.bits_in_last, 128);
        self.a.extend(other.a);
        self.b.extend(other.b);
        self.c.extend(other.c);
    }

    pub fn add_t<T: Sharable>(
        &mut self,
        a: Aby3Share<T>,
        b: Aby3Share<T>,
        c: Aby3Share<T>,
    ) -> Result<(), Error> {
        let open = 128 - self.bits_in_last;
        if open == 0 {
            // put all into a new element
            let (aa, ab) = a.get_ab();
            let aa = aa.upgrade_to_128();
            let ab = ab.upgrade_to_128();
            self.a.push(Aby3Share::new(aa, ab));
        } else if open > T::Share::K {
            // TODO wip
        }
        todo!()
    }
}
