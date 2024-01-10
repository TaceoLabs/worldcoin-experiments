use crate::prelude::{Aby3Share, Error};

#[derive(Clone, Debug, Default)]
pub struct Triples {
    a: Vec<Aby3Share<u128>>,
    b: Vec<Aby3Share<u128>>,
    c: Vec<Aby3Share<u128>>,
}

impl Triples {
    pub fn new(a: Vec<Aby3Share<u128>>, b: Vec<Aby3Share<u128>>, c: Vec<Aby3Share<u128>>) -> Self {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), c.len());
        Self { a, b, c }
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
        self.a.extend(other.a);
        self.b.extend(other.b);
        self.c.extend(other.c);
    }
}
