use crate::{
    prelude::{Aby3Share, Error, Sharable},
    types::ring_element::RingImpl,
};

#[derive(Clone, Debug)]
pub struct Triples {
    a: Vec<Aby3Share<u128>>,
    b: Vec<Aby3Share<u128>>,
    c: Vec<Aby3Share<u128>>,
    bits_in_last: usize,
}

impl Default for Triples {
    fn default() -> Self {
        Self {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            bits_in_last: 128,
        }
    }
}

impl Triples {
    pub fn new(a: Vec<Aby3Share<u128>>, b: Vec<Aby3Share<u128>>, c: Vec<Aby3Share<u128>>) -> Self {
        let bits_in_last = 128;
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
        self.bits_in_last = 128;
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
        self.bits_in_last = 128;
        Ok((a, b, c))
    }

    pub fn extend(&mut self, other: Self) {
        assert_eq!(other.bits_in_last, 128);
        self.a.extend(other.a);
        self.b.extend(other.b);
        self.c.extend(other.c);
    }

    fn push_t<T: Sharable>(a: &Aby3Share<T>, buffer: &mut Vec<Aby3Share<u128>>) {
        let (aa, ab) = a.clone().get_ab();
        let aa = aa.upgrade_to_128();
        let ab = ab.upgrade_to_128();
        buffer.push(Aby3Share::new(aa, ab));
    }

    fn add_all_t<T: Sharable>(a: &Aby3Share<T>, buffer: &mut [Aby3Share<u128>]) {
        let a_ = buffer.last_mut().expect("Is present");
        let (aa, ab) = a.clone().get_ab();
        let aa = aa.upgrade_to_128();
        let ab = ab.upgrade_to_128();

        a_.a <<= T::Share::K as u32;
        a_.b <<= T::Share::K as u32;
        a_.a |= aa;
        a_.b |= ab;
    }

    fn split_and_add_t<T: Sharable>(
        a: &Aby3Share<T>,
        buffer: &mut Vec<Aby3Share<u128>>,
        open: usize,
    ) {
        let a_ = buffer.last_mut().expect("Is present");
        let (aa, ab) = a.clone().get_ab();
        let mut aa = aa.upgrade_to_128();
        let mut ab = ab.upgrade_to_128();

        a_.a <<= open as u32;
        a_.b <<= open as u32;
        let mask = (1 << open) - 1;
        a_.a |= aa.to_owned() & mask;
        a_.b |= ab.to_owned() & mask;

        aa >>= open as u32;
        ab >>= open as u32;
        buffer.push(Aby3Share::new(aa, ab));
    }

    pub fn add_t<T: Sharable>(&mut self, a: &Aby3Share<T>, b: &Aby3Share<T>, c: &Aby3Share<T>) {
        let open = 128 - self.bits_in_last;
        if open == 0 {
            // put all into a new element
            Self::push_t(a, &mut self.a);
            Self::push_t(b, &mut self.b);
            Self::push_t(c, &mut self.c);

            self.bits_in_last = T::Share::K;
        } else if open >= T::Share::K {
            Self::add_all_t(a, &mut self.a);
            Self::add_all_t(b, &mut self.b);
            Self::add_all_t(c, &mut self.c);

            self.bits_in_last += T::Share::K;
        } else {
            // 0 < open < T::Share::K
            // We have to split
            let diff = T::Share::K - open;
            debug_assert!(open < T::Share::K);
            debug_assert!(open > 0);
            Self::split_and_add_t(a, &mut self.a, open);
            Self::split_and_add_t(b, &mut self.b, open);
            Self::split_and_add_t(c, &mut self.c, open);

            self.bits_in_last = diff;
        }
    }

    pub fn add_many_t<T: Sharable>(
        &mut self,
        a: &Vec<Aby3Share<T>>,
        b: &Vec<Aby3Share<T>>,
        c: &Vec<Aby3Share<T>>,
    ) {
        debug_assert_eq!(a.len(), b.len());
        debug_assert_eq!(a.len(), c.len());

        // TODO maybe optimize this
        for ((a_, b_), c_) in a.iter().zip(b).zip(c) {
            self.add_t(a_, b_, c_);
        }
    }
}
