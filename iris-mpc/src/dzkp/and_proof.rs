use super::{gf2p64::GF2p64, polynomial::Poly};
use crate::types::ring_element::RingImpl;
use rand::{Rng, SeedableRng};

#[derive(Default)]
struct Input {
    a0: bool,
    a1: bool,
    b0: bool,
    b1: bool,
    r: bool,
    s: bool,
}

pub(crate) struct Proof {
    w: Vec<Poly<GF2p64>>,
    a: Vec<Poly<GF2p64>>,
}

#[derive(Default)]
pub(crate) struct AndProof {
    l: usize,
    m: usize,
    proof: Vec<Input>,       // For P0: This is the proof of P0
    verify_prev: Vec<Input>, // For P1: This is to verify the proof of P0
    verify_next: Vec<Input>, // For P2: This is to verify the proof of P0
}

impl AndProof {
    // const D: usize = 64; // This is because of the GF2p64 modulus implementation

    #[allow(clippy::too_many_arguments)]
    pub fn register_and<T: RingImpl>(
        &mut self,
        mut a0: T,
        mut a1: T,
        mut b0: T,
        mut b1: T,
        mut r0: T,
        mut r1: T,
        mut s0: T,
        mut s1: T,
    ) {
        self.proof.reserve(T::K);
        self.verify_prev.reserve(T::K);
        self.verify_next.reserve(T::K);

        for i in 0..T::K {
            let a0_i = T::one() & &a0 == T::one();
            let a1_i = T::one() & &a1 == T::one();
            let b0_i = T::one() & &b0 == T::one();
            let b1_i = T::one() & &b1 == T::one();
            let r0_i = T::one() & &r0 == T::one();
            let r1_i = T::one() & &r1 == T::one();
            let s0_i = T::one() & &s0 == T::one();
            let s1_i = T::one() & &s1 == T::one();

            a0 >>= 1;
            a1 >>= 1;
            b0 >>= 1;
            b1 >>= 1;
            r0 >>= 1;
            r1 >>= 1;
            s0 >>= 1;
            s1 >>= 1;

            let proof = Input {
                a0: a0_i,
                a1: a1_i,
                b0: b0_i,
                b1: b1_i,
                r: r0_i ^ r1_i,
                s: s0_i,
            };
            self.proof.push(proof);

            let verify_prev = Input {
                a0: a1_i,
                a1: false,
                b0: b1_i,
                b1: false,
                r: r1_i,
                s: s1_i,
            };
            self.verify_prev.push(verify_prev);

            let verify_next = Input {
                a0: false,
                a1: a0_i,
                b0: false,
                b1: b0_i,
                r: r0_i, // No negation, since bits negated are bits
                s: false,
            };
            self.verify_next.push(verify_next);
        }
    }

    pub fn get_muls(&self) -> usize {
        self.proof.len()
    }

    pub fn set_parameters(&mut self, l: usize, m: usize) {
        let muls = l * m;
        assert!(self.get_muls() <= muls);
        let diff = self.get_muls() - muls;
        self.proof.reserve(diff);
        self.verify_prev.reserve(diff);
        self.verify_next.reserve(diff);

        for _ in 0..diff {
            self.proof.push(Input::default());
            self.verify_prev.push(Input::default());
            self.verify_next.push(Input::default());
        }
        self.l = l;
        self.m = m;
    }

    pub fn proof<R: Rng + SeedableRng>(
        &self,
        thetas: &[GF2p64],
        lagrange_polys: &[Poly<GF2p64>],
        rng: &mut R,
    ) -> (R::Seed, Proof) {
        assert_eq!(self.l, thetas.len());
        assert_eq!(self.m + 1, lagrange_polys.len());
        todo!()
    }
}
