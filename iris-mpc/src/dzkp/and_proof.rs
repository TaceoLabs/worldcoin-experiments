use super::{gf2p64::GF2p64, polynomial::Poly};
use crate::{prelude::Error, types::ring_element::RingImpl};
use itertools::Itertools;
use num_traits::{One, Zero};
use rand::{
    distributions::{Distribution, Standard},
    Rng, SeedableRng,
};
use std::ops::{Add, AddAssign, Index, Mul, Sub};

#[derive(Clone, Default)]
struct Input {
    a0: bool,
    a1: bool,
    b0: bool,
    b1: bool,
    r: bool,
    s: bool,
}

impl Index<usize> for Input {
    type Output = bool;

    fn index(&self, index: usize) -> &Self::Output {
        match index {
            0 => &self.a0,
            1 => &self.a1,
            2 => &self.b0,
            3 => &self.b1,
            4 => &self.r,
            5 => &self.s,
            _ => panic!("Index out of bounds"),
        }
    }
}

#[derive(Default)]
pub(crate) struct Proof {
    w: Vec<GF2p64>,
    a: Vec<GF2p64>,
}

#[derive(Default)]
pub(crate) struct SharedVerify {
    f: Vec<GF2p64>,
    pr: GF2p64,
    b: GF2p64,
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
    const D: usize = 64; // This is because of the GF2p64 modulus implementation

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

    pub fn calc_params(&self) -> (usize, usize) {
        // TODO these parameters might be chosen to be not correct
        let muls = self.get_muls();
        let l = f64::ceil(f64::sqrt(muls as f64)) as usize;
        let m = f64::ceil(muls as f64 / l as f64) as usize;
        (l, m)
    }

    pub fn set_parameters(&mut self, l: usize, m: usize) {
        let muls = l * m;
        assert!(self.get_muls() <= muls);
        let diff = muls - self.get_muls();
        self.proof.resize(diff, Input::default());
        self.verify_prev.resize(diff, Input::default());
        self.verify_next.resize(diff, Input::default());

        self.l = l;
        self.m = m;

        let security =
            f64::log2((2 * m + 1) as f64) - f64::log2(f64::powi(2., Self::D as i32) - m as f64);

        assert!(security < -40.);
    }

    fn c<A>(f: Vec<A>) -> A
    where
        A: Clone
            + for<'a> Mul<&'a A, Output = A>
            + for<'a> Add<&'a A, Output = A>
            + for<'a> Sub<&'a A, Output = A>,
    {
        assert_eq!(f.len(), 6);

        f[0].to_owned() * &f[2] + &(f[0].to_owned() * &f[3]) + &(f[1].to_owned() * &f[2]) + &f[4]
            - &f[5]
    }

    fn g<A, B>(thetas: &[A], f: Vec<B>) -> B
    where
        B: Clone
            + for<'a> Mul<&'a B, Output = B>
            + for<'a> Add<&'a B, Output = B>
            + for<'a> Sub<&'a B, Output = B>
            + Zero
            + for<'a> Mul<&'a A, Output = B>
            + AddAssign,
    {
        let mut res = B::zero();

        // according to https://stackoverflow.com/questions/66446258/rust-chunks-method-with-owned-values this is copyless
        let f: Vec<Vec<B>> = f
            .into_iter()
            .chunks(6)
            .into_iter()
            .map(|chunk| chunk.collect())
            .collect();

        for (theta, f_) in thetas.iter().zip(f.into_iter()) {
            let poly = Self::c(f_);
            res += poly * theta;
        }
        res
    }

    pub fn proof<R: Rng + SeedableRng>(
        &self,
        thetas: &[GF2p64],
        lagrange_polys: &[Poly<GF2p64>],
        rng: &mut R,
    ) -> (R::Seed, Proof)
    where
        Standard: Distribution<R::Seed>,
        R::Seed: Clone,
    {
        assert_eq!(self.l, thetas.len());
        assert_eq!(self.m + 1, lagrange_polys.len());

        let muls = self.get_muls();
        assert_eq!(muls, self.l);
        assert_eq!(muls, self.m);

        let circuit_size = 6 * self.l;

        let w = (0..circuit_size)
            .map(|_| GF2p64::new(rng.gen::<u64>()))
            .collect::<Vec<_>>();

        let mut f = Vec::with_capacity(circuit_size);
        for j in 0..self.l {
            for i in 0..6 {
                let mut vec = Vec::with_capacity(self.m + 1);
                vec.push(w[i * self.l + j]);
                for l in 0..self.m {
                    vec.push(GF2p64::lift(self.proof[j * self.m + l][i]));
                }
                f.push(Poly::interpolate(&vec, lagrange_polys));
            }
        }

        let mut g = Self::g(thetas, f);

        let seed = rng.gen::<R::Seed>();
        let mut share_rng = R::from_seed(seed.to_owned());

        let mut proof = Proof::default();
        proof.w.reserve(circuit_size);
        proof.a.reserve(2 * self.m + 1);

        for w_ in w {
            let rand = GF2p64::new(share_rng.gen::<u64>());
            proof.w.push(w_ - rand);
        }
        if g.coeffs.len() != 2 * self.m + 1 {
            g.coeffs.resize(2 * self.m + 1, GF2p64::zero());
        }
        for g_ in g.coeffs {
            let rand = GF2p64::new(share_rng.gen::<u64>());
            proof.a.push(g_ - rand);
        }

        (seed, proof)
    }

    fn verify_pi(
        &self,
        betas: &[GF2p64],
        r: &GF2p64,
        lagrange_polys: &[Poly<GF2p64>],
        coords: &[GF2p64],
        verify: &[Input],
        proof: Proof,
    ) -> SharedVerify {
        assert_eq!(self.m, betas.len());
        assert_eq!(self.m + 1, lagrange_polys.len());
        assert_eq!(self.m * self.l, verify.len());
        assert_eq!(self.m + 1, coords.len());

        let circuit_size = 6 * self.l;

        let mut f = Vec::with_capacity(circuit_size);
        for j in 0..self.l {
            for i in 0..6 {
                let mut vec = Vec::with_capacity(self.m + 1);
                vec.push(proof.w[i * self.l + j]);
                for l in 0..self.m {
                    vec.push(GF2p64::lift(verify[j * self.m + l][i]));
                }
                f.push(Poly::interpolate(&vec, lagrange_polys).evaluate(r));
            }
        }

        let mut pr = GF2p64::zero();
        let mut b = GF2p64::zero();

        for (beta, coord) in betas.iter().zip(coords.iter().skip(1)) {
            let mut j_pow = GF2p64::one();
            let mut sum = GF2p64::zero();
            for a in proof.a.iter().copied() {
                sum += a * j_pow;
                j_pow *= coord;
            }
            sum *= beta;
            b += sum;
        }

        let mut r_pow = GF2p64::one();
        for a in proof.a.into_iter() {
            pr += a * r_pow;
            r_pow *= r;
        }

        SharedVerify { f, pr, b }
    }

    pub fn verify_prev(
        &self,
        betas: &[GF2p64],
        r: &GF2p64,
        lagrange_polys: &[Poly<GF2p64>],
        coords: &[GF2p64],
        proof: Proof,
    ) -> SharedVerify {
        self.verify_pi(betas, r, lagrange_polys, coords, &self.verify_prev, proof)
    }

    pub fn verify_next(
        &self,
        betas: &[GF2p64],
        r: &GF2p64,
        lagrange_polys: &[Poly<GF2p64>],
        coords: &[GF2p64],
        proof: Proof,
    ) -> SharedVerify {
        self.verify_pi(betas, r, lagrange_polys, coords, &self.verify_next, proof)
    }

    pub fn combine_verifications(
        &self,
        thetas: &[GF2p64],
        verify_prev: SharedVerify,
        verify_next: SharedVerify,
    ) -> Result<(), Error> {
        assert_eq!(self.l, thetas.len());

        let (mut f1, pr1, b1) = (verify_prev.f, verify_prev.pr, verify_prev.b);
        let (f2, pr2, b2) = (verify_next.f, verify_next.pr, verify_next.b);

        if !(b1 + b2).is_zero() {
            return Err(Error::DZKPVerifyError);
        }

        if f1.len() != f2.len() {
            return Err(Error::DZKPVerifyError);
        }

        for (f1_, f2_) in f1.iter_mut().zip(f2.iter()) {
            *f1_ += f2_;
        }

        let pr_ = Self::g(thetas, f1);

        if pr_ != pr1 + pr2 {
            return Err(Error::DZKPVerifyError);
        }

        Ok(())
    }
}
