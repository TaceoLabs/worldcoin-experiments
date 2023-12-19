use super::polynomial::Poly;
use crate::{
    aby3::utils, dzkp::irreducible_polys::IrreduciblePolys, prelude::Error,
    types::ring_element::RingImpl,
};
use itertools::Itertools;
use num_traits::{One, Zero};
use rand::{
    distributions::{Distribution, Standard},
    Rng, SeedableRng,
};
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Index, Mul, Sub};

#[derive(Clone, Default)]
struct Input<T: RingImpl> {
    a0: Vec<T>,
    a1: Vec<T>,
    b0: Vec<T>,
    b1: Vec<T>,
    r: T,
    s: T,
}

impl<T: RingImpl> Index<usize> for Input<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        let dot = self.a0.len();
        if index < dot {
            return &self.a0[index];
        }
        if index < 2 * dot {
            return &self.a1[index - dot];
        }
        if index < 3 * dot {
            return &self.b0[index - 2 * dot];
        }
        if index < 4 * dot {
            return &self.b1[index - 3 * dot];
        }
        if index == 4 * dot {
            return &self.r;
        }
        if index == 5 * dot {
            return &self.s;
        }
        panic!("Index out of bounds");
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct Proof<T: RingImpl> {
    w: Vec<Poly<T>>,
    a: Vec<Poly<T>>,
}

impl<T: RingImpl> Proof<T>
where
    Standard: Distribution<T>,
{
    pub fn from_seed<R: Rng + SeedableRng>(
        seed: R::Seed,
        l: usize,
        m: usize,
        d: usize,
        dot: usize,
    ) -> Self {
        let mut rng = R::from_seed(seed);
        let w = (0..(4 * dot + 2) * l)
            .map(|_| Poly::random(d, &mut rng))
            .collect::<Vec<_>>();
        let a = (0..(2 * m + 1))
            .map(|_| Poly::random(d, &mut rng))
            .collect::<Vec<_>>();
        Self { w, a }
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct SharedVerify<T: RingImpl> {
    f: Vec<Poly<T>>,
    pr: Poly<T>,
    b: Poly<T>,
}

#[derive(Default)]
pub(crate) struct DotProof<T: RingImpl> {
    l: usize,
    m: usize,
    dot_size: usize,
    max_dot: usize,
    modulus: Poly<T>,
    proof: Vec<Input<T>>,       // For P0: This is the proof of P0
    verify_prev: Vec<Input<T>>, // For P1: This is to verify the proof of P0
    verify_next: Vec<Input<T>>, // For P2: This is to verify the proof of P0
}

impl<T: RingImpl> DotProof<T>
where
    Standard: Distribution<T>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn register_dot(
        &mut self,
        mut a0: Vec<T>,
        mut a1: Vec<T>,
        mut b0: Vec<T>,
        mut b1: Vec<T>,
        r0: T,
        r1: T,
        s0: T,
        s1: T,
    ) {
        let len = a0.len();
        assert_eq!(len, a1.len());
        assert_eq!(len, b0.len());
        assert_eq!(len, b1.len());

        if len < self.dot_size {
            a0.resize(self.dot_size, T::zero());
            a1.resize(self.dot_size, T::zero());
            b0.resize(self.dot_size, T::zero());
            b1.resize(self.dot_size, T::zero());
        }

        if len > self.dot_size {
            self.max_dot = self.proof.len();
            self.dot_size = len;
        }

        let proof = Input {
            a0: a0.to_owned(),
            a1: a1.to_owned(),
            b0: b0.to_owned(),
            b1: b1.to_owned(),
            r: r0.to_owned() - &r1,
            s: s0,
        };
        self.proof.push(proof);

        let verify_prev = Input {
            a0: a1,
            a1: vec![T::zero(); self.dot_size],
            b0: b1,
            b1: vec![T::zero(); self.dot_size],
            r: r1,
            s: s1,
        };
        self.verify_prev.push(verify_prev);

        let verify_next = Input {
            a0: vec![T::zero(); self.dot_size],
            a1: a0,
            b0: vec![T::zero(); self.dot_size],
            b1: b0,
            r: -r0,
            s: T::zero(),
        };
        self.verify_next.push(verify_next);
    }

    pub fn get_muls(&self) -> usize {
        self.proof.len()
    }

    pub fn get_dot(&self) -> usize {
        self.dot_size
    }

    pub fn lagrange_points(num: usize) -> Vec<Poly<T>> {
        let mut points = Vec::with_capacity(num);
        for i in 0..num {
            points.push(Poly::from_vec(utils::to_bits(i)));
        }
        points
    }

    pub fn calc_params(&self) -> (usize, usize) {
        // TODO these parameters might be chosen to be not correct
        let muls = self.get_muls();
        let m = f64::ceil(f64::sqrt(((4 * self.dot_size + 2) * muls) as f64)) as usize;
        let l = f64::ceil(muls as f64 / m as f64) as usize;
        (l, m)
    }

    pub fn set_parameters(&mut self, l: usize, m: usize) {
        let muls = l * m;
        assert!(self.get_muls() <= muls);
        self.proof.resize(muls, Input::default());
        self.verify_prev.resize(muls, Input::default());
        self.verify_next.resize(muls, Input::default());

        self.l = l;
        self.m = m;

        // Pad
        for (p, (v_prev, v_next)) in self
            .proof
            .iter_mut()
            .zip(self.verify_prev.iter_mut().zip(self.verify_next.iter_mut()))
            .take(self.max_dot)
        {
            p.a0.resize(self.dot_size, T::zero());
            p.a1.resize(self.dot_size, T::zero());
            p.b0.resize(self.dot_size, T::zero());
            p.b1.resize(self.dot_size, T::zero());
            v_prev.a0.resize(self.dot_size, T::zero());
            v_prev.a1.resize(self.dot_size, T::zero());
            v_prev.b0.resize(self.dot_size, T::zero());
            v_prev.b1.resize(self.dot_size, T::zero());
            v_next.a0.resize(self.dot_size, T::zero());
            v_next.a1.resize(self.dot_size, T::zero());
            v_next.b0.resize(self.dot_size, T::zero());
            v_next.b1.resize(self.dot_size, T::zero());
        }

        let gamma = f64::ceil(f64::log2((2 * m) as f64)) as usize;
        let d = gamma + 40;
        self.modulus = IrreduciblePolys::get(d);
    }

    pub fn get_mod_d(&self) -> usize {
        self.modulus.degree()
    }

    pub fn get_modulus(&self) -> &Poly<T> {
        &self.modulus
    }

    fn c<A>(f: Vec<A>, dot: usize) -> A
    where
        A: Clone
            + for<'a> Mul<&'a A, Output = A>
            + for<'a> Add<&'a A, Output = A>
            + Add<A, Output = A>
            + AddAssign
            + for<'a> Sub<&'a A, Output = A>,
    {
        assert_eq!(f.len(), 4 * dot + 2);
        let mut res = f[4 * dot].to_owned() - &f[4 * dot + 1];
        for i in 0..dot {
            res += f[i].to_owned() * &f[2 * dot + i]
                + f[i].to_owned() * &f[3 * dot + i]
                + f[dot + i].to_owned() * &f[2 * dot + i];
        }
        res
    }

    fn g<A, B>(thetas: &[A], f: Vec<B>, dot: usize) -> B
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
            .chunks(4 * dot + 2)
            .into_iter()
            .map(|chunk| chunk.collect())
            .collect();

        for (theta, f_) in thetas.iter().zip(f.into_iter()) {
            let poly = Self::c(f_, dot);
            res += poly * theta;
        }
        res
    }

    pub fn prove<R: Rng + SeedableRng>(
        &self,
        thetas: &[Poly<T>],
        lagrange_polys: &[Poly<Poly<T>>],
        rng: &mut R,
    ) -> (R::Seed, Proof<T>)
    where
        Standard: Distribution<R::Seed>,
        R::Seed: Clone,
    {
        assert_eq!(self.l, thetas.len());
        assert_eq!(self.m + 1, lagrange_polys.len());

        let muls = self.get_muls();
        assert_eq!(muls, self.l * self.m);
        let circuit_size = (4 * self.dot_size + 2) * self.l;
        let d = self.get_mod_d() - 1;

        let w = (0..circuit_size)
            .map(|_| Poly::random(d, rng))
            .collect::<Vec<_>>();

        let mut f = Vec::with_capacity(circuit_size);
        for j in 0..self.l {
            for i in 0..(4 * self.dot_size + 2) {
                let mut vec = Vec::with_capacity(self.m + 1);
                vec.push(w[i * self.l + j].to_owned());
                for l in 0..self.m {
                    vec.push(Poly::lift(self.proof[j * self.m + l][i].to_owned()));
                }
                f.push(Poly::interpolate(&vec, lagrange_polys));
            }
        }

        let mut g = Self::g(thetas, f, self.dot_size);
        g.reduce_coeffs(&self.modulus);

        let seed = rng.gen::<R::Seed>();
        let mut share_rng = R::from_seed(seed.to_owned());

        let mut proof = Proof::default();
        proof.w.reserve(circuit_size);
        proof.a.reserve(2 * self.m + 1);

        for w_ in w {
            let rand = Poly::random(d, &mut share_rng);
            proof.w.push(w_ - rand);
        }
        if g.coeffs.len() != 2 * self.m + 1 {
            g.coeffs.resize(2 * self.m + 1, Poly::zero());
        }
        for g_ in g.coeffs {
            let rand = Poly::random(d, &mut share_rng);
            proof.a.push(g_ - rand);
        }

        (seed, proof)
    }

    fn verify_pi(
        &self,
        betas: &[Poly<T>],
        r: &Poly<T>,
        lagrange_polys: &[Poly<Poly<T>>],
        coords: &[Poly<T>],
        verify: &[Input<T>],
        proof: Proof<T>,
    ) -> Result<SharedVerify<T>, Error> {
        assert_eq!(self.m, betas.len());
        assert_eq!(self.m + 1, lagrange_polys.len());
        assert_eq!(self.m * self.l, verify.len());
        assert_eq!(self.m + 1, coords.len());

        let circuit_size = (4 * self.dot_size + 2) * self.l;
        if proof.w.len() != circuit_size || proof.a.len() != 2 * self.m + 1 {
            return Err(Error::DZKPVerifyError);
        }

        let mut f = Vec::with_capacity(circuit_size);
        for j in 0..self.l {
            for i in 0..(4 * self.dot_size + 2) {
                let mut vec = Vec::with_capacity(self.m + 1);
                vec.push(proof.w[i * self.l + j].to_owned());
                for l in 0..self.m {
                    vec.push(Poly::lift(verify[j * self.m + l][i].to_owned()));
                }
                f.push(Poly::interpolate(&vec, lagrange_polys).evaluate(r) % &self.modulus);
            }
        }

        let mut pr = Poly::zero();
        let mut b = Poly::zero();

        for (beta, coord) in betas.iter().zip(coords.iter().skip(1)) {
            let mut j_pow = Poly::one();
            let mut sum = Poly::zero();
            for a in proof.a.iter().cloned() {
                sum += a * &j_pow;
                j_pow *= coord;
            }
            sum *= beta;
            b += sum;
        }

        let mut r_pow = Poly::one();
        for a in proof.a.into_iter() {
            pr += a * &r_pow;
            r_pow *= r;
        }

        pr = pr % &self.modulus;
        b = b % &self.modulus;

        Ok(SharedVerify { f, pr, b })
    }

    pub fn verify_prev(
        &self,
        betas: &[Poly<T>],
        r: &Poly<T>,
        lagrange_polys: &[Poly<Poly<T>>],
        coords: &[Poly<T>],
        proof: Proof<T>,
    ) -> Result<SharedVerify<T>, Error> {
        self.verify_pi(betas, r, lagrange_polys, coords, &self.verify_prev, proof)
    }

    pub fn verify_next(
        &self,
        betas: &[Poly<T>],
        r: &Poly<T>,
        lagrange_polys: &[Poly<Poly<T>>],
        coords: &[Poly<T>],
        proof: Proof<T>,
    ) -> Result<SharedVerify<T>, Error> {
        self.verify_pi(betas, r, lagrange_polys, coords, &self.verify_next, proof)
    }

    pub fn combine_verifications(
        &self,
        thetas: &[Poly<T>],
        verify_prev: SharedVerify<T>,
        verify_next: SharedVerify<T>,
    ) -> Result<(), Error> {
        assert_eq!(self.l, thetas.len());

        let (mut f1, pr1, b1) = (verify_prev.f, verify_prev.pr, verify_prev.b);
        let (f2, pr2, b2) = (verify_next.f, verify_next.pr, verify_next.b);

        if !(b1 + b2).is_zero() {
            return Err(Error::DZKPVerifyError);
        }

        if f1.len() != f2.len() || f1.len() != (4 * self.dot_size + 2) * self.l {
            return Err(Error::DZKPVerifyError);
        }

        for (f1_, f2_) in f1.iter_mut().zip(f2.iter()) {
            *f1_ += f2_;
        }

        let pr_ = Self::g(thetas, f1, self.dot_size) % &self.modulus;

        if pr_ != (pr1 + pr2) {
            return Err(Error::DZKPVerifyError);
        }

        Ok(())
    }
}
