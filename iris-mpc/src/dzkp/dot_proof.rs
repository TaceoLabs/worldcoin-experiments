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
    pub fn from_seed<R: Rng + SeedableRng>(seed: R::Seed, l: usize, m: usize, d: usize) -> Self {
        todo!()
        let mut rng = R::from_seed(seed);
        let w = (0..6 * l)
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
        a0: Vec<T>,
        a1: Vec<T>,
        b0: Vec<T>,
        b1: Vec<T>,
        r0: T,
        r1: T,
        s0: T,
        s1: T,
    ) {
        todo!()
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
            a1: T::zero(),
            b0: b1,
            b1: T::zero(),
            r: r1,
            s: s1,
        };
        self.verify_prev.push(verify_prev);

        let verify_next = Input {
            a0: T::zero(),
            a1: a0,
            b0: T::zero(),
            b1: b0,
            r: -r0,
            s: T::zero(),
        };
        self.verify_next.push(verify_next);
    }

    pub fn get_muls(&self) -> usize {
        self.proof.len()
    }

    pub fn lagrange_points(num: usize) -> Vec<Poly<T>> {
        let mut points = Vec::with_capacity(num);
        for i in 0..num {
            points.push(Poly::from_vec(utils::to_bits(i)));
        }
        points
    }

    pub fn calc_params(&self) -> (usize, usize) {
        todo!()
        // TODO these parameters might be chosen to be not correct
        let muls = self.get_muls();
        let l = f64::ceil(f64::sqrt(muls as f64)) as usize;
        let m = f64::ceil(muls as f64 / l as f64) as usize;
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

    fn c<A>(f: Vec<A>) -> A
    where
        A: Clone
            + for<'a> Mul<&'a A, Output = A>
            + for<'a> Add<&'a A, Output = A>
            + Add<A, Output = A>
            + for<'a> Sub<&'a A, Output = A>,
    {
        assert_eq!(f.len(), 6);
        todo!()

        f[0].to_owned() * &f[2] + f[0].to_owned() * &f[3] + f[1].to_owned() * &f[2] + &f[4] - &f[5]
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

        todo!()
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
        todo!()
        assert_eq!(self.l, thetas.len());
        assert_eq!(self.m + 1, lagrange_polys.len());

        let muls = self.get_muls();
        assert_eq!(muls, self.l * self.m);
        let circuit_size = 6 * self.l;
        let d = self.get_mod_d() - 1;

        let w = (0..circuit_size)
            .map(|_| Poly::random(d, rng))
            .collect::<Vec<_>>();

        let mut f = Vec::with_capacity(circuit_size);
        for j in 0..self.l {
            for i in 0..6 {
                let mut vec = Vec::with_capacity(self.m + 1);
                vec.push(w[i * self.l + j].to_owned());
                for l in 0..self.m {
                    vec.push(Poly::lift(self.proof[j * self.m + l][i].to_owned()));
                }
                f.push(Poly::interpolate(&vec, lagrange_polys));
            }
        }

        let mut g = Self::g(thetas, f);
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

        todo!()
        if proof.w.len() != 6 * self.l || proof.a.len() != 2 * self.m + 1 {
            return Err(Error::DZKPVerifyError);
        }
        let circuit_size = 6 * self.l;

        let mut f = Vec::with_capacity(circuit_size);
        for j in 0..self.l {
            for i in 0..6 {
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

        todo!()
        let (mut f1, pr1, b1) = (verify_prev.f, verify_prev.pr, verify_prev.b);
        let (f2, pr2, b2) = (verify_next.f, verify_next.pr, verify_next.b);

        if !(b1 + b2).is_zero() {
            return Err(Error::DZKPVerifyError);
        }

        if f1.len() != f2.len() || f1.len() != 6 * self.l {
            return Err(Error::DZKPVerifyError);
        }

        for (f1_, f2_) in f1.iter_mut().zip(f2.iter()) {
            *f1_ += f2_;
        }

        let pr_ = Self::g(thetas, f1) % &self.modulus;

        if pr_ != (pr1 + pr2) {
            return Err(Error::DZKPVerifyError);
        }

        Ok(())
    }
}
