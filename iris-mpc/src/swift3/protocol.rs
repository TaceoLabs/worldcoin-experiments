use super::{
    random::prf::{Prf, PrfSeed},
    share::Share,
};
use crate::{
    aby3::utils,
    commitment::{CommitOpening, Commitment},
    dzkp::{
        and_proof::{AndProof, Proof as AndProofStruct},
        dot_proof::{DotProof, Proof as DotProofStruct},
        gf2p64::GF2p64,
        polynomial::Poly,
    },
    prelude::{Aby3Share, Bit, Error, MpcTrait, Sharable},
    traits::{binary_trait::BinaryMpcTrait, network_trait::NetworkTrait, security::MaliciousAbort},
    types::ring_element::{RingElement, RingImpl},
};
use crate::{
    dzkp::mul_proof::{MulProof, Proof as MulProofStruct},
    iris::protocol::OR_TREE_PACK_SIZE,
};
use bytes::{Bytes, BytesMut};
use num_traits::Zero;
use rand::{
    distributions::{Distribution, Standard},
    Rng, SeedableRng,
};
use rand_chacha::ChaCha12Rng;
use sha2::{digest::Output, Digest, Sha512};
use std::{marker::PhantomData, ops::Mul};

pub struct Swift3<N: NetworkTrait, U: Sharable> {
    network: N,
    prf: Prf,
    send_queue_next: BytesMut,
    send_queue_prev: BytesMut,
    rcv_queue_next: BytesMut,
    rcv_queue_prev: BytesMut,
    and_proof: AndProof,
    mul_proof: MulProof<U::Share>,
    dot_proof: DotProof<U::Share>,
    _data: PhantomData<U>,
}

impl<N: NetworkTrait, U: Sharable> MaliciousAbort for Swift3<N, U> {}

macro_rules! reduce_or {
    ($([$typ_a:ident, $typ_b:ident,$name_a:ident,$name_b:ident]),*) => {
        $(
             fn $name_a(&mut self, a: Share<$typ_a>) -> Result<Share<Bit>, Error> {
                let (a, b, c) = a.get_abc();
                let (a1, a2) = utils::split::<$typ_a, $typ_b>(a);
                let (b1, b2) = utils::split::<$typ_a, $typ_b>(b);
                let (c1, c2) = utils::split::<$typ_a, $typ_b>(c);

                let share_a = Share::new(a1, b1, c1);
                let share_b = Share::new(a2, b2, c2);

                let out = <Self as BinaryMpcTrait::<$typ_b, Share<$typ_b>>>::or(self, share_a, share_b)?;
                self.$name_b(out)
            }
        )*
    };
}

impl<N: NetworkTrait, U: Sharable> Swift3<N, U>
where
    Standard: Distribution<U::Share>,
{
    pub fn new(network: N) -> Self {
        let prf = Prf::default();
        let send_queue_next = BytesMut::new();
        let send_queue_prev = BytesMut::new();
        let rcv_queue_next = BytesMut::new();
        let rcv_queue_prev = BytesMut::new();

        Self {
            network,
            prf,
            send_queue_next,
            send_queue_prev,
            rcv_queue_next,
            rcv_queue_prev,
            and_proof: AndProof::default(),
            mul_proof: MulProof::default(),
            dot_proof: DotProof::default(),
            _data: PhantomData,
        }
    }

    fn a2b_pre<T: Sharable>(&mut self, x: Share<T>) -> (Share<T>, Share<T>, Share<T>) {
        let (a, b, c) = x.get_abc();

        let mut x1 = Share::<T>::zero();
        let mut x2 = Share::<T>::zero();
        let mut x3 = Share::<T>::zero();

        match self.network.get_id() {
            0 => {
                x1.a = c - a;
                x3.b = -b;
            }
            1 => {
                x1.b = c - b;
                x2.a = -a;
            }
            2 => {
                x2.b = -b;
                x3.a = -a;
            }
            _ => unreachable!(),
        }
        (x1, x2, x3)
    }

    fn send_seed_commitment(
        &mut self,
        comm1: &[u8],
        comm2: &[u8],
        comm3: &[u8],
        id1: usize,
        id2: usize,
    ) -> Result<(), Error> {
        let mut msg1 = BytesMut::new();
        msg1.extend_from_slice(comm1);
        msg1.extend_from_slice(comm3);
        let msg1 = msg1.freeze();

        let mut msg2 = BytesMut::new();
        msg2.extend_from_slice(comm2);
        msg2.extend_from_slice(comm3);
        let msg2 = msg2.freeze();

        self.network.send(id1, msg1)?;
        self.network.send(id2, msg2)?;

        Ok(())
    }

    #[inline(always)]
    fn jmp_send<T: Sharable>(&mut self, value: T::Share, id: usize) -> Result<(), Error> {
        utils::send_value(&mut self.network, value, id)
    }

    #[inline(always)]
    fn jmp_send_many<T: Sharable>(
        &mut self,
        values: Vec<T::Share>,
        id: usize,
    ) -> Result<(), Error> {
        utils::send_vec(&mut self.network, values, id)
    }

    fn jmp_queue<T: Sharable>(&mut self, value: T::Share, id: usize) -> Result<(), Error> {
        let my_id = self.network.get_id();
        if id == (my_id + 1) % 3 {
            value.add_to_bytes(&mut self.send_queue_next);
        } else if id == (my_id + 2) % 3 {
            value.add_to_bytes(&mut self.send_queue_prev);
        } else {
            return Err(Error::IdError(id));
        }
        Ok(())
    }

    fn jmp_queue_many<T: Sharable>(
        &mut self,
        values: Vec<T::Share>,
        id: usize,
    ) -> Result<(), Error> {
        let my_id = self.network.get_id();
        if id == (my_id + 1) % 3 {
            for value in values {
                value.add_to_bytes(&mut self.send_queue_next);
            }
        } else if id == (my_id + 2) % 3 {
            for value in values {
                value.add_to_bytes(&mut self.send_queue_prev);
            }
        } else {
            return Err(Error::IdError(id));
        }
        Ok(())
    }

    fn mul_pre<T: Sharable>(&self, a: Share<T>, b: Share<T>) -> (Aby3Share<T>, Aby3Share<T>) {
        let (x_a, x_b, _) = a.get_abc();
        let (y_a, y_b, _) = b.get_abc();

        // ABY3 Sharing:
        // P0: (alpha1, alpha3)
        // P1: (alpha2, alpha1)
        // P2: (alpha3, alpha2)

        let d = Aby3Share::new(x_a, x_b);
        let e = Aby3Share::new(y_a, y_b);

        (d, e)
    }

    fn mul_post(&mut self, a: Share<U>, b: Share<U>, de: Aby3Share<U>) -> Result<Share<U>, Error>
    where
        Standard: Distribution<U::Share>,
    {
        let id = self.network.get_id();

        let (x_a, x_b, x_c) = a.get_abc();
        let (y_a, y_b, y_c) = b.get_abc();
        let (de_a, de_b) = de.get_ab();

        let r1 = self.prf.gen_1::<U::Share>();
        let r2 = self.prf.gen_2::<U::Share>();

        let y_a = -x_a * &y_c - y_a * &x_c + de_a - &r1;
        let y_b = -x_b * &y_c - y_b * &x_c + de_b - &r2;
        let z_c = x_c * y_c;

        let share = match id {
            0 => {
                let y1 = y_a;
                let y3 = y_b;
                self.jmp_send::<U>(y1.to_owned(), 2)?;
                self.jmp_send::<U>(y3.to_owned(), 1)?;
                self.jshare(None, 1, 2, 0)?
            }
            1 => {
                let y2 = y_a;
                let y1 = y_b;
                self.jmp_queue::<U>(y1.to_owned(), 2)?;
                let y3 = self.jmp_receive::<U>(0)?;
                let zr = y1 + y2 + y3 + z_c;
                self.jshare(Some(U::from_sharetype(zr)), 1, 2, 0)?
            }
            2 => {
                let y3 = y_a;
                let y2 = y_b;
                self.jmp_queue::<U>(y3.to_owned(), 1)?;
                let y1 = self.jmp_receive::<U>(0)?;
                let zr = y1 + y2 + y3 + z_c;
                self.jshare(Some(U::from_sharetype(zr)), 1, 2, 0)?
            }
            _ => unreachable!(),
        };

        let r = Share::new(r1, r2, U::Share::zero());

        Ok(share - r)
    }

    fn and_post<T: Sharable>(
        &mut self,
        a: Share<T>,
        b: Share<T>,
        de: Aby3Share<T>,
    ) -> Result<Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        let id = self.network.get_id();

        let (x_a, x_b, x_c) = a.get_abc();
        let (y_a, y_b, y_c) = b.get_abc();
        let (de_a, de_b) = de.get_ab();

        let r1 = self.prf.gen_1::<T::Share>();
        let r2 = self.prf.gen_2::<T::Share>();

        let y_a = x_a & &y_c ^ y_a & &x_c ^ de_a ^ &r1;
        let y_b = x_b & &y_c ^ y_b & &x_c ^ de_b ^ &r2;
        let z_c = x_c & y_c;

        let share = match id {
            0 => {
                let y1 = y_a;
                let y3 = y_b;
                self.jmp_send::<T>(y1.to_owned(), 2)?;
                self.jmp_send::<T>(y3.to_owned(), 1)?;
                self.jshare_binary(None, 1, 2, 0)?
            }
            1 => {
                let y2 = y_a;
                let y1 = y_b;
                self.jmp_queue::<T>(y1.to_owned(), 2)?;
                let y3 = self.jmp_receive::<T>(0)?;
                let zr = y1 ^ y2 ^ y3 ^ z_c;
                self.jshare_binary(Some(T::from_sharetype(zr)), 1, 2, 0)?
            }
            2 => {
                let y3 = y_a;
                let y2 = y_b;
                self.jmp_queue::<T>(y3.to_owned(), 1)?;
                let y1 = self.jmp_receive::<T>(0)?;
                let zr = y1 ^ y2 ^ y3 ^ z_c;
                self.jshare_binary(Some(T::from_sharetype(zr)), 1, 2, 0)?
            }
            _ => unreachable!(),
        };

        let r = Share::new(r1, r2, T::Share::zero());

        Ok(share ^ r)
    }

    fn and_post_many<T: Sharable>(
        &mut self,
        a: Vec<Share<T>>,
        b: Vec<Share<T>>,
        de: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Share<T>>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        let len = a.len();
        debug_assert_eq!(len, b.len());
        debug_assert_eq!(len, de.len());
        let id = self.network.get_id();

        let mut shares = Vec::with_capacity(len);

        match id {
            0 => {
                let mut y1s = Vec::with_capacity(len);
                let mut y3s = Vec::with_capacity(len);
                let mut rs = Vec::with_capacity(len);

                for (de, (a, b)) in de.into_iter().zip(a.into_iter().zip(b)) {
                    let (x_a, x_b, x_c) = a.get_abc();
                    let (y_a, y_b, y_c) = b.get_abc();
                    let (de_a, de_b) = de.get_ab();

                    let r1 = self.prf.gen_1::<T::Share>();
                    let r2 = self.prf.gen_2::<T::Share>();

                    let y1 = x_a & &y_c ^ y_a & &x_c ^ de_a ^ &r1;
                    let y3 = x_b & &y_c ^ y_b & &x_c ^ de_b ^ &r2;
                    let r = Share::new(r1, r2, T::Share::zero());
                    y1s.push(y1);
                    y3s.push(y3);
                    rs.push(r);
                }
                self.jmp_send_many::<T>(y1s, 2)?;
                self.jmp_send_many::<T>(y3s, 1)?;

                let resp = self.jshare_binary_many(None, 1, 2, 0, len)?;
                for (share, r) in resp.into_iter().zip(rs) {
                    shares.push(share ^ r);
                }
            }
            1 => {
                let mut zr = Vec::with_capacity(len);
                let mut y1s = Vec::with_capacity(len);
                let mut rs = Vec::with_capacity(len);

                for (de, (a, b)) in de.into_iter().zip(a.into_iter().zip(b)) {
                    let (x_a, x_b, x_c) = a.get_abc();
                    let (y_a, y_b, y_c) = b.get_abc();
                    let (de_a, de_b) = de.get_ab();

                    let r1 = self.prf.gen_1::<T::Share>();
                    let r2 = self.prf.gen_2::<T::Share>();

                    let y2 = x_a & &y_c ^ y_a & &x_c ^ de_a ^ &r1;
                    let y1 = x_b & &y_c ^ y_b & &x_c ^ de_b ^ &r2;
                    let z_c = x_c & y_c;
                    let r = Share::new(r1, r2, T::Share::zero());
                    zr.push(T::from_sharetype(y2 ^ z_c ^ &y1));
                    y1s.push(y1);
                    rs.push(r);
                }
                self.jmp_queue_many::<T>(y1s, 2)?;
                let y3s = self.jmp_receive_many::<T>(0, len)?;

                for (zr_, y3) in zr.iter_mut().zip(y3s) {
                    *zr_ ^= T::from_sharetype(y3);
                }

                let resp = self.jshare_binary_many(Some(zr), 1, 2, 0, len)?;
                for (share, r) in resp.into_iter().zip(rs) {
                    shares.push(share ^ r);
                }
            }
            2 => {
                let mut zr = Vec::with_capacity(len);
                let mut y3s = Vec::with_capacity(len);
                let mut rs = Vec::with_capacity(len);

                for (de, (a, b)) in de.into_iter().zip(a.into_iter().zip(b)) {
                    let (x_a, x_b, x_c) = a.get_abc();
                    let (y_a, y_b, y_c) = b.get_abc();
                    let (de_a, de_b) = de.get_ab();

                    let r1 = self.prf.gen_1::<T::Share>();
                    let r2 = self.prf.gen_2::<T::Share>();

                    let y3 = x_a & &y_c ^ y_a & &x_c ^ &de_a ^ &r1;
                    let y2 = x_b & &y_c ^ y_b & &x_c ^ de_b ^ &r2;
                    let z_c = x_c & y_c;
                    let r = Share::new(r1, r2, T::Share::zero());
                    zr.push(T::from_sharetype(y2 ^ z_c ^ &y3));
                    y3s.push(y3);
                    rs.push(r);
                }
                self.jmp_queue_many::<T>(y3s, 1)?;
                let y1s = self.jmp_receive_many::<T>(0, len)?;

                for (zr_, y1) in zr.iter_mut().zip(y1s) {
                    *zr_ ^= T::from_sharetype(y1);
                }

                let resp = self.jshare_binary_many(Some(zr), 1, 2, 0, len)?;
                for (share, r) in resp.into_iter().zip(rs) {
                    shares.push(share ^ r);
                }
            }
            _ => unreachable!(),
        };

        Ok(shares)
    }

    fn dot_post(
        &mut self,
        a: Vec<Share<U>>,
        b: Vec<Share<U>>,
        de: Aby3Share<U>,
    ) -> Result<Share<U>, Error>
    where
        Standard: Distribution<U::Share>,
    {
        debug_assert_eq!(a.len(), b.len());
        let id = self.network.get_id();

        let r1 = self.prf.gen_1::<U::Share>();
        let r2 = self.prf.gen_2::<U::Share>();

        let (de_a, de_b) = de.get_ab();

        let mut y_a_ = de_a - &r1;
        let mut y_b_ = de_b - &r2;
        let mut z_c = U::Share::zero();

        for (a, b) in a.into_iter().zip(b) {
            let (x_a, x_b, x_c) = a.get_abc();
            let (y_a, y_b, y_c) = b.get_abc();

            y_a_ -= x_a * &y_c + y_a * &x_c;
            y_b_ -= x_b * &y_c + y_b * &x_c;
            z_c += x_c * y_c;
        }

        let share = match id {
            0 => {
                let y1 = y_a_;
                let y3 = y_b_;
                self.jmp_send::<U>(y1.to_owned(), 2)?;
                self.jmp_send::<U>(y3.to_owned(), 1)?;
                self.jshare(None, 1, 2, 0)?
            }
            1 => {
                let y2 = y_a_;
                let y1 = y_b_;
                self.jmp_queue::<U>(y1.to_owned(), 2)?;
                let y3 = self.jmp_receive::<U>(0)?;
                let zr = y1 + y2 + y3 + z_c;
                self.jshare(Some(U::from_sharetype(zr)), 1, 2, 0)?
            }
            2 => {
                let y3 = y_a_;
                let y2 = y_b_;
                self.jmp_queue::<U>(y3.to_owned(), 1)?;
                let y1 = self.jmp_receive::<U>(0)?;
                let zr = y1 + y2 + y3 + z_c;
                self.jshare(Some(U::from_sharetype(zr)), 1, 2, 0)?
            }
            _ => unreachable!(),
        };

        let r = Share::new(r1, r2, U::Share::zero());

        Ok(share - r)
    }

    fn dot_post_many(
        &mut self,
        a: &[Vec<Share<U>>],
        b: &[Vec<Share<U>>],
        de: Vec<Aby3Share<U>>,
    ) -> Result<Vec<Share<U>>, Error>
    where
        Standard: Distribution<U::Share>,
    {
        let len = a.len();
        debug_assert_eq!(len, b.len());
        debug_assert_eq!(len, de.len());
        let id = self.network.get_id();

        let mut shares = Vec::with_capacity(len);
        tracing::debug!("starting dot post many");

        match id {
            0 => {
                let mut y1s = Vec::with_capacity(len);
                let mut y3s = Vec::with_capacity(len);
                let mut rs = Vec::with_capacity(len);

                for (de, (a, b)) in de.into_iter().zip(a.iter().zip(b)) {
                    let (de_a, de_b) = de.get_ab();

                    let r1 = self.prf.gen_1::<U::Share>();
                    let r2 = self.prf.gen_2::<U::Share>();

                    let mut y1 = de_a - &r1;
                    let mut y3 = de_b - &r2;

                    for (a, b) in a.iter().zip(b) {
                        let (x_a, x_b, x_c) = a.clone().get_abc();
                        let (y_a, y_b, y_c) = b.clone().get_abc();

                        y1 -= x_a * &y_c + y_a * &x_c;
                        y3 -= x_b * &y_c + y_b * &x_c;
                    }
                    let r = Share::new(r1, r2, U::Share::zero());
                    y1s.push(y1);
                    y3s.push(y3);
                    rs.push(r);
                }
                tracing::debug!("jmp_send_many -> 2");
                self.jmp_send_many::<U>(y1s, 2)?;
                tracing::debug!("jmp_send_many -> 1");
                self.jmp_send_many::<U>(y3s, 1)?;

                tracing::debug!("jshare_many 1,2 -> 0");
                let resp = self.jshare_many(None, 1, 2, 0, len)?;
                for (share, r) in resp.into_iter().zip(rs) {
                    shares.push(share - r);
                }
            }
            1 => {
                let mut zr = Vec::with_capacity(len);
                let mut y1s = Vec::with_capacity(len);
                let mut rs = Vec::with_capacity(len);

                for (de, (a, b)) in de.into_iter().zip(a.iter().zip(b)) {
                    let (de_a, de_b) = de.get_ab();

                    let r1 = self.prf.gen_1::<U::Share>();
                    let r2 = self.prf.gen_2::<U::Share>();

                    let mut y2 = de_a - &r1;
                    let mut y1 = de_b - &r2;
                    let mut z_c = U::Share::zero();

                    for (a, b) in a.iter().zip(b) {
                        let (x_a, x_b, x_c) = a.clone().get_abc();
                        let (y_a, y_b, y_c) = b.clone().get_abc();

                        y2 -= x_a * &y_c + y_a * &x_c;
                        y1 -= x_b * &y_c + y_b * &x_c;
                        z_c += x_c * y_c;
                    }
                    let r = Share::new(r1, r2, U::Share::zero());
                    zr.push(U::from_sharetype(y2 + z_c + &y1));
                    y1s.push(y1);
                    rs.push(r);
                }
                tracing::debug!("jmp_queue_many -> 2");
                self.jmp_queue_many::<U>(y1s, 2)?;
                tracing::debug!("jmp_recv_many <- 0");
                let y3s = self.jmp_receive_many::<U>(0, len)?;

                for (zr_, y3) in zr.iter_mut().zip(y3s) {
                    *zr_ = zr_.wrapping_add(&U::from_sharetype(y3));
                }

                tracing::debug!("jshare_many 1,2 -> 0");
                let resp = self.jshare_many(Some(zr), 1, 2, 0, len)?;
                for (share, r) in resp.into_iter().zip(rs) {
                    shares.push(share - r);
                }
            }
            2 => {
                let mut zr = Vec::with_capacity(len);
                let mut y3s = Vec::with_capacity(len);
                let mut rs = Vec::with_capacity(len);

                for (de, (a, b)) in de.into_iter().zip(a.iter().zip(b)) {
                    let (de_a, de_b) = de.get_ab();

                    let r1 = self.prf.gen_1::<U::Share>();
                    let r2 = self.prf.gen_2::<U::Share>();

                    let mut y3 = de_a - &r1;
                    let mut y2 = de_b - &r2;
                    let mut z_c = U::Share::zero();

                    for (a, b) in a.iter().zip(b) {
                        let (x_a, x_b, x_c) = a.clone().get_abc();
                        let (y_a, y_b, y_c) = b.clone().get_abc();

                        y3 -= x_a * &y_c + y_a * &x_c;
                        y2 -= x_b * &y_c + y_b * &x_c;
                        z_c += x_c * y_c;
                    }
                    let r = Share::new(r1, r2, U::Share::zero());
                    zr.push(U::from_sharetype(y2 + z_c + &y3));
                    y3s.push(y3);
                    rs.push(r);
                }
                tracing::debug!("jmp_queue_many -> 1");
                self.jmp_queue_many::<U>(y3s, 1)?;
                tracing::debug!("jmp_recv_many <- 0");
                let y1s = self.jmp_receive_many::<U>(0, len)?;

                for (zr_, y1) in zr.iter_mut().zip(y1s) {
                    *zr_ = zr_.wrapping_add(&U::from_sharetype(y1));
                }

                tracing::debug!("jshare_many 1,2 -> 0");
                let resp = self.jshare_many(Some(zr), 1, 2, 0, len)?;
                for (share, r) in resp.into_iter().zip(rs) {
                    shares.push(share - r);
                }
            }
            _ => unreachable!(),
        }
        tracing::debug!("done with dot post many");

        Ok(shares)
    }

    fn and_verify(&mut self) -> Result<(), Error> {
        let (l, m) = self.and_proof.calc_params();
        self.and_proof.set_parameters(l, m);

        tracing::trace!("Starting lagrange interpolation");

        // lagrange: Maybe put into a file and read here
        let coords = AndProof::lagrange_points(m + 1);
        let lagrange_polys = Poly::<GF2p64>::lagrange_polys(&coords);

        tracing::trace!("Finished lagrange interpolation");

        let seed = self.prf.gen_p::<<ChaCha12Rng as SeedableRng>::Seed>();
        let mut theta_rng = ChaCha12Rng::from_seed(seed);
        let thetas = Self::get_rands_for_and_dzkp::<ChaCha12Rng>(l, &mut theta_rng);

        let mut prover_rng = ChaCha12Rng::from_entropy();
        let (seed, proof) = self.and_proof.prove::<ChaCha12Rng>(
            &thetas[self.network.get_id()],
            &lagrange_polys,
            &mut prover_rng,
        );

        tracing::trace!("Finished proof generation");

        // Communication: Send proofs around
        let (proof_prev, proof_next) =
            self.send_receive_and_dzkp::<ChaCha12Rng>(&proof, seed, l, m)?;

        // coin the betas
        let mut betas_rng = ChaCha12Rng::from_seed(self.coin::<ChaCha12Rng>(&mut prover_rng)?);
        let betas = Self::get_rands_for_and_dzkp(m, &mut betas_rng);
        let r = Self::get_and_r(m, &mut betas_rng);

        let (prev_id, next_id) = match self.network.get_id() {
            0 => (2, 1),
            1 => (0, 2),
            2 => (1, 0),
            _ => unreachable!(),
        };

        let shared_verify_prev = self.and_proof.verify_prev(
            &betas[prev_id],
            &r[prev_id],
            &lagrange_polys,
            &coords,
            proof_prev,
        )?;

        let shared_verify_next = self.and_proof.verify_next(
            &betas[next_id],
            &r[next_id],
            &lagrange_polys,
            &coords,
            proof_next,
        )?;

        // send prev_verification to next
        self.network.send_next_id(Bytes::from(
            bincode::serialize(&shared_verify_prev).map_err(|_| Error::SerializationError)?,
        ))?;
        let bytes = self.network.receive_prev_id()?;
        let shared_verify_rcv =
            bincode::deserialize(&bytes).map_err(|_| Error::SerializationError)?;

        // finally, combine the shared verifications to verify the proof of next_id
        self.and_proof.combine_verifications(
            &thetas[next_id],
            shared_verify_rcv,
            shared_verify_next,
        )?;

        Ok(())
    }

    fn mul_verify(&mut self) -> Result<(), Error> {
        let (l, m) = self.mul_proof.calc_params();
        self.mul_proof.set_parameters(l, m);

        tracing::trace!("Starting lagrange interpolation");

        // lagrange: Maybe put into a file and read here
        let coords = MulProof::lagrange_points(m + 1);
        let lagrange_polys =
            Poly::<Poly<U::Share>>::lagrange_polys(&coords, self.mul_proof.get_modulus());

        let d = self.mul_proof.get_mod_d() - 1;

        tracing::trace!("Finished lagrange interpolation");

        let seed = self.prf.gen_p::<<ChaCha12Rng as SeedableRng>::Seed>();
        let mut theta_rng = ChaCha12Rng::from_seed(seed);
        let thetas = Self::get_rands_for_mul_dzkp::<ChaCha12Rng>(l, d, &mut theta_rng);

        let mut prover_rng = ChaCha12Rng::from_entropy();
        let (seed, proof) = self.mul_proof.prove::<ChaCha12Rng>(
            &thetas[self.network.get_id()],
            &lagrange_polys,
            &mut prover_rng,
        );

        tracing::trace!("Finished proof generation");

        // Communication: Send proofs around
        let (proof_prev, proof_next) =
            self.send_receive_mul_dzkp::<ChaCha12Rng>(&proof, seed, l, m, d)?;

        // coin the betas
        let mut betas_rng = ChaCha12Rng::from_seed(self.coin::<ChaCha12Rng>(&mut prover_rng)?);
        let betas = Self::get_rands_for_mul_dzkp(m, d, &mut betas_rng);
        let r = Self::get_mul_r(d, &mut betas_rng);

        let (prev_id, next_id) = match self.network.get_id() {
            0 => (2, 1),
            1 => (0, 2),
            2 => (1, 0),
            _ => unreachable!(),
        };

        let shared_verify_prev = self.mul_proof.verify_prev(
            &betas[prev_id],
            &r[prev_id],
            &lagrange_polys,
            &coords,
            proof_prev,
        )?;

        let shared_verify_next = self.mul_proof.verify_next(
            &betas[next_id],
            &r[next_id],
            &lagrange_polys,
            &coords,
            proof_next,
        )?;

        // send prev_verification to next
        self.network.send_next_id(Bytes::from(
            bincode::serialize(&shared_verify_prev).map_err(|_| Error::SerializationError)?,
        ))?;
        let bytes = self.network.receive_prev_id()?;
        let shared_verify_rcv =
            bincode::deserialize(&bytes).map_err(|_| Error::SerializationError)?;

        // finally, combine the shared verifications to verify the proof of next_id
        self.mul_proof.combine_verifications(
            &thetas[next_id],
            shared_verify_rcv,
            shared_verify_next,
        )?;

        Ok(())
    }

    fn dot_verify(&mut self) -> Result<(), Error> {
        let (l, m) = self.dot_proof.calc_params();
        self.dot_proof.set_parameters(l, m);

        tracing::trace!("Starting lagrange interpolation");

        // lagrange: Maybe put into a file and read here
        let coords = DotProof::lagrange_points(m + 1);
        let lagrange_polys =
            Poly::<Poly<U::Share>>::lagrange_polys(&coords, self.dot_proof.get_modulus());

        let d = self.dot_proof.get_mod_d() - 1;
        let dot = self.dot_proof.get_dot();

        tracing::trace!("Finished lagrange interpolation");

        let seed = self.prf.gen_p::<<ChaCha12Rng as SeedableRng>::Seed>();
        let mut theta_rng = ChaCha12Rng::from_seed(seed);
        let thetas = Self::get_rands_for_mul_dzkp::<ChaCha12Rng>(l, d, &mut theta_rng);

        let mut prover_rng = ChaCha12Rng::from_entropy();
        let (seed, proof) = self.dot_proof.prove::<ChaCha12Rng>(
            &thetas[self.network.get_id()],
            &lagrange_polys,
            &mut prover_rng,
        );

        tracing::trace!("Finished proof generation");

        // Communication: Send proofs around
        let (proof_prev, proof_next) =
            self.send_receive_dot_dzkp::<ChaCha12Rng>(&proof, seed, l, m, d, dot)?;

        // coin the betas
        let mut betas_rng = ChaCha12Rng::from_seed(self.coin::<ChaCha12Rng>(&mut prover_rng)?);
        let betas = Self::get_rands_for_mul_dzkp(m, d, &mut betas_rng);
        let r = Self::get_mul_r(d, &mut betas_rng);

        let (prev_id, next_id) = match self.network.get_id() {
            0 => (2, 1),
            1 => (0, 2),
            2 => (1, 0),
            _ => unreachable!(),
        };

        let shared_verify_prev = self.dot_proof.verify_prev(
            &betas[prev_id],
            &r[prev_id],
            &lagrange_polys,
            &coords,
            proof_prev,
        )?;

        let shared_verify_next = self.dot_proof.verify_next(
            &betas[next_id],
            &r[next_id],
            &lagrange_polys,
            &coords,
            proof_next,
        )?;

        // send prev_verification to next
        self.network.send_next_id(Bytes::from(
            bincode::serialize(&shared_verify_prev).map_err(|_| Error::SerializationError)?,
        ))?;
        let bytes = self.network.receive_prev_id()?;
        let shared_verify_rcv =
            bincode::deserialize(&bytes).map_err(|_| Error::SerializationError)?;

        // finally, combine the shared verifications to verify the proof of next_id
        self.dot_proof.combine_verifications(
            &thetas[next_id],
            shared_verify_rcv,
            shared_verify_next,
        )?;

        Ok(())
    }

    fn aby_mul(&mut self, a: Aby3Share<U>, b: Aby3Share<U>) -> Result<Aby3Share<U>, Error>
    where
        Standard: Distribution<U::Share>,
    {
        let (r0, r1) = self.prf.gen_for_zero_share::<U>();
        let rand = r0.to_owned() - &r1;
        let mut c = a.to_owned() * &b;
        c.a += rand;

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned())?;

        // Register for proof
        let (a0, a1) = a.get_ab();
        let (b0, b1) = b.get_ab();
        let (s0, s1) = c.to_owned().get_ab();
        self.mul_proof.register_mul(a0, a1, b0, b1, r0, r1, s0, s1);

        Ok(c)
    }

    fn aby_and<T: Sharable>(
        &mut self,
        a: Aby3Share<T>,
        b: Aby3Share<T>,
    ) -> Result<Aby3Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        let (r0, r1) = self.prf.gen_for_zero_share::<T>();
        let rand = r0.to_owned() ^ &r1;
        let mut c = a.to_owned() & &b;
        c.a ^= rand;

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned())?;

        // Register for proof
        let (a0, a1) = a.get_ab();
        let (b0, b1) = b.get_ab();
        let (s0, s1) = c.to_owned().get_ab();

        self.and_proof.register_and(a0, a1, b0, b1, r0, r1, s0, s1);

        Ok(c)
    }

    fn aby_and_many<T: Sharable>(
        &mut self,
        a: Vec<Aby3Share<T>>,
        b: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<T>>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        debug_assert_eq!(a.len(), b.len());

        let mut shares_a = Vec::with_capacity(a.len());
        let mut rs: Vec<Aby3Share<T>> = Vec::with_capacity(a.len());

        for (a_, b_) in a.iter().cloned().zip(b.iter().cloned()) {
            let (r0, r1) = self.prf.gen_for_zero_share::<T>();
            let rand = r0.to_owned() ^ &r1;
            let mut c = a_ & b_;
            c.a ^= rand;
            shares_a.push(c.a);
            rs.push(Aby3Share::new(r0, r1));
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned())?;

        let res: Vec<Aby3Share<T>> = shares_a
            .into_iter()
            .zip(shares_b.into_iter())
            .map(|(a_, b_)| Aby3Share::new(a_, b_))
            .collect();

        // Register for proof
        for (((a, b), c), r) in a
            .into_iter()
            .zip(b.into_iter())
            .zip(res.iter())
            .zip(rs.into_iter())
        {
            let (a0, a1) = a.get_ab();
            let (b0, b1) = b.get_ab();
            let (r0, r1) = r.get_ab();
            let (s0, s1) = c.to_owned().get_ab();

            self.and_proof.register_and(a0, a1, b0, b1, r0, r1, s0, s1);
        }

        Ok(res)
    }

    fn aby_dot(&mut self, a: Vec<Aby3Share<U>>, b: Vec<Aby3Share<U>>) -> Result<Aby3Share<U>, Error>
    where
        Standard: Distribution<U::Share>,
    {
        let len = a.len();
        debug_assert_eq!(len, b.len());

        let (r0, r1) = self.prf.gen_for_zero_share::<U>();
        let rand = r0.to_owned() - &r1;

        let mut a0 = Vec::with_capacity(len);
        let mut a1 = Vec::with_capacity(len);
        let mut b0 = Vec::with_capacity(len);
        let mut b1 = Vec::with_capacity(len);

        let mut c = Aby3Share::new(rand, U::zero().to_sharetype());
        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            c += a_.to_owned() * &b_;

            // Register for proof
            let (a0_, a1_) = a_.get_ab();
            let (b0_, b1_) = b_.get_ab();
            a0.push(a0_);
            a1.push(a1_);
            b0.push(b0_);
            b1.push(b1_);
        }

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned())?;

        let (s0, s1) = c.to_owned().get_ab();

        self.dot_proof.register_dot(a0, a1, b0, b1, r0, r1, s0, s1);

        Ok(c)
    }

    fn aby_dot_many(
        &mut self,
        a: Vec<Vec<Aby3Share<U>>>,
        b: Vec<Vec<Aby3Share<U>>>,
    ) -> Result<Vec<Aby3Share<U>>, Error>
    where
        Standard: Distribution<U::Share>,
    {
        let len = a.len();
        debug_assert_eq!(len, b.len());

        let mut shares_a = Vec::with_capacity(len);

        let mut a0 = Vec::with_capacity(len);
        let mut a1 = Vec::with_capacity(len);
        let mut b0 = Vec::with_capacity(len);
        let mut b1 = Vec::with_capacity(len);
        let mut r0 = Vec::with_capacity(len);
        let mut r1 = Vec::with_capacity(len);

        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            let (r0_, r1_) = self.prf.gen_for_zero_share::<U>();
            let mut rand = r0_.to_owned() - &r1_;
            let len_ = a_.len();
            debug_assert_eq!(len_, b_.len());

            r0.push(r0_);
            r1.push(r1_);

            let mut a0_ = Vec::with_capacity(len_);
            let mut a1_ = Vec::with_capacity(len_);
            let mut b0_ = Vec::with_capacity(len_);
            let mut b1_ = Vec::with_capacity(len_);

            for (a__, b__) in a_.into_iter().zip(b_.into_iter()) {
                rand += (a__.to_owned() * &b__).a;

                // Register for proof
                let (a0__, a1__) = a__.get_ab();
                let (b0__, b1__) = b__.get_ab();
                a0_.push(a0__);
                a1_.push(a1__);
                b0_.push(b0__);
                b1_.push(b1__);
            }
            a0.push(a0_);
            a1.push(a1_);
            b0.push(b0_);
            b1.push(b1_);
            shares_a.push(rand);
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned())?;

        let mut res = Vec::with_capacity(len);

        for (a0, (a1, (b0, (b1, (r0, (r1, (s0, s1))))))) in a0.into_iter().zip(
            a1.into_iter().zip(
                b0.into_iter().zip(
                    b1.into_iter().zip(
                        r0.into_iter().zip(
                            r1.into_iter()
                                .zip(shares_a.into_iter().zip(shares_b.into_iter())),
                        ),
                    ),
                ),
            ),
        ) {
            let c = Aby3Share::new(s0.to_owned(), s1.to_owned());
            res.push(c);
            self.dot_proof.register_dot(a0, a1, b0, b1, r0, r1, s0, s1);
        }

        Ok(res)
    }

    fn jmp_receive<T: Sharable>(&mut self, id: usize) -> Result<T::Share, Error> {
        // I should receive from id, and later the hash from the third party
        let value: T::Share = utils::receive_value(&mut self.network, id)?;

        let my_id = self.network.get_id();
        // if id==next_id, i should recv from prev and vice versa
        if id == (my_id + 1) % 3 {
            value.to_owned().add_to_bytes(&mut self.rcv_queue_prev);
        } else if id == (my_id + 2) % 3 {
            value.to_owned().add_to_bytes(&mut self.rcv_queue_next);
        } else {
            return Err(Error::IdError(id));
        }

        Ok(value)
    }

    fn jmp_receive_many<T: Sharable>(
        &mut self,
        id: usize,
        len: usize,
    ) -> Result<Vec<T::Share>, Error> {
        // I should receive from id, and later the hash from the third party
        let values: Vec<T::Share> = utils::receive_vec(&mut self.network, id, len)?;

        let my_id = self.network.get_id();
        // if id==next_id, i should recv from prev and vice versa
        if id == (my_id + 1) % 3 {
            for value in values.iter().cloned() {
                value.add_to_bytes(&mut self.rcv_queue_prev);
            }
        } else if id == (my_id + 2) % 3 {
            for value in values.iter().cloned() {
                value.add_to_bytes(&mut self.rcv_queue_next);
            }
        } else {
            return Err(Error::IdError(id));
        }

        Ok(values)
    }

    fn clear_and_hash(data: &mut BytesMut) -> Output<Sha512> {
        let mut swap = BytesMut::new();
        std::mem::swap(&mut swap, data);
        let bytes = swap.freeze();
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        hasher.finalize()
    }

    fn jmp_verify(&mut self) -> Result<(), Error> {
        let id = self.network.get_id();
        let next_id = (id + 1) % 3;
        let prev_id = (id + 2) % 3;

        let send_next = Self::clear_and_hash(&mut self.send_queue_next);
        let send_prev = Self::clear_and_hash(&mut self.send_queue_prev);
        let hash_next = Self::clear_and_hash(&mut self.rcv_queue_next);
        let hash_prev = Self::clear_and_hash(&mut self.rcv_queue_prev);

        self.network
            .send(next_id, Bytes::from(send_next.to_vec()))?;
        self.network
            .send(prev_id, Bytes::from(send_prev.to_vec()))?;

        let rcv_prev = self.network.receive(prev_id)?;
        let rcv_next = self.network.receive(next_id)?;

        if rcv_prev.as_ref() != hash_prev.as_slice() || rcv_next.as_ref() != hash_next.as_slice() {
            return Err(Error::JmpVerifyError);
        }

        Ok(())
    }

    fn jshare<T: Sharable>(
        &mut self,
        input: Option<T>,
        mut sender1: usize,
        mut sender2: usize,
        receiver: usize,
    ) -> Result<Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        if sender2 != ((sender1 + 1) % 3) {
            std::mem::swap(&mut sender1, &mut sender2);
        }

        let self_id = self.network.get_id();
        debug_assert!(sender1 != sender2);
        debug_assert!(sender1 != receiver);
        debug_assert!(sender2 != receiver);
        if ((sender1 == self_id) || (sender2 == self_id)) && input.is_none() {
            return Err(Error::ValueError("Cannot share None".to_string()));
        }

        let alpha_p = self.prf.gen_p::<T::Share>();

        let share = if self_id == sender1 {
            let alpha_1 = self.prf.gen_1::<T::Share>();
            let alpha = alpha_1.to_owned() + &alpha_p + &alpha_p;
            let beta = alpha + input.unwrap().to_sharetype();
            self.jmp_send::<T>(beta.to_owned(), receiver)?;
            Share::new(alpha_1, alpha_p, beta)
        } else if self_id == sender2 {
            let alpha_1 = self.prf.gen_2::<T::Share>();
            let alpha = alpha_1.to_owned() + &alpha_p + &alpha_p;
            let beta = alpha + input.unwrap().to_sharetype();
            self.jmp_queue::<T>(beta.to_owned(), receiver)?;
            Share::new(alpha_p, alpha_1, beta)
        } else if self_id == receiver {
            let beta = self.jmp_receive::<T>(sender1)?;
            Share::new(alpha_p.to_owned(), alpha_p, beta)
        } else {
            unreachable!()
        };

        Ok(share)
    }

    fn jshare_many<T: Sharable>(
        &mut self,
        input: Option<Vec<T>>,
        mut sender1: usize,
        mut sender2: usize,
        receiver: usize,
        len: usize,
    ) -> Result<Vec<Share<T>>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        if sender2 != ((sender1 + 1) % 3) {
            std::mem::swap(&mut sender1, &mut sender2);
        }

        let self_id = self.network.get_id();
        debug_assert!(sender1 != sender2);
        debug_assert!(sender1 != receiver);
        debug_assert!(sender2 != receiver);
        if ((sender1 == self_id) || (sender2 == self_id)) && input.is_none() {
            return Err(Error::ValueError("Cannot share None".to_string()));
        }
        let mut shares = Vec::with_capacity(len);

        if self_id == sender1 {
            let mut alphas_1 = Vec::with_capacity(len);
            let mut alphas_p = Vec::with_capacity(len);
            let mut betas = Vec::with_capacity(len);

            let input = input.unwrap();
            if input.len() != len {
                return Err(Error::InvalidSizeError);
            }
            for inp in input.into_iter() {
                let alpha_p = self.prf.gen_p::<T::Share>();
                let alpha_1 = self.prf.gen_1::<T::Share>();
                let alpha = alpha_1.to_owned() + &alpha_p + &alpha_p;
                let beta = alpha + inp.to_sharetype();
                betas.push(beta);
                alphas_1.push(alpha_1);
                alphas_p.push(alpha_p);
            }

            self.jmp_send_many::<T>(betas.to_owned(), receiver)?;
            for ((alpha_1, alpha_p), beta) in alphas_1.into_iter().zip(alphas_p).zip(betas) {
                shares.push(Share::new(alpha_1, alpha_p, beta));
            }
        } else if self_id == sender2 {
            let mut alphas_1 = Vec::with_capacity(len);
            let mut alphas_p = Vec::with_capacity(len);
            let mut betas = Vec::with_capacity(len);

            let input = input.unwrap();
            if input.len() != len {
                return Err(Error::InvalidSizeError);
            }
            for inp in input.into_iter() {
                let alpha_p = self.prf.gen_p::<T::Share>();
                let alpha_1 = self.prf.gen_2::<T::Share>();
                let alpha = alpha_1.to_owned() + &alpha_p + &alpha_p;
                let beta = alpha + inp.to_sharetype();
                betas.push(beta);
                alphas_1.push(alpha_1);
                alphas_p.push(alpha_p);
            }

            self.jmp_queue_many::<T>(betas.to_owned(), receiver)?;
            for ((alpha_1, alpha_p), beta) in alphas_1.into_iter().zip(alphas_p).zip(betas) {
                shares.push(Share::new(alpha_p, alpha_1, beta));
            }
        } else if self_id == receiver {
            let betas = self.jmp_receive_many::<T>(sender1, len)?;
            for beta in betas {
                let alpha_p = self.prf.gen_p::<T::Share>();
                shares.push(Share::new(alpha_p.to_owned(), alpha_p, beta));
            }
        } else {
            unreachable!()
        };

        Ok(shares)
    }

    fn jshare_binary<T: Sharable>(
        &mut self,
        input: Option<T>,
        mut sender1: usize,
        mut sender2: usize,
        receiver: usize,
    ) -> Result<Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        if sender2 != ((sender1 + 1) % 3) {
            std::mem::swap(&mut sender1, &mut sender2);
        }

        let self_id = self.network.get_id();
        debug_assert!(sender1 != sender2);
        debug_assert!(sender1 != receiver);
        debug_assert!(sender2 != receiver);
        if ((sender1 == self_id) || (sender2 == self_id)) && input.is_none() {
            return Err(Error::ValueError("Cannot share None".to_string()));
        }

        let alpha_p = self.prf.gen_p::<T::Share>();

        let share = if self_id == sender1 {
            let alpha_1 = self.prf.gen_1::<T::Share>();
            let alpha = alpha_1.to_owned();
            let beta = alpha ^ input.unwrap().to_sharetype();
            self.jmp_send::<T>(beta.to_owned(), receiver)?;
            Share::new(alpha_1, alpha_p, beta)
        } else if self_id == sender2 {
            let alpha_1 = self.prf.gen_2::<T::Share>();
            let alpha = alpha_1.to_owned();
            let beta = alpha ^ input.unwrap().to_sharetype();
            self.jmp_queue::<T>(beta.to_owned(), receiver)?;
            Share::new(alpha_p, alpha_1, beta)
        } else if self_id == receiver {
            let beta = self.jmp_receive::<T>(sender1)?;
            Share::new(alpha_p.to_owned(), alpha_p, beta)
        } else {
            unreachable!()
        };

        Ok(share)
    }

    fn jshare_binary_many<T: Sharable>(
        &mut self,
        input: Option<Vec<T>>,
        mut sender1: usize,
        mut sender2: usize,
        receiver: usize,
        len: usize,
    ) -> Result<Vec<Share<T>>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        if sender2 != ((sender1 + 1) % 3) {
            std::mem::swap(&mut sender1, &mut sender2);
        }

        let self_id = self.network.get_id();
        debug_assert!(sender1 != sender2);
        debug_assert!(sender1 != receiver);
        debug_assert!(sender2 != receiver);
        if ((sender1 == self_id) || (sender2 == self_id)) && input.is_none() {
            return Err(Error::ValueError("Cannot share None".to_string()));
        }
        let mut shares = Vec::with_capacity(len);

        if self_id == sender1 {
            let mut alphas_1 = Vec::with_capacity(len);
            let mut alphas_p = Vec::with_capacity(len);
            let mut betas = Vec::with_capacity(len);

            let input = input.unwrap();
            if input.len() != len {
                return Err(Error::InvalidSizeError);
            }
            for inp in input.into_iter() {
                let alpha_p = self.prf.gen_p::<T::Share>();
                let alpha_1 = self.prf.gen_1::<T::Share>();
                let alpha = alpha_1.to_owned();
                let beta = alpha ^ inp.to_sharetype();
                betas.push(beta);
                alphas_1.push(alpha_1);
                alphas_p.push(alpha_p);
            }

            self.jmp_send_many::<T>(betas.to_owned(), receiver)?;
            for ((alpha_1, alpha_p), beta) in alphas_1.into_iter().zip(alphas_p).zip(betas) {
                shares.push(Share::new(alpha_1, alpha_p, beta));
            }
        } else if self_id == sender2 {
            let mut alphas_1 = Vec::with_capacity(len);
            let mut alphas_p = Vec::with_capacity(len);
            let mut betas = Vec::with_capacity(len);

            let input = input.unwrap();
            if input.len() != len {
                return Err(Error::InvalidSizeError);
            }
            for inp in input.into_iter() {
                let alpha_p = self.prf.gen_p::<T::Share>();
                let alpha_1 = self.prf.gen_2::<T::Share>();
                let alpha = alpha_1.to_owned();
                let beta = alpha ^ inp.to_sharetype();
                betas.push(beta);
                alphas_1.push(alpha_1);
                alphas_p.push(alpha_p);
            }

            self.jmp_queue_many::<T>(betas.to_owned(), receiver)?;
            for ((alpha_1, alpha_p), beta) in alphas_1.into_iter().zip(alphas_p).zip(betas) {
                shares.push(Share::new(alpha_p, alpha_1, beta));
            }
        } else if self_id == receiver {
            let betas = self.jmp_receive_many::<T>(sender1, len)?;
            for beta in betas {
                let alpha_p = self.prf.gen_p::<T::Share>();
                shares.push(Share::new(alpha_p.to_owned(), alpha_p, beta));
            }
        } else {
            unreachable!()
        };

        Ok(shares)
    }

    fn send_seed_opening(
        &mut self,
        opening1: &CommitOpening<RingElement<u8>>,
        opening2: &CommitOpening<RingElement<u8>>,
        opening3: &CommitOpening<RingElement<u8>>,
        id1: usize,
        id2: usize,
    ) -> Result<(), Error> {
        let mut msg1 = BytesMut::new();
        let mut msg2 = BytesMut::new();
        for val in opening1.values.iter().cloned() {
            val.add_to_bytes(&mut msg1);
        }
        msg1.extend_from_slice(&opening1.rand);

        for val in opening2.values.iter().cloned() {
            val.add_to_bytes(&mut msg2);
        }
        msg2.extend_from_slice(&opening2.rand);

        for val in opening3.values.iter().cloned() {
            val.to_owned().add_to_bytes(&mut msg1);
            val.add_to_bytes(&mut msg2);
        }
        msg1.extend_from_slice(&opening3.rand);
        msg2.extend_from_slice(&opening3.rand);

        let msg1 = msg1.freeze();
        let msg2 = msg2.freeze();

        self.network.send(id1, msg1)?;
        self.network.send(id2, msg2)?;

        Ok(())
    }

    fn setup_prf(&mut self) -> Result<(), Error> {
        let seed1 = Prf::gen_seed();
        let seed2 = Prf::gen_seed();
        let seed3 = Prf::gen_seed();
        self.setup_prf_from_seed([seed1, seed2, seed3])
    }

    fn verify_commitment(data: &[u8], rand: [u8; 32], comm: Vec<u8>) -> bool {
        let opening = CommitOpening {
            values: RingElement::convert_slice_rev(data).to_vec(),
            rand,
        };
        opening.verify(comm)
    }

    fn setup_prf_from_seed(&mut self, seeds: [PrfSeed; 3]) -> Result<(), Error> {
        let id = self.network.get_id();
        let ids = match id {
            0 => (1, 2),
            1 => (0, 2),
            2 => (0, 1),
            _ => unreachable!(),
        };

        let mut rng = ChaCha12Rng::from_entropy();

        let comm1 =
            Commitment::commit(RingElement::convert_slice_rev(&seeds[0]).to_vec(), &mut rng);
        let comm2 =
            Commitment::commit(RingElement::convert_slice_rev(&seeds[1]).to_vec(), &mut rng);
        let comm3 =
            Commitment::commit(RingElement::convert_slice_rev(&seeds[2]).to_vec(), &mut rng);

        // First communication round: Send commitments
        self.send_seed_commitment(&comm1.comm, &comm2.comm, &comm3.comm, ids.0, ids.1)?;

        let msg1 = self.network.receive(ids.0)?;
        let msg2 = self.network.receive(ids.1)?;

        let comm_size = Commitment::<RingElement<u8>>::get_comm_size();

        if msg1.len() != 2 * comm_size || msg2.len() != 2 * comm_size {
            return Err(Error::InvalidMessageSize);
        }
        let mut rcv_comm1 = Vec::with_capacity(comm_size);
        let mut rcv_comm2 = Vec::with_capacity(comm_size);
        let mut rcv_comm3 = Vec::with_capacity(comm_size);
        let mut rcv_comm4 = Vec::with_capacity(comm_size);

        msg1[..comm_size].clone_into(&mut rcv_comm1);
        msg1[comm_size..].clone_into(&mut rcv_comm2);

        msg2[..comm_size].clone_into(&mut rcv_comm3);
        msg2[comm_size..].clone_into(&mut rcv_comm4);

        // second communication round: send opening:
        let open1 = comm1.open();
        let open2 = comm2.open();
        let open3 = comm3.open();
        self.send_seed_opening(&open1, &open2, &open3, ids.0, ids.1)?;

        let msg1 = self.network.receive(ids.0)?;
        let msg2 = self.network.receive(ids.1)?;

        let seed_size = seeds[0].len();
        let rand_size = Commitment::<RingElement<u8>>::get_rand_size();
        debug_assert_eq!(rand_size, 32);

        if msg1.len() != 2 * (seed_size + rand_size) || msg2.len() != 2 * (seed_size + rand_size) {
            return Err(Error::InvalidMessageSize);
        }
        let mut rcv_open1 = Vec::with_capacity(seed_size);
        let mut rcv_open2 = Vec::with_capacity(seed_size);
        let mut rcv_open3 = Vec::with_capacity(seed_size);
        let mut rcv_open4 = Vec::with_capacity(seed_size);

        let mut rcv_rand1 = [0; 32];
        let mut rcv_rand2 = [0; 32];
        let mut rcv_rand3 = [0; 32];
        let mut rcv_rand4 = [0; 32];

        msg1[..seed_size].clone_into(&mut rcv_open1);
        rcv_rand1.copy_from_slice(&msg1[seed_size..seed_size + rand_size]);
        msg1[seed_size + rand_size..2 * seed_size + rand_size].clone_into(&mut rcv_open2);
        rcv_rand2.copy_from_slice(&msg1[2 * seed_size + rand_size..]);

        msg2[..seed_size].clone_into(&mut rcv_open3);
        rcv_rand3.copy_from_slice(&msg2[seed_size..seed_size + rand_size]);
        msg2[seed_size + rand_size..2 * seed_size + rand_size].clone_into(&mut rcv_open4);
        rcv_rand4.copy_from_slice(&msg2[2 * seed_size + rand_size..]);

        if !Self::verify_commitment(&rcv_open1, rcv_rand1, rcv_comm1)
            || !Self::verify_commitment(&rcv_open2, rcv_rand2, rcv_comm2)
        {
            return Err(Error::InvalidCommitment(ids.0));
        }
        if !Self::verify_commitment(&rcv_open3, rcv_rand3, rcv_comm3)
            || !Self::verify_commitment(&rcv_open4, rcv_rand4, rcv_comm4)
        {
            return Err(Error::InvalidCommitment(ids.1));
        }

        // Finally done: Just initialize the PRFs now
        let mut seed1 = [0u8; 32];
        let mut seed2 = [0u8; 32];
        let mut seed3 = [0u8; 32];

        for (r, (a, b)) in seed1
            .iter_mut()
            .zip(seeds[0].iter().zip(rcv_open1.into_iter()))
        {
            *r = b ^ a;
        }

        for (r, (a, b)) in seed2
            .iter_mut()
            .zip(seeds[1].iter().zip(rcv_open3.into_iter()))
        {
            *r = b ^ a;
        }

        for (r, (a, (b, c))) in seed3.iter_mut().zip(
            seeds[2]
                .iter()
                .zip(rcv_open2.into_iter().zip(rcv_open4.into_iter())),
        ) {
            *r = b ^ a ^ c;
        }

        if id == 1 {
            self.prf = Prf::new(seed2, seed1, seed3);
        } else {
            self.prf = Prf::new(seed1, seed2, seed3);
        }

        Ok(())
    }

    fn pack<T: Sharable>(&self, a: Vec<Share<Bit>>) -> Vec<Share<T>> {
        let outlen = (a.len() + T::Share::K - 1) / T::Share::K;
        let mut out = Vec::with_capacity(outlen);

        for a_ in a.chunks(T::Share::K) {
            let mut share_a = T::Share::zero();
            let mut share_b = T::Share::zero();
            let mut share_c = T::Share::zero();
            for (i, bit) in a_.iter().enumerate() {
                let (bit_a, bit_b, bit_c) = bit.to_owned().get_abc();
                share_a |= T::Share::from(bit_a.convert().convert()) << (i as u32);
                share_b |= T::Share::from(bit_b.convert().convert()) << (i as u32);
                share_c |= T::Share::from(bit_c.convert().convert()) << (i as u32);
            }
            let share = Share::new(share_a, share_b, share_c);
            out.push(share);
        }

        out
    }

    reduce_or!(
        [u128, u64, reduce_or_u128, reduce_or_u64],
        [u64, u32, reduce_or_u64, reduce_or_u32],
        [u32, u16, reduce_or_u32, reduce_or_u16],
        [u16, u8, reduce_or_u16, reduce_or_u8]
    );

    fn reduce_or_u8(&mut self, a: Share<u8>) -> Result<Share<Bit>, Error> {
        const K: usize = 8;

        let mut decomp: Vec<Share<Bit>> = Vec::with_capacity(K);
        for i in 0..K as u32 {
            let bit_a = ((a.a.to_owned() >> i) & RingElement(1)) == RingElement(1);
            let bit_b = ((a.b.to_owned() >> i) & RingElement(1)) == RingElement(1);
            let bit_c = ((a.c.to_owned() >> i) & RingElement(1)) == RingElement(1);

            decomp.push(Share::new(
                <Bit as Sharable>::Share::from(bit_a),
                <Bit as Sharable>::Share::from(bit_b),
                <Bit as Sharable>::Share::from(bit_c),
            ));
        }

        let mut k = K;
        while k != 1 {
            k >>= 1;
            decomp = <Self as BinaryMpcTrait<Bit, Share<Bit>>>::or_many(
                self,
                decomp[..k].to_vec(),
                decomp[k..].to_vec(),
            )?;
        }

        Ok(decomp[0].to_owned())
    }

    fn coin<R: Rng + SeedableRng>(&mut self, rng: &mut R) -> Result<R::Seed, Error>
    where
        Standard: Distribution<R::Seed>,
        R::Seed: AsRef<[u8]>,
    {
        let ids = match self.network.get_id() {
            0 => (1, 2),
            1 => (0, 2),
            2 => (0, 1),
            _ => unreachable!(),
        };

        let mut seed = rng.gen::<R::Seed>();

        let comm = Commitment::commit(RingElement::convert_slice_rev(seed.as_ref()).to_vec(), rng);

        let (open, rand, comm) = (comm.values, comm.rand, comm.comm);

        // Broadcast commitment
        let res = self.network.broadcast(Bytes::from(comm))?;

        let comm_size = Commitment::<RingElement<u8>>::get_comm_size();
        if res[ids.0].len() != comm_size || res[ids.1].len() != comm_size {
            return Err(Error::InvalidMessageSize);
        }
        let mut rcv_comm1 = Vec::with_capacity(comm_size);
        let mut rcv_comm2 = Vec::with_capacity(comm_size);
        res[ids.0].as_ref().clone_into(&mut rcv_comm1);
        res[ids.1].as_ref().clone_into(&mut rcv_comm2);

        // Broadcast opening
        let mut msg = BytesMut::new();
        for val in open.into_iter() {
            val.add_to_bytes(&mut msg);
        }
        msg.extend_from_slice(&rand);
        let msg = msg.freeze();
        let res = self.network.broadcast(msg)?;

        let seed_size = seed.as_ref().len();
        let rand_size = Commitment::<RingElement<u8>>::get_rand_size();

        if res[ids.0].len() != seed_size + rand_size || res[ids.1].len() != seed_size + rand_size {
            return Err(Error::InvalidMessageSize);
        }
        let mut rcv_open1 = Vec::with_capacity(seed_size);
        let mut rcv_open2 = Vec::with_capacity(seed_size);
        let mut rcv_rand1 = [0; 32];
        let mut rcv_rand2 = [0; 32];

        res[ids.0][..seed_size].clone_into(&mut rcv_open1);
        rcv_rand1.copy_from_slice(&res[ids.0][seed_size..seed_size + rand_size]);
        res[ids.1][..seed_size].clone_into(&mut rcv_open2);
        rcv_rand2.copy_from_slice(&res[ids.1][seed_size..seed_size + rand_size]);

        if !Self::verify_commitment(&rcv_open1, rcv_rand1, rcv_comm1) {
            return Err(Error::InvalidCommitment(ids.0));
        }

        if !Self::verify_commitment(&rcv_open2, rcv_rand2, rcv_comm2) {
            return Err(Error::InvalidCommitment(ids.1));
        }

        seed.as_mut()
            .iter_mut()
            .zip(rcv_open1.into_iter().zip(rcv_open2.into_iter()))
            .for_each(|(r, (a, b))| *r ^= a ^ b);

        Ok(seed)
    }

    fn send_receive_and_dzkp<R: Rng + SeedableRng>(
        &mut self,
        proof: &AndProofStruct,
        seed: R::Seed,
        l: usize,
        m: usize,
    ) -> Result<(AndProofStruct, AndProofStruct), Error>
    where
        R::Seed: AsRef<[u8]>,
    {
        self.network.send_next_id(Bytes::from(
            bincode::serialize(&proof).map_err(|_| Error::SerializationError)?,
        ))?;
        self.network
            .send_prev_id(Bytes::from(seed.as_ref().to_vec()))?;

        let proof_bytes = self.network.receive_prev_id()?;
        let proof_prev =
            bincode::deserialize(&proof_bytes).map_err(|_| Error::SerializationError)?;

        let seed_next = self.network.receive_next_id()?.freeze();
        if seed_next.len() != seed.as_ref().len() {
            return Err(Error::InvalidMessageSize);
        }
        let mut seed_next_ = <ChaCha12Rng as SeedableRng>::Seed::default();
        seed_next_
            .iter_mut()
            .zip(seed_next.into_iter())
            .for_each(|(a, b)| *a = b);
        let proof_next = AndProofStruct::from_seed::<ChaCha12Rng>(seed_next_, l, m);

        Ok((proof_prev, proof_next))
    }

    #[allow(unused)]
    fn send_receive_mul_dzkp<R: Rng + SeedableRng>(
        &mut self,
        proof: &MulProofStruct<U::Share>,
        seed: R::Seed,
        l: usize,
        m: usize,
        d: usize,
    ) -> Result<(MulProofStruct<U::Share>, MulProofStruct<U::Share>), Error>
    where
        R::Seed: AsRef<[u8]>,
    {
        self.network.send_next_id(Bytes::from(
            bincode::serialize(&proof).map_err(|_| Error::SerializationError)?,
        ))?;
        self.network
            .send_prev_id(Bytes::from(seed.as_ref().to_vec()))?;

        let proof_bytes = self.network.receive_prev_id()?;
        let proof_prev =
            bincode::deserialize(&proof_bytes).map_err(|_| Error::SerializationError)?;

        let seed_next = self.network.receive_next_id()?.freeze();
        if seed_next.len() != seed.as_ref().len() {
            return Err(Error::InvalidMessageSize);
        }
        let mut seed_next_ = <ChaCha12Rng as SeedableRng>::Seed::default();
        seed_next_
            .iter_mut()
            .zip(seed_next.into_iter())
            .for_each(|(a, b)| *a = b);
        let proof_next = MulProofStruct::from_seed::<ChaCha12Rng>(seed_next_, l, m, d);

        Ok((proof_prev, proof_next))
    }

    fn get_rands_for_and_dzkp<R: Rng>(size: usize, rng: &mut R) -> [Vec<GF2p64>; 3] {
        let mut rands = [
            Vec::with_capacity(size),
            Vec::with_capacity(size),
            Vec::with_capacity(size),
        ];

        // Theta_i/Beta_i for party i's proof
        for rand in rands.iter_mut() {
            for _ in 0..size {
                rand.push(GF2p64::random(rng));
            }
        }
        rands
    }

    fn send_receive_dot_dzkp<R: Rng + SeedableRng>(
        &mut self,
        proof: &DotProofStruct<U::Share>,
        seed: R::Seed,
        l: usize,
        m: usize,
        d: usize,
        dot: usize,
    ) -> Result<(DotProofStruct<U::Share>, DotProofStruct<U::Share>), Error>
    where
        R::Seed: AsRef<[u8]>,
    {
        self.network.send_next_id(Bytes::from(
            bincode::serialize(&proof).map_err(|_| Error::SerializationError)?,
        ))?;
        self.network
            .send_prev_id(Bytes::from(seed.as_ref().to_vec()))?;

        let proof_bytes = self.network.receive_prev_id()?;
        let proof_prev =
            bincode::deserialize(&proof_bytes).map_err(|_| Error::SerializationError)?;

        let seed_next = self.network.receive_next_id()?.freeze();
        if seed_next.len() != seed.as_ref().len() {
            return Err(Error::InvalidMessageSize);
        }
        let mut seed_next_ = <ChaCha12Rng as SeedableRng>::Seed::default();
        seed_next_
            .iter_mut()
            .zip(seed_next.into_iter())
            .for_each(|(a, b)| *a = b);
        let proof_next = DotProofStruct::from_seed::<ChaCha12Rng>(seed_next_, l, m, d, dot);

        Ok((proof_prev, proof_next))
    }

    fn get_rands_for_mul_dzkp<R: Rng>(
        size: usize,
        d: usize,
        rng: &mut R,
    ) -> [Vec<Poly<U::Share>>; 3] {
        let mut rands = [
            Vec::with_capacity(size),
            Vec::with_capacity(size),
            Vec::with_capacity(size),
        ];

        // Theta_i/Beta_i for party i's proof
        for rand in rands.iter_mut() {
            for _ in 0..size {
                rand.push(Poly::random(d, rng));
            }
        }
        rands
    }

    fn get_and_r<R: Rng>(m: usize, rng: &mut R) -> [GF2p64; 3] {
        let mut rs = [rng.gen::<u64>(), rng.gen::<u64>(), rng.gen::<u64>()];

        for r in rs.iter_mut() {
            while *r <= m as u64 {
                *r = rng.gen::<u64>();
            }
        }

        [GF2p64::new(rs[0]), GF2p64::new(rs[1]), GF2p64::new(rs[2])]
    }

    fn get_mul_r<R: Rng>(d: usize, rng: &mut R) -> [Poly<U::Share>; 3] {
        let mut rs = [
            Poly::random(d, rng),
            Poly::random(d, rng),
            Poly::random(d, rng),
        ];

        for r in rs.iter_mut() {
            while r.coeffs[0].is_zero() {
                *r = Poly::random(d, rng)
            }
        }

        rs
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, Share<T>, Share<Bit>> for Swift3<N, T>
where
    Standard: Distribution<T::Share>,
    Share<T>: Mul<T::Share, Output = Share<T>>,
{
    fn get_id(&self) -> usize {
        self.network.get_id()
    }

    fn finish(self) -> Result<(), Error> {
        self.network.shutdown()?;
        Ok(())
    }

    fn preprocess(&mut self) -> Result<(), Error> {
        self.setup_prf()
    }

    fn set_mac_key(&mut self, _key: Share<T>) {}
    fn set_new_mac_key(&mut self) {}
    #[cfg(test)]
    fn open_mac_key(&mut self) -> Result<T::VerificationShare, Error> {
        Ok(T::VerificationShare::default())
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        Ok(self.network.print_connection_stats(out)?)
    }

    fn input(&mut self, input: Option<T>, id: usize) -> Result<Share<T>, Error> {
        let self_id = self.get_id();
        if id == self_id && input.is_none() {
            return Err(Error::ValueError("Cannot share None".to_string()));
        }

        let share = match id {
            0 => {
                if self_id == 0 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let alpha2 = self.prf.gen_p::<T::Share>();
                    let alpha3 = self.prf.gen_2::<T::Share>();
                    let alpha = alpha2 + &alpha1 + &alpha3;
                    let beta = input.unwrap().to_sharetype() + alpha;
                    utils::send_value(&mut self.network, beta.to_owned(), 1)?;
                    self.jmp_send::<T>(beta.to_owned(), 2)?;
                    Share::new(alpha1, alpha3, beta)
                } else if self_id == 1 {
                    let alpha1 = self.prf.gen_2::<T::Share>();
                    let alpha2 = self.prf.gen_p::<T::Share>();
                    let beta: T::Share = utils::receive_value(&mut self.network, 0)?;
                    self.jmp_queue::<T>(beta.to_owned(), 2)?;
                    Share::new(alpha2, alpha1, beta)
                } else if self_id == 2 {
                    let alpha2 = self.prf.gen_p::<T::Share>();
                    let alpha3 = self.prf.gen_1::<T::Share>();
                    let beta = self.jmp_receive::<T>(0)?;
                    Share::new(alpha3, alpha2, beta)
                } else {
                    unreachable!()
                }
            }
            1 => {
                if self_id == 1 {
                    let alpha1 = self.prf.gen_2::<T::Share>();
                    let alpha2 = self.prf.gen_1::<T::Share>();
                    let alpha3 = self.prf.gen_p::<T::Share>();
                    let alpha = alpha3 + &alpha1 + &alpha2;
                    let beta = input.unwrap().to_sharetype() + alpha;
                    utils::send_value(&mut self.network, beta.to_owned(), 2)?;
                    self.jmp_send::<T>(beta.to_owned(), 0)?;
                    Share::new(alpha2, alpha1, beta)
                } else if self_id == 2 {
                    let alpha2 = self.prf.gen_2::<T::Share>();
                    let alpha3 = self.prf.gen_p::<T::Share>();
                    let beta: T::Share = utils::receive_value(&mut self.network, 1)?;
                    self.jmp_queue::<T>(beta.to_owned(), 0)?;
                    Share::new(alpha3, alpha2, beta)
                } else if self_id == 0 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let alpha3 = self.prf.gen_p::<T::Share>();
                    let beta = self.jmp_receive::<T>(1)?;
                    Share::new(alpha1, alpha3, beta)
                } else {
                    unreachable!()
                }
            }
            2 => {
                if self_id == 2 {
                    let alpha1 = self.prf.gen_p::<T::Share>();
                    let alpha2 = self.prf.gen_2::<T::Share>();
                    let alpha3 = self.prf.gen_1::<T::Share>();
                    let alpha = alpha1 + &alpha2 + &alpha3;
                    let beta = input.unwrap().to_sharetype() + alpha;
                    utils::send_value(&mut self.network, beta.to_owned(), 1)?;
                    self.jmp_send::<T>(beta.to_owned(), 0)?;
                    Share::new(alpha3, alpha2, beta)
                } else if self_id == 1 {
                    let alpha1 = self.prf.gen_p::<T::Share>();
                    let alpha2 = self.prf.gen_1::<T::Share>();
                    let beta: T::Share = utils::receive_value(&mut self.network, 2)?;
                    self.jmp_queue::<T>(beta.to_owned(), 0)?;
                    Share::new(alpha2, alpha1, beta)
                } else if self_id == 0 {
                    let alpha1 = self.prf.gen_p::<T::Share>();
                    let alpha3 = self.prf.gen_2::<T::Share>();
                    let beta = self.jmp_receive::<T>(2)?;
                    Share::new(alpha1, alpha3, beta)
                } else {
                    unreachable!()
                }
            }
            _ => unreachable!(),
        };

        Ok(share)
    }

    #[cfg(test)]
    fn input_all(&mut self, input: T) -> Result<Vec<Share<T>>, Error> {
        // Since this is only for testing we perform a bad one
        let mut inputs = [None; 3];
        inputs[self.get_id()] = Some(input);
        let mut shares = Vec::with_capacity(3);

        for (i, inp) in inputs.into_iter().enumerate() {
            shares.push(self.input(inp.to_owned(), i)?);
        }

        Ok(shares)
    }

    fn share<R: Rng>(input: T, _mac_key: T::VerificationShare, rng: &mut R) -> Vec<Share<T>> {
        let alpha1 = rng.gen::<T::Share>();
        let alpha2 = rng.gen::<T::Share>();
        let alpha3 = rng.gen::<T::Share>();

        let beta = input.to_sharetype() + &alpha1 + &alpha2 + &alpha3;

        let share1 = Share::new(alpha1.to_owned(), alpha3.to_owned(), beta.to_owned());
        let share2 = Share::new(alpha2.to_owned(), alpha1, beta.to_owned());
        let share3 = Share::new(alpha3, alpha2, beta);

        vec![share1, share2, share3]
    }

    fn open(&mut self, share: Share<T>) -> Result<T, Error> {
        self.jmp_verify()?;

        let id = self.network.get_id();
        let (a, b, c) = share.get_abc();

        let rcv = if id == 0 {
            self.jmp_send::<T>(a.to_owned(), 2)?;
            self.jmp_send::<T>(b.to_owned(), 1)?;
            self.jmp_receive::<T>(1)?
        } else if id == 1 {
            self.jmp_send::<T>(a.to_owned(), 0)?;
            self.jmp_queue::<T>(b.to_owned(), 2)?;
            self.jmp_receive::<T>(0)?
        } else if id == 2 {
            self.jmp_queue::<T>(b.to_owned(), 0)?;
            self.jmp_queue::<T>(a.to_owned(), 1)?;
            self.jmp_receive::<T>(0)?
        } else {
            unreachable!()
        };

        self.jmp_verify()?;

        Ok(T::from_sharetype(c - a - b - rcv))
    }

    fn open_many(&mut self, shares: Vec<Share<T>>) -> Result<Vec<T>, Error> {
        self.jmp_verify()?;

        let id = self.network.get_id();
        let len = shares.len();
        let mut a = Vec::with_capacity(len);
        let mut b = Vec::with_capacity(len);
        let mut c = Vec::with_capacity(len);

        for share in shares {
            let (a_, b_, c_) = share.get_abc();
            a.push(a_);
            b.push(b_);
            c.push(c_);
        }

        let rcv = if id == 0 {
            self.jmp_send_many::<T>(a.to_owned(), 2)?;
            self.jmp_send_many::<T>(b.to_owned(), 1)?;
            self.jmp_receive_many::<T>(1, len)?
        } else if id == 1 {
            self.jmp_send_many::<T>(a.to_owned(), 0)?;
            self.jmp_queue_many::<T>(b.to_owned(), 2)?;
            self.jmp_receive_many::<T>(0, len)?
        } else if id == 2 {
            self.jmp_queue_many::<T>(b.to_owned(), 0)?;
            self.jmp_queue_many::<T>(a.to_owned(), 1)?;
            self.jmp_receive_many::<T>(0, len)?
        } else {
            unreachable!()
        };

        self.jmp_verify()?;

        let mut output = Vec::with_capacity(len);

        for (rcv_, (a_, (b_, c_))) in rcv.into_iter().zip(a.into_iter().zip(b.into_iter().zip(c))) {
            output.push(T::from_sharetype(c_ - a_ - b_ - rcv_));
        }

        Ok(output)
    }

    fn open_bit(&mut self, share: Share<Bit>) -> Result<bool, Error> {
        self.jmp_verify()?;

        let id = self.network.get_id();
        let (a, b, c) = share.get_abc();

        let rcv = if id == 0 {
            self.jmp_send::<Bit>(a.to_owned(), 2)?;
            self.jmp_send::<Bit>(b.to_owned(), 1)?;
            self.jmp_receive::<Bit>(1)?
        } else if id == 1 {
            self.jmp_send::<Bit>(a.to_owned(), 0)?;
            self.jmp_queue::<Bit>(b.to_owned(), 2)?;
            self.jmp_receive::<Bit>(0)?
        } else if id == 2 {
            self.jmp_queue::<Bit>(b.to_owned(), 0)?;
            self.jmp_queue::<Bit>(a.to_owned(), 1)?;
            self.jmp_receive::<Bit>(0)?
        } else {
            unreachable!()
        };

        self.jmp_verify()?;

        Ok((c ^ a ^ b ^ rcv).convert().convert())
    }

    fn open_bit_many(&mut self, shares: Vec<Share<Bit>>) -> Result<Vec<bool>, Error> {
        self.jmp_verify()?;

        let id = self.network.get_id();
        let len = shares.len();
        let mut a = Vec::with_capacity(len);
        let mut b = Vec::with_capacity(len);
        let mut c = Vec::with_capacity(len);

        for share in shares {
            let (a_, b_, c_) = share.get_abc();
            a.push(a_);
            b.push(b_);
            c.push(c_);
        }

        let rcv = if id == 0 {
            self.jmp_send_many::<Bit>(a.to_owned(), 2)?;
            self.jmp_send_many::<Bit>(b.to_owned(), 1)?;
            self.jmp_receive_many::<Bit>(1, len)?
        } else if id == 1 {
            self.jmp_send_many::<Bit>(a.to_owned(), 0)?;
            self.jmp_queue_many::<Bit>(b.to_owned(), 2)?;
            self.jmp_receive_many::<Bit>(0, len)?
        } else if id == 2 {
            self.jmp_queue_many::<Bit>(b.to_owned(), 0)?;
            self.jmp_queue_many::<Bit>(a.to_owned(), 1)?;
            self.jmp_receive_many::<Bit>(0, len)?
        } else {
            unreachable!()
        };

        self.jmp_verify()?;

        let mut output = Vec::with_capacity(len);

        for (rcv_, (a_, (b_, c_))) in rcv.into_iter().zip(a.into_iter().zip(b.into_iter().zip(c))) {
            output.push((c_ ^ a_ ^ b_ ^ rcv_).convert().convert());
        }

        Ok(output)
    }

    fn add(&self, a: Share<T>, b: Share<T>) -> Share<T> {
        a + b
    }

    fn sub(&self, a: Share<T>, b: Share<T>) -> Share<T> {
        a - b
    }

    fn add_const(&self, a: Share<T>, b: T) -> Share<T> {
        a.add_const(&b.to_sharetype())
    }

    fn sub_const(&self, a: Share<T>, b: T) -> Share<T> {
        a.sub_const(&b.to_sharetype())
    }

    fn mul(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let (d, e) = self.mul_pre(a.to_owned(), b.to_owned());
        let de = self.aby_mul(d, e)?;
        self.mul_post(a, b, de)
    }

    fn mul_const(&self, a: Share<T>, b: T) -> Share<T> {
        a * b.to_sharetype()
    }

    fn dot(&mut self, a: Vec<Share<T>>, b: Vec<Share<T>>) -> Result<Share<T>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut d = Vec::with_capacity(len);
        let mut e = Vec::with_capacity(len);

        for (a_, b_) in a.iter().cloned().zip(b.iter().cloned()) {
            let (d_, e_) = self.mul_pre(a_, b_);
            d.push(d_);
            e.push(e_);
        }

        let de = self.aby_dot(d, e)?;
        self.dot_post(a, b, de)
    }

    fn dot_many(
        &mut self,
        a: &[Vec<Share<T>>],
        b: &[Vec<Share<T>>],
    ) -> Result<Vec<Share<T>>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut shares_d = Vec::with_capacity(len);
        let mut shares_e = Vec::with_capacity(len);

        for (a_, b_) in a.iter().cloned().zip(b.iter().cloned()) {
            let mut d = Vec::with_capacity(len);
            let mut e = Vec::with_capacity(len);

            for (a__, b__) in a_.into_iter().zip(b_.into_iter()) {
                let (d_, e_) = self.mul_pre(a__, b__);
                d.push(d_);
                e.push(e_);
            }

            shares_d.push(d);
            shares_e.push(e);
        }

        let de = self.aby_dot_many(shares_d, shares_e)?;
        self.dot_post_many(a, b, de)
    }

    fn get_msb(&mut self, a: Share<T>) -> Result<Share<Bit>, Error> {
        let bits = self.arithmetic_to_binary(a)?;
        Ok(bits.get_msb())
    }

    fn get_msb_many(&mut self, a: Vec<Share<T>>) -> Result<Vec<Share<Bit>>, Error> {
        let bits = self.arithmetic_to_binary_many(a)?;
        let res = bits.into_iter().map(|a| a.get_msb()).collect();
        Ok(res)
    }

    fn binary_or(&mut self, a: Share<Bit>, b: Share<Bit>) -> Result<Share<Bit>, Error> {
        <Self as BinaryMpcTrait<Bit, Share<Bit>>>::or(self, a, b)
    }

    fn reduce_binary_or(&mut self, a: Vec<Share<Bit>>) -> Result<Share<Bit>, Error> {
        let packed = self.pack(a);
        let reduced = utils::or_tree::<u128, _, _, OR_TREE_PACK_SIZE>(self, packed)?;
        self.reduce_or_u128(reduced)
    }

    fn verify(&mut self) -> Result<(), Error> {
        {
            // We do this here seperately since it is only active during testing
            if self.mul_proof.get_muls() != 0 {
                self.mul_verify()?;
            }
        }

        if self.and_proof.get_muls() != 0 {
            self.and_verify()?;
        }

        if self.dot_proof.get_muls() != 0 {
            self.dot_verify()?;
        }

        Ok(())
    }
}

impl<N: NetworkTrait, T: Sharable, U: Sharable> BinaryMpcTrait<T, Share<T>> for Swift3<N, U>
where
    Standard: Distribution<T::Share>,
    Standard: Distribution<U::Share>,
{
    fn and(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let (d, e) = self.mul_pre(a.to_owned(), b.to_owned());
        let de = self.aby_and::<T>(d, e)?;
        self.and_post(a, b, de)
    }

    fn and_many(&mut self, a: Vec<Share<T>>, b: Vec<Share<T>>) -> Result<Vec<Share<T>>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut d = Vec::with_capacity(len);
        let mut e = Vec::with_capacity(len);

        for (a_, b_) in a.iter().cloned().zip(b.iter().cloned()) {
            let (d_, e_) = self.mul_pre(a_, b_);
            d.push(d_);
            e.push(e_);
        }

        let de = self.aby_and_many::<T>(d, e)?;
        self.and_post_many(a, b, de)
    }

    fn arithmetic_to_binary(&mut self, x: Share<T>) -> Result<Share<T>, Error> {
        let (x1, x2, x3) = self.a2b_pre(x);
        self.binary_add_3(x1, x2, x3)
    }

    fn arithmetic_to_binary_many(&mut self, x: Vec<Share<T>>) -> Result<Vec<Share<T>>, Error> {
        let len = x.len();
        let mut x1 = Vec::with_capacity(len);
        let mut x2 = Vec::with_capacity(len);
        let mut x3 = Vec::with_capacity(len);

        for x_ in x {
            let (x1_, x2_, x3_) = self.a2b_pre(x_);
            x1.push(x1_);
            x2.push(x2_);
            x3.push(x3_);
        }
        self.binary_add_3_many(x1, x2, x3)
    }
}
