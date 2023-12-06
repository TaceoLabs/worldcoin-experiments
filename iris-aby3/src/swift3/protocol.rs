use super::{
    random::prf::{Prf, PrfSeed},
    share::Share,
};
use crate::{
    aby3::utils,
    commitment::{CommitOpening, Commitment},
    prelude::{Aby3Share, Bit, Error, MpcTrait, Sharable},
    traits::{binary_trait::BinaryMpcTrait, network_trait::NetworkTrait, security::MaliciousAbort},
    types::ring_element::{RingElement, RingImpl},
};
use bytes::{Bytes, BytesMut};
use num_traits::Zero;
use rand::{
    distributions::{Distribution, Standard},
    Rng, SeedableRng,
};
use rand_chacha::ChaCha12Rng;
use sha2::{digest::Output, Digest, Sha512};
use std::ops::Mul;

pub struct Swift3<N: NetworkTrait> {
    network: N,
    prf: Prf,
    send_queue_next: BytesMut,
    send_queue_prev: BytesMut,
    rcv_queue_next: BytesMut,
    rcv_queue_prev: BytesMut,
}

impl<N: NetworkTrait> MaliciousAbort for Swift3<N> {}

macro_rules! reduce_or {
    ($([$typ_a:ident, $typ_b:ident,$name_a:ident,$name_b:ident]),*) => {
        $(
            async fn $name_a(&mut self, a: Share<$typ_a>) -> Result<Share<Bit>, Error> {
                let (a, b, c) = a.get_abc();
                let (a1, a2) = utils::split::<$typ_a, $typ_b>(a);
                let (b1, b2) = utils::split::<$typ_a, $typ_b>(b);
                let (c1, c2) = utils::split::<$typ_a, $typ_b>(c);

                let share_a = Share::new(a1, b1, c1);
                let share_b = Share::new(a2, b2, c2);

                let out = self.or(share_a, share_b).await?;
                self.$name_b(out).await
            }
        )*
    };
}

impl<N: NetworkTrait> Swift3<N> {
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
        }
    }

    fn a2b_pre<T: Sharable>(&self, x: Share<T>) -> (Share<T>, Share<T>, Share<T>) {
        // TODO wrong?
        let (a, b, c) = x.get_abc();

        let mut x1 = Share::<T>::zero();
        let mut x2 = Share::<T>::zero();
        let mut x3 = Share::<T>::zero();

        match self.network.get_id() {
            0 => {
                x2.a = -a;
                x3.b = -b;
            }
            1 => {
                x1.b = b.to_owned();
                // x1.c = b;
                x2.a = -a;
            }
            2 => {
                x1.b = b.to_owned();
                // x1.c = b;
                x3.b = -a;
            }
            _ => unreachable!(),
        }
        (x1, x2, x3)
    }

    async fn send_seed_commitment(
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

        self.network.send(id1, msg1).await?;
        self.network.send(id2, msg2).await?;

        Ok(())
    }

    #[inline(always)]
    async fn jmp_send<T: Sharable>(&mut self, value: T::Share, id: usize) -> Result<(), Error> {
        utils::send_value(&mut self.network, value, id).await
    }

    #[inline(always)]
    async fn jmp_send_many<T: Sharable>(
        &mut self,
        values: Vec<T::Share>,
        id: usize,
    ) -> Result<(), Error> {
        utils::send_vec(&mut self.network, values, id).await
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
        let (x_a, x_b, x_c) = a.get_abc();
        let (y_a, y_b, y_c) = b.get_abc();

        // ABY3 Sharing:
        // P0: (alpha1, alpha2)
        // P1: (gamma, alpha1)
        // P2: (alpha2, gamma)
        let (d, e) = match self.network.get_id() {
            0 => {
                let d = Aby3Share::new(x_a, x_b);
                let e = Aby3Share::new(y_a, y_b);
                (d, e)
            }
            1 => {
                let d = Aby3Share::new(x_c, x_a);
                let e = Aby3Share::new(y_c, y_a);
                (d, e)
            }
            2 => {
                let d = Aby3Share::new(x_a, x_c);
                let e = Aby3Share::new(y_a, y_c);
                (d, e)
            }
            _ => unreachable!(),
        };

        (d, e)
    }

    async fn mul_post<T: Sharable>(
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

        let share = if id == 0 {
            let alpha1 = self.prf.gen_1::<T::Share>();
            let alpha2 = self.prf.gen_2::<T::Share>();
            let (xi1, xi2) = de.get_ab();
            let beta_z1 = -x_c.to_owned() * y_a - y_c.to_owned() * x_a + &alpha1 + xi1;
            let beta_z2 = -x_c * y_b - y_c * x_b + &alpha2 + xi2;
            self.jmp_send::<T>(beta_z1, 2).await?;
            self.jmp_send::<T>(beta_z2, 1).await?;
            let c = self.jmp_receive::<T>(1).await?;
            Share::new(alpha1, alpha2, c)
        } else {
            let alpha = self.prf.gen_1::<T::Share>();
            let gamma = self.prf.gen_2::<T::Share>();
            let (psi, xi) = if id == 1 {
                de.get_ab()
            } else {
                let (xi, psi) = de.get_ab();
                (psi, xi)
            };
            let psi = psi - x_c.to_owned() * &y_c;
            let beta_gamma_x = x_c + &x_b;
            let beta_gamma_y = y_c + &y_b;
            let beta_z1 = -beta_gamma_x * y_a - beta_gamma_y * x_a + &alpha + xi;
            self.jmp_queue::<T>(beta_z1.to_owned(), 3 - id)?;
            let beta_z2 = self.jmp_receive::<T>(0).await?;
            let beta_z = beta_z1 + beta_z2 + x_b * y_b + psi;
            if id == 1 {
                self.jmp_send::<T>(beta_z.to_owned() + &gamma, 0).await?;
            } else {
                self.jmp_queue::<T>(beta_z.to_owned() + &gamma, 0)?;
            }
            Share::new(alpha, beta_z, gamma)
        };

        Ok(share)
    }

    async fn and_post<T: Sharable>(
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

        let share = if id == 0 {
            let alpha1 = self.prf.gen_1::<T::Share>();
            let alpha2 = self.prf.gen_2::<T::Share>();
            let (xi1, xi2) = de.get_ab();
            let beta_z1 = x_c.to_owned() & y_a ^ y_c.to_owned() & x_a ^ &alpha1 ^ xi1;
            let beta_z2 = x_c & y_b ^ y_c & x_b ^ &alpha2 ^ xi2;
            self.jmp_send::<T>(beta_z1, 2).await?;
            self.jmp_send::<T>(beta_z2, 1).await?;
            let c = self.jmp_receive::<T>(1).await?;
            Share::new(alpha1, alpha2, c)
        } else {
            let alpha = self.prf.gen_1::<T::Share>();
            let gamma = self.prf.gen_2::<T::Share>();
            let (psi, xi) = if id == 1 {
                de.get_ab()
            } else {
                let (xi, psi) = de.get_ab();
                (psi, xi)
            };
            let psi = psi ^ x_c.to_owned() & &y_c;
            let beta_gamma_x = x_c ^ &x_b;
            let beta_gamma_y = y_c ^ &y_b;
            let beta_z1 = beta_gamma_x & y_a ^ beta_gamma_y & x_a ^ &alpha ^ xi;
            self.jmp_queue::<T>(beta_z1.to_owned(), 3 - id)?;
            let beta_z2 = self.jmp_receive::<T>(0).await?;
            let beta_z = beta_z1 ^ beta_z2 ^ x_b & y_b ^ psi;
            if id == 1 {
                self.jmp_send::<T>(beta_z.to_owned() ^ &gamma, 0).await?;
            } else {
                self.jmp_queue::<T>(beta_z.to_owned() ^ &gamma, 0)?;
            }
            Share::new(alpha, beta_z, gamma)
        };

        Ok(share)
    }

    async fn and_post_many<T: Sharable>(
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
        if id == 0 {
            let mut betas_z1 = Vec::with_capacity(len);
            let mut betas_z2 = Vec::with_capacity(len);

            for ((a, b), de) in a.into_iter().zip(b.into_iter()).zip(de.into_iter()) {
                let (x_a, x_b, x_c) = a.get_abc();
                let (y_a, y_b, y_c) = b.get_abc();

                let alpha1 = self.prf.gen_1::<T::Share>();
                let alpha2 = self.prf.gen_2::<T::Share>();
                let (xi1, xi2) = de.get_ab();
                let beta_z1 = x_c.to_owned() & y_a ^ y_c.to_owned() & x_a ^ &alpha1 ^ xi1;
                let beta_z2 = x_c & y_b ^ y_c & x_b ^ &alpha2 ^ xi2;
                betas_z1.push(beta_z1);
                betas_z2.push(beta_z2);
                shares.push(Share::new(alpha1, alpha2, T::Share::zero()));
            }
            self.jmp_send_many::<T>(betas_z1, 2).await?;
            self.jmp_send_many::<T>(betas_z2, 1).await?;
            let c = self.jmp_receive_many::<T>(1, len).await?;

            for (share, c) in shares.iter_mut().zip(c.into_iter()) {
                share.c = c;
            }
        } else {
            let mut betas_z1 = Vec::with_capacity(len);
            let mut betas_z = Vec::with_capacity(len);

            for ((a, b), de) in a.into_iter().zip(b.into_iter()).zip(de.into_iter()) {
                let (x_a, x_b, x_c) = a.get_abc();
                let (y_a, y_b, y_c) = b.get_abc();

                let alpha = self.prf.gen_1::<T::Share>();
                let gamma = self.prf.gen_2::<T::Share>();
                let (psi, xi) = if id == 1 {
                    de.get_ab()
                } else {
                    let (xi, psi) = de.get_ab();
                    (psi, xi)
                };
                let psi = psi ^ x_c.to_owned() & &y_c;
                let beta_gamma_x = x_c ^ &x_b;
                let beta_gamma_y = y_c ^ &y_b;
                let beta_z1 = beta_gamma_x & y_a ^ beta_gamma_y & x_a ^ &alpha ^ xi;
                let beta_z = psi ^ x_b & y_b;
                betas_z1.push(beta_z1);
                betas_z.push(beta_z);
                shares.push(Share::new(alpha, T::Share::zero(), gamma));
            }

            self.jmp_queue_many::<T>(betas_z1.to_owned(), 3 - id)?;
            let betas_z2 = self.jmp_receive_many::<T>(0, len).await?;
            for ((a, s), (b, c)) in betas_z
                .iter_mut()
                .zip(shares.iter_mut())
                .zip(betas_z1.into_iter().zip(betas_z2.into_iter()))
            {
                *a ^= b ^ c;
                s.b = a.to_owned();
                *a ^= &s.c; // + gamma for sending
            }

            if id == 1 {
                self.jmp_send_many::<T>(betas_z, 0).await?;
            } else {
                self.jmp_queue_many::<T>(betas_z, 0)?;
            }
        }

        Ok(shares)
    }

    async fn dot_post<T: Sharable>(
        &mut self,
        a: Vec<Share<T>>,
        b: Vec<Share<T>>,
        de: Aby3Share<T>,
    ) -> Result<Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        debug_assert_eq!(a.len(), b.len());
        let id = self.network.get_id();

        let share = if id == 0 {
            let alpha1 = self.prf.gen_1::<T::Share>();
            let alpha2 = self.prf.gen_2::<T::Share>();
            let (xi1, xi2) = de.get_ab();
            let mut beta_z1 = xi1 + &alpha1;
            let mut beta_z2 = xi2 + &alpha2;

            for (a, b) in a.into_iter().zip(b.into_iter()) {
                let (x_a, x_b, x_c) = a.get_abc();
                let (y_a, y_b, y_c) = b.get_abc();
                beta_z1 -= x_c.to_owned() * y_a + y_c.to_owned() * x_a;
                beta_z2 -= x_c * y_b + y_c * x_b;
            }
            self.jmp_send::<T>(beta_z1, 2).await?;
            self.jmp_send::<T>(beta_z2, 1).await?;
            let c = self.jmp_receive::<T>(1).await?;
            Share::new(alpha1, alpha2, c)
        } else {
            let alpha = self.prf.gen_1::<T::Share>();
            let gamma = self.prf.gen_2::<T::Share>();
            let (psi, xi) = if id == 1 {
                de.get_ab()
            } else {
                let (xi, psi) = de.get_ab();
                (psi, xi)
            };

            let mut beta_z1 = xi + &alpha;
            let mut beta_z = psi;

            for (a, b) in a.into_iter().zip(b.into_iter()) {
                let (x_a, x_b, x_c) = a.get_abc();
                let (y_a, y_b, y_c) = b.get_abc();

                beta_z -= x_c.to_owned() * &y_c;
                let beta_gamma_x = x_c + &x_b;
                let beta_gamma_y = y_c + &y_b;
                beta_z1 -= beta_gamma_x * y_a + beta_gamma_y * x_a;
                beta_z += x_b * y_b;
            }

            self.jmp_queue::<T>(beta_z1.to_owned(), 3 - id)?;
            let beta_z2 = self.jmp_receive::<T>(0).await?;
            let beta_z = beta_z1 + beta_z2 + beta_z;
            if id == 1 {
                self.jmp_send::<T>(beta_z.to_owned() + &gamma, 0).await?;
            } else {
                self.jmp_queue::<T>(beta_z.to_owned() + &gamma, 0)?;
            }
            Share::new(alpha, beta_z, gamma)
        };

        Ok(share)
    }

    async fn dot_post_many<T: Sharable>(
        &mut self,
        a: Vec<Vec<Share<T>>>,
        b: Vec<Vec<Share<T>>>,
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
        if id == 0 {
            let mut betas_z1 = Vec::with_capacity(len);
            let mut betas_z2 = Vec::with_capacity(len);

            for ((a, b), de) in a.into_iter().zip(b.into_iter()).zip(de.into_iter()) {
                let alpha1 = self.prf.gen_1::<T::Share>();
                let alpha2 = self.prf.gen_2::<T::Share>();
                let (xi1, xi2) = de.get_ab();
                let mut beta_z1 = xi1 + &alpha1;
                let mut beta_z2 = xi2 + &alpha2;

                debug_assert_eq!(a.len(), b.len());
                for (a, b) in a.into_iter().zip(b.into_iter()) {
                    let (x_a, x_b, x_c) = a.get_abc();
                    let (y_a, y_b, y_c) = b.get_abc();
                    beta_z1 -= x_c.to_owned() * y_a + y_c.to_owned() * x_a;
                    beta_z2 -= x_c * y_b + y_c * x_b;
                }
                betas_z1.push(beta_z1);
                betas_z2.push(beta_z2);
                shares.push(Share::new(alpha1, alpha2, T::Share::zero()));
            }
            self.jmp_send_many::<T>(betas_z1, 2).await?;
            self.jmp_send_many::<T>(betas_z2, 1).await?;
            let c = self.jmp_receive_many::<T>(1, len).await?;

            for (share, c) in shares.iter_mut().zip(c.into_iter()) {
                share.c = c;
            }
        } else {
            let mut betas_z1 = Vec::with_capacity(len);
            let mut betas_z = Vec::with_capacity(len);

            for ((a, b), de) in a.into_iter().zip(b.into_iter()).zip(de.into_iter()) {
                let alpha = self.prf.gen_1::<T::Share>();
                let gamma = self.prf.gen_2::<T::Share>();
                let (psi, xi) = if id == 1 {
                    de.get_ab()
                } else {
                    let (xi, psi) = de.get_ab();
                    (psi, xi)
                };

                let mut beta_z1 = xi + &alpha;
                let mut beta_z = psi;

                debug_assert_eq!(a.len(), b.len());
                for (a, b) in a.into_iter().zip(b.into_iter()) {
                    let (x_a, x_b, x_c) = a.get_abc();
                    let (y_a, y_b, y_c) = b.get_abc();

                    beta_z -= x_c.to_owned() * &y_c;
                    let beta_gamma_x = x_c + &x_b;
                    let beta_gamma_y = y_c + &y_b;
                    beta_z1 -= beta_gamma_x * y_a + beta_gamma_y * x_a;
                    beta_z += x_b * y_b;
                }
                betas_z1.push(beta_z1);
                betas_z.push(beta_z);
                shares.push(Share::new(alpha, T::Share::zero(), gamma));
            }

            self.jmp_queue_many::<T>(betas_z1.to_owned(), 3 - id)?;
            let betas_z2 = self.jmp_receive_many::<T>(0, len).await?;
            for ((a, s), (b, c)) in betas_z
                .iter_mut()
                .zip(shares.iter_mut())
                .zip(betas_z1.into_iter().zip(betas_z2.into_iter()))
            {
                *a += b + c;
                s.b = a.to_owned();
                *a += &s.c; // + gamma for sending
            }

            if id == 1 {
                self.jmp_send_many::<T>(betas_z, 0).await?;
            } else {
                self.jmp_queue_many::<T>(betas_z, 0)?;
            }
        }

        Ok(shares)
    }

    async fn aby_mul<T: Sharable>(
        &mut self,
        a: Aby3Share<T>,
        b: Aby3Share<T>,
    ) -> Result<Aby3Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        // TODO this is just semi honest!!!!!
        let rand = self.prf.gen_aby_zero_share::<T>();
        let mut c = a * b;
        c.a += rand;

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned()).await?;

        Ok(c)
    }

    async fn aby_and<T: Sharable>(
        &mut self,
        a: Aby3Share<T>,
        b: Aby3Share<T>,
    ) -> Result<Aby3Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        // TODO this is just semi honest!!!!!
        let rand = self.prf.gen_aby_binary_zero_share::<T>();
        let mut c = a & b;
        c.a ^= rand;

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned()).await?;

        Ok(c)
    }

    async fn aby_and_many<T: Sharable>(
        &mut self,
        a: Vec<Aby3Share<T>>,
        b: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<T>>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        debug_assert_eq!(a.len(), b.len());
        // TODO this is just semi honest!!!!!

        let mut shares_a = Vec::with_capacity(a.len());
        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            let rand = self.prf.gen_aby_binary_zero_share::<T>();
            let mut c = a_ & b_;
            c.a ^= rand;
            shares_a.push(c.a);
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned()).await?;

        let res = shares_a
            .into_iter()
            .zip(shares_b.into_iter())
            .map(|(a_, b_)| Aby3Share::new(a_, b_))
            .collect();

        Ok(res)
    }

    async fn aby_dot<T: Sharable>(
        &mut self,
        a: Vec<Aby3Share<T>>,
        b: Vec<Aby3Share<T>>,
    ) -> Result<Aby3Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        debug_assert_eq!(a.len(), b.len());

        // TODO this is just semi honest!!!!!
        let rand = self.prf.gen_aby_zero_share::<T>();

        let mut c = Aby3Share::new(rand, T::zero().to_sharetype());
        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            c += a_ * b_;
        }

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned()).await?;

        Ok(c)
    }

    async fn aby_dot_many<T: Sharable>(
        &mut self,
        a: Vec<Vec<Aby3Share<T>>>,
        b: Vec<Vec<Aby3Share<T>>>,
    ) -> Result<Vec<Aby3Share<T>>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        debug_assert_eq!(a.len(), b.len());
        // TODO this is just semi honest!!!!!

        let mut shares_a = Vec::with_capacity(a.len());

        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            let mut rand = self.prf.gen_aby_zero_share::<T>();
            debug_assert_eq!(a_.len(), b_.len());

            for (a__, b__) in a_.into_iter().zip(b_.into_iter()) {
                rand += (a__ * b__).a;
            }
            shares_a.push(rand);
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned()).await?;

        let res = shares_a
            .into_iter()
            .zip(shares_b.into_iter())
            .map(|(a_, b_)| Aby3Share::new(a_, b_))
            .collect();

        Ok(res)
    }

    async fn jmp_receive<T: Sharable>(&mut self, id: usize) -> Result<T::Share, Error> {
        // I should receive from id, and later the hash from the third party
        let value: T::Share = utils::receive_value(&mut self.network, id).await?;

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

    async fn jmp_receive_many<T: Sharable>(
        &mut self,
        id: usize,
        len: usize,
    ) -> Result<Vec<T::Share>, Error> {
        // I should receive from id, and later the hash from the third party
        let values: Vec<T::Share> = utils::receive_vec(&mut self.network, id, len).await?;

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

    async fn jmp_verify(&mut self) -> Result<(), Error> {
        let id = self.network.get_id();
        let next_id = (id + 1) % 3;
        let prev_id = (id + 2) % 3;

        let send_next = Self::clear_and_hash(&mut self.send_queue_next);
        let send_prev = Self::clear_and_hash(&mut self.send_queue_prev);
        let hash_next = Self::clear_and_hash(&mut self.rcv_queue_next);
        let hash_prev = Self::clear_and_hash(&mut self.rcv_queue_prev);

        self.network
            .send(next_id, Bytes::from(send_next.to_vec()))
            .await?;
        self.network
            .send(prev_id, Bytes::from(send_prev.to_vec()))
            .await?;

        let rcv_prev = self.network.receive(prev_id).await?;
        let rcv_next = self.network.receive(next_id).await?;

        if rcv_prev.as_ref() != hash_prev.as_slice() || rcv_next.as_ref() != hash_next.as_slice() {
            return Err(Error::JmpVerifyError);
        }

        Ok(())
    }

    async fn send_seed_opening(
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

        self.network.send(id1, msg1).await?;
        self.network.send(id2, msg2).await?;

        Ok(())
    }

    async fn setup_prf(&mut self) -> Result<(), Error> {
        let seed1 = Prf::gen_seed();
        let seed2 = Prf::gen_seed();
        let seed3 = Prf::gen_seed();
        self.setup_prf_from_seed([seed1, seed2, seed3]).await
    }

    fn verify_commitment(data: &[u8], rand: [u8; 32], comm: Vec<u8>) -> bool {
        let opening = CommitOpening {
            values: RingElement::convert_slice_rev(data).to_vec(),
            rand,
        };
        opening.verify(comm)
    }

    async fn setup_prf_from_seed(&mut self, seeds: [PrfSeed; 3]) -> Result<(), Error> {
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
        self.send_seed_commitment(&comm1.comm, &comm2.comm, &comm3.comm, ids.0, ids.1)
            .await?;

        let msg1 = self.network.receive(ids.0).await?;
        let msg2 = self.network.receive(ids.1).await?;

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
        self.send_seed_opening(&open1, &open2, &open3, ids.0, ids.1)
            .await?;

        let msg1 = self.network.receive(ids.0).await?;
        let msg2 = self.network.receive(ids.1).await?;

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
        let outlen = (a.len() + T::Share::get_k() - 1) / T::Share::get_k();
        let mut out = Vec::with_capacity(outlen);

        for a_ in a.chunks(T::Share::get_k()) {
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

    async fn reduce_or_u8(&mut self, a: Share<u8>) -> Result<Share<Bit>, Error> {
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
            )
            .await?;
        }

        Ok(decomp[0].to_owned())
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, Share<T>, Share<Bit>> for Swift3<N>
where
    Standard: Distribution<T::Share>,
    Share<T>: Mul<T::Share, Output = Share<T>>,
{
    fn get_id(&self) -> usize {
        self.network.get_id()
    }

    async fn finish(self) -> Result<(), Error> {
        self.network.shutdown().await?;
        Ok(())
    }

    async fn preprocess(&mut self) -> Result<(), Error> {
        self.setup_prf().await
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        Ok(self.network.print_connection_stats(out)?)
    }

    async fn input(&mut self, input: Option<T>, id: usize) -> Result<Share<T>, Error> {
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
                    utils::send_value(&mut self.network, beta.to_owned(), 1).await?;
                    self.jmp_send::<T>(beta.to_owned(), 2).await?;
                    Share::new(alpha1, alpha3, beta)
                } else if self_id == 1 {
                    let alpha1 = self.prf.gen_2::<T::Share>();
                    let alpha2 = self.prf.gen_p::<T::Share>();
                    let beta: T::Share = utils::receive_value(&mut self.network, 0).await?;
                    self.jmp_queue::<T>(beta.to_owned(), 2)?;
                    Share::new(alpha2, alpha1, beta)
                } else if self_id == 2 {
                    let alpha2 = self.prf.gen_p::<T::Share>();
                    let alpha3 = self.prf.gen_1::<T::Share>();
                    let beta = self.jmp_receive::<T>(0).await?;
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
                    utils::send_value(&mut self.network, beta.to_owned(), 2).await?;
                    self.jmp_send::<T>(beta.to_owned(), 0).await?;
                    Share::new(alpha2, alpha1, beta)
                } else if self_id == 2 {
                    let alpha2 = self.prf.gen_2::<T::Share>();
                    let alpha3 = self.prf.gen_p::<T::Share>();
                    let beta: T::Share = utils::receive_value(&mut self.network, 1).await?;
                    self.jmp_queue::<T>(beta.to_owned(), 0)?;
                    Share::new(alpha3, alpha2, beta)
                } else if self_id == 0 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let alpha3 = self.prf.gen_p::<T::Share>();
                    let beta = self.jmp_receive::<T>(1).await?;
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
                    utils::send_value(&mut self.network, beta.to_owned(), 1).await?;
                    self.jmp_send::<T>(beta.to_owned(), 0).await?;
                    Share::new(alpha3, alpha2, beta)
                } else if self_id == 1 {
                    let alpha1 = self.prf.gen_p::<T::Share>();
                    let alpha2 = self.prf.gen_1::<T::Share>();
                    let beta: T::Share = utils::receive_value(&mut self.network, 2).await?;
                    self.jmp_queue::<T>(beta.to_owned(), 0)?;
                    Share::new(alpha2, alpha1, beta)
                } else if self_id == 0 {
                    let alpha1 = self.prf.gen_p::<T::Share>();
                    let alpha3 = self.prf.gen_2::<T::Share>();
                    let beta = self.jmp_receive::<T>(2).await?;
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
    async fn input_all(&mut self, input: T) -> Result<Vec<Share<T>>, Error> {
        // Since this is only for testing we perform a bad one
        let mut inputs = [None; 3];
        inputs[self.get_id()] = Some(input);
        let mut shares = Vec::with_capacity(3);

        for (i, inp) in inputs.into_iter().enumerate() {
            shares.push(self.input(inp.to_owned(), i).await?);
        }

        Ok(shares)
    }

    fn share<R: Rng>(input: T, rng: &mut R) -> Vec<Share<T>> {
        let alpha1 = rng.gen::<T::Share>();
        let alpha2 = rng.gen::<T::Share>();
        let alpha3 = rng.gen::<T::Share>();

        let beta = input.to_sharetype() + &alpha1 + &alpha2 + &alpha3;

        let share1 = Share::new(alpha1.to_owned(), alpha3.to_owned(), beta.to_owned());
        let share2 = Share::new(alpha2.to_owned(), alpha1, beta.to_owned());
        let share3 = Share::new(alpha3, alpha2, beta);

        vec![share1, share2, share3]
    }

    async fn open(&mut self, share: Share<T>) -> Result<T, Error> {
        self.jmp_verify().await?;

        let id = self.network.get_id();
        let (a, b, c) = share.get_abc();

        let rcv = if id == 0 {
            self.jmp_send::<T>(a.to_owned(), 2).await?;
            self.jmp_send::<T>(b.to_owned(), 1).await?;
            self.jmp_receive::<T>(1).await?
        } else if id == 1 {
            self.jmp_send::<T>(a.to_owned(), 0).await?;
            self.jmp_queue::<T>(b.to_owned(), 2)?;
            self.jmp_receive::<T>(0).await?
        } else if id == 2 {
            self.jmp_queue::<T>(b.to_owned(), 0)?;
            self.jmp_queue::<T>(a.to_owned(), 1)?;
            self.jmp_receive::<T>(0).await?
        } else {
            unreachable!()
        };

        self.jmp_verify().await?;

        Ok(T::from_sharetype(c - a - b - rcv))
    }

    async fn open_many(&mut self, shares: Vec<Share<T>>) -> Result<Vec<T>, Error> {
        self.jmp_verify().await?;

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
            self.jmp_send_many::<T>(a.to_owned(), 2).await?;
            self.jmp_send_many::<T>(b.to_owned(), 1).await?;
            self.jmp_receive_many::<T>(1, len).await?
        } else if id == 1 {
            self.jmp_send_many::<T>(a.to_owned(), 0).await?;
            self.jmp_queue_many::<T>(b.to_owned(), 2)?;
            self.jmp_receive_many::<T>(0, len).await?
        } else if id == 2 {
            self.jmp_queue_many::<T>(b.to_owned(), 0)?;
            self.jmp_queue_many::<T>(a.to_owned(), 1)?;
            self.jmp_receive_many::<T>(0, len).await?
        } else {
            unreachable!()
        };

        self.jmp_verify().await?;

        let mut output = Vec::with_capacity(len);

        for (rcv_, (a_, (b_, c_))) in rcv.into_iter().zip(a.into_iter().zip(b.into_iter().zip(c))) {
            output.push(T::from_sharetype(c_ - a_ - b_ - rcv_));
        }

        Ok(output)
    }

    async fn open_bit(&mut self, share: Share<Bit>) -> Result<bool, Error> {
        self.jmp_verify().await?;

        let id = self.network.get_id();
        let (a, b, c) = share.get_abc();

        let rcv = if id == 0 {
            self.jmp_send::<Bit>(a.to_owned(), 2).await?;
            self.jmp_send::<Bit>(b.to_owned(), 1).await?;
            self.jmp_receive::<Bit>(1).await?
        } else if id == 1 {
            self.jmp_send::<Bit>(a.to_owned(), 0).await?;
            self.jmp_queue::<Bit>(b.to_owned(), 2)?;
            self.jmp_receive::<Bit>(0).await?
        } else if id == 2 {
            self.jmp_queue::<Bit>(b.to_owned(), 0)?;
            self.jmp_queue::<Bit>(a.to_owned(), 1)?;
            self.jmp_receive::<Bit>(0).await?
        } else {
            unreachable!()
        };

        self.jmp_verify().await?;

        Ok((c ^ a ^ b ^ rcv).convert().convert())
    }

    async fn open_bit_many(&mut self, shares: Vec<Share<Bit>>) -> Result<Vec<bool>, Error> {
        self.jmp_verify().await?;

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
            self.jmp_send_many::<Bit>(a.to_owned(), 2).await?;
            self.jmp_send_many::<Bit>(b.to_owned(), 1).await?;
            self.jmp_receive_many::<Bit>(1, len).await?
        } else if id == 1 {
            self.jmp_send_many::<Bit>(a.to_owned(), 0).await?;
            self.jmp_queue_many::<Bit>(b.to_owned(), 2)?;
            self.jmp_receive_many::<Bit>(0, len).await?
        } else if id == 2 {
            self.jmp_queue_many::<Bit>(b.to_owned(), 0)?;
            self.jmp_queue_many::<Bit>(a.to_owned(), 1)?;
            self.jmp_receive_many::<Bit>(0, len).await?
        } else {
            unreachable!()
        };

        self.jmp_verify().await?;

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

    async fn mul(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let (d, e) = self.mul_pre(a.to_owned(), b.to_owned());
        let de = self.aby_mul::<T>(d, e).await?;
        self.mul_post(a, b, de).await
    }

    fn mul_const(&self, a: Share<T>, b: T) -> Share<T> {
        a * b.to_sharetype()
    }

    async fn dot(&mut self, a: Vec<Share<T>>, b: Vec<Share<T>>) -> Result<Share<T>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvlidSizeError);
        }

        let mut d = Vec::with_capacity(len);
        let mut e = Vec::with_capacity(len);

        for (a_, b_) in a.iter().cloned().zip(b.iter().cloned()) {
            let (d_, e_) = self.mul_pre(a_, b_);
            d.push(d_);
            e.push(e_);
        }

        let de = self.aby_dot::<T>(d, e).await?;
        self.dot_post(a, b, de).await
    }

    async fn dot_many(
        &mut self,
        a: Vec<Vec<Share<T>>>,
        b: Vec<Vec<Share<T>>>,
    ) -> Result<Vec<Share<T>>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvlidSizeError);
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

        let de = self.aby_dot_many::<T>(shares_d, shares_e).await?;
        self.dot_post_many(a, b, de).await
    }

    async fn get_msb(&mut self, a: Share<T>) -> Result<Share<Bit>, Error> {
        let bits = self.arithmetic_to_binary(a).await?;
        Ok(bits.get_msb())
    }

    async fn get_msb_many(&mut self, a: Vec<Share<T>>) -> Result<Vec<Share<Bit>>, Error> {
        let bits = self.arithmetic_to_binary_many(a).await?;
        let res = bits.into_iter().map(|a| a.get_msb()).collect();
        Ok(res)
    }

    async fn binary_or(&mut self, a: Share<Bit>, b: Share<Bit>) -> Result<Share<Bit>, Error> {
        <Self as BinaryMpcTrait<Bit, Share<Bit>>>::or(self, a, b).await
    }

    async fn reduce_binary_or(&mut self, a: Vec<Share<Bit>>) -> Result<Share<Bit>, Error> {
        let packed = self.pack(a);
        let reduced = utils::or_tree::<u128, _, _>(self, packed).await?;
        self.reduce_or_u128(reduced).await
    }
}

impl<N: NetworkTrait, T: Sharable> BinaryMpcTrait<T, Share<T>> for Swift3<N>
where
    Standard: Distribution<T::Share>,
{
    async fn and(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let (d, e) = self.mul_pre(a.to_owned(), b.to_owned());
        let de = self.aby_and::<T>(d, e).await?;
        self.and_post(a, b, de).await
    }

    async fn and_many(
        &mut self,
        a: Vec<Share<T>>,
        b: Vec<Share<T>>,
    ) -> Result<Vec<Share<T>>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvlidSizeError);
        }

        let mut d = Vec::with_capacity(len);
        let mut e = Vec::with_capacity(len);

        for (a_, b_) in a.iter().cloned().zip(b.iter().cloned()) {
            let (d_, e_) = self.mul_pre(a_, b_);
            d.push(d_);
            e.push(e_);
        }

        let de = self.aby_and_many::<T>(d, e).await?;
        self.and_post_many(a, b, de).await
    }

    async fn arithmetic_to_binary(&mut self, x: Share<T>) -> Result<Share<T>, Error> {
        let (x1, x2, x3) = self.a2b_pre(x);
        self.binary_add_3(x1, x2, x3).await
    }

    async fn arithmetic_to_binary_many(
        &mut self,
        x: Vec<Share<T>>,
    ) -> Result<Vec<Share<T>>, Error> {
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
        self.binary_add_3_many(x1, x2, x3).await
    }
}
