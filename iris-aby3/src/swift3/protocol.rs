use super::{
    random::prf::{Prf, PrfSeed},
    share::Share,
};
use crate::{
    aby3::utils,
    commitment::{CommitOpening, Commitment},
    prelude::{Aby3Share, Bit, Error, MpcTrait, Sharable},
    traits::{network_trait::NetworkTrait, security::MaliciousAbort},
    types::ring_element::{RingElement, RingImpl},
};
use bytes::{Bytes, BytesMut};
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

// TODO Plan is to compute everything on the fly and just implement abort. Thus rec has no prep phase and all the other subprotocols are not split into prep/online
// TODO first implement MUL without triple checks, see if everything works and add it later

impl<N: NetworkTrait> MaliciousAbort for Swift3<N> {}

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

    async fn aby_mul<T: Sharable>(
        &mut self,
        d: Aby3Share<T>,
        e: Aby3Share<T>,
    ) -> Result<Aby3Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        // TODO this is just semi honest!!!!!
        let rand = self.prf.gen_aby_zero_share::<T>();
        let mut c = d * e;
        c.a += rand;

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned()).await?;

        Ok(c)
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

        self.prf = Prf::new(seed1, seed2, seed3);

        Ok(())
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, Share<T>, Share<Bit>> for Swift3<N>
where
    Standard: Distribution<T::Share>,
    Share<T>: Mul<Output = Share<T>>,
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
                let gamma = self.prf.gen_p::<T::Share>();
                if self_id == 0 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let alpha2 = self.prf.gen_2::<T::Share>();
                    let beta = input.unwrap().to_sharetype() + &alpha1 + &alpha2;
                    utils::send_value(&mut self.network, beta.to_owned(), 1).await?;
                    self.jmp_send::<T>(beta.to_owned(), 2).await?;
                    Share::new(alpha1, alpha2, beta + &gamma)
                } else if self_id == 1 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let beta: T::Share = utils::receive_value(&mut self.network, 0).await?;
                    self.jmp_queue::<T>(beta.to_owned(), 2)?;
                    Share::new(alpha1, beta, gamma)
                } else if self_id == 2 {
                    let alpha2 = self.prf.gen_1::<T::Share>();
                    let beta = self.jmp_receive::<T>(0).await?;
                    Share::new(alpha2, beta, gamma)
                } else {
                    unreachable!()
                }
            }
            1 => {
                let alpha2 = self.prf.gen_p::<T::Share>();
                if self_id == 0 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let beta_gamma = self.jmp_receive::<T>(1).await?;
                    Share::new(alpha1, alpha2, beta_gamma)
                } else if self_id == 1 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let gamma = self.prf.gen_2::<T::Share>();
                    let beta = input.unwrap().to_sharetype() + &alpha1 + &alpha2;
                    utils::send_value(&mut self.network, beta.to_owned(), 2).await?;
                    self.jmp_send::<T>(beta.to_owned() + &gamma, 0).await?;
                    Share::new(alpha1, beta, gamma)
                } else if self_id == 2 {
                    let gamma = self.prf.gen_2::<T::Share>();
                    let beta: T::Share = utils::receive_value(&mut self.network, 1).await?;
                    self.jmp_queue::<T>(beta.to_owned() + &gamma, 0)?;
                    Share::new(alpha2, beta, gamma)
                } else {
                    unreachable!()
                }
            }
            2 => {
                let alpha1 = self.prf.gen_p::<T::Share>();
                if self_id == 0 {
                    let alpha2 = self.prf.gen_2::<T::Share>();
                    let beta_gamma = self.jmp_receive::<T>(1).await?;
                    Share::new(alpha1, alpha2, beta_gamma)
                } else if self_id == 1 {
                    let gamma = self.prf.gen_2::<T::Share>();
                    let beta: T::Share = utils::receive_value(&mut self.network, 2).await?;
                    self.jmp_send::<T>(beta.to_owned() + &gamma, 0).await?;
                    Share::new(alpha1, beta, gamma)
                } else if self_id == 2 {
                    let alpha2 = self.prf.gen_1::<T::Share>();
                    let gamma = self.prf.gen_2::<T::Share>();
                    let beta = input.unwrap().to_sharetype() + &alpha1 + &alpha2;
                    utils::send_value(&mut self.network, beta.to_owned(), 1).await?;
                    self.jmp_queue::<T>(beta.to_owned() + &gamma, 0)?;
                    Share::new(alpha2, beta, gamma)
                } else {
                    unreachable!()
                }
            }
            _ => {
                unreachable!()
            }
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
        let gamma = rng.gen::<T::Share>();

        let beta = input.to_sharetype() + &alpha1 + &alpha2;

        let share1 = Share::new(
            alpha1.to_owned(),
            alpha2.to_owned(),
            beta.to_owned() + &gamma,
        );
        let share2 = Share::new(alpha1, beta.to_owned(), gamma.to_owned());
        let share3 = Share::new(alpha2, beta, gamma);

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
            self.jmp_send::<T>(c.to_owned(), 0).await?;
            self.jmp_queue::<T>(a.to_owned(), 2)?;
            self.jmp_receive::<T>(0).await?
        } else if id == 2 {
            self.jmp_queue::<T>(c.to_owned(), 0)?;
            self.jmp_queue::<T>(a.to_owned(), 1)?;
            self.jmp_receive::<T>(0).await?
        } else {
            unreachable!()
        };

        self.jmp_verify().await?;

        let output = match id {
            0 => c - a - b - rcv,
            1 => b - a - rcv,
            2 => b - a - rcv,
            _ => unreachable!(),
        };
        Ok(T::from_sharetype(output))
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
            self.jmp_send_many::<T>(c.to_owned(), 0).await?;
            self.jmp_queue_many::<T>(a.to_owned(), 2)?;
            self.jmp_receive_many::<T>(0, len).await?
        } else if id == 2 {
            self.jmp_queue_many::<T>(c.to_owned(), 0)?;
            self.jmp_queue_many::<T>(a.to_owned(), 1)?;
            self.jmp_receive_many::<T>(0, len).await?
        } else {
            unreachable!()
        };

        self.jmp_verify().await?;

        let mut output = Vec::with_capacity(len);

        if id == 0 {
            for (rcv_, (a_, (b_, c_))) in
                rcv.into_iter().zip(a.into_iter().zip(b.into_iter().zip(c)))
            {
                output.push(T::from_sharetype(c_ - a_ - b_ - rcv_));
            }
        } else if id < 3 {
            for (rcv_, (a_, b_)) in rcv.into_iter().zip(a.into_iter().zip(b.into_iter())) {
                output.push(T::from_sharetype(b_ - a_ - rcv_));
            }
        } else {
            unreachable!()
        }

        Ok(output)
    }

    async fn open_bit(&mut self, share: Share<Bit>) -> Result<bool, Error> {
        todo!()
    }

    async fn open_bit_many(&mut self, shares: Vec<Share<Bit>>) -> Result<Vec<bool>, Error> {
        todo!()
    }

    fn add(&self, a: Share<T>, b: Share<T>) -> Share<T> {
        a + b
    }

    fn sub(&self, a: Share<T>, b: Share<T>) -> Share<T> {
        a - b
    }

    fn add_const(&self, a: Share<T>, b: T) -> Share<T> {
        a.add_const(
            &b.to_sharetype(),
            self.network
                .get_id()
                .try_into()
                .expect("ID is checked during establishing connection"),
        )
    }

    fn sub_const(&self, a: Share<T>, b: T) -> Share<T> {
        a.sub_const(
            &b.to_sharetype(),
            self.network
                .get_id()
                .try_into()
                .expect("ID is checked during establishing connection"),
        )
    }

    async fn mul(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let id = self.get_id();

        let (x_a, x_b, x_c) = a.get_abc();
        let (y_a, y_b, y_c) = b.get_abc();

        // ABY3 Sharing:
        // P0: (alpha1, alpha2)
        // P1: (gamma, alpha1)
        // P2: (alpha2, gamma)
        let (d, e) = match id {
            0 => {
                let d = Aby3Share::new(x_a.to_owned(), x_b.to_owned());
                let e = Aby3Share::new(y_a.to_owned(), y_b.to_owned());
                (d, e)
            }
            1 => {
                let d = Aby3Share::new(x_c.to_owned(), x_a.to_owned());
                let e = Aby3Share::new(y_c.to_owned(), y_a.to_owned());
                (d, e)
            }
            2 => {
                let d = Aby3Share::new(x_a.to_owned(), x_c.to_owned());
                let e = Aby3Share::new(y_a.to_owned(), y_c.to_owned());
                (d, e)
            }
            _ => unreachable!(),
        };

        let de = self.aby_mul::<T>(d, e).await?;

        let share = match id {
            0 => {
                let alpha1 = self.prf.gen_1::<T::Share>();
                let alpha2 = self.prf.gen_2::<T::Share>();
                let (xi1, xi2) = de.get_ab();
                let beta_z1 = -x_c.to_owned() * y_a - y_c.to_owned() * x_a + &alpha1 + xi1;
                let beta_z2 = -x_c * y_b - y_c * x_b + &alpha2 + xi2;
                self.jmp_send::<T>(beta_z1, 2).await?;
                self.jmp_send::<T>(beta_z2, 1).await?;
                let c = self.jmp_receive::<T>(1).await?;
                Share::new(alpha1, alpha2, c)
            }
            1 => {
                let alpha1 = self.prf.gen_1::<T::Share>();
                let gamma = self.prf.gen_2::<T::Share>();
                let (psi, xi1) = de.get_ab();
                let psi = psi - x_c.to_owned() * &y_c;
                let beta_gamma_x = x_c + &x_b;
                let beta_gamma_y = y_c + &y_b;
                let beta_z1 = -beta_gamma_x * y_a - beta_gamma_y.to_owned() * x_a + &alpha1 + xi1;
                self.jmp_queue::<T>(beta_z1.to_owned(), 2)?;
                let beta_z2 = self.jmp_receive::<T>(0).await?;
                let beta_z = beta_z1 + beta_z2 + x_b * y_b + psi;
                self.jmp_send::<T>(beta_z.to_owned() + &gamma, 0).await?;
                Share::new(alpha1, beta_z, gamma)
            }
            2 => {
                let alpha2 = self.prf.gen_1::<T::Share>();
                let gamma = self.prf.gen_2::<T::Share>();
                let (xi2, psi) = de.get_ab();
                let psi = psi - x_c.to_owned() * &y_c;
                let beta_gamma_x = x_c + &x_b;
                let beta_gamma_y = y_c + &y_b;
                let beta_z2 = -beta_gamma_x * y_a - beta_gamma_y.to_owned() * x_a + &alpha2 + xi2;
                self.jmp_queue::<T>(beta_z2.to_owned(), 1)?;
                let beta_z1 = self.jmp_receive::<T>(0).await?;
                let beta_z = beta_z1 + beta_z2 + x_b * y_b + psi;
                self.jmp_queue::<T>(beta_z.to_owned() + &gamma, 0)?;
                Share::new(alpha2, beta_z, gamma)
            }
            _ => unreachable!(),
        };

        Ok(share)
    }

    fn mul_const(&self, a: Share<T>, b: T) -> Share<T> {
        a * b.to_sharetype()
    }

    async fn dot(&mut self, a: Vec<Share<T>>, b: Vec<Share<T>>) -> Result<Share<T>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvlidSizeError);
        }

        todo!()
    }

    async fn dot_many(
        &mut self,
        a: Vec<Vec<Share<T>>>,
        b: Vec<Vec<Share<T>>>,
    ) -> Result<Vec<Share<T>>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvlidSizeError);
        }

        todo!()
    }

    async fn get_msb(&mut self, a: Share<T>) -> Result<Share<Bit>, Error> {
        todo!()
    }

    async fn get_msb_many(&mut self, a: Vec<Share<T>>) -> Result<Vec<Share<Bit>>, Error> {
        todo!()
    }

    async fn binary_or(&mut self, a: Share<Bit>, b: Share<Bit>) -> Result<Share<Bit>, Error> {
        todo!()
    }

    async fn reduce_binary_or(&mut self, a: Vec<Share<Bit>>) -> Result<Share<Bit>, Error> {
        todo!()
    }
}
