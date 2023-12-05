use super::{
    random::prf::{Prf, PrfSeed},
    share::Share,
};
use crate::{
    commitment::{CommitOpening, Commitment},
    prelude::{Bit, Error, MpcTrait, Sharable},
    traits::{network_trait::NetworkTrait, security::MaliciousAbort},
    types::ring_element::{ring_vec_from_bytes, ring_vec_to_bytes, RingElement, RingImpl},
};
use bytes::BytesMut;
use num_traits::Zero;
use rand::{
    distributions::{Distribution, Standard},
    Rng, SeedableRng,
};
use rand_chacha::ChaCha12Rng;
use std::ops::Mul;

pub struct Swift3<N: NetworkTrait> {
    network: N,
    prf: Prf,
}

// TODO Plan is to compute everything on the fly and just implement abort. Thus recv has no prep phase and all the other subprotocols are not split into prep/online
// TODO first implement MUL without triple checks, see if everything works and add it later

impl<N: NetworkTrait> MaliciousAbort for Swift3<N> {}

impl<N: NetworkTrait> Swift3<N> {
    pub fn new(network: N) -> Self {
        let prf = Prf::default();

        Self { network, prf }
    }

    async fn send_value<R: RingImpl>(&mut self, value: R, id: usize) -> Result<(), Error> {
        Ok(self.network.send(id, value.to_bytes()).await?)
    }

    async fn receive_value<R: RingImpl>(&mut self, id: usize) -> Result<R, Error> {
        let response = self.network.receive(id).await?;
        R::from_bytes_mut(response)
    }

    async fn send_vec<R: RingImpl>(&mut self, value: Vec<R>, id: usize) -> Result<(), Error> {
        Ok(self.network.send(id, ring_vec_to_bytes(value)).await?)
    }

    async fn receive_vec<R: RingImpl>(&mut self, id: usize, len: usize) -> Result<Vec<R>, Error> {
        let response = self.network.receive(id).await?;
        ring_vec_from_bytes(response, len)
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

    async fn jmp_send<T: Sharable>(
        &mut self,
        send_id1: usize,
        send_id2: usize,
        recv_id: usize,
        value: Option<T::Share>,
    ) -> Result<Option<T::Share>, Error> {
        if send_id1 > 2 || send_id2 > 2 || recv_id > 2 {
            return Err(Error::ValueError("JMP IDs out of range".to_string()));
        }
        if send_id1 == send_id2 || send_id1 == recv_id || send_id2 == recv_id {
            return Err(Error::ValueError("JMP IDs equal".to_string()));
        }

        let id = self.network.get_id();
        if (id == send_id1 || id == send_id2) && value.is_none() {
            return Err(Error::ValueError("Cannot share None".to_string()));
        }

        let result = if id == send_id1 {
            self.send_value(value.unwrap(), recv_id).await?;
            None
        } else if id == send_id2 {
            // TODO save for jmp verify
            None
        } else if id == recv_id {
            Some(self.receive_value(recv_id).await?)
        } else {
            unreachable!()
        };

        // TODO packed jmp verify!!!! at the end

        Ok(result)
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
                    self.send_value(beta.to_owned(), 1).await?;
                    self.jmp_send::<T>(0, 1, 2, Some(beta.to_owned())).await?;
                    Share::new(alpha1, alpha2, beta + &gamma)
                } else if self_id == 1 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let beta = self.receive_value::<T::Share>(0).await?;
                    self.jmp_send::<T>(0, 1, 2, Some(beta.to_owned())).await?;
                    // Receive beta
                    Share::new(alpha1, beta, gamma)
                } else if self_id == 2 {
                    let alpha2 = self.prf.gen_1::<T::Share>();
                    let beta = self.jmp_send::<T>(0, 1, 2, None).await?;
                    let beta = beta.ok_or(Error::ValueError("None received".to_string()))?;
                    Share::new(alpha2, beta, gamma)
                } else {
                    unreachable!()
                }
            }
            1 => {
                let alpha2 = self.prf.gen_p::<T::Share>();
                if self_id == 0 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let beta_gamma = self.jmp_send::<T>(1, 2, 0, None).await?;
                    let beta_gamma =
                        beta_gamma.ok_or(Error::ValueError("None received".to_string()))?;
                    Share::new(alpha1, alpha2, beta_gamma)
                } else if self_id == 1 {
                    let alpha1 = self.prf.gen_1::<T::Share>();
                    let gamma = self.prf.gen_2::<T::Share>();
                    let beta = input.unwrap().to_sharetype() + &alpha1 + &alpha2;
                    self.send_value(beta.to_owned(), 2).await?;
                    self.jmp_send::<T>(1, 2, 0, Some(beta.to_owned() + &gamma))
                        .await?;
                    Share::new(alpha1, beta, gamma)
                } else if self_id == 2 {
                    let gamma = self.prf.gen_2::<T::Share>();
                    let beta = self.receive_value::<T::Share>(1).await?;
                    self.jmp_send::<T>(1, 2, 0, Some(beta.to_owned() + &gamma))
                        .await?;
                    Share::new(alpha2, beta, gamma)
                } else {
                    unreachable!()
                }
            }
            2 => {
                let alpha1 = self.prf.gen_p::<T::Share>();
                if self_id == 0 {
                    let alpha2 = self.prf.gen_2::<T::Share>();
                    let beta_gamma = self.jmp_send::<T>(1, 2, 0, None).await?;
                    let beta_gamma =
                        beta_gamma.ok_or(Error::ValueError("None received".to_string()))?;
                    Share::new(alpha1, alpha2, beta_gamma)
                } else if self_id == 1 {
                    let gamma = self.prf.gen_2::<T::Share>();
                    let beta = self.receive_value::<T::Share>(2).await?;
                    self.jmp_send::<T>(1, 2, 0, Some(beta.to_owned() + &gamma))
                        .await?;
                    Share::new(alpha1, beta, gamma)
                } else if self_id == 2 {
                    let alpha2 = self.prf.gen_1::<T::Share>();
                    let gamma = self.prf.gen_2::<T::Share>();
                    let beta = input.unwrap().to_sharetype() + &alpha1 + &alpha2;
                    self.send_value(beta.to_owned(), 1).await?;
                    self.jmp_send::<T>(1, 2, 0, Some(beta.to_owned() + &gamma))
                        .await?;
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
        let id = self.network.get_id();
        // TODO verify jmp sends from before

        let (a, b, c) = share.get_abc();
        let inputs = match id {
            0 => (Some(a.to_owned()), Some(b.to_owned()), None),
            1 => (Some(a.to_owned()), None, Some(c.to_owned())),
            2 => (None, Some(a.to_owned()), Some(c.to_owned())),
            _ => unreachable!(),
        };

        // Todo jmp_send_many?
        let r1 = self.jmp_send::<T>(0, 1, 2, inputs.0).await?;
        let r2 = self.jmp_send::<T>(0, 2, 1, inputs.1).await?;
        let r3 = self.jmp_send::<T>(1, 2, 0, inputs.2).await?;

        // TODO verify jmp sends from now

        let output = match id {
            0 => c - a - b - r1.ok_or(Error::ValueError("None received".to_string()))?,
            1 => b - a - r2.ok_or(Error::ValueError("None received".to_string()))?,
            2 => b - a - r3.ok_or(Error::ValueError("None received".to_string()))?,
            _ => unreachable!(),
        };
        Ok(T::from_sharetype(output))
    }

    async fn open_many(&mut self, shares: Vec<Share<T>>) -> Result<Vec<T>, Error> {
        todo!()
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
        todo!()
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
