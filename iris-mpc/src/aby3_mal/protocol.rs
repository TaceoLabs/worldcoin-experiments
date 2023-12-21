use crate::aby3::id::PartyID;
use crate::aby3::random::prf::{Prf, PrfSeed};
use crate::aby3::share::Share;
use crate::aby3::utils;
use crate::commitment::{CommitOpening, Commitment};
use crate::error::Error;
use crate::traits::binary_trait::BinaryMpcTrait;
use crate::traits::mpc_trait::MpcTrait;
use crate::traits::network_trait::NetworkTrait;
use crate::traits::security::MaliciousAbort;
use crate::types::bit::Bit;
use crate::types::ring_element::{RingElement, RingImpl};
use crate::types::sharable::Sharable;
use bytes::{Bytes, BytesMut};
use num_traits::Zero;
use rand::distributions::{Distribution, Standard};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use sha2::digest::Output;
use sha2::{Digest, Sha512};
use std::ops::{BitAnd, Mul, MulAssign};

pub struct MalAby3<N: NetworkTrait> {
    network: N,
    prf: Prf,
    send_queue_prev: BytesMut,
    rcv_queue_next: BytesMut,
}

impl<N: NetworkTrait> MaliciousAbort for MalAby3<N> {}

macro_rules! reduce_or {
    ($([$typ_a:ident, $typ_b:ident,$name_a:ident,$name_b:ident]),*) => {
        $(
            async fn $name_a(&mut self, a: Share<$typ_a>) -> Result<Share<Bit>, Error> {
                let (a, b) = a.get_ab();
                let (a1, a2) = utils::split::<$typ_a, $typ_b>(a);
                let (b1, b2) = utils::split::<$typ_a, $typ_b>(b);

                let share_a = Share::new(a1, b1);
                let share_b = Share::new(a2, b2);

                let out = self.or(share_a, share_b).await?;
                self.$name_b(out).await
            }
        )*
    };
}

impl<N: NetworkTrait> MalAby3<N> {
    pub fn new(network: N) -> Self {
        let prf = Prf::default();
        let send_queue_prev = BytesMut::new();
        let rcv_queue_next = BytesMut::new();

        Self {
            network,
            prf,
            send_queue_prev,
            rcv_queue_next,
        }
    }

    #[inline(always)]
    async fn jmp_send<T: Sharable>(&mut self, send: T::Share) -> Result<(), Error> {
        utils::send_value_next(&mut self.network, send).await
    }

    #[inline(always)]
    fn jmp_buffer<T: Sharable>(&mut self, buffer: T::Share) {
        buffer.add_to_bytes(&mut self.send_queue_prev);
    }

    #[inline(always)]
    async fn jmp_send_many<T: Sharable>(&mut self, send: Vec<T::Share>) -> Result<(), Error> {
        utils::send_vec_next(&mut self.network, send).await
    }

    fn jmp_buffer_many<T: Sharable>(&mut self, buffer: Vec<T::Share>) {
        for value in buffer.into_iter() {
            value.add_to_bytes(&mut self.send_queue_prev);
        }
    }

    async fn jmp_receive<T: Sharable>(&mut self) -> Result<T::Share, Error> {
        let value: T::Share = utils::receive_value_prev(&mut self.network).await?;
        value.to_owned().add_to_bytes(&mut self.rcv_queue_next);
        Ok(value)
    }

    async fn jmp_receive_many<T: Sharable>(&mut self, len: usize) -> Result<Vec<T::Share>, Error> {
        let values: Vec<T::Share> = utils::receive_vec_prev(&mut self.network, len).await?;

        for value in values.iter().cloned() {
            value.add_to_bytes(&mut self.rcv_queue_next);
        }

        Ok(values)
    }

    async fn jmp_send_receive<T: Sharable>(
        &mut self,
        send: T::Share,
        buffer: T::Share,
    ) -> Result<T::Share, Error> {
        self.jmp_buffer::<T>(buffer);
        self.jmp_send::<T>(send).await?;
        self.jmp_receive::<T>().await
    }

    async fn jmp_send_receive_many<T: Sharable>(
        &mut self,
        send: Vec<T::Share>,
        buffer: Vec<T::Share>,
    ) -> Result<Vec<T::Share>, Error> {
        let len = send.len();
        self.jmp_buffer_many::<T>(buffer);
        self.jmp_send_many::<T>(send).await?;
        self.jmp_receive_many::<T>(len).await
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
        let send_prev = Self::clear_and_hash(&mut self.send_queue_prev);
        let hash_next = Self::clear_and_hash(&mut self.rcv_queue_next);

        self.network
            .send_prev_id(Bytes::from(send_prev.to_vec()))
            .await?;

        let rcv_next = self.network.receive_next_id().await?;

        if rcv_next.as_ref() != hash_next.as_slice() {
            return Err(Error::JmpVerifyError);
        }

        Ok(())
    }

    async fn coin<R: Rng + SeedableRng>(&mut self) -> Result<R::Seed, Error>
    where
        Standard: Distribution<R::Seed>,
        R::Seed: AsRef<[u8]>,
    {
        let (mut seed1, seed2) = self.prf.gen_rands::<R::Seed>();

        let seed3 = self
            .jmp_send_receive_many::<u8>(
                RingElement::convert_slice_rev(seed2.as_ref()).to_vec(),
                RingElement::convert_slice_rev(seed1.as_ref()).to_vec(),
            )
            .await?;

        for (s1, (s2, s3)) in seed1
            .as_mut()
            .iter_mut()
            .zip(seed2.as_ref().iter().zip(seed3.into_iter()))
        {
            *s1 ^= s3.0 ^ s2;
        }

        Ok(seed1)
    }

    async fn aby_mul_many<T: Sharable>(
        &mut self,
        a: Vec<Share<T>>,
        b: Vec<Share<T>>,
    ) -> Result<Vec<Share<T>>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        debug_assert_eq!(a.len(), b.len());

        let mut shares_a = Vec::with_capacity(a.len());

        for (a_, b_) in a.iter().cloned().zip(b.iter().cloned()) {
            let rand = self.prf.gen_zero_share::<T>();
            let mut c = a_ * b_;
            c.a += rand;
            shares_a.push(c.a);
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned()).await?;

        let res: Vec<Share<T>> = shares_a
            .into_iter()
            .zip(shares_b.into_iter())
            .map(|(a_, b_)| Share::new(a_, b_))
            .collect();

        Ok(res)
    }

    #[cfg(test)]
    async fn get_mul_triple<T: Sharable, R: Rng + SeedableRng>(
        &mut self,
    ) -> Result<(Share<T>, Share<T>, Share<T>), Error>
    where
        Standard: Distribution<<T::VerificationShare as Sharable>::Share>,
        Standard: Distribution<R::Seed>,
        Share<T::VerificationShare>: for<'a> Mul<
            &'a <T::VerificationShare as Sharable>::Share,
            Output = Share<T::VerificationShare>,
        >,
        Share<T::VerificationShare>:
            Mul<<T::VerificationShare as Sharable>::Share, Output = Share<T::VerificationShare>>,
        R::Seed: AsRef<[u8]>,
    {
        #[allow(type_alias_bounds)]
        type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

        assert!(UShare::<T>::K - T::Share::K >= 40);

        let a = self.prf.gen_rand::<T::VerificationShare>();
        let a_ = self.prf.gen_rand::<T::VerificationShare>();
        let b = self.prf.gen_rand::<T::VerificationShare>();

        let cs = self
            .aby_mul_many(
                vec![a.to_owned(), a_.to_owned()],
                vec![b.to_owned(), b.to_owned()],
            )
            .await?;

        let seed = self.coin::<R>().await?;
        let mut rng = R::from_seed(seed);

        let r = rng.gen::<UShare<T>>();
        let v_ = a.to_owned() * &r - a_;
        let v = self.reconstruct(v_).await?.to_sharetype();
        self.jmp_verify().await?;

        let w = b.to_owned() * v - cs[0].to_owned() * r + &cs[1];
        let (wa, wb) = w.get_ab();
        let w_neg = -wa.to_owned() - &wb;

        // hash based verification
        let mut hasher = Sha512::new();
        match self.network.get_id() {
            0 => {
                hasher.update(wa.to_bytes());
                hasher.update(w_neg.to_bytes());
                hasher.update(wb.to_bytes());
            }
            1 => {
                hasher.update(wb.to_bytes());
                hasher.update(wa.to_bytes());
                hasher.update(w_neg.to_bytes());
            }
            2 => {
                hasher.update(w_neg.to_bytes());
                hasher.update(wb.to_bytes());
                hasher.update(wa.to_bytes());
            }
            _ => unreachable!(),
        };
        let digest = hasher.finalize();

        let hashes = self.network.broadcast(Bytes::from(digest.to_vec())).await?;
        debug_assert_eq!(hashes.len(), 3);

        if hashes[0] != hashes[1] || hashes[0] != hashes[2] {
            return Err(Error::VerifyError);
        }

        let a = Share::from_verificationtype(a);
        let b = Share::from_verificationtype(b);
        let c = Share::from_verificationtype(cs[0].to_owned());

        Ok((a, b, c))
    }

    async fn get_mul_triple_many<T: Sharable, R: Rng + SeedableRng>(
        &mut self,
        len: usize,
    ) -> Result<(Vec<Share<T>>, Vec<Share<T>>, Vec<Share<T>>), Error>
    where
        Standard: Distribution<<T::VerificationShare as Sharable>::Share>,
        Standard: Distribution<R::Seed>,
        Share<T::VerificationShare>:
            for<'a> MulAssign<&'a <T::VerificationShare as Sharable>::Share>,
        Share<T::VerificationShare>: for<'a> Mul<
            &'a <T::VerificationShare as Sharable>::Share,
            Output = Share<T::VerificationShare>,
        >,
        Share<T::VerificationShare>:
            Mul<<T::VerificationShare as Sharable>::Share, Output = Share<T::VerificationShare>>,
        R::Seed: AsRef<[u8]>,
    {
        #[allow(type_alias_bounds)]
        type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

        assert!(UShare::<T>::K - T::Share::K >= 40);

        let mut a_mul: Vec<Share<T::VerificationShare>> = (0..len)
            .map(|_| self.prf.gen_rand::<T::VerificationShare>())
            .collect();

        let mut b_mul: Vec<Share<T::VerificationShare>> = (0..len)
            .map(|_| self.prf.gen_rand::<T::VerificationShare>())
            .collect();

        // Truncate already
        let mut a = Vec::with_capacity(len);
        let mut b = Vec::with_capacity(len);

        for (a_, b_) in a_mul.iter().cloned().zip(b_mul.iter().cloned()) {
            a.push(Share::from_verificationtype(a_));
            b.push(Share::from_verificationtype(b_));
        }

        // Get the second mul triple
        a_mul.reserve(len);
        for _ in 0..len {
            a_mul.push(self.prf.gen_rand());
        }
        let b_mul_ = b_mul.clone();
        b_mul.extend(b_mul_);

        let cs = self
            .aby_mul_many(a_mul.to_owned(), b_mul.to_owned())
            .await?;

        let seed = self.coin::<R>().await?;
        let mut rng = R::from_seed(seed);

        let r = rng.gen::<UShare<T>>();
        let mut v_ = a_mul[..len].to_vec();
        for (des, a_) in v_.iter_mut().zip(a_mul.into_iter().skip(len)) {
            *des *= &r;
            *des -= a_;
        }

        let v = self.reconstruct_many(v_).await?;
        self.jmp_verify().await?;

        // hash based verification
        let mut hasher = Sha512::new();

        match self.network.get_id() {
            0 => {
                for ((b_, v_), (c_0, c_1)) in b_mul
                    .into_iter()
                    .take(len)
                    .zip(v.into_iter())
                    .zip(cs.iter().take(len).zip(cs.iter().skip(len)))
                {
                    let w_ = b_ * v_.to_sharetype() - c_0.to_owned() * &r + c_1.to_owned();

                    let (wa, wb) = w_.get_ab();
                    let w_neg = -wa.to_owned() - &wb;

                    hasher.update(wa.to_bytes());
                    hasher.update(w_neg.to_bytes());
                    hasher.update(wb.to_bytes());
                }
            }
            1 => {
                for ((b_, v_), (c_0, c_1)) in b_mul
                    .into_iter()
                    .take(len)
                    .zip(v.into_iter())
                    .zip(cs.iter().take(len).zip(cs.iter().skip(len)))
                {
                    let w_ = b_ * v_.to_sharetype() - c_0.to_owned() * &r + c_1.to_owned();

                    let (wa, wb) = w_.get_ab();
                    let w_neg = -wa.to_owned() - &wb;

                    hasher.update(wb.to_bytes());
                    hasher.update(wa.to_bytes());
                    hasher.update(w_neg.to_bytes());
                }
            }
            2 => {
                for ((b_, v_), (c_0, c_1)) in b_mul
                    .into_iter()
                    .take(len)
                    .zip(v.into_iter())
                    .zip(cs.iter().take(len).zip(cs.iter().skip(len)))
                {
                    let w_ = b_ * v_.to_sharetype() - c_0.to_owned() * &r + c_1.to_owned();

                    let (wa, wb) = w_.get_ab();
                    let w_neg = -wa.to_owned() - &wb;

                    hasher.update(w_neg.to_bytes());
                    hasher.update(wb.to_bytes());
                    hasher.update(wa.to_bytes());
                }
            }

            _ => unreachable!(),
        }

        let digest = hasher.finalize();

        let hashes = self.network.broadcast(Bytes::from(digest.to_vec())).await?;
        debug_assert_eq!(hashes.len(), 3);

        if hashes[0] != hashes[1] || hashes[0] != hashes[2] {
            return Err(Error::VerifyError);
        }

        let mut c = Vec::with_capacity(len);
        for c_ in cs.into_iter().take(len) {
            c.push(Share::from_verificationtype(c_));
        }

        Ok((a, b, c))
    }

    async fn send_seed_opening(
        &mut self,
        opening1: &CommitOpening<RingElement<u8>>,
        opening2: &CommitOpening<RingElement<u8>>,
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

        let msg1 = msg1.freeze();
        let msg2 = msg2.freeze();

        self.network.send_next_id(msg1).await?;
        self.network.send_prev_id(msg2).await?;

        Ok(())
    }

    fn verify_commitment(data: &[u8], rand: [u8; 32], comm: Vec<u8>) -> bool {
        let opening = CommitOpening {
            values: RingElement::convert_slice_rev(data).to_vec(),
            rand,
        };
        opening.verify(comm)
    }

    async fn setup_prf(&mut self) -> Result<(), Error> {
        let seed1 = Prf::gen_seed();
        let seed2 = Prf::gen_seed();
        self.setup_prf_from_seed(seed1, seed2).await
    }

    async fn setup_prf_from_seed(&mut self, seed1: PrfSeed, seed2: PrfSeed) -> Result<(), Error> {
        let mut rng = ChaCha12Rng::from_entropy();

        let comm1 = Commitment::commit(RingElement::convert_slice_rev(&seed1).to_vec(), &mut rng);
        let comm2 = Commitment::commit(RingElement::convert_slice_rev(&seed2).to_vec(), &mut rng);

        // First communication round: Send commitments
        self.network
            .send_next_id(Bytes::from(comm1.comm.to_owned()))
            .await?;
        self.network
            .send_prev_id(Bytes::from(comm2.comm.to_owned()))
            .await?;

        let msg1 = self.network.receive_next_id().await?;
        let msg2 = self.network.receive_prev_id().await?;

        let comm_size = Commitment::<RingElement<u8>>::get_comm_size();

        if msg1.len() != comm_size || msg2.len() != comm_size {
            return Err(Error::InvalidMessageSize);
        }
        let rcv_comm1 = msg1.to_vec();
        let rcv_comm2 = msg2.to_vec();

        // second communication round: send opening:
        let open1 = comm1.open();
        let open2 = comm2.open();

        self.send_seed_opening(&open1, &open2).await?;

        let msg1 = self.network.receive_next_id().await?;
        let msg2 = self.network.receive_prev_id().await?;

        let seed_size = seed1.len();
        let rand_size = Commitment::<RingElement<u8>>::get_rand_size();
        debug_assert_eq!(rand_size, 32);

        if msg1.len() != seed_size + rand_size || msg2.len() != seed_size + rand_size {
            return Err(Error::InvalidMessageSize);
        }

        let mut rcv_open1 = Vec::with_capacity(seed_size);
        let mut rcv_open2 = Vec::with_capacity(seed_size);
        let mut rcv_rand1 = [0; 32];
        let mut rcv_rand2 = [0; 32];

        msg1[..seed_size].clone_into(&mut rcv_open1);
        rcv_rand1.copy_from_slice(&msg1[seed_size..]);
        msg2[..seed_size].clone_into(&mut rcv_open2);
        rcv_rand2.copy_from_slice(&msg2[seed_size..]);

        if !Self::verify_commitment(&rcv_open1, rcv_rand1, rcv_comm1) {
            return Err(Error::InvalidCommitment((self.network.get_id() + 1) % 3));
        }
        if !Self::verify_commitment(&rcv_open2, rcv_rand2, rcv_comm2) {
            return Err(Error::InvalidCommitment((self.network.get_id() + 2) % 3));
        }

        // Finally done: Just initialize the PRFs now
        let mut seed1_ = [0u8; 32];
        let mut seed2_ = [0u8; 32];

        for (r, (a, b)) in seed1_
            .iter_mut()
            .zip(seed1.iter().zip(rcv_open1.into_iter()))
        {
            *r = b ^ a;
        }

        for (r, (a, b)) in seed2_
            .iter_mut()
            .zip(seed2.iter().zip(rcv_open2.into_iter()))
        {
            *r = b ^ a;
        }

        self.prf = Prf::new(seed1_, seed2_);

        Ok(())
    }

    fn a2b_pre<T: Sharable>(&self, x: Share<T>) -> (Share<T>, Share<T>, Share<T>) {
        let (a, b) = x.get_ab();

        let mut x1 = Share::<T>::zero();
        let mut x2 = Share::<T>::zero();
        let mut x3 = Share::<T>::zero();

        match self.network.get_id() {
            0 => {
                x1.a = a;
                x3.b = b;
            }
            1 => {
                x2.a = a;
                x1.b = b;
            }
            2 => {
                x3.a = a;
                x2.b = b;
            }
            _ => unreachable!(),
        }
        (x1, x2, x3)
    }

    fn pack_exact<T: Sharable>(&self, a: Vec<Share<Bit>>) -> Share<T> {
        debug_assert!(a.len() <= T::Share::K);
        let mut share_a = T::Share::zero();
        let mut share_b = T::Share::zero();
        for (i, bit) in a.iter().enumerate() {
            let (bit_a, bit_b) = bit.to_owned().get_ab();
            share_a |= T::Share::from(bit_a.convert().convert()) << (i as u32);
            share_b |= T::Share::from(bit_b.convert().convert()) << (i as u32);
        }
        Share::new(share_a, share_b)
    }

    fn pack<T: Sharable>(&self, a: Vec<Share<Bit>>) -> Vec<Share<T>> {
        let outlen = (a.len() + T::Share::K - 1) / T::Share::K;
        let mut out = Vec::with_capacity(outlen);

        for a_ in a.chunks(T::Share::K) {
            let share = self.pack_exact(a_.to_vec());
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

            decomp.push(Share::new(
                <Bit as Sharable>::Share::from(bit_a),
                <Bit as Sharable>::Share::from(bit_b),
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

    // Open without jmp_verify
    #[cfg(test)]
    async fn reconstruct<T: Sharable>(&mut self, share: Share<T>) -> Result<T, Error> {
        let (a, b) = share.to_owned().get_ab();
        let c = self.jmp_send_receive::<T>(b, a).await?;

        Ok(T::from_sharetype(share.a + share.b + c))
    }

    // Open_many without jmp_verify
    async fn reconstruct_many<T: Sharable>(
        &mut self,
        shares: Vec<Share<T>>,
    ) -> Result<Vec<T>, Error> {
        let len = shares.len();
        let mut shares_a = Vec::with_capacity(len);
        let mut shares_b = Vec::with_capacity(len);

        for share in shares.iter().cloned() {
            let (a, b) = share.get_ab();
            shares_a.push(a);
            shares_b.push(b);
        }

        let shares_c = self.jmp_send_receive_many::<T>(shares_b, shares_a).await?;

        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| T::from_sharetype(c + &s.a + &s.b))
            .collect();
        Ok(res)
    }

    // Open_many without jmp_verify
    async fn reconstruct_binary_many<T: Sharable>(
        &mut self,
        shares: Vec<Share<T>>,
    ) -> Result<Vec<T>, Error> {
        let len = shares.len();
        let mut shares_a = Vec::with_capacity(len);
        let mut shares_b = Vec::with_capacity(len);

        for share in shares.iter().cloned() {
            let (a, b) = share.get_ab();
            shares_a.push(a);
            shares_b.push(b);
        }

        let shares_c = self.jmp_send_receive_many::<T>(shares_b, shares_a).await?;

        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| T::from_sharetype(c ^ &s.a ^ &s.b))
            .collect();
        Ok(res)
    }

    async fn reconstruct_id<T: Sharable>(
        &mut self,
        share: Share<T>,
        id: usize,
    ) -> Result<Option<T>, Error> {
        if id >= self.network.get_num_parties() {
            return Err(Error::IdError(id));
        }

        let my_id = self.network.get_id();
        let sender = (id + 2) % 3;

        if my_id == id {
            let c = self.jmp_receive::<T>().await?;
            Ok(Some(T::from_sharetype(share.a + share.b + c)))
        } else if my_id == sender {
            self.jmp_send::<T>(share.get_b()).await?;
            Ok(None)
        } else {
            self.jmp_buffer::<T>(share.get_a());
            Ok(None)
        }
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, Share<T>, Share<Bit>> for MalAby3<N>
where
    Standard: Distribution<T::Share>,
    Standard: Distribution<<T::VerificationShare as Sharable>::Share>,
    Share<T>: Mul<Output = Share<T>>,
    Share<T>: Mul<Output = Share<T>>,
    Share<T>: Mul<T::Share, Output = Share<T>>,
    Share<T::VerificationShare>: for<'a> Mul<
        &'a <T::VerificationShare as Sharable>::Share,
        Output = Share<T::VerificationShare>,
    >,
    Share<T::VerificationShare>:
        Mul<<T::VerificationShare as Sharable>::Share, Output = Share<T::VerificationShare>>,
    Share<T>: BitAnd<T::Share, Output = Share<T>>,
    Share<T>: BitAnd<Share<T>, Output = Share<T>>,
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
        if id >= self.network.get_num_parties() {
            return Err(Error::IdError(id));
        }
        let my_id = self.get_id();

        let mut share = self.prf.gen_rand::<T>();
        let opened = self.reconstruct_id(share.to_owned(), id).await?;

        let res = if id == my_id {
            let value = match input {
                Some(x) => x,
                None => return Err(Error::ValueError("Cannot share None".to_string())),
            };
            let value =
                value.to_sharetype() - opened.expect("msg should be received").to_sharetype();
            share.a += &value;

            utils::send_value_next(&mut self.network, value.to_owned()).await?;
            utils::send_value_prev(&mut self.network, value).await?;
            share
        } else if my_id == (id + 1) % 3 {
            let value = utils::receive_value_prev::<_, T::Share>(&mut self.network).await?;
            utils::send_value_next(&mut self.network, value.to_owned()).await?;
            let value_ = utils::receive_value_next(&mut self.network).await?;
            if value != value_ {
                return Err(Error::VerifyError);
            }
            share.b += value;
            share
        } else {
            let value = utils::receive_value_next::<_, T::Share>(&mut self.network).await?;
            utils::send_value_prev(&mut self.network, value.to_owned()).await?;
            let value_ = utils::receive_value_prev(&mut self.network).await?;
            if value != value_ {
                return Err(Error::VerifyError);
            }
            share
        };

        Ok(res)
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
        let a = rng.gen::<T::Share>();
        let b = rng.gen::<T::Share>();
        let c = input.to_sharetype() - &a - &b;

        let share1 = Share::new(a.to_owned(), c.to_owned());
        let share2 = Share::new(b.to_owned(), a);
        let share3 = Share::new(c, b);

        vec![share1, share2, share3]
    }

    async fn open(&mut self, share: Share<T>) -> Result<T, Error> {
        self.jmp_verify().await?;

        let (a, b) = share.to_owned().get_ab();
        let c = self.jmp_send_receive::<T>(b, a).await?;

        self.jmp_verify().await?;
        Ok(T::from_sharetype(share.a + share.b + c))
    }

    async fn open_many(&mut self, shares: Vec<Share<T>>) -> Result<Vec<T>, Error> {
        self.jmp_verify().await?;

        let len = shares.len();
        let mut shares_a = Vec::with_capacity(len);
        let mut shares_b = Vec::with_capacity(len);

        for share in shares.iter().cloned() {
            let (a, b) = share.get_ab();
            shares_a.push(a);
            shares_b.push(b);
        }

        let shares_c = self.jmp_send_receive_many::<T>(shares_b, shares_a).await?;

        self.jmp_verify().await?;
        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| T::from_sharetype(c + &s.a + &s.b))
            .collect();
        Ok(res)
    }

    async fn open_bit(&mut self, share: Share<Bit>) -> Result<bool, Error> {
        self.jmp_verify().await?;

        let (a, b) = share.to_owned().get_ab();
        let c = self.jmp_send_receive::<Bit>(b, a).await?;

        self.jmp_verify().await?;
        Ok((share.a ^ share.b ^ c).convert().convert())
    }

    async fn open_bit_many(&mut self, shares: Vec<Share<Bit>>) -> Result<Vec<bool>, Error> {
        self.jmp_verify().await?;

        let len = shares.len();
        let mut shares_a = Vec::with_capacity(len);
        let mut shares_b = Vec::with_capacity(len);

        for share in shares.iter().cloned() {
            let (a, b) = share.get_ab();
            shares_a.push(a);
            shares_b.push(b);
        }

        let shares_c = self
            .jmp_send_receive_many::<Bit>(shares_b, shares_a)
            .await?;
        self.jmp_verify().await?;

        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| (c ^ &s.a ^ &s.b).convert().convert())
            .collect();
        Ok(res)
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

    #[cfg(test)]
    async fn mul(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let (x, y, z) = self.get_mul_triple::<T, ChaCha12Rng>().await?;

        let u = a.to_owned() - &x;
        let v = b.to_owned() - &y;

        let uv = self.reconstruct_many(vec![u, v]).await?;
        let u = uv[0].to_sharetype();
        let v = uv[1].to_sharetype();
        let uv = u.to_owned() * &v;

        let mut c = z + b * u + a * v;
        c.sub_assign_const(
            &uv,
            PartyID::try_from(self.get_id() as u8).expect("ID is in range"),
        );

        Ok(c)
    }

    fn mul_const(&self, a: Share<T>, b: T) -> Share<T> {
        a * b.to_sharetype()
    }

    async fn dot(&mut self, a: Vec<Share<T>>, b: Vec<Share<T>>) -> Result<Share<T>, Error> {
        // TODO this is semihonest
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let rand = self.prf.gen_zero_share::<T>();
        let mut c = Share::new(rand, T::zero().to_sharetype());
        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            c += a_ * b_;
        }

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned()).await?;

        Ok(c)
    }

    async fn dot_many(
        &mut self,
        a: Vec<Vec<Share<T>>>,
        b: Vec<Vec<Share<T>>>,
    ) -> Result<Vec<Share<T>>, Error> {
        // TODO this is semihonest
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut shares_a = Vec::with_capacity(a.len());

        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            let mut rand = self.prf.gen_zero_share::<T>();
            if a_.len() != b_.len() {
                return Err(Error::InvalidSizeError);
            }
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
            .map(|(a_, b_)| Share::new(a_, b_))
            .collect();

        Ok(res)
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

    async fn verify(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl<N: NetworkTrait, T: Sharable> BinaryMpcTrait<T, Share<T>> for MalAby3<N>
where
    Standard: Distribution<T::Share>,
    Share<T>: BitAnd<T::Share, Output = Share<T>>,
    Share<T>: BitAnd<Share<T>, Output = Share<T>>,
{
    async fn and(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let len = T::Share::K;
        let (x, y, z) = self.get_mul_triple_many::<Bit, ChaCha12Rng>(len).await?;

        let x = self.pack_exact::<T>(x);
        let y = self.pack_exact::<T>(y);
        let z = self.pack_exact::<T>(z);

        let u = a.to_owned() ^ &x;
        let v = b.to_owned() ^ &y;

        let uv = self.reconstruct_binary_many(vec![u, v]).await?;
        let u = uv[0].to_sharetype();
        let v = uv[1].to_sharetype();
        let uv = u.to_owned() & &v;

        let mut c = z ^ (b & u) ^ (a & v);
        c.xor_assign_const(
            &uv,
            PartyID::try_from(self.network.get_id() as u8).expect("ID is in range"),
        );

        Ok(c)
    }

    async fn and_many(
        &mut self,
        a: Vec<Share<T>>,
        b: Vec<Share<T>>,
    ) -> Result<Vec<Share<T>>, Error> {
        // TODO this is semihonest
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }
        let mut shares_a = Vec::with_capacity(a.len());
        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            let rand = self.prf.gen_binary_zero_share::<T>();
            let mut c = a_ & b_;
            c.a ^= rand;
            shares_a.push(c.a);
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned()).await?;

        let res = shares_a
            .into_iter()
            .zip(shares_b.into_iter())
            .map(|(a_, b_)| Share::new(a_, b_))
            .collect();

        Ok(res)
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
