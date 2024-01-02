use super::share::Share;
use crate::{
    aby3::utils,
    iris::protocol::OR_TREE_PACK_SIZE,
    prelude::{Aby3, Aby3Share, Bit, Error, MpcTrait, NetworkTrait, Sharable},
    traits::binary_trait::BinaryMpcTrait,
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
use std::ops::{Mul, MulAssign};

#[allow(type_alias_bounds)]
pub(crate) type TShare<T: Sharable> = Share<T::VerificationShare>;
#[allow(type_alias_bounds)]
pub(crate) type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

pub struct SpdzWise<N: NetworkTrait, U: Sharable> {
    aby3: Aby3<N>,
    mac_key: Aby3Share<U>,
    verifyqueue: Vec<Share<U>>, // For arithmetic
    send_queue_prev: BytesMut,  // For binary
    rcv_queue_next: BytesMut,   // For binary
}

impl<N: NetworkTrait, U: Sharable> SpdzWise<N, U>
where
    Standard: Distribution<U::Share>,
    Aby3Share<U>: Mul<U::Share, Output = Aby3Share<U>>,
{
    pub fn new(network: N) -> Self {
        let aby3 = Aby3::new(network);
        let send_queue_prev = BytesMut::new();
        let rcv_queue_next = BytesMut::new();

        Self {
            aby3,
            mac_key: Aby3Share::default(),
            verifyqueue: Vec::new(),
            send_queue_prev,
            rcv_queue_next,
        }
    }

    pub fn get_r(&self) -> Aby3Share<U> {
        self.mac_key.to_owned()
    }

    #[cfg(test)]
    pub(crate) fn aby_open(&mut self, share: Aby3Share<U>) -> Result<U, Error> {
        self.aby3.open(share)
    }

    fn get_id(&self) -> usize {
        self.aby3.network.get_id()
    }

    fn hash_based_zero_verifiy(&mut self, w: Aby3Share<U>) -> Result<(), Error> {
        let (wa, wb) = w.get_ab();
        let w_neg = -wa.to_owned() - &wb;

        let mut hasher = Sha512::new();
        match self.get_id() {
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

        let hashes = self.aby3.network.broadcast(Bytes::from(digest.to_vec()))?;
        debug_assert_eq!(hashes.len(), 3);

        if hashes[0] != hashes[1] || hashes[0] != hashes[2] {
            Err(Error::VerifyError)
        } else {
            Ok(())
        }
    }

    fn verify_macs(&mut self) -> Result<(), Error> {
        if self.verifyqueue.is_empty() {
            return Ok(());
        }

        let len = self.verifyqueue.len();
        let rands = (0..len)
            .map(|_| self.aby3.prf.gen_rand::<U>())
            .collect::<Vec<_>>();

        let mut swap = Vec::new();
        std::mem::swap(&mut swap, &mut self.verifyqueue);

        let mut values = Vec::with_capacity(len);
        let mut macs = Vec::with_capacity(len);

        for share in swap.into_iter() {
            let (value, mac) = share.get();
            values.push(value);
            macs.push(mac);
        }

        let res = <_ as MpcTrait<U, Aby3Share<U>, Aby3Share<Bit>>>::dot_many(
            &mut self.aby3,
            &[values, macs],
            &[rands.to_owned(), rands.to_owned()],
        )?;

        let r = self.get_r();
        let mul = <_ as MpcTrait<U, Aby3Share<U>, Aby3Share<Bit>>>::mul(
            &mut self.aby3,
            res[0].to_owned(),
            r,
        )?;
        let zero = mul - &res[1];
        self.hash_based_zero_verifiy(zero)
    }

    #[inline(always)]
    fn jmp_send<T: Sharable>(&mut self, send: T::Share) -> Result<(), Error> {
        utils::send_value_next(&mut self.aby3.network, send)
    }

    #[inline(always)]
    fn jmp_buffer<T: Sharable>(&mut self, buffer: T::Share) {
        buffer.add_to_bytes(&mut self.send_queue_prev);
    }

    #[inline(always)]
    fn jmp_send_many<T: Sharable>(&mut self, send: Vec<T::Share>) -> Result<(), Error> {
        utils::send_vec_next(&mut self.aby3.network, send)
    }

    fn jmp_buffer_many<T: Sharable>(&mut self, buffer: Vec<T::Share>) {
        for value in buffer.into_iter() {
            value.add_to_bytes(&mut self.send_queue_prev);
        }
    }

    fn jmp_receive<T: Sharable>(&mut self) -> Result<T::Share, Error> {
        let value: T::Share = utils::receive_value_prev(&mut self.aby3.network)?;
        value.to_owned().add_to_bytes(&mut self.rcv_queue_next);
        Ok(value)
    }

    fn jmp_receive_many<T: Sharable>(&mut self, len: usize) -> Result<Vec<T::Share>, Error> {
        let values: Vec<T::Share> = utils::receive_vec_prev(&mut self.aby3.network, len)?;

        for value in values.iter().cloned() {
            value.add_to_bytes(&mut self.rcv_queue_next);
        }

        Ok(values)
    }

    fn jmp_send_receive<T: Sharable>(
        &mut self,
        send: T::Share,
        buffer: T::Share,
    ) -> Result<T::Share, Error> {
        self.jmp_buffer::<T>(buffer);
        self.jmp_send::<T>(send)?;
        self.jmp_receive::<T>()
    }

    fn jmp_send_receive_many<T: Sharable>(
        &mut self,
        send: Vec<T::Share>,
        buffer: Vec<T::Share>,
    ) -> Result<Vec<T::Share>, Error> {
        let len = send.len();
        self.jmp_buffer_many::<T>(buffer);
        self.jmp_send_many::<T>(send)?;
        self.jmp_receive_many::<T>(len)
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
        let send_prev = Self::clear_and_hash(&mut self.send_queue_prev);
        let hash_next = Self::clear_and_hash(&mut self.rcv_queue_next);

        self.aby3
            .network
            .send_prev_id(Bytes::from(send_prev.to_vec()))?;

        let rcv_next = self.aby3.network.receive_next_id()?;

        if rcv_next.as_ref() != hash_next.as_slice() {
            return Err(Error::JmpVerifyError);
        }

        Ok(())
    }

    fn coin<R: Rng + SeedableRng>(&mut self) -> Result<R::Seed, Error>
    where
        Standard: Distribution<R::Seed>,
        R::Seed: AsRef<[u8]>,
    {
        let (mut seed1, seed2) = self.aby3.prf.gen_rands::<R::Seed>();

        let seed3 = self.jmp_send_receive_many::<u8>(
            RingElement::convert_slice_rev(seed2.as_ref()).to_vec(),
            RingElement::convert_slice_rev(seed1.as_ref()).to_vec(),
        )?;

        for (s1, (s2, s3)) in seed1
            .as_mut()
            .iter_mut()
            .zip(seed2.as_ref().iter().zip(seed3.into_iter()))
        {
            *s1 ^= s3.0 ^ s2;
        }

        Ok(seed1)
    }

    // Open_aby3_many without jmp_verify
    fn reconstruct_many<T: Sharable>(
        &mut self,
        shares: Vec<Aby3Share<T>>,
    ) -> Result<Vec<T>, Error> {
        let len = shares.len();
        let mut shares_a = Vec::with_capacity(len);
        let mut shares_b = Vec::with_capacity(len);

        for share in shares.iter().cloned() {
            let (a, b) = share.get_ab();
            shares_a.push(a);
            shares_b.push(b);
        }

        let shares_c = self.jmp_send_receive_many::<T>(shares_b, shares_a)?;

        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| T::from_sharetype(c + &s.a + &s.b))
            .collect();
        Ok(res)
    }

    fn mul_sacrifice_many<T: Sharable, R: Rng + SeedableRng>(
        &mut self,
        a: Vec<Aby3Share<T>>,
        b: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<T>>, Error>
    where
        Standard: Distribution<<T::VerificationShare as Sharable>::Share>,
        Standard: Distribution<R::Seed>,
        Aby3Share<T::VerificationShare>:
            for<'a> MulAssign<&'a <T::VerificationShare as Sharable>::Share>,
        Aby3Share<T::VerificationShare>: for<'a> Mul<
            &'a <T::VerificationShare as Sharable>::Share,
            Output = Aby3Share<T::VerificationShare>,
        >,
        Aby3Share<T::VerificationShare>: Mul<
            <T::VerificationShare as Sharable>::Share,
            Output = Aby3Share<T::VerificationShare>,
        >,
        R::Seed: AsRef<[u8]>,
    {
        let len = a.len();
        debug_assert_eq!(len, b.len());

        #[allow(type_alias_bounds)]
        type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

        assert!(UShare::<T>::K - T::Share::K >= 40);

        let mut a_mul = a
            .into_iter()
            .map(|a_| a_.to_verificationtype())
            .collect::<Vec<_>>();
        let mut b_mul = b
            .into_iter()
            .map(|a_| a_.to_verificationtype())
            .collect::<Vec<_>>();

        let mut v_ = a_mul.to_owned();

        // Get the second mul triple
        a_mul.reserve(len);
        for _ in 0..len {
            a_mul.push(self.aby3.prf.gen_rand());
        }
        let b_mul_ = b_mul.clone();
        b_mul.extend(b_mul.to_owned());
        let a_ = a_mul[len..].to_vec();

        // Finally Mul
        let cs = self.aby3.mul_many(a_mul, b_mul)?;

        let seed = self.coin::<R>()?;
        let mut rng = R::from_seed(seed);

        let r = rng.gen::<UShare<T>>();

        for (des, a_) in v_.iter_mut().zip(a_.into_iter()) {
            *des *= &r;
            *des -= a_;
        }

        let v = self.reconstruct_many(v_)?;
        self.jmp_verify()?;

        // hash based verification
        let mut hasher = Sha512::new();

        match self.get_id() {
            0 => {
                for ((b_, v_), (c_0, c_1)) in b_mul_
                    .into_iter()
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
                for ((b_, v_), (c_0, c_1)) in b_mul_
                    .into_iter()
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
                for ((b_, v_), (c_0, c_1)) in b_mul_
                    .into_iter()
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

        let hashes = self.aby3.network.broadcast(Bytes::from(digest.to_vec()))?;
        debug_assert_eq!(hashes.len(), 3);

        if hashes[0] != hashes[1] || hashes[0] != hashes[2] {
            return Err(Error::VerifyError);
        }

        let mut c = Vec::with_capacity(len);
        for c_ in cs.into_iter().take(len) {
            c.push(Aby3Share::from_verificationtype(c_));
        }

        Ok(c)
    }

    fn pack_exact<T: Sharable>(&self, a: Vec<Aby3Share<Bit>>) -> Aby3Share<T> {
        debug_assert!(a.len() <= T::Share::K);
        let mut share_a = T::Share::zero();
        let mut share_b = T::Share::zero();
        for (i, bit) in a.iter().enumerate() {
            let (bit_a, bit_b) = bit.to_owned().get_ab();
            share_a |= T::Share::from(bit_a.convert().convert()) << (i as u32);
            share_b |= T::Share::from(bit_b.convert().convert()) << (i as u32);
        }
        Aby3Share::new(share_a, share_b)
    }

    fn pack<T: Sharable>(&self, a: Vec<Aby3Share<Bit>>) -> Vec<Aby3Share<T>> {
        let outlen = (a.len() + T::Share::K - 1) / T::Share::K;
        let mut out = Vec::with_capacity(outlen);

        for a_ in a.chunks(T::Share::K) {
            let share = self.pack_exact(a_.to_vec());
            out.push(share);
        }

        out
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, TShare<T>, Aby3Share<Bit>>
    for SpdzWise<N, T::VerificationShare>
where
    Standard: Distribution<UShare<T>>,
    Standard: Distribution<T::Share>,
    Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
    Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
{
    fn get_id(&self) -> usize {
        self.get_id()
    }

    fn preprocess(&mut self) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::preprocess(&mut self.aby3)
        ?;

        Ok(())
    }

    fn set_mac_key(&mut self, key: TShare<T>) {
        let mac = key.get_mac();
        self.mac_key = mac;
    }

    fn set_new_mac_key(&mut self) {
        self.mac_key = self.aby3.prf.gen_rand::<T::VerificationShare>();
    }

    #[cfg(test)]
    fn open_mac_key(&mut self) -> Result<T::VerificationShare, Error> {
        let r = self.get_r();
        self.aby_open(r)
    }

    fn finish(self) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::finish(self.aby3)
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::print_connection_stats(&self.aby3, out)
    }

    fn input(&mut self, input: Option<T>, id: usize) -> Result<TShare<T>, Error> {
        let input = input.map(|i| T::to_verificationshare(i));

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::input(&mut self.aby3, input, id)?;

        let r = self.get_r();
        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul(&mut self.aby3, value.to_owned(), r)?;

        let share = Share::new(value, mac);

        self.verifyqueue.push(share.to_owned());

        Ok(share)
    }

    #[cfg(test)]
    fn input_all(&mut self, input: T) -> Result<Vec<TShare<T>>, Error> {
        // Since this is only for testing we perform a bad one
        let mut inputs = [None; 3];
        inputs[self.get_id()] = Some(input);
        let mut shares = Vec::with_capacity(3);

        for (i, inp) in inputs.into_iter().enumerate() {
            shares.push(self.input(inp.to_owned(), i)?);
        }

        Ok(shares)
    }

    fn share<R: rand::prelude::Rng>(
        input: T,
        mac_key: T::VerificationShare,
        rng: &mut R,
    ) -> Vec<TShare<T>> {
        let input = T::to_verificationtype(input.to_sharetype());
        let rz = mac_key.to_sharetype() * &input;

        let values = <Aby3<N> as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::share(
            T::VerificationShare::from_sharetype(input),
            <T::VerificationShare as Sharable>::VerificationShare::default(),
            rng,
        );

        let macs = <Aby3<N> as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::share(
            T::VerificationShare::from_sharetype(rz),
            <T::VerificationShare as Sharable>::VerificationShare::default(),
            rng,
        );

        values
            .into_iter()
            .zip(macs)
            .map(|(v, m)| Share::new(v, m))
            .collect()
    }

    fn open(&mut self, share: TShare<T>) -> Result<T, Error> {
        self.verifyqueue.push(share.to_owned());
        self.verify_macs()?;

        let result = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::open(&mut self.aby3, share.get_value())?;

        Ok(T::from_verificationshare(result))
    }

    fn open_many(&mut self, shares: Vec<TShare<T>>) -> Result<Vec<T>, Error> {
        self.verifyqueue.extend(shares.to_owned());
        self.verify_macs()?;

        let values = shares.into_iter().map(|s| s.get_value()).collect();

        let result = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::open_many(&mut self.aby3, values)?;

        let result = result
            .into_iter()
            .map(|r| T::from_verificationshare(r))
            .collect();

        Ok(result)
    }

    fn open_bit(&mut self, share: Aby3Share<Bit>) -> Result<bool, Error> {
        self.jmp_verify()?;

        let (a, b) = share.to_owned().get_ab();
        let c = self.jmp_send_receive::<Bit>(b, a)?;

        self.jmp_verify()?;
        Ok((share.a ^ share.b ^ c).convert().convert())
    }

    fn open_bit_many(&mut self, shares: Vec<Aby3Share<Bit>>) -> Result<Vec<bool>, Error> {
        self.jmp_verify()?;

        let len = shares.len();
        let mut shares_a = Vec::with_capacity(len);
        let mut shares_b = Vec::with_capacity(len);

        for share in shares.iter().cloned() {
            let (a, b) = share.get_ab();
            shares_a.push(a);
            shares_b.push(b);
        }

        let shares_c = self.jmp_send_receive_many::<Bit>(shares_b, shares_a)?;
        self.jmp_verify()?;

        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| (c ^ &s.a ^ &s.b).convert().convert())
            .collect();
        Ok(res)
    }

    fn add(&self, a: TShare<T>, b: TShare<T>) -> TShare<T> {
        let (a_v, a_m) = a.get();
        let (b_v, b_m) = b.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::add(&self.aby3, a_v, b_v);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::add(&self.aby3, a_m, b_m);

        Share::new(value, mac)
    }

    fn add_const(&self, a: TShare<T>, b: T) -> TShare<T> {
        let b = T::to_verificationshare(b);
        let (a_v, a_m) = a.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::add_const(&self.aby3, a_v, b);

        let mac_b = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul_const(&self.aby3, self.get_r(), b);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::add(&self.aby3, a_m, mac_b);

        Share::new(value, mac)
    }

    fn sub(&self, a: TShare<T>, b: TShare<T>) -> TShare<T> {
        let (a_v, a_m) = a.get();
        let (b_v, b_m) = b.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::sub(&self.aby3, a_v, b_v);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::sub(&self.aby3, a_m, b_m);

        Share::new(value, mac)
    }

    fn sub_const(&self, a: TShare<T>, b: T) -> TShare<T> {
        let b = T::to_verificationshare(b);
        let (a_v, a_m) = a.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::sub_const(&self.aby3, a_v, b);

        let mac_b = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul_const(&self.aby3, self.get_r(), b);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::sub(&self.aby3, a_m, mac_b);

        Share::new(value, mac)
    }

    fn mul(&mut self, a: TShare<T>, b: TShare<T>) -> Result<TShare<T>, Error> {
        let (a_v, a_m) = a.get();
        let b_v = b.get_value();

        let values = self
            .aby3
            .mul_many(vec![a_v, a_m], vec![b_v.to_owned(), b_v])?;

        let result = Share::new(values[0].to_owned(), values[1].to_owned());

        self.verifyqueue.push(result.to_owned());
        Ok(result)
    }

    fn mul_const(&self, a: TShare<T>, b: T) -> TShare<T> {
        let b = T::to_verificationshare(b);
        let (a_v, a_m) = a.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul_const(&self.aby3, a_v, b);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul_const(&self.aby3, a_m, b);

        Share::new(value, mac)
    }

    fn dot(&mut self, a: Vec<TShare<T>>, b: Vec<TShare<T>>) -> Result<TShare<T>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }
        let mut a_values = Vec::with_capacity(len);
        let mut a_macs = Vec::with_capacity(len);
        let mut b_values = Vec::with_capacity(len);

        for (a, b) in a.into_iter().zip(b.into_iter()) {
            let (a_v, a_m) = a.get();
            let b_v = b.get_value();
            a_values.push(a_v);
            a_macs.push(a_m);
            b_values.push(b_v);
        }

        let res = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::dot_many(
            &mut self.aby3,
            &[a_values, a_macs],
            &[b_values.to_owned(), b_values],
        )?;

        let result = Share::new(res[0].to_owned(), res[1].to_owned());

        self.verifyqueue.push(result.to_owned());
        Ok(result)
    }

    fn dot_many(
        &mut self,
        a: &[Vec<TShare<T>>],
        b: &[Vec<TShare<T>>],
    ) -> Result<Vec<TShare<T>>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut a_values = Vec::with_capacity(len);
        let mut a_macs = Vec::with_capacity(len);
        let mut b_values = Vec::with_capacity(len);

        for (a, b) in a.iter().zip(b.iter()) {
            let mut a_v = Vec::with_capacity(len);
            let mut a_m = Vec::with_capacity(len);
            let mut b_v = Vec::with_capacity(len);
            for (a, b) in a.iter().cloned().zip(b.iter().cloned()) {
                let (a_v_, a_m_) = a.get();
                let b_v_ = b.get_value();
                a_v.push(a_v_);
                a_m.push(a_m_);
                b_v.push(b_v_);
            }
            a_values.push(a_v);
            a_macs.push(a_m);
            b_values.push(b_v);
        }

        a_values.extend(a_macs);
        b_values.extend(b_values.to_owned());

        let values = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::dot_many(&mut self.aby3, &a_values, &b_values)?;

        let mut result = Vec::with_capacity(len);
        self.verifyqueue.reserve(len);

        for (value, mac) in values
            .iter()
            .take(len)
            .cloned()
            .zip(values.iter().skip(len).cloned())
        {
            let share = Share::new(value, mac);
            self.verifyqueue.push(share.to_owned());
            result.push(share);
        }

        Ok(result)
    }

    fn get_msb(&mut self, a: TShare<T>) -> Result<Aby3Share<Bit>, Error> {
        self.verifyqueue.push(a.to_owned());
        self.verify_macs()?;

        // protocol switch
        let value = Aby3Share::<T>::from_verificationtype(a.get_value());
        let bits = self.arithmetic_to_binary(value)?;
        Ok(bits.get_msb())
    }

    fn get_msb_many(&mut self, a: Vec<TShare<T>>) -> Result<Vec<Aby3Share<Bit>>, Error> {
        self.verifyqueue.extend(a.to_owned());
        self.verify_macs()?;

        // protocol switch
        let values = a
            .into_iter()
            .map(|a| Aby3Share::<T>::from_verificationtype(a.get_value()))
            .collect();
        let bits = self.arithmetic_to_binary_many(values)?;
        let res = bits.into_iter().map(|a| a.get_msb()).collect();
        Ok(res)
    }

    fn binary_or(&mut self, a: Aby3Share<Bit>, b: Aby3Share<Bit>) -> Result<Aby3Share<Bit>, Error> {
        <Self as BinaryMpcTrait<Bit, Aby3Share<Bit>>>::or(self, a, b)
    }

    fn reduce_binary_or(&mut self, a: Vec<Aby3Share<Bit>>) -> Result<Aby3Share<Bit>, Error> {
        const PACK_SIZE: usize = OR_TREE_PACK_SIZE * 128;
        utils::or_tree::<Bit, _, _, PACK_SIZE>(self, a)
    }

    fn verify(&mut self) -> Result<(), Error> {
        self.verify_macs()
    }
}

impl<N: NetworkTrait, T: Sharable, U: Sharable> BinaryMpcTrait<T, Aby3Share<T>> for SpdzWise<N, U>
where
    Standard: Distribution<U::Share>,
    Aby3Share<U>: Mul<U::Share, Output = Aby3Share<U>>,
{
    fn and(&mut self, a: Aby3Share<T>, b: Aby3Share<T>) -> Result<Aby3Share<T>, Error> {
        let a_bits = a.to_bits();
        let b_bits = b.to_bits();

        let c_bits = self.mul_sacrifice_many::<Bit, ChaCha12Rng>(a_bits, b_bits)?;

        let c = self.pack_exact(c_bits);
        Ok(c)
    }

    fn and_many(
        &mut self,
        a: Vec<Aby3Share<T>>,
        b: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<T>>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut a_bits = Vec::with_capacity(T::Share::K * len);
        let mut b_bits = Vec::with_capacity(T::Share::K * len);

        for a in a.into_iter() {
            a_bits.extend(a.to_bits());
        }

        for b in b.into_iter() {
            b_bits.extend(b.to_bits());
        }

        let c_bits = self.mul_sacrifice_many::<Bit, ChaCha12Rng>(a_bits, b_bits)?;

        let c = self.pack::<T>(c_bits);
        Ok(c)
    }

    fn arithmetic_to_binary(&mut self, x: Aby3Share<T>) -> Result<Aby3Share<T>, Error> {
        let (x1, x2, x3) = self.aby3.a2b_pre(x);
        self.binary_add_3(x1, x2, x3)
    }

    fn arithmetic_to_binary_many(
        &mut self,
        x: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<T>>, Error> {
        let len = x.len();
        let mut x1 = Vec::with_capacity(len);
        let mut x2 = Vec::with_capacity(len);
        let mut x3 = Vec::with_capacity(len);

        for x_ in x {
            let (x1_, x2_, x3_) = self.aby3.a2b_pre(x_);
            x1.push(x1_);
            x2.push(x2_);
            x3.push(x3_);
        }
        self.binary_add_3_many(x1, x2, x3)
    }
}
