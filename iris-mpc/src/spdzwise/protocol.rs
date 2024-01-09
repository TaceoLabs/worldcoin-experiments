use super::{share::Share, vecshare::VecShare};
use crate::{
    aby3::utils,
    prelude::{Aby3, Aby3Share, Bit, Error, MpcTrait, NetworkTrait, Sharable},
    traits::{binary_trait::BinaryMpcTrait, share_trait::VecShareTrait},
    types::ring_element::{RingElement, RingImpl},
};
use bytes::{Bytes, BytesMut};
use num_traits::Zero;
use plain_reference::IrisCodeArray;
use rand::{
    distributions::{Distribution, Standard},
    Rng, SeedableRng,
};
use rand_chacha::ChaCha12Rng;
use sha2::{digest::Output, Digest, Sha512};
use std::ops::Mul;

#[allow(type_alias_bounds)]
pub(crate) type TShare<T: Sharable> = Share<T::VerificationShare>;
#[allow(type_alias_bounds)]
pub(crate) type VecTShare<T: Sharable> = VecShare<T::VerificationShare>;
#[allow(type_alias_bounds)]
pub(crate) type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

#[derive(Clone, Debug, Default)]
struct Triples {
    a: Vec<Aby3Share<u128>>,
    b: Vec<Aby3Share<u128>>,
    c: Vec<Aby3Share<u128>>,
}

impl Triples {
    fn new(a: Vec<Aby3Share<u128>>, b: Vec<Aby3Share<u128>>, c: Vec<Aby3Share<u128>>) -> Self {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), c.len());
        Self { a, b, c }
    }
}

pub struct SpdzWise<N: NetworkTrait, U: Sharable> {
    aby3: Aby3<N>,
    mac_key: Aby3Share<U>,
    verifyqueue: VecShare<U>,  // For arithmetic
    send_queue_prev: BytesMut, // For binary
    rcv_queue_next: BytesMut,  // For binary
    prec_triples: Triples,
    triple_buffer: Triples,
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
            verifyqueue: VecShare::default(),
            send_queue_prev,
            rcv_queue_next,
            prec_triples: Triples::default(),
            triple_buffer: Triples::default(),
        }
    }

    pub fn get_r(&self) -> Aby3Share<U> {
        self.mac_key.to_owned()
    }

    #[cfg(test)]
    pub(crate) async fn aby_open(&mut self, share: Aby3Share<U>) -> Result<U, Error> {
        self.aby3.open(share).await
    }

    fn get_id(&self) -> usize {
        self.aby3.network.get_id()
    }

    async fn hash_based_zero_verify(&mut self, w: Aby3Share<U>) -> Result<(), Error> {
        let (wa, wb) = w.get_ab();
        let w_neg = -wa.to_owned() - &wb;

        let mut hasher = Sha512::new();
        match self.get_id() {
            0 => {
                wa.add_to_hash(&mut hasher);
                w_neg.add_to_hash(&mut hasher);
                wb.add_to_hash(&mut hasher);
            }
            1 => {
                wb.add_to_hash(&mut hasher);
                wa.add_to_hash(&mut hasher);
                w_neg.add_to_hash(&mut hasher);
            }
            2 => {
                w_neg.add_to_hash(&mut hasher);
                wb.add_to_hash(&mut hasher);
                wa.add_to_hash(&mut hasher);
            }
            _ => unreachable!(),
        };
        let digest = hasher.finalize();

        let hashes = self
            .aby3
            .network
            .broadcast(Bytes::from(digest.to_vec()))
            .await?;
        debug_assert_eq!(hashes.len(), 3);

        if hashes[0] != hashes[1] || hashes[0] != hashes[2] {
            Err(Error::VerifyError)
        } else {
            Ok(())
        }
    }

    async fn verify_macs(&mut self) -> Result<(), Error> {
        if self.verifyqueue.is_empty() {
            return Ok(());
        }

        let len = self.verifyqueue.len();
        let rands = (0..len)
            .map(|_| self.aby3.prf.gen_rand::<U>())
            .collect::<Vec<_>>();

        let mut swap = VecShare::default();
        std::mem::swap(&mut swap, &mut self.verifyqueue);

        let (values, macs) = swap.get();

        let res = <_ as MpcTrait<U, Aby3Share<U>, Aby3Share<Bit>>>::dot_many(
            &mut self.aby3,
            &[values, macs],
            &[rands.to_owned(), rands.to_owned()],
        )
        .await?;

        let r = self.get_r();
        let mul = <_ as MpcTrait<U, Aby3Share<U>, Aby3Share<Bit>>>::mul(
            &mut self.aby3,
            res[0].to_owned(),
            r,
        )
        .await?;
        let zero = mul - &res[1];
        self.hash_based_zero_verify(zero).await
    }

    #[inline(always)]
    async fn jmp_send<T: Sharable>(&mut self, send: T::Share) -> Result<(), Error> {
        utils::send_value_next(&mut self.aby3.network, send).await
    }

    #[inline(always)]
    fn jmp_buffer<T: Sharable>(&mut self, buffer: T::Share) {
        buffer.add_to_bytes(&mut self.send_queue_prev);
    }

    #[inline(always)]
    async fn jmp_send_many<T: Sharable>(&mut self, send: Vec<T::Share>) -> Result<(), Error> {
        utils::send_vec_next(&mut self.aby3.network, send).await
    }

    fn jmp_buffer_many<T: Sharable>(&mut self, buffer: Vec<T::Share>) {
        for value in buffer.into_iter() {
            value.add_to_bytes(&mut self.send_queue_prev);
        }
    }

    async fn jmp_receive<T: Sharable>(&mut self) -> Result<T::Share, Error> {
        let value: T::Share = utils::receive_value_prev(&mut self.aby3.network).await?;
        value.to_owned().add_to_bytes(&mut self.rcv_queue_next);
        Ok(value)
    }

    async fn jmp_receive_many<T: Sharable>(&mut self, len: usize) -> Result<Vec<T::Share>, Error> {
        let values: Vec<T::Share> = utils::receive_vec_prev(&mut self.aby3.network, len).await?;

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

        self.aby3
            .network
            .send_prev_id(Bytes::from(send_prev.to_vec()))
            .await?;

        let rcv_next = self.aby3.network.receive_next_id().await?;

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
        let (mut seed1, seed2) = self.aby3.prf.gen_rands::<R::Seed>();

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

    #[inline(always)]
    fn swap_bit(a: &mut [Aby3Share<u128>], i: usize, j: usize) {
        let i_ = i / 128;
        let i_mod = i % 128;
        let j_ = j / 128;
        let j_mod = j % 128;

        let aa_i = a[i_].a.get_bit(i_mod);
        let aa_j = a[j_].a.get_bit(j_mod);
        a[i_].a.set_bit(i_mod, aa_j);
        a[j_].a.set_bit(j_mod, aa_i);

        let ab_i = a[i_].b.get_bit(i_mod);
        let ab_j = a[j_].b.get_bit(j_mod);
        a[i_].b.set_bit(i_mod, ab_j);
        a[j_].b.set_bit(j_mod, ab_i);
    }

    async fn permute<R: Rng + SeedableRng>(
        &mut self,
        a: &mut [Aby3Share<u128>],
        b: &mut [Aby3Share<u128>],
        c: &mut [Aby3Share<u128>],
    ) -> Result<(), Error>
    where
        Standard: Distribution<R::Seed>,
        R::Seed: AsRef<[u8]>,
    {
        let len = a.len();
        let bitlen = len * 128;
        if len != b.len() || len != c.len() {
            return Err(Error::InvalidSizeError);
        }

        let seed = self.coin::<R>().await?;
        let mut rng = R::from_seed(seed);

        for j in 0..bitlen {
            let i = rng.gen_range(j..bitlen);

            Self::swap_bit(a, i, j);
            Self::swap_bit(b, i, j);
            Self::swap_bit(c, i, j);
        }

        Ok(())
    }

    async fn generate_triples<R: Rng + SeedableRng>(
        &mut self,
        num: usize, // number of u128 bit to produce
    ) -> Result<Triples, Error>
    where
        Standard: Distribution<R::Seed>,
        R::Seed: AsRef<[u8]>,
    {
        // https://www.ieee-security.org/TC/SP2017/papers/96.pdf
        // Assumes B=2 buckets (Secure when generating 2^20 triples)
        const N: usize = 8192; // # of 128 bit registers, corresponds to 2^20 AND GATES
                               // Here we have C=128 which is significantly more than required for security
        let n = std::cmp::max(num, N);
        let a = (0..2 * n + 1)
            .map(|_| self.aby3.prf.gen_rand::<u128>())
            .collect::<Vec<_>>();
        let b = (0..2 * n + 1)
            .map(|_| self.aby3.prf.gen_rand::<u128>())
            .collect::<Vec<_>>();

        let c = self
            .aby3_and_many::<u128>(a.to_owned(), b.to_owned())
            .await?;

        // Split to buckets
        let (a_triple, mut a_sacrifice) = a.split_at(n);
        let (b_triple, mut b_sacrifice) = b.split_at(n);
        let (c_triple, mut c_sacrifice) = c.split_at(n);

        // permute second bucket
        self.permute::<R>(&mut a_sacrifice, &mut b_sacrifice, &mut c_sacrifice)
            .await?;

        // Open 128 bit triples
        let a_open = a_sacrifice.pop().expect("Enough triples generated");
        let b_open = b_sacrifice.pop().expect("Enough triples generated");
        let c_open = c_sacrifice.pop().expect("Enough triples generated");

        let opened = self
            .aby3_open_bin_many::<u128>(vec![a_open, b_open, c_open])
            .await?;
        if opened[0].to_owned() & &opened[1] != opened[2] {
            return Err(Error::VerifyError);
        }

        // Check each element in first bucket using sacrifice bucket
        self.verify_triples(
            &a_triple,
            &b_triple,
            &c_triple,
            a_sacrifice,
            b_sacrifice,
            c_sacrifice,
        )
        .await?;

        Ok(Triples::new(a_triple, b_triple, c_triple))
    }

    async fn verify_triples(
        &mut self,
        a: &[Aby3Share<u128>],
        b: &[Aby3Share<u128>],
        c: &[Aby3Share<u128>],
        x: Vec<Aby3Share<u128>>,
        y: Vec<Aby3Share<u128>>,
        z: Vec<Aby3Share<u128>>,
    ) -> Result<(), Error> {
        let id = self.get_id();
        // hash based verification
        let mut hasher = Sha512::new();

        let n = a.len();
        debug_assert_eq!(n, b.len());
        debug_assert_eq!(n, c.len());
        debug_assert_eq!(n, x.len());
        debug_assert_eq!(n, y.len());
        debug_assert_eq!(n, z.len());

        let mut pq = Vec::with_capacity(2 * n);
        for (a_, x) in a.iter().zip(x) {
            pq.push(x ^ a_);
        }
        for (b_, y) in b.iter().zip(y) {
            pq.push(y ^ b_);
        }

        let pq_open = self.aby3_open_bin_many::<u128>(pq).await?;
        let p = &pq_open[..n];
        let q = &pq_open[n..];

        match id {
            0 => {
                for ((c, (a, b)), (z, (p, q))) in c
                    .iter()
                    .zip(a.iter().cloned().zip(b.iter().cloned()))
                    .zip(z.into_iter().zip(p.iter().zip(q.iter())))
                {
                    let mut w = z ^ c ^ (a & q) ^ (b & p);
                    w.a ^= p.to_owned() & q; // Party0

                    let (wa, wb) = w.get_ab();
                    let w_neg = wa.to_owned() ^ &wb;

                    wa.add_to_hash(&mut hasher);
                    w_neg.add_to_hash(&mut hasher);
                    wb.add_to_hash(&mut hasher);
                }
            }
            1 => {
                for ((c, (a, b)), (z, (p, q))) in c
                    .iter()
                    .zip(a.iter().cloned().zip(b.iter().cloned()))
                    .zip(z.into_iter().zip(p.iter().zip(q.iter())))
                {
                    let mut w = z ^ c ^ (a & q) ^ (b & p);
                    w.b ^= p.to_owned() & q; // Party1

                    let (wa, wb) = w.get_ab();
                    let w_neg = wa.to_owned() ^ &wb;

                    wb.add_to_hash(&mut hasher);
                    wa.add_to_hash(&mut hasher);
                    w_neg.add_to_hash(&mut hasher);
                }
            }
            2 => {
                for ((c, (a, b)), (z, (p, q))) in c
                    .iter()
                    .zip(a.iter().cloned().zip(b.iter().cloned()))
                    .zip(z.into_iter().zip(p.iter().zip(q.iter())))
                {
                    let w = z ^ c ^ (a & q) ^ (b & p);

                    let (wa, wb) = w.get_ab();
                    let w_neg = wa.to_owned() ^ &wb;

                    w_neg.add_to_hash(&mut hasher);
                    wb.add_to_hash(&mut hasher);
                    wa.add_to_hash(&mut hasher);
                }
            }
            _ => unreachable!(),
        }

        let digest = hasher.finalize();

        let hashes = self
            .aby3
            .network
            .broadcast(Bytes::from(digest.to_vec()))
            .await?;
        debug_assert_eq!(hashes.len(), 3);

        if hashes[0] != hashes[1] || hashes[0] != hashes[2] {
            return Err(Error::VerifyError);
        }

        Ok(())
    }

    async fn aby3_and<T: Sharable>(
        &mut self,
        a: Aby3Share<T>,
        b: Aby3Share<T>,
    ) -> Result<Aby3Share<T>, Error>
    where
        Standard: Distribution<T::Share>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
    {
        self.aby3.and(a, b).await
    }

    async fn aby3_and_many<T: Sharable>(
        &mut self,
        a: Vec<Aby3Share<T>>,
        b: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<T>>, Error>
    where
        Standard: Distribution<T::Share>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
    {
        self.aby3.and_many(a, b).await
    }

    async fn aby3_open_bin_many<T: Sharable>(
        &mut self,
        shares: Vec<Aby3Share<T>>,
    ) -> Result<Vec<T::Share>, Error>
    where
        Standard: Distribution<T::Share>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
    {
        let shares_b = shares.iter().map(|s| s.b.to_owned()).collect();
        let shares_c = utils::send_and_receive_vec(&mut self.aby3.network, shares_b).await?;
        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| c ^ &s.a ^ &s.b)
            .collect();
        Ok(res)
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

    async fn preprocess(&mut self) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::preprocess(&mut self.aby3)
        .await?;

        // TODO maybe modify here
        self.prec_triples = self.generate_triples::<ChaCha12Rng>(8192).await?;

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
    async fn open_mac_key(&mut self) -> Result<T::VerificationShare, Error> {
        let r = self.get_r();
        self.aby_open(r).await
    }

    async fn finish(self) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::finish(self.aby3)
        .await
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::print_connection_stats(&self.aby3, out)
    }

    async fn input(&mut self, input: Option<T>, id: usize) -> Result<TShare<T>, Error> {
        let input = input.map(|i| T::to_verificationshare(i));

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::input(&mut self.aby3, input, id)
        .await?;

        let r = self.get_r();
        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul(&mut self.aby3, value.to_owned(), r)
        .await?;

        let share = Share::new(value, mac);

        self.verifyqueue.push(share.to_owned());

        Ok(share)
    }

    #[cfg(test)]
    async fn input_all(&mut self, input: T) -> Result<Vec<TShare<T>>, Error> {
        // Since this is only for testing we perform a bad one
        let mut inputs = [None; 3];
        inputs[self.get_id()] = Some(input);
        let mut shares = Vec::with_capacity(3);

        for (i, inp) in inputs.into_iter().enumerate() {
            shares.push(self.input(inp.to_owned(), i).await?);
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

    async fn open(&mut self, share: TShare<T>) -> Result<T, Error> {
        self.verifyqueue.push(share.to_owned());
        self.verify_macs().await?;

        let result = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::open(&mut self.aby3, share.get_value())
        .await?;

        Ok(T::from_verificationshare(result))
    }

    async fn open_many(&mut self, shares: VecTShare<T>) -> Result<Vec<T>, Error> {
        self.verifyqueue.extend(shares.to_owned());
        self.verify_macs().await?;

        let result = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::open_many(&mut self.aby3, shares.get_values())
        .await?;

        let result = result
            .into_iter()
            .map(|r| T::from_verificationshare(r))
            .collect();

        Ok(result)
    }

    async fn open_bit(&mut self, share: Aby3Share<Bit>) -> Result<bool, Error> {
        self.jmp_verify().await?;

        let (a, b) = share.to_owned().get_ab();
        let c = self.jmp_send_receive::<Bit>(b, a).await?;

        self.jmp_verify().await?;
        Ok((share.a ^ share.b ^ c).convert().convert())
    }

    async fn open_bit_many(&mut self, shares: Vec<Aby3Share<Bit>>) -> Result<Vec<bool>, Error> {
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

    async fn mul(&mut self, a: TShare<T>, b: TShare<T>) -> Result<TShare<T>, Error> {
        let (a_v, a_m) = a.get();
        let b_v = b.get_value();

        let values = self
            .aby3
            .mul_many(vec![a_v, a_m], vec![b_v.to_owned(), b_v])
            .await?;

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

    async fn dot(&mut self, a: VecTShare<T>, b: VecTShare<T>) -> Result<TShare<T>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let (a_values, a_macs) = a.get();
        let b_values = b.get_values();

        let res = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::dot_many(
            &mut self.aby3,
            &[a_values, a_macs],
            &[b_values.to_owned(), b_values],
        )
        .await?;

        let result = Share::new(res[0].to_owned(), res[1].to_owned());

        // Add to verification queue
        self.verifyqueue.push(result.to_owned());
        Ok(result)
    }

    async fn dot_many(
        &mut self,
        a: &[VecTShare<T>],
        b: &[VecTShare<T>],
    ) -> Result<Vec<TShare<T>>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut shares_a = Vec::with_capacity(2 * len);
        let mut mac_shares_a = Vec::with_capacity(2 * len);

        for (a, b) in a.iter().cloned().zip(b.iter().cloned()) {
            let (a_v, a_m) = a.get();
            let b_v = b.get_values();

            if a_v.len() != b_v.len() {
                return Err(Error::InvalidSizeError);
            }

            let mut rand = self.aby3.prf.gen_zero_share::<T::VerificationShare>();
            let mut rand2 = self.aby3.prf.gen_zero_share::<T::VerificationShare>();

            for (a_, b_) in a_v.into_iter().zip(b_v.iter()) {
                rand += (a_ * b_).a;
            }
            shares_a.push(rand);

            for (a_, b_) in a_m.into_iter().zip(b_v.iter()) {
                rand2 += (a_ * b_).a;
            }
            mac_shares_a.push(rand2);
        }

        shares_a.extend(mac_shares_a);

        // Network: reshare
        let shares_b =
            utils::send_and_receive_vec(&mut self.aby3.network, shares_a.to_owned()).await?;

        let mac_a = shares_a[len..].to_vec();
        let mac_b = shares_b[len..].to_vec();

        let res = shares_a
            .into_iter()
            .zip(mac_a)
            .zip(shares_b.into_iter().zip(mac_b))
            .map(|((a_val, a_mac), (b_val, b_mac))| {
                let share = Aby3Share::new(a_val, b_val);
                let mac = Aby3Share::new(a_mac, b_mac);
                Share::new(share, mac)
            })
            .collect::<Vec<_>>();

        // Add to verification queue
        self.verifyqueue.reserve(len);
        for r in res.iter().cloned() {
            self.verifyqueue.push(r);
        }

        Ok(res)
    }

    async fn masked_dot_many(
        &mut self,
        a: &VecTShare<T>,
        b: &[VecTShare<T>],
        masks: &[IrisCodeArray],
    ) -> Result<Vec<TShare<T>>, Error> {
        let len = b.len();
        if a.len() != IrisCodeArray::IRIS_CODE_SIZE {
            return Err(Error::InvalidSizeError);
        }

        let mut shares_a = Vec::with_capacity(2 * len);
        let mut mac_shares_a = Vec::with_capacity(2 * len);

        for (b, mask) in b.iter().zip(masks.iter()) {
            let mut rand = self.aby3.prf.gen_zero_share::<T::VerificationShare>();
            let mut rand2 = self.aby3.prf.gen_zero_share::<T::VerificationShare>();

            for (bit, ((a_, b_), am)) in mask
                .bits()
                .zip(a.values.iter().zip(b.values.iter()).zip(a.macs.iter()))
            {
                // only aggregate if mask is set
                if bit {
                    rand += (a_.clone() * b_).a;
                    rand2 += (am.clone() * b_).a;
                    // TODO: check if we can allow ref * ref ops in RingImpl
                }
            }
            shares_a.push(rand);
            mac_shares_a.push(rand2);
        }

        shares_a.extend(mac_shares_a);

        // Network: reshare
        let shares_b =
            utils::send_and_receive_vec(&mut self.aby3.network, shares_a.to_owned()).await?;

        let mac_a = shares_a[len..].to_vec();
        let mac_b = shares_b[len..].to_vec();

        let res = shares_a
            .into_iter()
            .zip(mac_a)
            .zip(shares_b.into_iter().zip(mac_b))
            .map(|((a_val, a_mac), (b_val, b_mac))| {
                let share = Aby3Share::new(a_val, b_val);
                let mac = Aby3Share::new(a_mac, b_mac);
                Share::new(share, mac)
            })
            .collect::<Vec<_>>();

        // Add to verification queue
        self.verifyqueue.reserve(len);
        for r in res.iter().cloned() {
            self.verifyqueue.push(r);
        }

        Ok(res)
    }

    async fn get_msb(&mut self, a: TShare<T>) -> Result<Aby3Share<Bit>, Error> {
        self.verifyqueue.push(a.to_owned());
        self.verify_macs().await?;

        // protocol switch
        let value = Aby3Share::<T>::from_verificationtype(a.get_value());
        let bits = self.arithmetic_to_binary(value).await?;
        Ok(bits.get_msb())
    }

    async fn get_msb_many(&mut self, a: Vec<TShare<T>>) -> Result<Vec<Aby3Share<Bit>>, Error> {
        self.verifyqueue.reserve(a.len());
        for a_ in a.iter().cloned() {
            self.verifyqueue.push(a_);
        }
        self.verify_macs().await?;

        // protocol switch
        let values = a
            .into_iter()
            .map(|a| Aby3Share::<T>::from_verificationtype(a.get_value()))
            .collect();

        let bits = self.arithmetic_to_binary_many(values).await?;
        let res = bits.into_iter().map(|a| a.get_msb()).collect();
        Ok(res)
    }

    async fn binary_or(
        &mut self,
        a: Aby3Share<Bit>,
        b: Aby3Share<Bit>,
    ) -> Result<Aby3Share<Bit>, Error> {
        <Self as BinaryMpcTrait<Bit, Aby3Share<Bit>>>::or(self, a, b).await
    }

    async fn reduce_binary_or(
        &mut self,
        a: Vec<Aby3Share<Bit>>,
        chunk_size: usize,
    ) -> Result<Aby3Share<Bit>, Error> {
        let chunk_size = chunk_size * 128;
        utils::or_tree::<Bit, _, _>(self, a, chunk_size).await
    }

    async fn verify(&mut self) -> Result<(), Error> {
        self.verify_macs().await
    }
}

impl<N: NetworkTrait, T: Sharable, U: Sharable> BinaryMpcTrait<T, Aby3Share<T>> for SpdzWise<N, U>
where
    Standard: Distribution<U::Share>,
    Aby3Share<U>: Mul<U::Share, Output = Aby3Share<U>>,
{
    async fn and(&mut self, a: Aby3Share<T>, b: Aby3Share<T>) -> Result<Aby3Share<T>, Error> {
        todo!()
    }

    async fn and_many(
        &mut self,
        a: Vec<Aby3Share<T>>,
        b: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<T>>, Error> {
        todo!()
    }

    async fn arithmetic_to_binary(&mut self, x: Aby3Share<T>) -> Result<Aby3Share<T>, Error> {
        let (x1, x2, x3) = self.aby3.a2b_pre(x);
        self.binary_add_3(x1, x2, x3).await
    }

    async fn arithmetic_to_binary_many(
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
        self.binary_add_3_many(x1, x2, x3).await
    }
}
