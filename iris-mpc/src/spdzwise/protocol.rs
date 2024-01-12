use super::{share::Share, triples::Triples, vecshare::VecShare};
use crate::{
    aby3::utils,
    prelude::{Aby3, Aby3Share, Bit, Error, MpcTrait, NetworkTrait, Sharable},
    traits::{binary_trait::BinaryMpcTrait, security::MaliciousAbort, share_trait::VecShareTrait},
    types::ring_element::{RingElement, RingImpl},
};
use bytes::{Bytes, BytesMut};
use itertools::Itertools;
use num_traits::Zero;
use plain_reference::IrisCodeArray;
use rand::{
    distributions::{Distribution, Standard},
    Rng, SeedableRng,
};
use rand_chacha::ChaCha12Rng;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use sha2::{digest::Output, Digest, Sha512};
use std::ops::Mul;

#[allow(type_alias_bounds)]
pub(crate) type TShare<T: Sharable> = Share<T::VerificationShare>;
#[allow(type_alias_bounds)]
pub(crate) type VecTShare<T: Sharable> = VecShare<T::VerificationShare>;
#[allow(type_alias_bounds)]
pub(crate) type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

pub struct SpdzWise<N: NetworkTrait, U: Sharable> {
    aby3: Aby3<N>,
    mac_key: Aby3Share<U>,
    verifyqueue: VecShare<U>,  // For arithmetic
    send_queue_prev: BytesMut, // For binary
    rcv_queue_next: BytesMut,  // For binary
    prec_triples: Triples,
    triple_buffer: Triples,
}

impl<N: NetworkTrait, U: Sharable> MaliciousAbort for SpdzWise<N, U> {}

macro_rules! reduce_or {
    ($([$typ_a:ident, $typ_b:ident,$name_a:ident,$name_b:ident]),*) => {
        $(
            async fn $name_a(&mut self, a: Aby3Share<$typ_a>) -> Result<Aby3Share<Bit>, Error> {
                let (a, b) = a.get_ab();
                let (a1, a2) = utils::split::<$typ_a, $typ_b>(a);
                let (b1, b2) = utils::split::<$typ_a, $typ_b>(b);

                let share_a = Aby3Share::new(a1, b1);
                let share_b = Aby3Share::new(a2, b2);

                let out = <Self as BinaryMpcTrait<$typ_b, Aby3Share<$typ_b>>>::or(self, share_a, share_b).await?;
                self.$name_b(out).await
            }
        )*
    };
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
    async fn jmp_send_many<T: Sharable>(&mut self, send: &[T::Share]) -> Result<(), Error> {
        utils::send_vec_next(&mut self.aby3.network, send).await
    }

    fn jmp_buffer_many<T: Sharable>(&mut self, buffer: &[T::Share]) {
        for value in buffer {
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

        for value in values.iter() {
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
        send: &[T::Share],
        buffer: &[T::Share],
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
                RingElement::convert_slice_rev(seed2.as_ref()),
                RingElement::convert_slice_rev(seed1.as_ref()),
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
        const N: usize = 1usize << (20 - 7); // # of 128 bit registers, corresponds to 2^20 AND GATES
                                             // Here we have C=128 which is significantly more than required for security
        let n = std::cmp::max(num, N);
        let a = (0..2 * n + 1)
            .map(|_| self.aby3.prf.gen_rand::<u128>())
            .collect::<Vec<_>>();
        let b = (0..2 * n + 1)
            .map(|_| self.aby3.prf.gen_rand::<u128>())
            .collect::<Vec<_>>();

        let c = self.aby3_and_many::<u128>(&a, &b).await?;

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

        let pq_open = self.aby3_jmp_open_bin_many::<u128>(pq).await?;
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

    async fn verify_triple_queue<R: Rng + SeedableRng>(&mut self) -> Result<(), Error>
    where
        Standard: Distribution<R::Seed>,
        R::Seed: AsRef<[u8]>,
    {
        // We consume precomputed triples always as multiples of 128 bit
        let len = self.triple_buffer.len();
        if len == 0 {
            return Ok(());
        }
        let (a, b, c) = self.triple_buffer.get_all();
        let len_ = std::cmp::max(len, 1usize << (20 - 7)); // Permute at least 2^(20) triples, as required for security
        let (mut x, mut y, mut z) = self.prec_triples.get(len_)?;

        // Permute the precomputed triples again
        self.permute::<R>(&mut x, &mut y, &mut z).await?;

        if len_ > len {
            x.truncate(len);
            y.truncate(len);
            z.truncate(len);
        }

        // Finally verify
        self.verify_triples(&a, &b, &c, x, y, z).await?;

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

    // we need this since the method below takes a ref to vec
    #[allow(clippy::ptr_arg)]
    async fn aby3_and_many<T: Sharable>(
        &mut self,
        a: &Vec<Aby3Share<T>>,
        b: &Vec<Aby3Share<T>>,
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
        let shares_b = shares.iter().map(|s| &s.b);
        let shares_c = utils::send_iter_and_receive_iter(&mut self.aby3.network, shares_b).await?;
        let res = shares
            .iter()
            .zip(shares_c)
            .map(|(s, c)| c ^ &s.a ^ &s.b)
            .collect();
        Ok(res)
    }

    async fn aby3_jmp_open_bin_many<T: Sharable>(
        &mut self,
        shares: Vec<Aby3Share<T>>,
    ) -> Result<Vec<T::Share>, Error>
    where
        Standard: Distribution<T::Share>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
    {
        // self.jmp_verify().await?; // Not necessary how we use it now

        let len = shares.len();
        let mut shares_a = Vec::with_capacity(len);
        let mut shares_b = Vec::with_capacity(len);

        for share in shares.iter().cloned() {
            let (a, b) = share.get_ab();
            shares_a.push(a);
            shares_b.push(b);
        }

        let shares_c = self
            .jmp_send_receive_many::<T>(&shares_b, &shares_a)
            .await?;
        self.jmp_verify().await?;

        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| (c ^ &s.a ^ &s.b))
            .collect();
        Ok(res)
    }

    fn pack<T: Sharable>(&self, a: Vec<Aby3Share<Bit>>) -> Vec<Aby3Share<T>> {
        let outlen = (a.len() + T::Share::K - 1) / T::Share::K;
        let mut out = Vec::with_capacity(outlen);

        for a_ in a.chunks(T::Share::K) {
            let mut share_a = T::Share::zero();
            let mut share_b = T::Share::zero();
            for (i, bit) in a_.iter().enumerate() {
                let (bit_a, bit_b) = bit.to_owned().get_ab();
                share_a |= T::Share::from(bit_a.convert().convert()) << (i as u32);
                share_b |= T::Share::from(bit_b.convert().convert()) << (i as u32);
            }
            let share = Aby3Share::new(share_a, share_b);
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

    async fn reduce_or_u8(&mut self, a: Aby3Share<u8>) -> Result<Aby3Share<Bit>, Error> {
        const K: usize = 8;

        let mut decomp: Vec<Aby3Share<Bit>> = Vec::with_capacity(K);
        for i in 0..K as u32 {
            let bit_a = ((a.a.to_owned() >> i) & RingElement(1)) == RingElement(1);
            let bit_b = ((a.b.to_owned() >> i) & RingElement(1)) == RingElement(1);

            decomp.push(Aby3Share::new(
                <Bit as Sharable>::Share::from(bit_a),
                <Bit as Sharable>::Share::from(bit_b),
            ));
        }

        let mut k = K;
        while k != 1 {
            k >>= 1;
            decomp = <Self as BinaryMpcTrait<Bit, Aby3Share<Bit>>>::or_many(
                self,
                decomp[..k].to_vec(),
                decomp[k..].to_vec(),
            )
            .await?;
        }

        Ok(decomp[0].to_owned())
    }

    async fn transposed_pack_and(
        &mut self,
        x1: Vec<Vec<Aby3Share<u128>>>,
        x2: Vec<Vec<Aby3Share<u128>>>,
    ) -> Result<Vec<Vec<Aby3Share<u128>>>, Error> {
        let len = x1.len();
        debug_assert_eq!(len, x2.len());
        let inner_len = x1[0].len();

        let x3 = <Self as BinaryMpcTrait<u128, Aby3Share<u128>>>::and_many(
            self,
            &x1.into_iter().flatten().collect_vec(),
            &x2.into_iter().flatten().collect_vec(),
        )
        .await?;

        Ok(x3.chunks(inner_len))
    }

    async fn msb_adder_many<T: Sharable>(
        &mut self,
        x1: Vec<Aby3Share<T>>,
        x2: Vec<Aby3Share<T>>,
        x3: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<Bit>>, Error> {
        let len = x1.len();
        if len != x2.len() || len != x3.len() {
            return Err(Error::InvalidSizeError);
        }

        let x1 = utils::transpose_pack_u128::<T>(x1);
        let x2 = utils::transpose_pack_u128::<T>(x2);
        let mut x3 = utils::transpose_pack_u128::<T>(x3);

        // Full adder to get 2 * c and s
        let mut x2x3 = utils::transposed_pack_xor(&x2, &x3);
        let s = utils::transposed_pack_xor(&x1, &x2x3);
        let mut x1x3 = utils::transposed_pack_xor(&x1, &x3);
        // 2 * c
        x1x3.pop().expect("Enough elements present");
        x2x3.pop().expect("Enough elements present");
        x3.pop().expect("Enough elements present");
        let mut c = self.transposed_pack_and(x1x3, x2x3).await?;
        utils::transposed_pack_xor_assign(&mut c, &x3);

        // Add 2c + s via a ripple carry adder
        // LSB of c is 0
        // First round: half adder can be skipped due to LSB of c being 0
        let mut a = s;
        let mut b = c;

        // First full adder
        let mut c =
            <Self as BinaryMpcTrait<u128, Aby3Share<u128>>>::and_many(self, &a[1], &b[0]).await?;

        // For last round
        let a_msb = a.pop().expect("Enough elements present");
        let b_msb = b.pop().expect("Enough elements present");

        // 2 -> k-1
        for (a_, b_) in a.into_iter().skip(2).zip(b.into_iter().skip(1)) {
            let tmp_a =
                <Self as BinaryMpcTrait<u128, Aby3Share<u128>>>::xor_many(a_, c.to_owned())?;
            let tmp_b =
                <Self as BinaryMpcTrait<u128, Aby3Share<u128>>>::xor_many(b_, c.to_owned())?;
            let tmp_c =
                <Self as BinaryMpcTrait<u128, Aby3Share<u128>>>::and_many(self, &tmp_a, &tmp_b)
                    .await?;
            c = <Self as BinaryMpcTrait<u128, Aby3Share<u128>>>::xor_many(tmp_c, c)?;
        }

        let res = <Self as BinaryMpcTrait<u128, Aby3Share<u128>>>::xor_many(a_msb, b_msb)?;
        let res: Vec<Aby3Share<u128>> =
            <Self as BinaryMpcTrait<u128, Aby3Share<u128>>>::xor_many(res, c)?;

        // Extract bits for outputs
        let mut res = res
            .into_iter()
            .flat_map(|t| t.to_bits())
            .collect::<Vec<_>>();
        res.resize(len, Aby3Share::default());

        Ok(res)
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, TShare<T>, Aby3Share<Bit>>
    for SpdzWise<N, T::VerificationShare>
where
    Standard: Distribution<UShare<T>>,
    Standard: Distribution<T::Share>,
    Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
    Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
    Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
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

        Ok(())
    }

    async fn precompute_and_triples(&mut self, amount: usize) -> Result<(), Error> {
        let ands = self.prec_triples.len();
        let amount = (amount + 127) / 128; // We allow precomputing as multiples of 128 bit
        if ands <= amount {
            // We have to precompute AND gates
            let prec_triples = self.generate_triples::<ChaCha12Rng>(amount - ands).await?;
            self.prec_triples.extend(prec_triples);
        }
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
            .jmp_send_receive_many::<Bit>(&shares_b, &shares_a)
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

        // Network: reshare
        let (shares_b, mac_shares_b) =
            utils::send_slices_and_receive_iters(&mut self.aby3.network, &shares_a, &mac_shares_a)
                .await?;

        let res = shares_a
            .into_iter()
            .zip(mac_shares_a.into_iter())
            .zip(shares_b.zip(mac_shares_b))
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

        let rands = (0..b.len())
            .map(|_| self.aby3.prf.gen_zero_share::<T::VerificationShare>())
            .collect::<Vec<_>>();
        let rands2 = (0..b.len())
            .map(|_| self.aby3.prf.gen_zero_share::<T::VerificationShare>())
            .collect::<Vec<_>>();
        let mut shares_a = Vec::with_capacity(a.len());
        let mut mac_shares_a = Vec::with_capacity(len);

        rands
            .into_par_iter()
            .zip(b.par_iter())
            .zip(masks.par_iter())
            .map(|((mut rand, b_), mask_)| {
                for (bit, (a_, b__)) in mask_.bits().zip(a.values.iter().zip(b_.values.iter())) {
                    // only aggregate if mask is set
                    if bit {
                        rand += (a_.clone() * b__).a;
                    }
                }
                rand
            })
            .collect_into_vec(&mut shares_a);
        rands2
            .into_par_iter()
            .zip(b.par_iter())
            .zip(masks.par_iter())
            .map(|((mut rand, b_), mask_)| {
                for (bit, (a_, b__)) in mask_.bits().zip(a.macs.iter().zip(b_.values.iter())) {
                    // only aggregate if mask is set
                    if bit {
                        rand += (a_.clone() * b__).a;
                    }
                }
                rand
            })
            .collect_into_vec(&mut mac_shares_a);

        // Network: reshare
        let (shares_b, mac_shares_b) =
            utils::send_slices_and_receive_iters(&mut self.aby3.network, &shares_a, &mac_shares_a)
                .await?;

        let res = shares_a
            .into_iter()
            .zip(mac_shares_a.into_iter())
            .zip(shares_b.zip(mac_shares_b))
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
            .collect::<Vec<_>>();

        // TODO one can switch adder here

        // let bits = self.arithmetic_to_binary_many(values).await?;
        // let res = bits.into_iter().map(|a| a.get_msb()).collect();
        // Ok(res)

        let len = values.len();
        let mut x1 = Vec::with_capacity(len);
        let mut x2 = Vec::with_capacity(len);
        let mut x3 = Vec::with_capacity(len);

        for x_ in values {
            let (x1_, x2_, x3_) = self.aby3.a2b_pre(x_);
            x1.push(x1_);
            x2.push(x2_);
            x3.push(x3_);
        }

        self.msb_adder_many(x1, x2, x3).await
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
        let packed = self.pack(a);
        let reduced = utils::or_tree::<u128, _, _>(self, packed, chunk_size).await?;
        self.reduce_or_u128(reduced).await
    }

    async fn verify(&mut self) -> Result<(), Error> {
        self.verify_macs().await?;
        self.verify_triple_queue::<ChaCha12Rng>().await
    }
}

impl<N: NetworkTrait, T: Sharable, U: Sharable> BinaryMpcTrait<T, Aby3Share<T>> for SpdzWise<N, U>
where
    Standard: Distribution<U::Share>,
    Standard: Distribution<T::Share>,
    Aby3Share<U>: Mul<U::Share, Output = Aby3Share<U>>,
    Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
{
    async fn and(&mut self, a: Aby3Share<T>, b: Aby3Share<T>) -> Result<Aby3Share<T>, Error> {
        let c = self.aby3_and::<T>(a.to_owned(), b.to_owned()).await?;

        self.triple_buffer.add_t(&a, &b, &c);

        Ok(c)
    }

    async fn and_many(
        &mut self,
        a: &Vec<Aby3Share<T>>,
        b: &Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<T>>, Error> {
        let c = self.aby3_and_many::<T>(a, b).await?;

        self.triple_buffer.add_many_t(a, b, &c);

        Ok(c)
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
