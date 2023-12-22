use super::share::Share;
use crate::{
    prelude::{Aby3, Aby3Share, Bit, Error, MpcTrait, NetworkTrait, Sharable},
    traits::binary_trait::BinaryMpcTrait,
    types::ring_element::RingImpl,
};
use bytes::Bytes;
use rand::distributions::{Distribution, Standard};
use sha2::{Digest, Sha512};
use std::ops::{BitAnd, Mul};

#[allow(type_alias_bounds)]
pub(crate) type TShare<T: Sharable> = Share<T::VerificationShare>;
#[allow(type_alias_bounds)]
pub(crate) type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

pub struct SpdzWise<N: NetworkTrait, U: Sharable> {
    aby3: Aby3<N>,
    mac_key: Aby3Share<U>,
    verifyqueue: Vec<Share<U>>,
}

impl<N: NetworkTrait, U: Sharable> SpdzWise<N, U>
where
    Standard: Distribution<U::Share>,
    Aby3Share<U>: Mul<U::Share, Output = Aby3Share<U>>,
{
    pub fn new(network: N) -> Self {
        let aby3 = Aby3::new(network);
        Self {
            aby3,
            mac_key: Aby3Share::default(),
            verifyqueue: Vec::new(),
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

    async fn hash_based_zero_verifiy(&mut self, w: Aby3Share<U>) -> Result<(), Error> {
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
            vec![values, macs],
            vec![rands.to_owned(), rands.to_owned()],
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
        self.hash_based_zero_verifiy(zero).await
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
        let result = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::open(&mut self.aby3, share.get_value())
        .await?;

        Ok(T::from_verificationshare(result))
    }

    async fn open_many(&mut self, shares: Vec<TShare<T>>) -> Result<Vec<T>, Error> {
        let values = shares.into_iter().map(|s| s.get_value()).collect();

        let result = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::open_many(&mut self.aby3, values)
        .await?;

        let result = result
            .into_iter()
            .map(|r| T::from_verificationshare(r))
            .collect();

        Ok(result)
    }

    async fn open_bit(&mut self, share: Aby3Share<Bit>) -> Result<bool, Error> {
        todo!()
        // let result = <_ as MpcTrait<Aby3Share<Bit>Type, Aby3Share<Aby3Share<Bit>Type>, Aby3Share<Bit>>>::open(
        //     &mut self.aby3,
        //     share.get_value(),
        // )
        // .await?;

        // Ok(Bit::from_verificationshare(result).convert())
    }

    async fn open_bit_many(&mut self, shares: Vec<Aby3Share<Bit>>) -> Result<Vec<bool>, Error> {
        todo!()
        // let values = shares.into_iter().map(|s| s.get_value()).collect();

        // let result =
        //     <_ as MpcTrait<Aby3Share<Bit>Type, Aby3Share<Aby3Share<Bit>Type>, Aby3Share<Bit>>>::open_many(
        //         &mut self.aby3,
        //         values,
        //     )
        //     .await?;

        // let result = result
        //     .into_iter()
        //     .map(|r| Bit::from_verificationshare(r).convert())
        //     .collect();

        // Ok(result)
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

        // We make 2 muls because this mul is not part of the iris protocol and aby has no mul_many

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul(&mut self.aby3, a_v, b_v.to_owned())
        .await?;

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul(&mut self.aby3, a_m, b_v)
        .await?;

        let result = Share::new(value, mac);

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

    async fn dot(&mut self, a: Vec<TShare<T>>, b: Vec<TShare<T>>) -> Result<TShare<T>, Error> {
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
            vec![a_values, a_macs],
            vec![b_values.to_owned(), b_values],
        )
        .await?;

        let result = Share::new(res[0].to_owned(), res[1].to_owned());

        self.verifyqueue.push(result.to_owned());
        Ok(result)
    }

    async fn dot_many(
        &mut self,
        a: Vec<Vec<TShare<T>>>,
        b: Vec<Vec<TShare<T>>>,
    ) -> Result<Vec<TShare<T>>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut a_values = Vec::with_capacity(len);
        let mut a_macs = Vec::with_capacity(len);
        let mut b_values = Vec::with_capacity(len);

        for (a, b) in a.into_iter().zip(b.into_iter()) {
            let mut a_v = Vec::with_capacity(len);
            let mut a_m = Vec::with_capacity(len);
            let mut b_v = Vec::with_capacity(len);
            for (a, b) in a.into_iter().zip(b.into_iter()) {
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
        >>::dot_many(&mut self.aby3, a_values, b_values.to_owned())
        .await?;

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

    async fn get_msb(&mut self, a: TShare<T>) -> Result<Aby3Share<Bit>, Error> {
        self.verify_macs().await?;

        // protocol switch
        let value = Aby3Share::<T>::from_verificationtype(a.get_value());
        let bits = self.arithmetic_to_binary(value).await?;
        Ok(bits.get_msb())
    }

    async fn get_msb_many(&mut self, a: Vec<TShare<T>>) -> Result<Vec<Aby3Share<Bit>>, Error> {
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
        todo!()
    }

    async fn reduce_binary_or(&mut self, a: Vec<Aby3Share<Bit>>) -> Result<Aby3Share<Bit>, Error> {
        todo!()
    }

    async fn verify(&mut self) -> Result<(), Error> {
        self.verify_macs().await
    }
}

impl<N: NetworkTrait, T: Sharable, U: Sharable> BinaryMpcTrait<T, Aby3Share<T>> for SpdzWise<N, U>
where
    Standard: Distribution<T::Share>,
    // Share<T>: BitAnd<T::Share, Output = Share<T>>,
    // Share<T>: BitAnd<Share<T>, Output = Share<T>>,
{
    async fn and(&mut self, a: Aby3Share<T>, b: Aby3Share<T>) -> Result<Aby3Share<T>, Error> {
        todo!()
        // let len = T::Share::K;
        // let (x, y, z) = self.get_mul_triple_many::<Bit, ChaCha12Rng>(len).await?;

        // let x = self.pack_exact::<T>(x);
        // let y = self.pack_exact::<T>(y);
        // let z = self.pack_exact::<T>(z);

        // let u = a.to_owned() ^ &x;
        // let v = b.to_owned() ^ &y;

        // let uv = self.reconstruct_binary_many(vec![u, v]).await?;
        // let u = uv[0].to_sharetype();
        // let v = uv[1].to_sharetype();
        // let uv = u.to_owned() & &v;

        // let mut c = z ^ (b & u) ^ (a & v);
        // c.xor_assign_const(
        //     &uv,
        //     PartyID::try_from(self.network.get_id() as u8).expect("ID is in range"),
        // );

        // Ok(c)
    }

    async fn and_many(
        &mut self,
        a: Vec<Aby3Share<T>>,
        b: Vec<Aby3Share<T>>,
    ) -> Result<Vec<Aby3Share<T>>, Error> {
        todo!()
        // let len = a.len();
        // if len != b.len() {
        //     return Err(Error::InvalidSizeError);
        // }

        // let triple_len = T::Share::K * len;
        // let (x, y, z) = self
        //     .get_mul_triple_many::<Bit, ChaCha12Rng>(triple_len)
        //     .await?;
        // let x = self.pack::<T>(x);
        // let y = self.pack::<T>(y);
        // let z = self.pack::<T>(z);

        // let mut uv_ = Vec::with_capacity(2 * len);
        // for (a_, x_) in a.iter().cloned().zip(x.iter()) {
        //     uv_.push(a_ ^ x_);
        // }
        // for (b_, y_) in b.iter().cloned().zip(y.iter()) {
        //     uv_.push(b_ ^ y_);
        // }

        // let uv = self.reconstruct_binary_many(uv_).await?;

        // let mut res = Vec::with_capacity(len);

        // for (z, ((a, b), (u, v))) in z.into_iter().zip(
        //     a.into_iter()
        //         .zip(b.into_iter())
        //         .zip(uv.iter().take(len).zip(uv.iter().skip(len))),
        // ) {
        //     let u = u.to_sharetype();
        //     let v = v.to_sharetype();
        //     let uv = u.to_owned() & &v;

        //     let mut c = z ^ (b & u) ^ (a & v);
        //     c.xor_assign_const(
        //         &uv,
        //         PartyID::try_from(self.network.get_id() as u8).expect("ID is in range"),
        //     );
        //     res.push(c);
        // }

        // Ok(res)
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
