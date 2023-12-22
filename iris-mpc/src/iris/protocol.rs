use crate::aby3::utils::ceil_log2;
use crate::prelude::{Aby3Share, Error, MpcTrait, Sharable, SpzWiseShare, Swift3Share};
use crate::types::bit::Bit;
use crate::types::ring_element::RingImpl;
use num_traits::Zero;
use plain_reference::{IrisCode, IrisCodeArray};
use std::{marker::PhantomData, usize};

const IRIS_CODE_SIZE: usize = plain_reference::IrisCode::IRIS_CODE_SIZE;
const MASK_THRESHOLD: usize = plain_reference::MASK_THRESHOLD;
const MATCH_THRESHOLD_RATIO: f64 = plain_reference::MATCH_THRESHOLD_RATIO;
const PACK_SIZE: usize = 256; // TODO adjust

pub type IrisAby3<T, Mpc> = IrisProtocol<T, Aby3Share<T>, Aby3Share<Bit>, Mpc>;
pub type IrisSwift3<T, Mpc> = IrisProtocol<T, Swift3Share<T>, Swift3Share<Bit>, Mpc>;
#[allow(type_alias_bounds)]
pub type IrisSpdzWise<T: Sharable, Mpc> =
    IrisProtocol<T, SpzWiseShare<T::VerificationShare>, Aby3Share<Bit>, Mpc>;

pub struct IrisProtocol<T: Sharable, Ashare, Bshare, Mpc: MpcTrait<T, Ashare, Bshare>> {
    mpc: Mpc,
    phantom_t: PhantomData<T>,
    phantom_a: PhantomData<Ashare>,
    phantom_b: PhantomData<Bshare>,
}

impl<T: Sharable, Ashare: Clone, Bshare, Mpc: MpcTrait<T, Ashare, Bshare>>
    IrisProtocol<T, Ashare, Bshare, Mpc>
where
    Ashare: Zero,
    <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
{
    pub fn new(mpc: Mpc) -> Result<Self, Error> {
        if MATCH_THRESHOLD_RATIO >= 1.
            || MATCH_THRESHOLD_RATIO <= 0.
            || T::Share::K <= ceil_log2(IRIS_CODE_SIZE)
        // Comparison by checking msb of difference could produce an overflow
        {
            return Err(Error::ConfigError);
        }

        Ok(IrisProtocol {
            mpc,
            phantom_t: PhantomData,
            phantom_a: PhantomData,
            phantom_b: PhantomData,
        })
    }

    pub fn get_id(&self) -> usize {
        self.mpc.get_id()
    }

    pub fn get_mpc_ref(&self) -> &Mpc {
        &self.mpc
    }

    pub fn get_mpc_mut(&mut self) -> &mut Mpc {
        &mut self.mpc
    }

    pub fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        self.mpc.print_connection_stats(out)
    }

    pub async fn preprocessing(&mut self) -> Result<(), Error> {
        self.mpc.preprocess().await
    }

    pub fn set_mac_key(&mut self, key: Ashare) {
        self.mpc.set_mac_key(key);
    }

    pub fn set_new_mac_key(&mut self) {
        self.mpc.set_new_mac_key();
    }

    #[cfg(test)]
    pub async fn open_mac_key(&mut self) -> Result<T::VerificationShare, Error> {
        self.mpc.open_mac_key().await
    }

    pub async fn finish(self) -> Result<(), Error> {
        self.mpc.finish().await
    }

    #[cfg(test)]
    pub async fn verify(&mut self) -> Result<(), Error> {
        self.mpc.verify().await
    }

    pub(crate) fn combine_masks(
        &self,
        mask_a: &IrisCodeArray,
        mask_b: &IrisCodeArray,
    ) -> Result<IrisCodeArray, Error> {
        let combined_mask = *mask_a & *mask_b;
        let combined_mask_len = combined_mask.count_ones();
        // TODO: is this check needed?
        if combined_mask_len < MASK_THRESHOLD {
            return Err(Error::MaskHWError);
        }
        Ok(combined_mask)
    }

    pub(crate) fn apply_mask(
        &self,
        mut code: Vec<Ashare>,
        mask: &IrisCodeArray,
    ) -> Result<Vec<Ashare>, Error> {
        if code.len() != IRIS_CODE_SIZE {
            return Err(Error::InvalidCodeSizeError);
        }

        for (i, c) in code.iter_mut().enumerate() {
            if !mask.get_bit(i) {
                *c = Ashare::zero();
            }
        }
        Ok(code)
    }

    pub(crate) fn apply_mask_twice(
        &self,
        mut code1: Vec<Ashare>,
        mut code2: Vec<Ashare>,
        mask: &IrisCodeArray,
    ) -> Result<(Vec<Ashare>, Vec<Ashare>), Error> {
        if code1.len() != IRIS_CODE_SIZE || code2.len() != IRIS_CODE_SIZE {
            return Err(Error::InvalidCodeSizeError);
        }

        for i in 0..IRIS_CODE_SIZE {
            if !mask.get_bit(i) {
                code1[i] = Ashare::zero();
                code2[i] = Ashare::zero();
            }
        }
        Ok((code1, code2))
    }

    fn hamming_distance_post(
        &self,
        a: Vec<Ashare>,
        b: Vec<Ashare>,
        dot: Ashare,
    ) -> Result<Ashare, Error> {
        if a.is_empty() || a.len() != b.len() {
            return Err(Error::InvalidCodeSizeError);
        }

        let sum_a = a
            .into_iter()
            .reduce(|a_, b_| self.mpc.add(a_, b_))
            .expect("Size is not zero");
        let sum_b = b
            .into_iter()
            .reduce(|a_, b_| self.mpc.add(a_, b_))
            .expect("Size is not zero");

        let dot = self.mpc.mul_const(dot, T::try_from(2).unwrap());

        let sum = self.mpc.add(sum_a, sum_b);
        let res = self.mpc.sub(sum, dot);
        Ok(res)
    }

    #[allow(unused)]
    pub(crate) async fn hamming_distance(
        &mut self,
        a: Vec<Ashare>,
        b: Vec<Ashare>,
    ) -> Result<Ashare, Error> {
        let dot = self.mpc.dot(a.to_owned(), b.to_owned()).await?;
        self.hamming_distance_post(a, b, dot)
    }

    pub(crate) async fn hamming_distance_many(
        &mut self,
        a: Vec<Vec<Ashare>>,
        b: Vec<Vec<Ashare>>,
    ) -> Result<Vec<Ashare>, Error> {
        let dots = self.mpc.dot_many(&a, &b).await?;

        let mut res = Vec::with_capacity(dots.len());
        for ((a_, b_), dot) in a.into_iter().zip(b.into_iter()).zip(dots.into_iter()) {
            let r = self.hamming_distance_post(a_, b_, dot)?;
            res.push(r);
        }

        Ok(res)
    }

    fn get_cmp_diff(&self, hwd: Ashare, mask_ones: usize) -> Ashare {
        let threshold = (mask_ones as f64 * MATCH_THRESHOLD_RATIO) as usize;
        self.mpc.sub_const(
            hwd,
            threshold
                .try_into()
                .expect("Sizes are checked in constructor"),
        )
    }

    #[allow(unused)]
    pub(crate) async fn compare_threshold(
        &mut self,
        hwd: Ashare,
        mask_ones: usize,
    ) -> Result<Bshare, Error> {
        // a < b <=> msb(a - b)
        // Given no overflow, which is enforced in constructor
        let diff = self.get_cmp_diff(hwd, mask_ones);
        self.mpc.get_msb(diff).await
    }

    pub(crate) async fn compare_threshold_many(
        &mut self,
        hwds: Vec<Ashare>,
        mask_lens: Vec<usize>,
    ) -> Result<Vec<Bshare>, Error> {
        if hwds.len() != mask_lens.len() {
            return Err(Error::InvalidSizeError);
        }
        // a < b <=> msb(a - b)
        // Given no overflow, which is enforced in constructor
        let diffs = hwds
            .into_iter()
            .zip(mask_lens)
            .map(|(hwd, mask_len)| self.get_cmp_diff(hwd, mask_len))
            .collect();

        self.mpc.get_msb_many(diffs).await
    }

    #[allow(unused)]
    pub(crate) async fn compare_iris(
        &mut self,
        a: Vec<Ashare>,
        b: Vec<Ashare>,
        mask_a: &IrisCodeArray,
        mask_b: &IrisCodeArray,
    ) -> Result<Bshare, Error> {
        let mask = self.combine_masks(mask_a, mask_b)?;
        let (a, b) = self.apply_mask_twice(a, b, &mask)?;

        let hwd = self.hamming_distance(a, b).await?;

        self.compare_threshold(hwd, mask.count_ones()).await
    }

    pub(crate) async fn compare_iris_many(
        &mut self,
        a: Vec<Ashare>,
        b: &[Vec<Ashare>],
        mask_a: &IrisCodeArray,
        mask_b: &[IrisCodeArray],
    ) -> Result<Vec<Bshare>, Error> {
        let amount = b.len();
        if (amount != mask_b.len()) || (amount == 0) {
            return Err(Error::InvalidSizeError);
        }
        let mut a_vec = Vec::with_capacity(amount);
        let mut b_vec = Vec::with_capacity(amount);
        let mut mask_lens = Vec::with_capacity(amount);

        for (b_, mask_b_) in b.into_iter().zip(mask_b.iter()) {
            let mask = self.combine_masks(mask_a, mask_b_)?;
            let (iris_a, iris_b) = self.apply_mask_twice(a.clone(), b_.clone(), &mask)?;

            a_vec.push(iris_a);
            b_vec.push(iris_b);
            mask_lens.push(mask.count_ones());
        }

        let hwds = self.hamming_distance_many(a_vec, b_vec).await?;
        self.compare_threshold_many(hwds, mask_lens).await
    }

    pub async fn iris_in_db(
        &mut self,
        iris: Vec<Ashare>,
        db: &[Vec<Ashare>],
        mask_iris: &IrisCodeArray,
        mask_db: &[IrisCodeArray],
    ) -> Result<bool, Error> {
        let amount = db.len();
        if (amount != mask_db.len()) || (amount == 0) {
            return Err(Error::InvalidSizeError);
        }

        let mut bool_shares = Vec::with_capacity(amount);

        for (db_, mask_) in db.chunks(PACK_SIZE).zip(mask_db.chunks(PACK_SIZE)) {
            let res = self
                .compare_iris_many(iris.to_owned(), db_, mask_iris, mask_)
                .await?;
            bool_shares.extend(res);
        }

        let res = self.mpc.reduce_binary_or(bool_shares).await?;

        self.mpc.verify().await.unwrap();
        self.mpc.open_bit(res).await
    }
}
