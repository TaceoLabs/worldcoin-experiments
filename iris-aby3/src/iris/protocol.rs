use crate::aby3::utils::ceil_log2;
use crate::prelude::{Error, MpcTrait, Sharable};
use crate::types::ring_element::RingImpl;
use bitvec::{prelude::Lsb0, BitArr};
use std::{marker::PhantomData, ops::Mul, usize};

const IRIS_CODE_SIZE: usize = plain_reference::IRIS_CODE_SIZE;
const MASK_THRESHOLD: usize = plain_reference::MASK_THRESHOLD;
const MATCH_THRESHOLD_RATIO: f64 = plain_reference::MATCH_THRESHOLD_RATIO;
const PACK_SIZE: usize = 8;

pub type BitArr = BitArr!(for IRIS_CODE_SIZE, in u8, Lsb0);

pub struct IrisProtocol<T: Sharable, Ashare, Bshare, Mpc: MpcTrait<T, Ashare, Bshare>> {
    mpc: Mpc,
    phantom_t: PhantomData<T>,
    phantom_a: PhantomData<Ashare>,
    phantom_b: PhantomData<Bshare>,
}

impl<T: Sharable, Ashare: Clone, Bshare, Mpc: MpcTrait<T, Ashare, Bshare>>
    IrisProtocol<T, Ashare, Bshare, Mpc>
where
    Ashare: Mul<T::Share, Output = Ashare>,
    <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
{
    pub fn new(mpc: Mpc) -> Result<Self, Error> {
        if MATCH_THRESHOLD_RATIO >= 1.
            || MATCH_THRESHOLD_RATIO <= 0.
            || T::Share::get_k() <= ceil_log2(IRIS_CODE_SIZE)
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

    pub async fn preprocessing(&mut self) -> Result<(), Error> {
        self.mpc.preprocess().await
    }

    pub async fn finish(self) -> Result<(), Error> {
        self.mpc.finish().await
    }

    pub(crate) fn combine_masks(&self, mask_a: &BitArr, mask_b: &BitArr) -> Result<BitArr, Error> {
        let combined_mask = *mask_a & mask_b;
        let combined_mask_len = combined_mask.count_ones();
        // TODO: is this check needed?
        if combined_mask_len < MASK_THRESHOLD {
            return Err(Error::MaskHWError);
        }
        Ok(combined_mask)
    }

    pub(crate) fn apply_mask(
        &self,
        code: Vec<Ashare>,
        mask: &BitArr,
    ) -> Result<Vec<Ashare>, Error> {
        if code.len() != IRIS_CODE_SIZE {
            return Err(Error::InvlidCodeSizeError);
        }

        let mut masked_code = Vec::with_capacity(IRIS_CODE_SIZE);
        for (c, m) in code.into_iter().zip(mask.iter()) {
            masked_code.push(c * T::Share::from(*m));
        }
        Ok(masked_code)
    }

    fn hamming_distance_post(
        &self,
        a: Vec<Ashare>,
        b: Vec<Ashare>,
        dot: Ashare,
    ) -> Result<Ashare, Error> {
        if a.is_empty() || a.len() != b.len() {
            return Err(Error::InvlidCodeSizeError);
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
        let dots = self.mpc.dot_many(a.to_owned(), b.to_owned()).await?;

        let mut res = Vec::with_capacity(dots.len());
        for ((a_, b_), dot) in a.into_iter().zip(b.into_iter()).zip(dots.into_iter()) {
            let r = self.hamming_distance_post(a_, b_, dot)?;
            res.push(r);
        }

        Ok(res)
    }

    fn get_cmp_diff(&self, hwd: Ashare, mask_len: usize) -> Ashare {
        let threshold = (mask_len as f64 * MATCH_THRESHOLD_RATIO) as usize;
        self.mpc.sub_const(
            hwd,
            threshold
                .try_into()
                .expect("Sizes are checked in constructor"),
        )
    }

    pub(crate) async fn compare_threshold(
        &mut self,
        hwd: Ashare,
        mask_len: usize,
    ) -> Result<Bshare, Error> {
        // a < b <=> msb(a - b)
        // Given no overflow, which is enforced in constructor
        let diff = self.get_cmp_diff(hwd, mask_len);
        self.mpc.get_msb(diff).await
    }

    pub(crate) async fn compare_threshold_many(
        &mut self,
        hwds: Vec<Ashare>,
        mask_lens: Vec<usize>,
    ) -> Result<Vec<Bshare>, Error> {
        if hwds.len() != mask_lens.len() {
            return Err(Error::InvlidSizeError);
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

    pub(crate) async fn compare_iris(
        &mut self,
        a: Vec<Ashare>,
        b: Vec<Ashare>,
        mask_a: &BitArr,
        mask_b: &BitArr,
    ) -> Result<Bshare, Error> {
        let mask = self.combine_masks(mask_a, mask_b)?;
        let a = self.apply_mask(a, &mask)?;
        let b = self.apply_mask(b, &mask)?;

        let hwd = self.hamming_distance(a, b).await?;
        self.compare_threshold(hwd, mask.len()).await
    }

    pub(crate) async fn compare_iris_many(
        &mut self,
        a: Vec<Ashare>,
        b: Vec<Vec<Ashare>>,
        mask_a: &BitArr,
        mask_b: &[BitArr],
    ) -> Result<Vec<Bshare>, Error> {
        let amount = b.len();
        if (amount != mask_b.len()) || (amount == 0) {
            return Err(Error::InvlidSizeError);
        }
        let mut a_vec = Vec::with_capacity(amount);
        let mut b_vec = Vec::with_capacity(amount);
        let mut mask_lens = Vec::with_capacity(amount);

        for (b_, mask_b_) in b.into_iter().zip(mask_b.iter()) {
            let mask = self.combine_masks(mask_a, mask_b_)?;
            let iris_a = self.apply_mask(a.to_owned(), &mask)?;
            let iris_b = self.apply_mask(b_, &mask)?;

            a_vec.push(iris_a);
            b_vec.push(iris_b);
            mask_lens.push(mask.len());
        }

        let hwds = self.hamming_distance_many(a_vec, b_vec).await?;
        self.compare_threshold_many(hwds, mask_lens).await
        // TODO maybe pack bits
    }

    pub async fn iris_in_db(
        &mut self,
        iris: Vec<Ashare>,
        db: Vec<Vec<Ashare>>,
        mask_iris: &BitArr,
        mask_db: &[BitArr],
    ) -> Result<bool, Error> {
        let amount = db.len();
        if (amount != mask_db.len()) || (amount == 0) {
            return Err(Error::InvlidSizeError);
        }

        let mut bool_shares = Vec::with_capacity(amount);

        for db_ in db.chunks(PACK_SIZE) {
            let res = self
                .compare_iris_many(iris.to_owned(), db_.to_owned(), mask_iris, mask_db)
                .await?;
            bool_shares.extend(res);
        }

        todo!()
    }
}
