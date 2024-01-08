use crate::aby3::utils::ceil_log2;
use crate::prelude::{Aby3Share, Error, MpcTrait, Sharable, SpdzWiseShare, Swift3Share};
use crate::traits::share_trait::{ShareTrait, VecShareTrait};
use crate::types::bit::Bit;
use crate::types::ring_element::RingImpl;
use num_traits::Zero;
use plain_reference::IrisCodeArray;
use std::{marker::PhantomData, usize};

const IRIS_CODE_SIZE: usize = plain_reference::IrisCode::IRIS_CODE_SIZE;
const MASK_THRESHOLD: usize = plain_reference::MASK_THRESHOLD;
const MATCH_THRESHOLD_RATIO: f64 = plain_reference::MATCH_THRESHOLD_RATIO;

pub type IrisAby3<T, Mpc> = IrisProtocol<T, Aby3Share<T>, Aby3Share<Bit>, Mpc>;
pub type IrisSwift3<T, Mpc> = IrisProtocol<T, Swift3Share<T>, Swift3Share<Bit>, Mpc>;
#[allow(type_alias_bounds)]
pub type IrisSpdzWise<T: Sharable, Mpc> =
    IrisProtocol<T, SpdzWiseShare<T::VerificationShare>, Aby3Share<Bit>, Mpc>;

pub struct IrisProtocol<
    T: Sharable,
    Ashare: ShareTrait,
    Bshare: ShareTrait,
    Mpc: MpcTrait<T, Ashare, Bshare>,
> {
    mpc: Mpc,
    phantom_t: PhantomData<T>,
    phantom_a: PhantomData<Ashare>,
    phantom_b: PhantomData<Bshare>,
}

impl<T: Sharable, Ashare: ShareTrait, Bshare: ShareTrait, Mpc: MpcTrait<T, Ashare, Bshare>>
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

    fn masked_hamming_distance_post(
        &self,
        a: &Ashare::VecShare,
        b: &Ashare::VecShare,
        mask: &IrisCodeArray,
        dot: Ashare,
    ) -> Result<Ashare, Error> {
        if a.is_empty() || a.len() != b.len() {
            return Err(Error::InvalidCodeSizeError);
        }

        let (sum_a, sum_b) = Ashare::VecShare::filter_reduce_add_twice(a, b, mask)?;

        let dot = self.mpc.mul_const(dot, T::try_from(2).unwrap());

        let sum = self.mpc.add(sum_a, sum_b);
        let res = self.mpc.sub(sum, dot);
        Ok(res)
    }

    #[cfg(test)]
    pub(crate) async fn hamming_distance(
        &mut self,
        a: Ashare::VecShare,
        b: Ashare::VecShare,
    ) -> Result<Ashare, Error> {
        let res = self
            .masked_hamming_distance_many(&a, &[b], vec![IrisCodeArray::ONES])
            .await?;

        Ok(res[0].to_owned())
    }

    pub(crate) async fn masked_hamming_distance_many(
        &mut self,
        a: &Ashare::VecShare,
        b: &[Ashare::VecShare],
        masks: Vec<IrisCodeArray>,
    ) -> Result<Vec<Ashare>, Error> {
        let dots = self.mpc.masked_dot_many(a, b, &masks).await?;

        let mut res = Vec::with_capacity(dots.len());
        for ((b_, dot), mask) in b.iter().zip(dots.into_iter()).zip(masks.into_iter()) {
            let r = self.masked_hamming_distance_post(a, b_, &mask, dot)?;
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

    #[cfg(test)]
    pub(crate) async fn compare_threshold(
        &mut self,
        hwd: Ashare,
        mask_ones: usize,
    ) -> Result<Bshare, Error> {
        // a < b <=> msb(a - b)
        // Given no overflow, which is enforced in constructor
        let diff = self.get_cmp_diff(hwd, mask_ones);
        // This is written this way to help out rust-analyzer...
        Mpc::get_msb(&mut self.mpc, diff).await
    }

    pub(crate) async fn compare_threshold_many(
        &mut self,
        hwds: Vec<Ashare>,
        mask_lens: Vec<usize>,
    ) -> Result<Bshare::VecShare, Error> {
        if hwds.len() != mask_lens.len() {
            return Err(Error::InvalidSizeError);
        }
        // a < b <=> msb(a - b)
        // Given no overflow, which is enforced in constructor
        let mut diffs = Ashare::VecShare::with_capacity(hwds.len());
        for (hwd, mask_len) in hwds.into_iter().zip(mask_lens) {
            let diff = self.get_cmp_diff(hwd, mask_len);
            diffs.push(diff);
        }

        self.mpc.get_msb_many(diffs).await
    }

    #[cfg(test)]
    pub(crate) async fn compare_iris(
        &mut self,
        a: Ashare::VecShare,
        b: Ashare::VecShare,
        mask_a: &IrisCodeArray,
        mask_b: &IrisCodeArray,
    ) -> Result<Bshare, Error> {
        let tmp = self
            .compare_iris_many(&a, &[b], mask_a, &[mask_b.to_owned()])
            .await?;
        Ok(tmp.get_at(0))
    }

    pub(crate) async fn compare_iris_many(
        &mut self,
        a: &Ashare::VecShare,
        b: &[Ashare::VecShare],
        mask_a: &IrisCodeArray,
        mask_b: &[IrisCodeArray],
    ) -> Result<Bshare::VecShare, Error> {
        let amount = b.len();
        if (amount != mask_b.len()) || (amount == 0) {
            return Err(Error::InvalidSizeError);
        }

        let masks = mask_b
            .iter()
            .map(|b| self.combine_masks(mask_a, b))
            .collect::<Result<Vec<_>, _>>()?;
        let mask_lens: Vec<_> = masks.iter().map(|m| m.count_ones()).collect();

        let hwds = self.masked_hamming_distance_many(a, b, masks).await?;
        self.compare_threshold_many(hwds, mask_lens).await
    }

    pub async fn iris_in_db(
        &mut self,
        iris: &Ashare::VecShare,
        db: &[Ashare::VecShare],
        mask_iris: &IrisCodeArray,
        mask_db: &[IrisCodeArray],
        chunk_size: usize,
    ) -> Result<bool, Error> {
        let amount = db.len();
        if (amount != mask_db.len()) || (amount == 0) {
            return Err(Error::InvalidSizeError);
        }

        let mut bool_shares = Bshare::VecShare::with_capacity(amount);

        for (db_, mask_) in db.chunks(chunk_size).zip(mask_db.chunks(chunk_size)) {
            let res = self.compare_iris_many(iris, db_, mask_iris, mask_).await?;
            bool_shares.extend(res);
        }

        let res = self.mpc.reduce_binary_or(bool_shares, chunk_size).await?;

        self.mpc.verify().await.unwrap();
        self.mpc.open_bit(res).await
    }
}
