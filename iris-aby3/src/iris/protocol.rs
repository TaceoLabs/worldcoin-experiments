use crate::prelude::{Error, MpcTrait, Sharable};
use bitvec::{prelude::Lsb0, BitArr};
use std::{marker::PhantomData, ops::Mul, usize};

const IRIS_CODE_SIZE: usize = plain_reference::IRIS_CODE_SIZE;
const MASK_THRESHOLD: usize = plain_reference::MASK_THRESHOLD;

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
{
    pub fn new(mpc: Mpc) -> Self {
        IrisProtocol {
            mpc,
            phantom_t: PhantomData,
            phantom_a: PhantomData,
            phantom_b: PhantomData,
        }
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

    pub(crate) fn combine_masks(&self, a_mask: &BitArr, b_mask: &BitArr) -> Result<BitArr, Error> {
        let combined_mask = *a_mask & b_mask;
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

    pub(crate) async fn hamming_distance(
        &mut self,
        a: Vec<Ashare>,
        b: Vec<Ashare>,
    ) -> Result<Ashare, Error> {
        if a.is_empty() || a.len() != b.len() {
            return Err(Error::InvlidCodeSizeError);
        }

        let sum_a = a
            .iter()
            .cloned()
            .reduce(|a_, b_| self.mpc.add(a_, b_))
            .expect("Size is not zero");
        let sum_b = b
            .iter()
            .cloned()
            .reduce(|a_, b_| self.mpc.add(a_, b_))
            .expect("Size is not zero");

        let dot = self.mpc.dot(a, b).await?;
        let dot = self.mpc.add(dot.to_owned(), dot);

        let sum = self.mpc.add(sum_a, sum_b);
        let res = self.mpc.sub(sum, dot);

        Ok(res)
    }
}
