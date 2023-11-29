use crate::prelude::{Error, MpcTrait, Sharable};
use bitvec::{prelude::Lsb0, BitArr};
use std::{marker::PhantomData, ops::Mul, usize};

const IRIS_CODE_SIZE: usize = 12800;
const MASK_THRESHOLD_RATIO: f64 = 0.70;
const MASK_THRESHOLD: usize = (MASK_THRESHOLD_RATIO * IRIS_CODE_SIZE as f64) as usize;

type BitArr = BitArr!(for IRIS_CODE_SIZE, in u8, Lsb0);

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

    pub async fn preprocessing(&mut self) -> Result<(), Error> {
        self.mpc.preprocess().await
    }

    pub async fn finish(self) -> Result<(), Error> {
        self.mpc.finish().await
    }

    pub(crate) fn combine_masks(a_mask: &BitArr, b_mask: &BitArr) -> Result<BitArr, Error> {
        let combined_mask = *a_mask & b_mask;
        let combined_mask_len = combined_mask.count_ones();
        // TODO: is this check needed?
        if combined_mask_len < MASK_THRESHOLD {
            return Err(Error::MaskHWError);
        }
        Ok(combined_mask)
    }

    pub(crate) fn apply_mask(code: &[Ashare], mask: &BitArr) -> Result<Vec<Ashare>, Error> {
        if code.len() != IRIS_CODE_SIZE {
            return Err(Error::InvlidCodeSizeError);
        }

        let mut masked_code = Vec::with_capacity(IRIS_CODE_SIZE);
        for (c, m) in code.iter().zip(mask.iter()) {
            masked_code.push(c.to_owned() * T::Share::from(*m));
        }
        todo!()
    }
}
