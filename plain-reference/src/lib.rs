use core::panic;

use bitvec::{prelude::Lsb0, BitArr};
use rand::distributions::Bernoulli;
use rand::distributions::Distribution;
use rand::RngCore;

const IRIS_CODE_SIZE: usize = 12800;
const MASK_THRESHOLD_RATIO: f64 = 0.70;
const MASK_THRESHOLD: usize = (MASK_THRESHOLD_RATIO * IRIS_CODE_SIZE as f64) as usize;
const MATCH_THRESHOLD_RATIO: f64 = 0.34;

#[derive(Default, Debug)]
pub struct IrisCode {
    pub code: BitArr!(for IRIS_CODE_SIZE, in u8, Lsb0),
    pub mask: BitArr!(for IRIS_CODE_SIZE, in u8, Lsb0),
}

impl IrisCode {
    pub fn random() -> Self {
        let mut code = IrisCode::default();
        let rng = &mut rand::thread_rng();
        // Fill the code with random bytes
        rng.fill_bytes(code.code.as_raw_mut_slice());
        code.mask.fill(true);

        // remove about 10% of the mask bits
        let dist = Bernoulli::new(0.10).unwrap();

        // ...

        code.mask.as_mut_bitslice().iter_mut().for_each(|mut b| {
            if dist.sample(rng) {
                b.set(false);
            }
        });

        code
    }

    pub fn is_close(&self, other: &Self) -> bool {
        let combined_mask = self.mask & other.mask;
        let combined_mask_len = combined_mask.count_ones();
        // TODO: is this check needed?
        if combined_mask_len < MASK_THRESHOLD {
            panic!("combined mask has too few ones");
        }

        let combined_code = (self.code ^ other.code) & combined_mask;
        let code_distance = combined_code.count_ones();
        let match_threshold = (combined_mask_len as f64 * MATCH_THRESHOLD_RATIO) as usize;
        code_distance < match_threshold
    }
}
