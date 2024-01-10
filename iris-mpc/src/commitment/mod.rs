use crate::{aby3::utils::ring_slice_to_bytes, types::ring_element::RingImpl};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[derive(Clone, Debug)]
pub struct Commitment<R: RingImpl> {
    /// The values which were committed to.
    pub values: Vec<R>,
    /// The randomness used to create the commitment.
    pub rand: [u8; 32],
    /// The commitment itself, i.e., the hash of the value and the randomness.
    pub comm: Vec<u8>,
}

/// The struct representing the opening of the hash based commitment [`Commitment`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CommitOpening<R: RingImpl> {
    /// The values which were committed to.
    pub values: Vec<R>,
    /// The randomness used to create the commitment.
    pub rand: [u8; 32],
}

impl<R: RingImpl> Commitment<R> {
    pub fn get_comm_size() -> usize {
        Sha512::output_size()
    }

    pub fn get_rand_size() -> usize {
        32
    }

    pub fn commit<Rand: Rng>(values: Vec<R>, rng: &mut Rand) -> Self {
        let rand = rng.gen::<[u8; 32]>();
        Self::commit_with_rand(values, rand)
    }

    pub fn commit_with_rand(values: Vec<R>, rand: [u8; 32]) -> Self {
        let mut hasher = Sha512::new();
        let bytes = ring_slice_to_bytes(&values);
        hasher.update(bytes);
        hasher.update(rand);

        let comm = hasher.finalize().to_vec();
        Self { values, rand, comm }
    }

    pub fn open(self) -> CommitOpening<R> {
        CommitOpening {
            values: self.values,
            rand: self.rand,
        }
    }
}

impl<R: RingImpl> CommitOpening<R> {
    pub fn verify(self, comm: Vec<u8>) -> bool {
        let mut hasher = Sha512::new();
        let bytes = ring_slice_to_bytes(&self.values);
        hasher.update(bytes);
        hasher.update(self.rand);

        let comm2 = hasher.finalize().to_vec();
        comm == comm2
    }
}
