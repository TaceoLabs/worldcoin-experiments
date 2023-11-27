use crate::aby3::share::Share;
use crate::error::Error;
use crate::traits::{mpc_trait::MpcTrait, network_trait::NetworkTrait};
use crate::types::sharable::Sharable;

struct Aby3 {}

impl<N: NetworkTrait, T: Sharable> MpcTrait<N, Share<T>, Share<T>> for Aby3 {
    fn add(a: Share<T>, b: Share<T>) -> Share<T> {
        a + b
    }

    fn mul(network: &mut N, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        todo!()
    }
}
