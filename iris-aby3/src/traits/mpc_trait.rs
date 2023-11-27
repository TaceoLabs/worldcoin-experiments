use super::network_trait::NetworkTrait;
use crate::error::Error;

pub trait MpcTrait<N: NetworkTrait, Ashare, Bshare> {
    fn add(a: Ashare, b: Ashare) -> Ashare;
    fn mul(network: &mut N, a: Ashare, b: Ashare) -> Result<Ashare, Error>;
}
