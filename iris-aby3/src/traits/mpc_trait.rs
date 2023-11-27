use super::network_trait::Network;
use crate::error::Error;

pub trait Mpc<N: Network, Ashare, Bshare> {
    fn add(a: Ashare, b: Ashare) -> Ashare;
    fn mul(network: &mut N, a: Ashare, b: Bshare) -> Result<Ashare, Error>;
}
