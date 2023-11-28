use super::random::prf::PrfSeed;
use crate::{error::Error, traits::network_trait::NetworkTrait};
use bytes::{Buf, Bytes};
use std::io::Error as IOError;

pub(crate) fn bytes_to_seed(mut bytes: Bytes) -> Result<PrfSeed, Error> {
    if bytes.len() != 32 {
        Err(Error::Other(
            "cannot setup prf because wrong seed length from other party".to_owned(),
        ))
    } else {
        let mut their_seed: PrfSeed = [0; 32];
        bytes.copy_to_slice(&mut their_seed);
        Ok(their_seed)
    }
}

pub(crate) async fn send_and_receive<N: NetworkTrait>(
    network: &mut N,
    data: Bytes,
) -> Result<Bytes, IOError> {
    network.send_next_id(data).await?;
    let data = network.receive_prev_id().await?;
    Ok(data)
}
