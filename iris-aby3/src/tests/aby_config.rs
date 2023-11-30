pub mod aby3_config {

    use crate::{
        aby3::{binary_trait::BinaryMpcTrait, share::Share},
        prelude::{Aby3, Aby3Network, MpcTrait, Sharable},
        types::bit::Bit,
    };
    use mpc_net::config::{NetworkConfig, NetworkParty};
    use rand::distributions::{Distribution, Standard};
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        ops::Mul,
        path::PathBuf,
    };

    pub const NUM_PARTIES: usize = 3;
    const PORT: u16 = 10000;
    const IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const CERT_PATH: &str = "/src/tests/certs/";

    pub fn get_network_parties(port_offset: u16) -> Vec<NetworkParty> {
        let mut parties = Vec::with_capacity(NUM_PARTIES);

        for i in 0..NUM_PARTIES {
            let cert_path = PathBuf::from(format!(
                "{}{}cert{}.der",
                env!("CARGO_MANIFEST_DIR"),
                CERT_PATH,
                i
            ));

            let party = NetworkParty {
                id: i,
                dns_name: format!("party{}", i),
                socket_addr: std::net::SocketAddr::V4(SocketAddrV4::new(
                    IP,
                    PORT + port_offset + i as u16,
                )),
                cert_path,
            };
            parties.push(party);
        }

        parties
    }

    pub fn get_config(id: usize, port_offset: u16) -> NetworkConfig {
        assert!(id < NUM_PARTIES);

        let key_path = PathBuf::from(format!(
            "{}{}key{}.der",
            env!("CARGO_MANIFEST_DIR"),
            CERT_PATH,
            id
        ));

        NetworkConfig {
            parties: get_network_parties(port_offset),
            my_id: id,
            key_path,
        }
    }

    pub async fn get_protocol<T: Sharable>(id: usize, port_offset: u16) -> Aby3<Aby3Network>
    where
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let config = get_config(id, port_offset);
        let network = Aby3Network::new(config).await.unwrap();
        Aby3::new(network)
    }

    pub async fn get_preprocessed_protocol<T: Sharable>(
        id: usize,
        port_offset: u16,
    ) -> Aby3<Aby3Network>
    where
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        Aby3<Aby3Network>: BinaryMpcTrait<T>,
    {
        let mut protocol = get_protocol::<T>(id, port_offset).await;
        MpcTrait::<T, Share<T>, Share<Bit>>::preprocess(&mut protocol)
            .await
            .unwrap();
        protocol
    }
}
