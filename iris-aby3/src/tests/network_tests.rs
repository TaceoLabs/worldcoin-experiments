mod aby3_test {
    use mpc_net::config::{NetworkConfig, NetworkParty};
    use serial_test::serial;
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        path::PathBuf,
        time::Duration,
    };

    use crate::{
        aby3::{network::Aby3Network, protocol::Aby3, share::Share},
        traits::mpc_trait::MpcTrait,
    };

    const NUM_PARTIES: usize = 3;
    const PORT: u16 = 10000;
    const IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const CERT_PATH: &str = "/src/tests/certs/";

    fn get_network_parties() -> Vec<NetworkParty> {
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
                socket_addr: std::net::SocketAddr::V4(SocketAddrV4::new(IP, PORT + i as u16)),
                cert_path,
            };
            parties.push(party);
        }

        parties
    }

    fn get_config(id: usize) -> NetworkConfig {
        assert!(id < NUM_PARTIES);

        let key_path = PathBuf::from(format!(
            "{}{}key{}.der",
            env!("CARGO_MANIFEST_DIR"),
            CERT_PATH,
            id
        ));

        NetworkConfig {
            parties: get_network_parties(),
            my_id: id,
            key_path,
        }
    }

    #[test]
    fn test_network_config() {
        for i in 0..NUM_PARTIES {
            let config = get_config(i);
            assert!(config.check_config().is_ok());
        }
    }

    async fn add_test_party(id: usize) -> u16 {
        let config = get_config(id);
        let network = Aby3Network::new(config).await.unwrap();
        let mut protocol = Aby3::new(network);
        MpcTrait::<Share<u16>, Share<u16>>::preprocess(&mut protocol)
            .await
            .unwrap();

        1
    }

    #[tokio::test]
    #[serial]
    async fn add_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        for i in 0..NUM_PARTIES {
            let t = tokio::spawn(async move { add_test_party(i).await });
            tasks.push(t);
        }

        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let outs = t.await.expect("Task exited normally");
            results.push(outs);
        }

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
    }
}
