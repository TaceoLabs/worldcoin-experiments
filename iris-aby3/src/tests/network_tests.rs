mod aby3_test {
    use crate::{
        aby3::{network::Aby3Network, protocol::Aby3, share::Share},
        traits::mpc_trait::MpcTrait,
        types::{int_ring::IntRing2k, sharable::Sharable},
    };
    use mpc_net::config::{NetworkConfig, NetworkParty};
    use rand::{
        distributions::{Distribution, Standard},
        rngs::SmallRng,
        Rng, SeedableRng,
    };
    use serial_test::serial;
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        path::PathBuf,
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

    async fn get_preprocessed_protocol<T: Sharable>(id: usize) -> Aby3<Aby3Network>
    where
        Standard: Distribution<T::Share>,
    {
        let config = get_config(id);
        let network = Aby3Network::new(config).await.unwrap();
        let mut protocol = Aby3::new(network);
        MpcTrait::<T, Share<T>, Share<T>>::preprocess(&mut protocol)
            .await
            .unwrap();
        protocol
    }

    #[test]
    fn test_network_config() {
        for i in 0..NUM_PARTIES {
            let config = get_config(i);
            assert!(config.check_config().is_ok());
        }
    }

    async fn input_test_party<T: Sharable>(id: usize) -> (T, Vec<T>)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
    {
        let mut protocol = get_preprocessed_protocol::<T>(id).await;
        let rng = &mut SmallRng::from_entropy();
        let input = rng.gen::<T>();

        let shares = protocol.input_all(input).await.unwrap();
        let open = protocol.open_many(&shares).await.unwrap();

        MpcTrait::<T, Share<T>, Share<T>>::finish(protocol)
            .await
            .unwrap();
        (input, open)
    }

    #[tokio::test]
    #[serial]
    async fn input_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        for i in 0..NUM_PARTIES {
            let t = tokio::spawn(async move { input_test_party::<u16>(i).await });
            tasks.push(t);
        }

        let mut inputs = Vec::with_capacity(NUM_PARTIES);
        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let (inp, outp) = t.await.expect("Task exited normally");
            inputs.push(inp);
            results.push(outp);
        }

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        assert_eq!(&inputs, r0);
    }

    async fn add_test_party<T: Sharable>(id: usize) -> (T, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
    {
        let mut protocol = get_preprocessed_protocol::<T>(id).await;
        let rng = &mut SmallRng::from_entropy();
        let input = rng.gen::<T>();

        let shares = protocol.input_all(input).await.unwrap();

        let result = shares
            .into_iter()
            .reduce(|acc, x| protocol.add(acc, x))
            .unwrap();

        let open = protocol.open(result).await.unwrap();

        MpcTrait::<T, Share<T>, Share<T>>::finish(protocol)
            .await
            .unwrap();
        (input, open)
    }

    #[tokio::test]
    #[serial]
    async fn add_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        for i in 0..NUM_PARTIES {
            let t = tokio::spawn(async move { add_test_party::<u16>(i).await });
            tasks.push(t);
        }

        let mut sum = 0;
        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let (inp, outp) = t.await.expect("Task exited normally");
            sum.wrapping_add_assign(&inp);
            results.push(outp);
        }

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        assert_eq!(r0, &sum);
    }

    async fn mul_test_party<T: Sharable>(id: usize) -> (T, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
    {
        let mut protocol = get_preprocessed_protocol::<T>(id).await;
        let rng = &mut SmallRng::from_entropy();
        let input = rng.gen::<T>();

        let shares = protocol.input_all(input).await.unwrap();

        let mut result = shares[0].to_owned();
        for share in shares.into_iter().skip(1) {
            result = protocol.mul(result, share).await.unwrap();
        }

        let open = protocol.open(result).await.unwrap();

        MpcTrait::<T, Share<T>, Share<T>>::finish(protocol)
            .await
            .unwrap();
        (input, open)
    }

    #[tokio::test]
    #[serial]
    async fn mul_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        for i in 0..NUM_PARTIES {
            let t = tokio::spawn(async move { mul_test_party::<u16>(i).await });
            tasks.push(t);
        }

        let mut prod = 1;
        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let (inp, outp) = t.await.expect("Task exited normally");
            prod.wrapping_mul_assign(&inp);
            results.push(outp);
        }

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        assert_eq!(r0, &prod);
    }
}
