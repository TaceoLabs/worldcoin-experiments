mod aby3_test {
    use crate::{
        aby3::{protocol::Aby3, share::Share},
        prelude::{PartyTestNetwork, TestNetwork3p},
        traits::mpc_trait::{MpcTrait, Plain},
        types::{bit::Bit, int_ring::IntRing2k, sharable::Sharable},
    };
    use num_traits::Zero;
    use rand::{
        distributions::{Distribution, Standard},
        rngs::SmallRng,
        Rng, SeedableRng,
    };
    use std::ops::Mul;

    const NUM_PARTIES: usize = PartyTestNetwork::NUM_PARTIES;
    const DOT_SIZE: usize = 1000;

    async fn share_test_party<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
    ) -> (T, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut protocol = Aby3::<PartyTestNetwork>::new(net);
        protocol.preprocess().await.unwrap();
        let id = protocol.get_id();

        let mut rng = R::from_seed(seed);
        let input = rng.gen::<T>();

        let shares = Aby3::<PartyTestNetwork>::share(
            input.clone(),
            T::VerificationShare::default(),
            &mut rng,
        );
        protocol.verify().await.unwrap();
        let open = protocol.open(shares[id].to_owned()).await.unwrap();

        MpcTrait::<T, Share<T>, Share<Bit>>::finish(protocol)
            .await
            .unwrap();
        (input, open)
    }

    #[tokio::test]
    async fn share_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move { share_test_party::<u16, SmallRng>(n, seed).await });
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
        for i in inputs.iter() {
            assert_eq!(r0, i);
        }
    }

    async fn input_test_party<T: Sharable>(net: PartyTestNetwork) -> (T, Vec<T>)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut protocol = Aby3::<PartyTestNetwork>::new(net);
        protocol.preprocess().await.unwrap();

        let mut rng = SmallRng::from_entropy();
        let input = rng.gen::<T>();

        let shares = protocol.input_all(input).await.unwrap();
        protocol.verify().await.unwrap();
        let open = protocol.open_many(shares).await.unwrap();

        MpcTrait::<T, Share<T>, Share<Bit>>::finish(protocol)
            .await
            .unwrap();
        (input, open)
    }

    #[tokio::test]
    async fn input_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move { input_test_party::<u16>(n).await });
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

    async fn add_test_party<T: Sharable>(net: PartyTestNetwork) -> (T, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut protocol = Aby3::<PartyTestNetwork>::new(net);
        protocol.preprocess().await.unwrap();

        let mut rng = SmallRng::from_entropy();
        let input = rng.gen::<T>();

        let shares = protocol.input_all(input.clone()).await.unwrap();

        let result = shares
            .into_iter()
            .reduce(|acc, x| protocol.add(acc, x))
            .unwrap();

        protocol.verify().await.unwrap();
        let open = protocol.open(result).await.unwrap();

        MpcTrait::<T, Share<T>, Share<Bit>>::finish(protocol)
            .await
            .unwrap();
        (input, open)
    }

    #[tokio::test]
    async fn add_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move { add_test_party::<u16>(n).await });
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

    async fn sub_test_party<T: Sharable>(net: PartyTestNetwork) -> (T, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut protocol = Aby3::<PartyTestNetwork>::new(net);
        protocol.preprocess().await.unwrap();

        let mut rng = SmallRng::from_entropy();
        let input = rng.gen::<T>();

        let shares = protocol.input_all(input.clone()).await.unwrap();

        let result = shares
            .into_iter()
            .fold(Share::zero(), |acc, x| protocol.sub(acc, x));

        protocol.verify().await.unwrap();
        let open = protocol.open(result).await.unwrap();

        MpcTrait::<T, Share<T>, Share<Bit>>::finish(protocol)
            .await
            .unwrap();
        (input, open)
    }

    #[tokio::test]
    async fn sub_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move { sub_test_party::<u16>(n).await });
            tasks.push(t);
        }

        let mut sum = 0;
        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let (inp, outp) = t.await.expect("Task exited normally");
            sum.wrapping_sub_assign(&inp);
            results.push(outp);
        }

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        assert_eq!(r0, &sum);
    }

    async fn add_const_test_party<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
    ) -> (T, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut protocol = Aby3::<PartyTestNetwork>::new(net);
        protocol.preprocess().await.unwrap();

        let id = protocol.get_id();
        let mut rng = R::from_seed(seed);
        let mul = rng.gen::<T>();

        let input = if id == 0 {
            let mut rng = R::from_entropy();
            let inp = rng.gen::<T>();
            Some(inp)
        } else {
            None
        };
        let share = protocol.input(input.clone(), 0).await.unwrap();
        let result = protocol.add_const(share, mul);
        protocol.verify().await.unwrap();
        let open = protocol.open(result).await.unwrap();

        MpcTrait::<T, Share<T>, Share<Bit>>::finish(protocol)
            .await
            .unwrap();
        (input.unwrap_or(T::zero()), open)
    }

    #[tokio::test]
    async fn add_const_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let mut rng = SmallRng::from_seed(seed);
        let add = rng.gen::<u16>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t =
                tokio::spawn(async move { add_const_test_party::<u16, SmallRng>(n, seed).await });
            tasks.push(t);
        }

        let mut sum = 0;
        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let (inp, outp) = t.await.expect("Task exited normally");
            sum.wrapping_add_assign(&inp);
            results.push(outp);
        }
        let sum = sum.wrapping_add(add);

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        assert_eq!(r0, &sum);
    }

    async fn sub_const_test_party<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
    ) -> (T, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut protocol = Aby3::<PartyTestNetwork>::new(net);
        protocol.preprocess().await.unwrap();

        let id = protocol.get_id();
        let mut rng = R::from_seed(seed);
        let mul = rng.gen::<T>();

        let input = if id == 0 {
            let mut rng = R::from_entropy();
            let inp = rng.gen::<T>();
            Some(inp)
        } else {
            None
        };
        let share = protocol.input(input.clone(), 0).await.unwrap();
        let result = protocol.sub_const(share, mul);
        protocol.verify().await.unwrap();
        let open = protocol.open(result).await.unwrap();

        MpcTrait::<T, Share<T>, Share<Bit>>::finish(protocol)
            .await
            .unwrap();
        (input.unwrap_or(T::zero()), open)
    }

    #[tokio::test]
    async fn sub_const_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let mut rng = SmallRng::from_seed(seed);
        let add = rng.gen::<u16>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t =
                tokio::spawn(async move { sub_const_test_party::<u16, SmallRng>(n, seed).await });
            tasks.push(t);
        }

        let mut sum = 0;
        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let (inp, outp) = t.await.expect("Task exited normally");
            sum.wrapping_add_assign(&inp);
            results.push(outp);
        }
        let sum = sum.wrapping_sub(add);

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        assert_eq!(r0, &sum);
    }

    async fn mul_test_party<T: Sharable>(net: PartyTestNetwork) -> (T, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut protocol = Aby3::<PartyTestNetwork>::new(net);
        protocol.preprocess().await.unwrap();

        let mut rng = SmallRng::from_entropy();
        let input = rng.gen::<T>();

        let shares = protocol.input_all(input.clone()).await.unwrap();

        let mut result = shares[0].to_owned();
        for share in shares.into_iter().skip(1) {
            result = protocol.mul(result, share).await.unwrap();
        }

        protocol.verify().await.unwrap();
        let open = protocol.open(result).await.unwrap();

        MpcTrait::<T, Share<T>, Share<Bit>>::finish(protocol)
            .await
            .unwrap();
        (input, open)
    }

    #[tokio::test]
    async fn mul_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move { mul_test_party::<u16>(n).await });
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

    async fn mul_const_test_party<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
    ) -> (T, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut protocol = Aby3::<PartyTestNetwork>::new(net);
        protocol.preprocess().await.unwrap();

        let id = protocol.get_id();
        let mut rng = R::from_seed(seed);
        let mul = rng.gen::<T>();

        let input = if id == 0 {
            let mut rng = R::from_entropy();
            let inp = rng.gen::<T>();
            Some(inp)
        } else {
            None
        };
        let share = protocol.input(input, 0).await.unwrap();
        let result = protocol.mul_const(share, mul);
        protocol.verify().await.unwrap();
        let open = protocol.open(result).await.unwrap();

        MpcTrait::<T, Share<T>, Share<Bit>>::finish(protocol)
            .await
            .unwrap();
        (input.unwrap_or(T::zero()), open)
    }

    #[tokio::test]
    async fn mul_const_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let mut rng = SmallRng::from_seed(seed);
        let mul = rng.gen::<u16>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t =
                tokio::spawn(async move { mul_const_test_party::<u16, SmallRng>(n, seed).await });
            tasks.push(t);
        }

        let mut sum = 0;
        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let (inp, outp) = t.await.expect("Task exited normally");
            sum.wrapping_add_assign(&inp);
            results.push(outp);
        }
        let prod = sum.wrapping_mul(mul);

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        assert_eq!(r0, &prod);
    }

    async fn dot_test_party<T: Sharable>(net: PartyTestNetwork) -> (Vec<T>, T)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut protocol = Aby3::<PartyTestNetwork>::new(net);
        protocol.preprocess().await.unwrap();

        let id = protocol.get_id();
        let mut rng = SmallRng::from_entropy();

        let mut input = Vec::with_capacity(DOT_SIZE);
        let mut a = Vec::with_capacity(DOT_SIZE);
        let mut b = Vec::with_capacity(DOT_SIZE);
        for _ in 0..DOT_SIZE {
            let input1 = if id == 0 {
                let inp = rng.gen::<T>();
                input.push(inp);
                Some(inp)
            } else {
                None
            };
            let input2 = if id == 1 {
                let inp = rng.gen::<T>();
                input.push(inp);
                Some(inp)
            } else {
                None
            };
            let share1 = protocol.input(input1, 0).await.unwrap();
            let share2 = protocol.input(input2, 1).await.unwrap();
            a.push(share1);
            b.push(share2);
        }

        let result = protocol.dot(a, b).await.unwrap();
        protocol.verify().await.unwrap();
        let open = protocol.open(result).await.unwrap();

        MpcTrait::<T, Share<T>, Share<Bit>>::finish(protocol)
            .await
            .unwrap();
        (input, open)
    }

    #[tokio::test]
    async fn dot_test() {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move { dot_test_party::<u16>(n).await });
            tasks.push(t);
        }

        let mut inputs = Vec::with_capacity(2);
        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let (inp, outp) = t.await.expect("Task exited normally");
            if !inp.is_empty() {
                inputs.push(inp);
            }
            results.push(outp);
        }

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        let mut plain = Plain::default();
        let res = plain
            .dot(inputs[0].to_owned(), inputs[1].to_owned())
            .await
            .unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(r0, &res);
    }
}
