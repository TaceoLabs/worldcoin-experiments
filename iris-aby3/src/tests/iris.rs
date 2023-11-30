mod iris_test {
    use crate::{
        aby3::share::Share,
        iris::protocol::{BitArr, IrisProtocol},
        prelude::{Aby3, Aby3Network, MpcTrait, Sharable},
        tests::{aby_config::aby3_config, iris_config::iris_config::similar_iris},
        traits::mpc_trait::Plain,
        types::bit::Bit,
    };
    use plain_reference::IrisCode;
    use rand::{
        distributions::{Distribution, Standard},
        rngs::SmallRng,
        Rng, SeedableRng,
    };
    use serial_test::serial;
    use std::ops::Mul;

    const NUM_PARTIES: usize = aby3_config::NUM_PARTIES;
    const DB_SIZE: usize = 1000;
    const TESTRUNS: usize = 5;

    async fn mask_test_aby3_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        id: usize,
        port_offset: u16,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) -> Vec<BitArr>
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = aby3_config::get_protocol::<T>(id, port_offset).await;
        let mut iris = IrisProtocol::new(protocol).unwrap();

        iris.preprocessing().await.unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        let mut results = Vec::with_capacity(TESTRUNS);
        for _ in 0..TESTRUNS {
            let code = IrisCode::random_rng(&mut iris_rng);

            let mut shared_code = Vec::with_capacity(code.code.len());
            for bit in code.code.iter() {
                // We simulate the parties already knowing the shares of the code.
                let shares = Aby3::<Aby3Network>::share(T::from(*bit), &mut rng).await;
                shared_code.push(shares[id].to_owned());
            }

            let masked_code = iris.apply_mask(shared_code, &code.mask).unwrap();
            let open_masked_code = iris.get_mpc_mut().open_many(masked_code).await.unwrap();

            let mut bitarr = BitArr::default();
            for (mut bit, code_bit) in bitarr.iter_mut().zip(open_masked_code.into_iter()) {
                assert!(code_bit.is_zero() || code_bit.is_one());
                bit.set(code_bit == T::one());
            }
            results.push(bitarr);
        }

        iris.finish().await.unwrap();
        results
    }

    async fn mask_test_aby3_impl<T: Sharable>(port_offset: u16)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let iris_seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let seed: [u8; 32] = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let mut iris_rng = SmallRng::from_seed(iris_seed);

        for i in 0..NUM_PARTIES {
            let t = tokio::spawn(async move {
                mask_test_aby3_impl_inner::<T, SmallRng>(i, port_offset, seed, iris_seed).await
            });
            tasks.push(t);
        }

        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let r = t.await.expect("Task exited normally");
            results.push(r);
        }

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        // Compare to plain
        for r in r0.iter() {
            let plain = IrisCode::random_rng(&mut iris_rng);
            let plain_code = plain.code & plain.mask;
            assert_eq!(&plain_code, r);
        }
    }

    #[tokio::test]
    #[serial]
    async fn mask_test_aby3() {
        mask_test_aby3_impl::<u16>(150).await
    }

    async fn hwd_test_aby3_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        id: usize,
        port_offset: u16,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) -> Vec<T>
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = aby3_config::get_protocol::<T>(id, port_offset).await;
        let mut iris = IrisProtocol::new(protocol).unwrap();

        iris.preprocessing().await.unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        let mut results = Vec::with_capacity(TESTRUNS);
        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);

            let mut shared_code1 = Vec::with_capacity(code1.code.len());
            let mut shared_code2 = Vec::with_capacity(code2.code.len());
            for bit in code1.code.iter() {
                // We simulate the parties already knowing the shares of the code.
                let shares = Aby3::<Aby3Network>::share(T::from(*bit), &mut rng).await;
                shared_code1.push(shares[id].to_owned());
            }
            for bit in code2.code.iter() {
                // We simulate the parties already knowing the shares of the code.
                let shares = Aby3::<Aby3Network>::share(T::from(*bit), &mut rng).await;
                shared_code2.push(shares[id].to_owned());
            }

            let hwd = iris
                .hamming_distance(shared_code1, shared_code2)
                .await
                .unwrap();
            let open_hwd = iris.get_mpc_mut().open(hwd).await.unwrap();
            results.push(open_hwd);
        }

        iris.finish().await.unwrap();
        results
    }

    async fn hwd_test_aby3_impl<T: Sharable>(port_offset: u16)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let iris_seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let mut iris_rng = SmallRng::from_seed(iris_seed);

        for i in 0..NUM_PARTIES {
            let t = tokio::spawn(async move {
                hwd_test_aby3_impl_inner::<T, SmallRng>(i, port_offset, seed, iris_seed).await
            });
            tasks.push(t);
        }

        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let r = t.await.expect("Task exited normally");
            results.push(r);
        }

        let r0 = &results[0];
        for r in results.iter().skip(1) {
            assert_eq!(r0, r);
        }
        // Compare to plain
        for r in r0.iter() {
            let plain1 = IrisCode::random_rng(&mut iris_rng);
            let plain2 = IrisCode::random_rng(&mut iris_rng);
            let combined_code = plain1.code ^ plain2.code;
            let distance: T = combined_code
                .count_ones()
                .try_into()
                .expect("Overflow should not happene");
            assert_eq!(&distance, r);
        }
    }

    #[tokio::test]
    #[serial]
    async fn hwd_test_aby3() {
        hwd_test_aby3_impl::<u16>(160).await
    }

    async fn plain_hwd_test_inner<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut iris_rng = SmallRng::from_entropy();

        let protocol = Plain::default();
        let mut iris: IrisProtocol<T, T, bool, Plain> = IrisProtocol::new(protocol).unwrap();

        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);

            let a = code1.code.iter().map(|b| T::from(*b)).collect();
            let b = code2.code.iter().map(|b| T::from(*b)).collect();
            let distance = iris.hamming_distance(a, b).await.unwrap();

            let combined_code = code1.code ^ code2.code;
            let distance_: T = combined_code
                .count_ones()
                .try_into()
                .expect("Overflow should not happen");

            assert_eq!(distance, distance_);
        }
    }

    #[tokio::test]
    async fn plain_hwd_test() {
        plain_hwd_test_inner::<u16>().await
    }

    async fn plain_lt_tester<T: Sharable>(code1: IrisCode, code2: IrisCode) -> bool
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Plain::default();
        let mut iris: IrisProtocol<T, T, bool, Plain> = IrisProtocol::new(protocol).unwrap();

        let combined_mask = code1.mask & code2.mask;
        let combined_code = code1.code ^ code2.code;
        let masked_code = combined_code & combined_mask;

        let distance = masked_code.count_ones();
        let threshold =
            (combined_mask.len() as f64 * plain_reference::MATCH_THRESHOLD_RATIO) as usize;
        let cmp_ = distance < threshold;

        let distance = distance.try_into().expect("Overflow should not happen");

        let cmp = iris
            .compare_threshold(distance, combined_mask.len())
            .await
            .unwrap();

        assert_eq!(cmp, cmp_);
        cmp
    }

    async fn plain_lt_test_inner<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut iris_rng = SmallRng::from_entropy();

        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);
            let code3 = IrisCode::random_rng(&mut iris_rng);
            let code4 = similar_iris(&code3, &mut iris_rng);

            plain_lt_tester::<T>(code1, code2).await;
            assert!(plain_lt_tester::<T>(code3, code4).await);
        }
    }

    #[tokio::test]
    async fn plain_lt_test() {
        plain_lt_test_inner::<u16>().await
    }

    async fn lt_tester_aby3<T: Sharable, R: Rng, Mpc: MpcTrait<T, Share<T>, Share<Bit>>>(
        protocol: &mut IrisProtocol<T, Share<T>, Share<Bit>, Mpc>,
        rng: &mut R,
        code1: IrisCode,
        code2: IrisCode,
    ) -> bool
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let id = protocol.get_id();

        let combined_mask = code1.mask & code2.mask;
        let combined_code = code1.code ^ code2.code;
        let masked_code = combined_code & combined_mask;

        let distance = masked_code.count_ones();
        let threshold =
            (combined_mask.len() as f64 * plain_reference::MATCH_THRESHOLD_RATIO) as usize;
        let cmp_ = distance < threshold;

        let distance = distance.try_into().expect("Overflow should not happen");

        // We simulate the parties already knowing the share of the distance
        let share = Aby3::<Aby3Network>::share(distance, rng).await[id].to_owned();

        let share_cmp = protocol
            .compare_threshold(share, combined_mask.len())
            .await
            .unwrap();

        let cmp = protocol.get_mpc_mut().open_bit(share_cmp).await.unwrap();

        assert_eq!(cmp, cmp_);
        cmp
    }

    async fn lt_test_aby3_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        id: usize,
        port_offset: u16,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = aby3_config::get_protocol::<T>(id, port_offset).await;
        let mut iris = IrisProtocol::new(protocol).unwrap();

        iris.preprocessing().await.unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);
            let code3 = IrisCode::random_rng(&mut iris_rng);
            let code4 = similar_iris(&code3, &mut iris_rng);
            lt_tester_aby3::<T, _, _>(&mut iris, &mut rng, code1, code2).await;
            assert!(lt_tester_aby3::<T, _, _>(&mut iris, &mut rng, code3, code4).await);
        }

        iris.finish().await.unwrap();
    }

    async fn lt_test_aby3_impl<T: Sharable>(port_offset: u16)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let iris_seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();

        for i in 0..NUM_PARTIES {
            let t = tokio::spawn(async move {
                lt_test_aby3_impl_inner::<T, SmallRng>(i, port_offset, seed, iris_seed).await
            });
            tasks.push(t);
        }

        for t in tasks {
            t.await.expect("Task exited normally");
        }
    }

    #[tokio::test]
    #[serial]
    async fn lt_test_aby3() {
        lt_test_aby3_impl::<u16>(165).await
    }

    async fn plain_cmp_iris_tester<T: Sharable>(code1: IrisCode, code2: IrisCode) -> bool
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Plain::default();
        let mut iris: IrisProtocol<T, T, bool, Plain> = IrisProtocol::new(protocol).unwrap();

        let inp1 = code1.code.iter().map(|b| T::from(*b)).collect();
        let inp2 = code2.code.iter().map(|b| T::from(*b)).collect();

        let cmp = iris
            .compare_iris(inp1, inp2, &code1.mask, &code2.mask)
            .await
            .unwrap();

        let cmp_ = code1.is_close(&code2);
        assert_eq!(cmp, cmp_);
        cmp
    }

    async fn plain_cmp_iris_test_inner<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut iris_rng = SmallRng::from_entropy();

        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);
            let code3 = IrisCode::random_rng(&mut iris_rng);
            let code4 = similar_iris(&code3, &mut iris_rng);

            plain_cmp_iris_tester::<T>(code1, code2).await;
            assert!(plain_cmp_iris_tester::<T>(code3, code4).await);
        }
    }

    #[tokio::test]
    async fn plain_cmp_iris_test() {
        plain_cmp_iris_test_inner::<u16>().await
    }
}
