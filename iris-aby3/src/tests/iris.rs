mod iris_test {
    use crate::{
        aby3::share::Share,
        error::Error,
        iris::protocol::{BitArr, IrisProtocol},
        prelude::{Aby3, Aby3Network, MpcTrait, Sharable},
        tests::aby_config::aby3_config,
    };
    use plain_reference::IrisCode;
    use rand::{
        distributions::{Distribution, Standard},
        rngs::SmallRng,
        Rng, SeedableRng,
    };
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
    {
        let protocol = aby3_config::get_protocol::<T>(id, port_offset).await;
        let mut iris = IrisProtocol::new(protocol);

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
    {
        let protocol = aby3_config::get_protocol::<T>(id, port_offset).await;
        let mut iris = IrisProtocol::new(protocol);

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
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let iris_seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let seed: [u8; 32] = rng.gen::<<SmallRng as SeedableRng>::Seed>();
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
                .map_err(|_| Error::Other("Overflow has happened".to_string()))
                .unwrap();
            assert_eq!(&distance, r);
        }
    }

    #[tokio::test]
    async fn hwd_test_aby3() {
        hwd_test_aby3_impl::<u16>(150).await
    }
}
