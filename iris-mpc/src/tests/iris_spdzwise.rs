mod iris_mpc_test {
    use crate::{
        iris::protocol::{IrisProtocol, IrisSpdzWise},
        prelude::{Aby3Share, Bit, MpcTrait, PartyTestNetwork, Sharable, TestNetwork3p},
        spdzwise::{
            protocol::{SpdzWise, TShare, UShare, VecTShare},
            vecshare::VecShare,
        },
        tests::iris_config::iris_config::create_database,
        traits::{mpc_trait::Plain, share_trait::VecShareTrait},
    };
    use plain_reference::IrisCode;
    use rand::{
        distributions::{Distribution, Standard},
        Rng, SeedableRng,
    };
    use rand_chacha::ChaCha12Rng;
    use std::ops::Mul;

    const NUM_PARTIES: usize = PartyTestNetwork::NUM_PARTIES;
    const DB_SIZE: usize = 128;
    const CHUNK_SIZE: usize = 128;
    const TESTRUNS: usize = 5;

    fn iris_code_plain_type<T: Sharable>(code: &IrisCode) -> Vec<T> {
        let mut res = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        for i in 0..IrisCode::IRIS_CODE_SIZE {
            res.push(T::from(code.code.get_bit(i)));
        }
        res
    }

    fn share_iris_code<T: Sharable, R: Rng>(
        code: &IrisCode,
        mac_key: T::VerificationShare,
        id: usize,
        rng: &mut R,
    ) -> VecTShare<T>
    where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
    {
        let mut shared_code = VecShare::with_capacity(IrisCode::IRIS_CODE_SIZE);
        for i in 0..IrisCode::IRIS_CODE_SIZE {
            // We simulate the parties already knowing the shares of the code.
            let shares = SpdzWise::<PartyTestNetwork, T::VerificationShare>::share(
                T::from(code.code.get_bit(i)),
                mac_key,
                rng,
            );
            shared_code.push(shares[id].to_owned());
        }
        shared_code
    }

    async fn hwd_test_spdzwise_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) -> Vec<T>
    where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = SpdzWise::<PartyTestNetwork, T::VerificationShare>::new(net);
        let mut iris = IrisSpdzWise::<T, _>::new(protocol).unwrap();
        let id = iris.get_id();

        iris.preprocessing().await.unwrap();
        iris.set_new_mac_key();
        let r = iris.open_mac_key().await.unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        let mut results = Vec::with_capacity(TESTRUNS);
        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);

            let shared_code1 = share_iris_code::<T, _>(&code1, r, id, &mut rng);
            let shared_code2 = share_iris_code::<T, _>(&code2, r, id, &mut rng);

            let hwd = iris
                .hamming_distance(shared_code1, shared_code2)
                .await
                .unwrap();
            iris.verify().await.unwrap();
            let open_hwd = iris.get_mpc_mut().open(hwd).await.unwrap();
            results.push(open_hwd);
        }

        iris.finish().await.unwrap();
        results
    }

    async fn hwd_test_spdzwise_impl<T: Sharable>()
    where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = ChaCha12Rng::from_entropy();
        let iris_seed = rng.gen::<<ChaCha12Rng as SeedableRng>::Seed>();
        let seed = rng.gen::<<ChaCha12Rng as SeedableRng>::Seed>();
        let mut iris_rng = ChaCha12Rng::from_seed(iris_seed);

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move {
                hwd_test_spdzwise_impl_inner::<T, ChaCha12Rng>(n, seed, iris_seed).await
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
                .expect("Overflow should not happen");
            assert_eq!(&distance, r);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn hwd_test_spdzwise() {
        hwd_test_spdzwise_impl::<u16>().await
    }

    async fn plain_hwd_test_inner<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut iris_rng = ChaCha12Rng::from_entropy();

        let protocol = Plain::default();
        let mut iris: IrisProtocol<T, T, Bit, Plain> = IrisProtocol::new(protocol).unwrap();

        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);

            let a = iris_code_plain_type(&code1);
            let b = iris_code_plain_type(&code2);
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
        let mut iris: IrisProtocol<T, T, Bit, Plain> = IrisProtocol::new(protocol).unwrap();

        let combined_mask = code1.mask & code2.mask;
        let combined_code = code1.code ^ code2.code;
        let masked_code = combined_code & combined_mask;

        let distance = masked_code.count_ones();
        let threshold =
            ((combined_mask.count_ones() as f64) * plain_reference::MATCH_THRESHOLD_RATIO) as usize;
        let cmp_ = distance < threshold;

        let distance = distance.try_into().expect("Overflow should not happen");

        let cmp = iris
            .compare_threshold(distance, combined_mask.count_ones())
            .await
            .unwrap()
            .convert();

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
        let mut iris_rng = ChaCha12Rng::from_entropy();

        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);
            let code3 = code1.get_similar_iris(&mut iris_rng);

            plain_lt_tester::<T>(code1.to_owned(), code2).await;
            assert!(plain_lt_tester::<T>(code1, code3).await);
        }
    }

    #[tokio::test]
    async fn plain_lt_test() {
        plain_lt_test_inner::<u16>().await
    }

    async fn lt_tester_spdzwise<T: Sharable, R: Rng, Mpc: MpcTrait<T, TShare<T>, Aby3Share<Bit>>>(
        protocol: &mut IrisSpdzWise<T, Mpc>,
        rng: &mut R,
        code1: IrisCode,
        code2: IrisCode,
        mac_key: T::VerificationShare,
    ) -> bool
    where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let id = protocol.get_id();

        let combined_mask = code1.mask & code2.mask;
        let combined_code = code1.code ^ code2.code;
        let masked_code = combined_code & combined_mask;

        let distance = masked_code.count_ones();
        let threshold =
            ((combined_mask.count_ones() as f64) * plain_reference::MATCH_THRESHOLD_RATIO) as usize;
        let cmp_ = distance < threshold;

        let distance: T = distance.try_into().expect("Overflow should not happen");

        // We simulate the parties already knowing the share of the distance
        let share =
            SpdzWise::<PartyTestNetwork, T::VerificationShare>::share(distance, mac_key, rng)[id]
                .to_owned();

        // Get enough and triples
        let num_and_triples = protocol.msb_and_gates(1, CHUNK_SIZE);
        protocol
            .precompute_and_triples(num_and_triples)
            .await
            .unwrap();

        let share_cmp = protocol
            .compare_threshold(share, combined_mask.count_ones())
            .await
            .unwrap();

        protocol.verify().await.unwrap();
        let cmp = protocol.get_mpc_mut().open_bit(share_cmp).await.unwrap();

        assert_eq!(cmp, cmp_);
        cmp
    }

    async fn lt_test_spdzwise_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = SpdzWise::<PartyTestNetwork, T::VerificationShare>::new(net);
        let mut iris = IrisSpdzWise::<T, _>::new(protocol).unwrap();

        iris.preprocessing().await.unwrap();
        iris.set_new_mac_key();
        let r = iris.open_mac_key().await.unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);
            let code3 = code1.get_similar_iris(&mut iris_rng);
            lt_tester_spdzwise::<T, _, _>(&mut iris, &mut rng, code1.to_owned(), code2, r).await;
            assert!(lt_tester_spdzwise::<T, _, _>(&mut iris, &mut rng, code1, code3, r).await);
        }

        iris.finish().await.unwrap();
    }

    async fn lt_test_spdzwise_impl<T: Sharable>()
    where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = ChaCha12Rng::from_entropy();
        let iris_seed = rng.gen::<<ChaCha12Rng as SeedableRng>::Seed>();
        let seed = rng.gen::<<ChaCha12Rng as SeedableRng>::Seed>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move {
                lt_test_spdzwise_impl_inner::<T, ChaCha12Rng>(n, seed, iris_seed).await
            });
            tasks.push(t);
        }

        for t in tasks {
            t.await.expect("Task exited normally");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn lt_test_spdzwise() {
        lt_test_spdzwise_impl::<u16>().await
    }

    async fn plain_cmp_many_iris_tester<T: Sharable>(
        code1: IrisCode,
        code2: Vec<IrisCode>,
    ) -> Vec<bool>
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Plain::default();
        let mut iris: IrisProtocol<T, T, Bit, Plain> = IrisProtocol::new(protocol).unwrap();

        let inp1 = iris_code_plain_type(&code1);

        let mut inp2s = Vec::with_capacity(code2.len());
        let mut mask2 = Vec::with_capacity(code2.len());
        let mut cmp_ = Vec::with_capacity(code2.len());
        for code in code2 {
            let c = code1.is_close(&code);
            let inp2 = iris_code_plain_type(&code);
            cmp_.push(c);
            inp2s.push(inp2);
            mask2.push(code.mask);
        }

        let cmp = Bit::convert_vec(
            iris.compare_iris_many(&inp1, &inp2s, &code1.mask, &mask2)
                .await
                .unwrap(),
        );

        assert_eq!(cmp, cmp_);
        cmp
    }

    async fn plain_cmp_iris_tester<T: Sharable>(code1: IrisCode, code2: IrisCode) -> bool
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Plain::default();
        let mut iris: IrisProtocol<T, T, Bit, Plain> = IrisProtocol::new(protocol).unwrap();

        let inp1 = iris_code_plain_type(&code1);
        let inp2 = iris_code_plain_type(&code2);

        let cmp = iris
            .compare_iris(inp1, inp2, &code1.mask, &code2.mask)
            .await
            .unwrap()
            .convert();

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
        let mut iris_rng = ChaCha12Rng::from_entropy();

        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);
            let code3 = code1.get_similar_iris(&mut iris_rng);

            let c1 = plain_cmp_iris_tester::<T>(code1.to_owned(), code2.to_owned()).await;
            let c2 = plain_cmp_iris_tester::<T>(code1.to_owned(), code3.to_owned()).await;
            let c3 = plain_cmp_many_iris_tester::<T>(code1, vec![code2, code3]).await;
            assert_eq!(c1, c3[0]);
            assert_eq!(c2, c3[1]);
            assert!(c2);
        }
    }

    #[tokio::test]
    async fn plain_cmp_iris_test() {
        plain_cmp_iris_test_inner::<u16>().await
    }

    async fn cmp_many_iris_tester_spdzwise<
        T: Sharable,
        R: Rng,
        Mpc: MpcTrait<T, TShare<T>, Aby3Share<Bit>>,
    >(
        protocol: &mut IrisSpdzWise<T, Mpc>,
        rng: &mut R,
        code1: IrisCode,
        code2: Vec<IrisCode>,
        mac_key: T::VerificationShare,
    ) -> Vec<bool>
    where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let id = protocol.get_id();

        let shared_code1 = share_iris_code::<T, _>(&code1, mac_key, id, rng);
        let mut shared_codes2 = Vec::with_capacity(code2.len());
        let mut mask2 = Vec::with_capacity(code2.len());
        let mut cmp_ = Vec::with_capacity(code2.len());

        for code in code2 {
            let c = code1.is_close(&code);
            let shared_code2 = share_iris_code::<T, _>(&code, mac_key, id, rng);
            cmp_.push(c);
            shared_codes2.push(shared_code2);
            mask2.push(code.mask);
        }

        let share_cmp = protocol
            .compare_iris_many(&shared_code1, &shared_codes2, &code1.mask, &mask2)
            .await
            .unwrap();

        protocol.verify().await.unwrap();
        let cmp = protocol
            .get_mpc_mut()
            .open_bit_many(share_cmp)
            .await
            .unwrap();

        assert_eq!(cmp, cmp_);
        cmp
    }

    async fn cmp_iris_tester_spdzwise<
        T: Sharable,
        R: Rng,
        Mpc: MpcTrait<T, TShare<T>, Aby3Share<Bit>>,
    >(
        protocol: &mut IrisSpdzWise<T, Mpc>,
        rng: &mut R,
        code1: IrisCode,
        code2: IrisCode,
        mac_key: T::VerificationShare,
    ) -> bool
    where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let id = protocol.get_id();

        let shared_code1 = share_iris_code::<T, _>(&code1, mac_key, id, rng);
        let shared_code2 = share_iris_code::<T, _>(&code2, mac_key, id, rng);

        let share_cmp = protocol
            .compare_iris(shared_code1, shared_code2, &code1.mask, &code2.mask)
            .await
            .unwrap();

        protocol.verify().await.unwrap();
        let cmp = protocol.get_mpc_mut().open_bit(share_cmp).await.unwrap();

        let cmp_ = code1.is_close(&code2);
        assert_eq!(cmp, cmp_);
        cmp
    }

    async fn cmp_iris_test_spdzwise_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = SpdzWise::<PartyTestNetwork, T::VerificationShare>::new(net);
        let mut iris = IrisSpdzWise::<T, _>::new(protocol).unwrap();

        iris.preprocessing().await.unwrap();
        iris.set_new_mac_key();
        let r = iris.open_mac_key().await.unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        for _ in 0..TESTRUNS {
            // Get enough and triples
            let num_and_triples = iris.msb_and_gates(1, CHUNK_SIZE);
            iris.precompute_and_triples(num_and_triples).await.unwrap();

            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);
            let code3 = code1.get_similar_iris(&mut iris_rng);

            let c1 = cmp_iris_tester_spdzwise::<T, _, _>(
                &mut iris,
                &mut rng,
                code1.to_owned(),
                code2.to_owned(),
                r,
            )
            .await;
            iris.precompute_and_triples(num_and_triples).await.unwrap();
            let c2 = cmp_iris_tester_spdzwise::<T, _, _>(
                &mut iris,
                &mut rng,
                code1.to_owned(),
                code3.to_owned(),
                r,
            )
            .await;
            iris.precompute_and_triples(2 * num_and_triples)
                .await
                .unwrap();
            let c3 = cmp_many_iris_tester_spdzwise::<T, _, _>(
                &mut iris,
                &mut rng,
                code1,
                vec![code2, code3],
                r,
            )
            .await;
            assert_eq!(c1, c3[0]);
            assert_eq!(c2, c3[1]);
            assert!(c2);
        }

        iris.finish().await.unwrap();
    }

    async fn cmp_iris_test_spdzwise_impl<T: Sharable>()
    where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = ChaCha12Rng::from_entropy();
        let iris_seed = rng.gen::<<ChaCha12Rng as SeedableRng>::Seed>();
        let seed = rng.gen::<<ChaCha12Rng as SeedableRng>::Seed>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move {
                cmp_iris_test_spdzwise_impl_inner::<T, ChaCha12Rng>(n, seed, iris_seed).await
            });
            tasks.push(t);
        }

        for t in tasks {
            t.await.expect("Task exited normally");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn cmp_iris_test_spdzwise() {
        cmp_iris_test_spdzwise_impl::<u16>().await
    }

    async fn plain_full_test_inner<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut rng = ChaCha12Rng::from_entropy();

        // gen db and iris
        let db = create_database(DB_SIZE, &mut rng);
        let iris1 = IrisCode::random_rng(&mut rng);
        let iris2 = db[0].get_similar_iris(&mut rng);

        let mut db_t = Vec::with_capacity(db.len());
        let mut masks = Vec::with_capacity(db.len());
        let mut is_in1 = false;
        let mut is_in2 = false;

        // get plain result and share database
        for iris in db {
            is_in1 |= iris1.is_close(&iris);
            is_in2 |= iris2.is_close(&iris);

            let iris_t = iris_code_plain_type(&iris);
            db_t.push(iris_t);
            masks.push(iris.mask);
        }

        // share iris1 and iris2
        let iris1_ = iris_code_plain_type(&iris1);
        let iris2_ = iris_code_plain_type(&iris2);

        // calculate
        let protocol = Plain::default();
        let mut iris: IrisProtocol<T, T, Bit, Plain> = IrisProtocol::new(protocol).unwrap();

        let res1 = iris
            .iris_in_db(&iris1_, &db_t, &iris1.mask, &masks, CHUNK_SIZE)
            .await
            .unwrap();

        let res2 = iris
            .iris_in_db(&iris2_, &db_t, &iris2.mask, &masks, CHUNK_SIZE)
            .await
            .unwrap();

        assert_eq!(res1, is_in1);
        assert_eq!(res2, is_in2);
        assert!(res2);
    }

    #[tokio::test]
    async fn plain_full_test() {
        plain_full_test_inner::<u16>().await
    }

    async fn full_test_spdzwise_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = SpdzWise::<PartyTestNetwork, T::VerificationShare>::new(net);
        let mut iris = IrisSpdzWise::<T, _>::new(protocol).unwrap();
        let id = iris.get_id();

        iris.preprocessing().await.unwrap();
        iris.set_new_mac_key();
        let r = iris.open_mac_key().await.unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);

        // gen db and iris
        let db = create_database(DB_SIZE, &mut iris_rng);
        let iris1 = IrisCode::random_rng(&mut rng);
        let iris2 = db[0].get_similar_iris(&mut rng);

        let mut db_t = Vec::with_capacity(db.len());
        let mut masks = Vec::with_capacity(db.len());
        let mut is_in1 = false;
        let mut is_in2 = false;

        // get plain result and share database
        for iris in db {
            is_in1 |= iris1.is_close(&iris);
            is_in2 |= iris2.is_close(&iris);

            let iris_t = share_iris_code::<T, _>(&iris, r, id, &mut rng);

            db_t.push(iris_t);
            masks.push(iris.mask);
        }

        // share iris1 and iris2
        let iris1_ = share_iris_code::<T, _>(&iris1, r, id, &mut rng);
        let iris2_ = share_iris_code::<T, _>(&iris2, r, id, &mut rng);
        // calculate
        let res1 = iris
            .iris_in_db(&iris1_, &db_t, &iris1.mask, &masks, CHUNK_SIZE)
            .await
            .unwrap();

        let res2 = iris
            .iris_in_db(&iris2_, &db_t, &iris2.mask, &masks, CHUNK_SIZE)
            .await
            .unwrap();

        iris.finish().await.unwrap();

        assert_eq!(res1, is_in1);
        assert_eq!(res2, is_in2);
        assert!(res2);
    }

    async fn full_test_spdzwise_impl<T: Sharable>()
    where
        Standard: Distribution<UShare<T>>,
        Standard: Distribution<T::Share>,
        Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
        Aby3Share<T>: Mul<T::Share, Output = Aby3Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = ChaCha12Rng::from_entropy();
        let iris_seed = rng.gen::<<ChaCha12Rng as SeedableRng>::Seed>();
        let seed = rng.gen::<<ChaCha12Rng as SeedableRng>::Seed>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = tokio::spawn(async move {
                full_test_spdzwise_impl_inner::<T, ChaCha12Rng>(n, seed, iris_seed).await
            });
            tasks.push(t);
        }

        for t in tasks {
            t.await.expect("Task exited normally");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn full_test_spdzwise() {
        full_test_spdzwise_impl::<u16>().await
    }
}
