mod iris_swift3_test {
    use crate::{
        iris::protocol::IrisProtocol,
        prelude::{MpcTrait, PartyTestNetwork, Sharable, Swift3, TestNetwork3p},
        swift3::share::Share,
        tests::iris_config::iris_config::create_database,
        traits::mpc_trait::Plain,
        types::bit::Bit,
    };
    use plain_reference::{IrisCode, IrisCodeArray};
    use rand::{
        distributions::{Distribution, Standard},
        rngs::SmallRng,
        Rng, SeedableRng,
    };
    use std::ops::Mul;

    const NUM_PARTIES: usize = PartyTestNetwork::NUM_PARTIES;
    const DB_SIZE: usize = 128;
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
        id: usize,
        rng: &mut R,
    ) -> Vec<Share<T>>
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut shared_code = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        for i in 0..IrisCode::IRIS_CODE_SIZE {
            // We simulate the parties already knowing the shares of the code.
            let shares = Swift3::<PartyTestNetwork, _>::share(
                T::from(code.code.get_bit(i)),
                T::VerificationShare::default(),
                rng,
            );
            shared_code.push(shares[id].to_owned());
        }
        shared_code
    }

    fn mask_test_swift3_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) -> Vec<IrisCodeArray>
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Swift3::<PartyTestNetwork, _>::new(net);
        let mut iris = IrisProtocol::new(protocol).unwrap();
        let id = iris.get_id();

        iris.preprocessing().unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        let mut results = Vec::with_capacity(TESTRUNS);
        for _ in 0..TESTRUNS {
            let code = IrisCode::random_rng(&mut iris_rng);

            let shared_code = share_iris_code(&code, id, &mut rng);

            let masked_code = iris.apply_mask(shared_code, &code.mask).unwrap();
            iris.verify().unwrap();
            let open_masked_code = iris.get_mpc_mut().open_many(masked_code).unwrap();

            let mut bitarr = IrisCodeArray::default();
            for (i, code_bit) in open_masked_code.into_iter().enumerate() {
                assert!(code_bit.is_zero() || code_bit.is_one());
                bitarr.set_bit(i, code_bit == T::one());
            }
            results.push(bitarr);
        }

        iris.finish().unwrap();
        results
    }

    fn mask_test_swift3_impl<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let iris_seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let seed: [u8; 32] = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let mut iris_rng = SmallRng::from_seed(iris_seed);

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = std::thread::spawn(move || {
                mask_test_swift3_impl_inner::<T, SmallRng>(n, seed, iris_seed)
            });
            tasks.push(t);
        }

        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let r = t.join().expect("Task exited normally");
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

    #[test]
    fn mask_test_swift3() {
        mask_test_swift3_impl::<u16>()
    }

    fn hwd_test_swift3_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) -> Vec<T>
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Swift3::<PartyTestNetwork, _>::new(net);
        let mut iris = IrisProtocol::new(protocol).unwrap();
        let id = iris.get_id();

        iris.preprocessing().unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        let mut results = Vec::with_capacity(TESTRUNS);
        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);

            let shared_code1 = share_iris_code(&code1, id, &mut rng);
            let shared_code2 = share_iris_code(&code2, id, &mut rng);

            let hwd = iris.hamming_distance(shared_code1, shared_code2).unwrap();
            iris.verify().unwrap();
            let open_hwd = iris.get_mpc_mut().open(hwd).unwrap();
            results.push(open_hwd);
        }

        iris.finish().unwrap();
        results
    }

    fn hwd_test_swift3_impl<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let iris_seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let mut iris_rng = SmallRng::from_seed(iris_seed);

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = std::thread::spawn(move || {
                hwd_test_swift3_impl_inner::<T, SmallRng>(n, seed, iris_seed)
            });
            tasks.push(t);
        }

        let mut results = Vec::with_capacity(NUM_PARTIES);
        for t in tasks {
            let r = t.join().expect("Task exited normally");
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

    #[test]
    #[ignore]
    fn hwd_test_swift3() {
        hwd_test_swift3_impl::<u16>()
    }

    fn plain_hwd_test_inner<T: Sharable>()
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

            let a = iris_code_plain_type(&code1);
            let b = iris_code_plain_type(&code2);
            let distance = iris.hamming_distance(a, b).unwrap();

            let combined_code = code1.code ^ code2.code;
            let distance_: T = combined_code
                .count_ones()
                .try_into()
                .expect("Overflow should not happen");

            assert_eq!(distance, distance_);
        }
    }

    #[test]
    fn plain_hwd_test() {
        plain_hwd_test_inner::<u16>()
    }

    fn plain_lt_tester<T: Sharable>(code1: IrisCode, code2: IrisCode) -> bool
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
            ((combined_mask.count_ones() as f64) * plain_reference::MATCH_THRESHOLD_RATIO) as usize;
        let cmp_ = distance < threshold;

        let distance = distance.try_into().expect("Overflow should not happen");

        let cmp = iris
            .compare_threshold(distance, combined_mask.count_ones())
            .unwrap();

        assert_eq!(cmp, cmp_);
        cmp
    }

    fn plain_lt_test_inner<T: Sharable>()
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
            let code3 = code1.get_similar_iris(&mut iris_rng);

            plain_lt_tester::<T>(code1.to_owned(), code2);
            assert!(plain_lt_tester::<T>(code1, code3));
        }
    }

    #[test]
    fn plain_lt_test() {
        plain_lt_test_inner::<u16>()
    }

    fn lt_tester_swift3<T: Sharable, R: Rng, Mpc: MpcTrait<T, Share<T>, Share<Bit>>>(
        protocol: &mut IrisProtocol<T, Share<T>, Share<Bit>, Mpc>,
        rng: &mut R,
        code1: IrisCode,
        code2: IrisCode,
    ) -> bool
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
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

        let distance = distance.try_into().expect("Overflow should not happen");

        // We simulate the parties already knowing the share of the distance
        let share =
            Swift3::<PartyTestNetwork, _>::share(distance, T::VerificationShare::default(), rng)
                [id]
                .to_owned();

        let share_cmp = protocol
            .compare_threshold(share, combined_mask.count_ones())
            .unwrap();

        protocol.verify().unwrap();
        let cmp = protocol.get_mpc_mut().open_bit(share_cmp).unwrap();

        assert_eq!(cmp, cmp_);
        cmp
    }

    fn lt_test_swift3_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Swift3::<PartyTestNetwork, _>::new(net);
        let mut iris = IrisProtocol::new(protocol).unwrap();

        iris.preprocessing().unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);
            let code3 = code1.get_similar_iris(&mut iris_rng);
            lt_tester_swift3::<T, _, _>(&mut iris, &mut rng, code1.to_owned(), code2);
            assert!(lt_tester_swift3::<T, _, _>(
                &mut iris, &mut rng, code1, code3
            ));
        }

        iris.finish().unwrap();
    }

    fn lt_test_swift3_impl<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let iris_seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = std::thread::spawn(move || {
                lt_test_swift3_impl_inner::<T, SmallRng>(n, seed, iris_seed)
            });
            tasks.push(t);
        }

        for t in tasks {
            t.join().expect("Task exited normally");
        }
    }

    #[test]
    #[ignore]
    fn lt_test_swift3() {
        lt_test_swift3_impl::<u16>()
    }

    fn plain_cmp_many_iris_tester<T: Sharable>(code1: IrisCode, code2: Vec<IrisCode>) -> Vec<bool>
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Plain::default();
        let mut iris: IrisProtocol<T, T, bool, Plain> = IrisProtocol::new(protocol).unwrap();

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

        let cmp = iris
            .compare_iris_many(inp1, &inp2s, &code1.mask, &mask2)
            .unwrap();

        assert_eq!(cmp, cmp_);
        cmp
    }

    fn plain_cmp_iris_tester<T: Sharable>(code1: IrisCode, code2: IrisCode) -> bool
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Plain::default();
        let mut iris: IrisProtocol<T, T, bool, Plain> = IrisProtocol::new(protocol).unwrap();

        let inp1 = iris_code_plain_type(&code1);
        let inp2 = iris_code_plain_type(&code2);

        let cmp = iris
            .compare_iris(inp1, inp2, &code1.mask, &code2.mask)
            .unwrap();

        let cmp_ = code1.is_close(&code2);
        assert_eq!(cmp, cmp_);
        cmp
    }

    fn plain_cmp_iris_test_inner<T: Sharable>()
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
            let code3 = code1.get_similar_iris(&mut iris_rng);

            let c1 = plain_cmp_iris_tester::<T>(code1.to_owned(), code2.to_owned());
            let c2 = plain_cmp_iris_tester::<T>(code1.to_owned(), code3.to_owned());
            let c3 = plain_cmp_many_iris_tester::<T>(code1, vec![code2, code3]);
            assert_eq!(c1, c3[0]);
            assert_eq!(c2, c3[1]);
            assert!(c2);
        }
    }

    #[test]
    fn plain_cmp_iris_test() {
        plain_cmp_iris_test_inner::<u16>()
    }

    fn cmp_many_iris_tester_swift3<T: Sharable, R: Rng, Mpc: MpcTrait<T, Share<T>, Share<Bit>>>(
        protocol: &mut IrisProtocol<T, Share<T>, Share<Bit>, Mpc>,
        rng: &mut R,
        code1: IrisCode,
        code2: Vec<IrisCode>,
    ) -> Vec<bool>
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let id = protocol.get_id();

        let shared_code1 = share_iris_code(&code1, id, rng);
        let mut shared_codes2 = Vec::with_capacity(code2.len());
        let mut mask2 = Vec::with_capacity(code2.len());
        let mut cmp_ = Vec::with_capacity(code2.len());

        for code in code2 {
            let c = code1.is_close(&code);
            let shared_code2 = share_iris_code(&code, id, rng);
            cmp_.push(c);
            shared_codes2.push(shared_code2);
            mask2.push(code.mask);
        }

        let share_cmp = protocol
            .compare_iris_many(shared_code1, &shared_codes2, &code1.mask, &mask2)
            .unwrap();

        protocol.verify().unwrap();
        let cmp = protocol.get_mpc_mut().open_bit_many(share_cmp).unwrap();

        assert_eq!(cmp, cmp_);
        cmp
    }

    fn cmp_iris_tester_swift3<T: Sharable, R: Rng, Mpc: MpcTrait<T, Share<T>, Share<Bit>>>(
        protocol: &mut IrisProtocol<T, Share<T>, Share<Bit>, Mpc>,
        rng: &mut R,
        code1: IrisCode,
        code2: IrisCode,
    ) -> bool
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let id = protocol.get_id();

        let shared_code1 = share_iris_code(&code1, id, rng);
        let shared_code2 = share_iris_code(&code2, id, rng);

        let share_cmp = protocol
            .compare_iris(shared_code1, shared_code2, &code1.mask, &code2.mask)
            .unwrap();

        protocol.verify().unwrap();
        let cmp = protocol.get_mpc_mut().open_bit(share_cmp).unwrap();

        let cmp_ = code1.is_close(&code2);
        assert_eq!(cmp, cmp_);
        cmp
    }

    fn cmp_iris_test_swift3_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Swift3::<PartyTestNetwork, _>::new(net);
        let mut iris = IrisProtocol::new(protocol).unwrap();

        iris.preprocessing().unwrap();

        let mut iris_rng = R::from_seed(iris_seed);
        let mut rng = R::from_seed(seed);
        for _ in 0..TESTRUNS {
            let code1 = IrisCode::random_rng(&mut iris_rng);
            let code2 = IrisCode::random_rng(&mut iris_rng);
            let code3 = code1.get_similar_iris(&mut iris_rng);

            let c1 = cmp_iris_tester_swift3::<T, _, _>(
                &mut iris,
                &mut rng,
                code1.to_owned(),
                code2.to_owned(),
            );
            let c2 = cmp_iris_tester_swift3::<T, _, _>(
                &mut iris,
                &mut rng,
                code1.to_owned(),
                code3.to_owned(),
            );
            let c3 = cmp_many_iris_tester_swift3::<T, _, _>(
                &mut iris,
                &mut rng,
                code1,
                vec![code2, code3],
            );
            assert_eq!(c1, c3[0]);
            assert_eq!(c2, c3[1]);
            assert!(c2);
        }

        iris.finish().unwrap();
    }

    fn cmp_iris_test_swift3_impl<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let iris_seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = std::thread::spawn(move || {
                cmp_iris_test_swift3_impl_inner::<T, SmallRng>(n, seed, iris_seed)
            });
            tasks.push(t);
        }

        for t in tasks {
            t.join().expect("Task exited normally");
        }
    }

    #[test]
    #[ignore]
    fn cmp_iris_test_swift3() {
        cmp_iris_test_swift3_impl::<u16>()
    }

    fn plain_full_test_inner<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        T: Mul<T::Share, Output = T>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut rng = SmallRng::from_entropy();

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
        let mut iris: IrisProtocol<T, T, bool, Plain> = IrisProtocol::new(protocol).unwrap();

        let res1 = iris.iris_in_db(iris1_, &db_t, &iris1.mask, &masks).unwrap();

        let res2 = iris.iris_in_db(iris2_, &db_t, &iris2.mask, &masks).unwrap();

        assert_eq!(res1, is_in1);
        assert_eq!(res2, is_in2);
        assert!(res2);
    }

    #[test]
    fn plain_full_test() {
        plain_full_test_inner::<u16>()
    }

    fn full_test_swift3_impl_inner<T: Sharable, R: Rng + SeedableRng>(
        net: PartyTestNetwork,
        seed: R::Seed,
        iris_seed: R::Seed,
    ) where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let protocol = Swift3::<PartyTestNetwork, _>::new(net);
        let mut iris = IrisProtocol::new(protocol).unwrap();
        let id = iris.get_id();

        iris.preprocessing().unwrap();

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

            let iris_t = share_iris_code(&iris, id, &mut rng);

            db_t.push(iris_t);
            masks.push(iris.mask);
        }

        // share iris1 and iris2
        let iris1_ = share_iris_code(&iris1, id, &mut rng);
        let iris2_ = share_iris_code(&iris2, id, &mut rng);
        // calculate
        let res1 = iris.iris_in_db(iris1_, &db_t, &iris1.mask, &masks).unwrap();

        let res2 = iris.iris_in_db(iris2_, &db_t, &iris2.mask, &masks).unwrap();

        iris.finish().unwrap();

        assert_eq!(res1, is_in1);
        assert_eq!(res2, is_in2);
        assert!(res2);
    }

    fn full_test_swift3_impl<T: Sharable>()
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
        <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        let mut rng = SmallRng::from_entropy();
        let iris_seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();
        let seed = rng.gen::<<SmallRng as SeedableRng>::Seed>();

        let network = TestNetwork3p::new();
        let net = network.get_party_networks();

        for n in net {
            let t = std::thread::spawn(move || {
                full_test_swift3_impl_inner::<T, SmallRng>(n, seed, iris_seed)
            });
            tasks.push(t);
        }

        for t in tasks {
            t.join().expect("Task exited normally");
        }
    }

    #[test]
    #[ignore]
    fn full_test_swift3() {
        full_test_swift3_impl::<u16>()
    }
}
