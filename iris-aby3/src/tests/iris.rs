mod iris_test {
    use crate::{
        aby3::share::Share, iris::protocol::IrisProtocol, prelude::Sharable,
        tests::aby_config::aby3_config,
    };
    use rand::distributions::{Distribution, Standard};
    use std::ops::Mul;

    const NUM_PARTIES: usize = aby3_config::NUM_PARTIES;

    async fn basic_test_impl_inner<T: Sharable>(id: usize, port_offset: u16) -> bool
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let protocol = aby3_config::get_protocol::<T>(id, port_offset).await;
        let mut iris = IrisProtocol::new(protocol);

        iris.preprocessing().await.unwrap();

        iris.finish().await.unwrap();
        true
    }

    async fn basic_test_impl<T: Sharable>(port_offset: u16)
    where
        Standard: Distribution<T>,
        Standard: Distribution<T::Share>,
        Share<T>: Mul<Output = Share<T>>,
        Share<T>: Mul<T::Share, Output = Share<T>>,
    {
        let mut tasks = Vec::with_capacity(NUM_PARTIES);

        for i in 0..NUM_PARTIES {
            let t = tokio::spawn(async move { basic_test_impl_inner::<T>(i, port_offset).await });
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
    }

    #[tokio::test]
    async fn basic_test() {
        basic_test_impl::<u16>(150).await
    }
}
