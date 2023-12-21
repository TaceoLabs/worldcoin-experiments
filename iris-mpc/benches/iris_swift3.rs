use criterion::{black_box, criterion_group, criterion_main, Criterion};
use iris_mpc::prelude::{
    IrisProtocol, MpcTrait, PartyTestNetwork, Sharable, Swift3, Swift3Share, TestNetwork3p,
};
use plain_reference::{IrisCode, IrisCodeArray};
use rand::{
    distributions::{Distribution, Standard},
    rngs::SmallRng,
    Rng, SeedableRng,
};
use std::ops::Mul;
use tokio::runtime;

async fn iris_swift3_task<T: Sharable>(
    net: PartyTestNetwork,
    code: Vec<Swift3Share<T>>,
    mask: IrisCodeArray,
    shared_db: Vec<Vec<Swift3Share<T>>>,
    masks: Vec<IrisCodeArray>,
) -> bool
where
    Standard: Distribution<T::Share>,
    Swift3Share<T>: Mul<T::Share, Output = Swift3Share<T>>,
    <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
{
    let protocol = Swift3::<PartyTestNetwork, T>::new(net);
    let mut iris = IrisProtocol::new(protocol).unwrap();

    iris.preprocessing().await.unwrap();

    let res = iris
        .iris_in_db(code, &shared_db, &mask, &masks)
        .await
        .unwrap();

    iris.finish().await.unwrap();
    res
}

fn iris_swift3<T: Sharable, R: Rng>(
    c: &mut Criterion,
    shared_code: &[Vec<Vec<Swift3Share<T>>>],
    masks: &Vec<IrisCodeArray>,
    rng: &mut R,
) where
    Standard: Distribution<T::Share>,
    Swift3Share<T>: Mul<T::Share, Output = Swift3Share<T>>,
    <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
{
    assert_eq!(shared_code.len(), 3);
    let db_size = shared_code[0].len();
    assert_eq!(db_size, shared_code[1].len());
    assert_eq!(db_size, shared_code[2].len());

    let rt = runtime::Builder::new_multi_thread()
        .worker_threads(3)
        .build()
        .unwrap();

    // share an iris
    let iris = IrisCode::random_rng(rng);
    let mut code_a = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
    let mut code_b = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
    let mut code_c = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
    for i in 0..IrisCode::IRIS_CODE_SIZE {
        let shares = Swift3::<PartyTestNetwork, T>::share(T::from(iris.code.get_bit(i)), rng);
        assert_eq!(shares.len(), 3);
        code_a.push(shares[0].to_owned());
        code_b.push(shares[1].to_owned());
        code_c.push(shares[2].to_owned());
    }
    let shares = vec![code_a, code_b, code_c];
    let mask = iris.mask;

    c.bench_function(
        format!("Iris_matcher swift3 (DB: {db_size}, 3 parties)").as_str(),
        move |bench| {
            bench.to_async(&rt).iter(|| async {
                let network = TestNetwork3p::new();
                let net = network.get_party_networks();

                let mut parties = Vec::with_capacity(3);
                for (i, n) in net.into_iter().enumerate() {
                    parties.push(tokio::spawn(iris_swift3_task(
                        black_box(n),
                        black_box(shares[i].to_owned()),
                        black_box(mask),
                        black_box(shared_code[i].to_owned()),
                        black_box(masks.to_owned()),
                    )));
                }

                for party in parties {
                    party.await.unwrap();
                    black_box(())
                }
            });
        },
    );
}

fn create_db<R: Rng>(num_items: usize, rng: &mut R) -> Vec<IrisCode> {
    let mut database = Vec::with_capacity(num_items);
    for _ in 0..num_items {
        database.push(IrisCode::random_rng(rng));
    }
    database
}

#[allow(clippy::type_complexity)]
fn swift_share_db<T: Sharable, R: Rng>(
    db: Vec<IrisCode>,
    rng: &mut R,
) -> (Vec<Vec<Vec<Swift3Share<T>>>>, Vec<IrisCodeArray>)
where
    Standard: Distribution<T::Share>,
    Swift3Share<T>: Mul<T::Share, Output = Swift3Share<T>>,
{
    let mut shares_a = Vec::with_capacity(db.len());
    let mut shares_b = Vec::with_capacity(db.len());
    let mut shares_c = Vec::with_capacity(db.len());
    let mut masks = Vec::with_capacity(db.len());

    for code in db {
        let mut code_a = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        let mut code_b = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        let mut code_c = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        for i in 0..IrisCode::IRIS_CODE_SIZE {
            let shares = Swift3::<PartyTestNetwork, T>::share(T::from(code.code.get_bit(i)), rng);
            assert_eq!(shares.len(), 3);
            code_a.push(shares[0].to_owned());
            code_b.push(shares[1].to_owned());
            code_c.push(shares[2].to_owned());
        }
        shares_a.push(code_a);
        shares_b.push(code_b);
        shares_c.push(code_c);
        masks.push(code.mask);
    }

    (vec![shares_a, shares_b, shares_c], masks)
}

fn iris_benches(c: &mut Criterion, db_size: usize) {
    let mut rng = SmallRng::from_entropy();
    let db = create_db(db_size, &mut rng);
    let (shared_db, masks) = swift_share_db::<u16, _>(db, &mut rng);

    iris_swift3(c, &shared_db, &masks, &mut rng);
}

fn criterion_benchmark_iris_mpc(c: &mut Criterion) {
    let db_sizes = [1000];

    for s in db_sizes {
        iris_benches(c, s);
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_iris_mpc
);
criterion_main!(benches);