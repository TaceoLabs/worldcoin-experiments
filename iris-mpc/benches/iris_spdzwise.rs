use criterion::{criterion_group, criterion_main, Criterion};
use iris_mpc::prelude::{
    Aby3, Aby3Share, IrisSpdzWise, MpcTrait, PartyTestNetwork, Sharable, SpdzWise, SpdzWiseShare,
    TestNetwork3p,
};
use plain_reference::{IrisCode, IrisCodeArray};
use rand::{
    distributions::{Distribution, Standard},
    rngs::SmallRng,
    Rng, SeedableRng,
};
use std::ops::Mul;

#[allow(type_alias_bounds)]
pub(crate) type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

fn spdzwise_task<T: Sharable>(
    net: PartyTestNetwork,
    mac_key: SpdzWiseShare<T::VerificationShare>,
    code: Vec<SpdzWiseShare<T::VerificationShare>>,
    mask: IrisCodeArray,
    shared_db: Vec<Vec<SpdzWiseShare<T::VerificationShare>>>,
    masks: Vec<IrisCodeArray>,
) -> bool
where
    Standard: Distribution<UShare<T>>,
    Standard: Distribution<T::Share>,
    Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
    <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
{
    let protocol = SpdzWise::<PartyTestNetwork, T::VerificationShare>::new(net);
    let mut iris = IrisSpdzWise::<T, _>::new(protocol).unwrap();

    iris.preprocessing().unwrap();
    iris.set_mac_key(mac_key);

    let res = iris.iris_in_db(code, &shared_db, &mask, &masks).unwrap();

    iris.finish().unwrap();
    res
}

fn iris_spdzwise<T: Sharable, R: Rng>(
    c: &mut Criterion,
    shared_code: &[Vec<Vec<SpdzWiseShare<T::VerificationShare>>>],
    mac_key: T::VerificationShare,
    masks: &Vec<IrisCodeArray>,
    rng: &mut R,
) where
    Standard: Distribution<UShare<T>>,
    Standard: Distribution<T::Share>,
    Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
    Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
    <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
{
    assert_eq!(shared_code.len(), 3);
    let db_size = shared_code[0].len();
    assert_eq!(db_size, shared_code[1].len());
    assert_eq!(db_size, shared_code[2].len());

    // share an iris
    let iris = IrisCode::random_rng(rng);
    let mut code_a = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
    let mut code_b = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
    let mut code_c = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
    for i in 0..IrisCode::IRIS_CODE_SIZE {
        let shares = SpdzWise::<PartyTestNetwork, T::VerificationShare>::share(
            T::from(iris.code.get_bit(i)),
            mac_key,
            rng,
        );
        assert_eq!(shares.len(), 3);
        code_a.push(shares[0].to_owned());
        code_b.push(shares[1].to_owned());
        code_c.push(shares[2].to_owned());
    }
    let shares = vec![code_a, code_b, code_c];
    let mask = iris.mask;

    // We have to share the mac key as well and give it to the parties
    let mac_keys = Aby3::<PartyTestNetwork>::share(
        mac_key,
        <T::VerificationShare as Sharable>::VerificationShare::default(),
        rng,
    )
    .into_iter()
    .map(|m| SpdzWiseShare::new(Aby3Share::default(), m))
    .collect::<Vec<_>>();

    c.bench_function(
        format!("Iris_matcher spdzwise (DB: {db_size}, 3 parties)").as_str(),
        move |bench| {
            bench.iter(|| {
                let network = TestNetwork3p::new();
                let net = network.get_party_networks();

                let mut parties = Vec::with_capacity(3);
                for (i, n) in net.into_iter().enumerate() {
                    let share = shares[i].to_owned();
                    let mac_key = mac_keys[i].to_owned();
                    let share_code = shared_code[i].to_owned();
                    let masks = masks.to_owned();
                    parties.push(std::thread::spawn(move || {
                        spdzwise_task::<T>(n, mac_key, share, mask, share_code, masks)
                    }));
                }

                for party in parties {
                    party.join().unwrap();
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
fn spdzwise_share_db<T: Sharable, R: Rng>(
    db: Vec<IrisCode>,
    mac_key: T::VerificationShare,
    rng: &mut R,
) -> (
    Vec<Vec<Vec<SpdzWiseShare<T::VerificationShare>>>>,
    Vec<IrisCodeArray>,
)
where
    Standard: Distribution<UShare<T>>,
    Standard: Distribution<T::Share>,
    Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
    Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
    <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
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
            let shares = SpdzWise::<PartyTestNetwork, T::VerificationShare>::share(
                T::from(code.code.get_bit(i)),
                mac_key,
                rng,
            );
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
    let mac_key = rng.gen();
    let db = create_db(db_size, &mut rng);
    let (shared_db, masks) = spdzwise_share_db::<u16, _>(db.to_owned(), mac_key, &mut rng);

    iris_spdzwise::<u16, _>(c, &shared_db, mac_key, &masks, &mut rng);
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
