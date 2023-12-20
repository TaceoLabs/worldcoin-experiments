use criterion::{black_box, criterion_group, criterion_main, Criterion};
use plain_reference::IrisCode;
use rand::{rngs::SmallRng, Rng, SeedableRng};

fn iris_plain<R: Rng>(c: &mut Criterion, db: &[IrisCode], rng: &mut R) {
    let iris = IrisCode::random_rng(rng);
    let db_size = db.len();

    c.bench_function(
        format!("Iris_matcher plain (DB: {db_size})").as_str(),
        move |bench| {
            bench.iter(|| {
                let mut result = false;
                for code in black_box(db) {
                    result |= iris.is_close(code);
                }
                black_box(result)
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

fn iris_benches(c: &mut Criterion, db_size: usize) {
    let mut rng = SmallRng::from_entropy();
    let db = create_db(db_size, &mut rng);

    iris_plain(c, &db, &mut rng);
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
