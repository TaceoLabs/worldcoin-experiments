use criterion::{black_box, criterion_group, criterion_main, Criterion};
use plain_reference::IrisCode;

fn criterion_benchmark_iriscodearray(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let iris = IrisCode::random_rng(&mut rng);

    c.bench_function("IrisCodeArray::get_bit", move |bench| {
        bench.iter(|| {
            for i in 0..IrisCode::IRIS_CODE_SIZE {
                black_box(iris.code.get_bit(i));
            }
        });
    });
    c.bench_function("IrisCodeArray::bits", move |bench| {
        bench.iter(|| {
            for bit in iris.code.bits() {
                black_box(bit);
            }
        });
    });
    c.bench_function("IrisCodeArray::flip_bit", move |bench| {
        bench.iter(|| {
            for i in 0..IrisCode::IRIS_CODE_SIZE {
                black_box(iris.code.get_bit(i));
            }
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_iriscodearray
);
criterion_main!(benches);
