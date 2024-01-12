use criterion::{black_box, criterion_group, criterion_main, Criterion};
use iris_mpc::prelude::RingImpl;
use iris_mpc::prelude::{Aby3Share, Sharable};
use num_traits::Zero;
use plain_reference::{IrisCode, IrisCodeArray};

fn variant_combined<T: Sharable>(
    a: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>) {
    let (sum_a, sum_b) = a
        .iter()
        .zip(b.iter())
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .map(|((a_, b_), _)| (a_.to_owned(), b_.to_owned()))
        .reduce(|(aa, ab), (ba, bb)| (aa + ba, ab + bb))
        .expect("Size is not zero");
    (sum_a, sum_b)
}

fn variant_2_separate<T: Sharable>(
    a: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>) {
    let sum_a = a
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .map(|(a_, _)| a_.to_owned())
        .reduce(|aa, ba| aa + ba)
        .expect("Size is not zero");
    let sum_b = b
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .map(|(a_, _)| a_.to_owned())
        .reduce(|aa, ba| aa + ba)
        .expect("Size is not zero");
    (sum_a, sum_b)
}

fn variant_fold<T: Sharable>(
    a: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>) {
    let (sum_a, sum_b) = a
        .iter()
        .zip(b.iter())
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .fold(
            (Aby3Share::<T>::zero(), Aby3Share::<T>::zero()),
            |(aa, ab), ((ba, bb), _)| (aa + ba, ab + bb),
        );
    (sum_a, sum_b)
}

fn variant_fold_2_separate<T: Sharable>(
    a: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>) {
    let sum_a = a
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .fold(Aby3Share::<T>::zero(), |a, (b, _)| a + b);
    let sum_b = b
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .fold(Aby3Share::<T>::zero(), |a, (b, _)| a + b);
    (sum_a, sum_b)
}

fn variant_fold_get_bit<T: Sharable>(
    a: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>) {
    let (sum_a, sum_b) = a
        .iter()
        .zip(b.iter())
        .enumerate()
        .filter(|(i, _)| mask.get_bit(*i))
        .fold(
            (Aby3Share::<T>::zero(), Aby3Share::<T>::zero()),
            |(aa, ab), (_, (ba, bb))| (aa + ba, ab + bb),
        );
    (sum_a, sum_b)
}
fn variant_fold_get_bit_2_separate<T: Sharable>(
    a: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>) {
    let sum_a = a
        .iter()
        .enumerate()
        .filter(|(i, _)| mask.get_bit(*i))
        .fold(Aby3Share::<T>::zero(), |a, (_, b)| a + b);
    let sum_b = b
        .iter()
        .enumerate()
        .filter(|(i, _)| mask.get_bit(*i))
        .fold(Aby3Share::<T>::zero(), |a, (_, b)| a + b);
    (sum_a, sum_b)
}

fn variant_4_combined<T: Sharable>(
    a: &[Aby3Share<T>],
    a_mac: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    b_mac: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>, Aby3Share<T>, Aby3Share<T>) {
    let (sum_a, sum_amac, sum_b, sum_bmac) = a
        .iter()
        .zip(a_mac.iter())
        .zip(b.iter().zip(b_mac.iter()))
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .map(|(((aval, amac), (bval, bmac)), _)| {
            (
                aval.to_owned(),
                amac.to_owned(),
                bval.to_owned(),
                bmac.to_owned(),
            )
        })
        .reduce(|(aa, ab, ba, bb), (aa_, ab_, ba_, bb_)| (aa + aa_, ab + ab_, ba + ba_, bb + bb_))
        .expect("Size is not zero");
    (sum_a, sum_amac, sum_b, sum_bmac)
}

fn variant_4_separate<T: Sharable>(
    a: &[Aby3Share<T>],
    a_mac: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    b_mac: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>, Aby3Share<T>, Aby3Share<T>) {
    let sum_a = a
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .map(|(a_, _)| a_.to_owned())
        .reduce(|aa, ba| aa + ba)
        .expect("Size is not zero");
    let sum_amac = a_mac
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .map(|(a_, _)| a_.to_owned())
        .reduce(|aa, ba| aa + ba)
        .expect("Size is not zero");
    let sum_b = b
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .map(|(a_, _)| a_.to_owned())
        .reduce(|aa, ba| aa + ba)
        .expect("Size is not zero");
    let sum_bmac = b_mac
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .map(|(a_, _)| a_.to_owned())
        .reduce(|aa, ba| aa + ba)
        .expect("Size is not zero");

    (sum_a, sum_amac, sum_b, sum_bmac)
}

fn variant_4_fold<T: Sharable>(
    a: &[Aby3Share<T>],
    a_mac: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    b_mac: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>, Aby3Share<T>, Aby3Share<T>) {
    let (sum_a, sum_amac, sum_b, sum_bmac) = a
        .iter()
        .zip(a_mac.iter())
        .zip(b.iter().zip(b_mac.iter()))
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .fold(
            (
                Aby3Share::<T>::zero(),
                Aby3Share::<T>::zero(),
                Aby3Share::<T>::zero(),
                Aby3Share::<T>::zero(),
            ),
            |(aa, ab, ba, bb), (((aa_, ab_), (ba_, bb_)), _)| {
                (aa + aa_, ab + ab_, ba + ba_, bb + bb_)
            },
        );
    (sum_a, sum_amac, sum_b, sum_bmac)
}

fn variant_fold_4_separate<T: Sharable>(
    a: &[Aby3Share<T>],
    a_mac: &[Aby3Share<T>],
    b: &[Aby3Share<T>],
    b_mac: &[Aby3Share<T>],
    mask: &IrisCodeArray,
) -> (Aby3Share<T>, Aby3Share<T>, Aby3Share<T>, Aby3Share<T>) {
    let sum_a = a
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .fold(Aby3Share::<T>::zero(), |a, (b, _)| a + b);
    let sum_amac = a_mac
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .fold(Aby3Share::<T>::zero(), |a, (b, _)| a + b);
    let sum_b = b
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .fold(Aby3Share::<T>::zero(), |a, (b, _)| a + b);
    let sum_bmac = b_mac
        .iter()
        .zip(mask.bits())
        .filter(|(_, b)| *b)
        .fold(Aby3Share::<T>::zero(), |a, (b, _)| a + b);

    (sum_a, sum_amac, sum_b, sum_bmac)
}

fn criterion_benchmark_iriscodearray<T: Sharable>(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mask = IrisCodeArray::random_rng(&mut rng);
    let a = vec![Aby3Share::<T>::zero(); IrisCode::IRIS_CODE_SIZE];
    let b = vec![Aby3Share::<T>::zero(); IrisCode::IRIS_CODE_SIZE];

    {
        let mut group = c.benchmark_group(&format!("filter_reduce_add_twice, {}bit", T::Share::K));

        group.bench_function("combined", |bench| {
            bench.iter(|| variant_combined(&a, &b, &mask));
        });
        group.bench_function("2 separate ones", |bench| {
            bench.iter(|| variant_2_separate(&a, &b, &mask));
        });
        group.bench_function("fold instead of reduce", |bench| {
            bench.iter(|| variant_fold(&a, &b, &mask));
        });
        group.bench_function("fold instead of reduce, twice", |bench| {
            bench.iter(|| variant_fold_2_separate(&a, &b, &mask));
        });
        group.bench_function(
            "fold instead of reduce, with enumerate & get_bit",
            |bench| {
                bench.iter(|| variant_fold_get_bit(&a, &b, &mask));
            },
        );
        group.bench_function(
            "fold instead of reduce, with enumerate & get_bit, twice",
            |bench| {
                bench.iter(|| variant_fold_get_bit_2_separate(&a, &b, &mask));
            },
        );
        group.bench_function("fold with internal if", |bench| {
            bench.iter(|| {
                let (sum_a, sum_b) = a.iter().zip(b.iter()).zip(mask.bits()).fold(
                    (Aby3Share::<T>::zero(), Aby3Share::<T>::zero()),
                    |(aa, ab), ((ba, bb), b)| if b { (aa + ba, ab + bb) } else { (aa, ab) },
                );
                black_box((sum_a, sum_b))
            });
        });
        group.bench_function("fold with internal if, twice", |bench| {
            bench.iter(|| {
                let sum_a =
                    a.iter()
                        .zip(mask.bits())
                        .fold(
                            Aby3Share::<T>::zero(),
                            |a, (b, bit)| if bit { a + b } else { a },
                        );
                let sum_b =
                    a.iter()
                        .zip(mask.bits())
                        .fold(
                            Aby3Share::<T>::zero(),
                            |a, (b, bit)| if bit { a + b } else { a },
                        );
                black_box((sum_a, sum_b))
            });
        });
        group.finish();
    }

    let a_mac = vec![Aby3Share::<T>::zero(); IrisCode::IRIS_CODE_SIZE];
    let b_mac = vec![Aby3Share::<T>::zero(); IrisCode::IRIS_CODE_SIZE];

    let mut group2 = c.benchmark_group(&format!("filter_reduce_add_4times, {}bit", T::Share::K));
    group2.bench_function("combined", |bench| {
        bench.iter(|| variant_4_combined(&a, &a_mac, &b, &b_mac, &mask));
    });
    group2.bench_function("2 separate ones", |bench| {
        bench.iter(|| variant_4_separate(&a, &a_mac, &b, &b_mac, &mask));
    });
    group2.bench_function("fold instead of reduce", |bench| {
        bench.iter(|| variant_4_fold(&a, &a_mac, &b, &b_mac, &mask));
    });
    group2.bench_function("fold instead of reduce, twice", |bench| {
        bench.iter(|| variant_fold_4_separate(&a, &a_mac, &b, &b_mac, &mask));
    });

    group2.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_iriscodearray::<u16>, criterion_benchmark_iriscodearray::<u64>
);
criterion_main!(benches);
