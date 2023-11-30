#[allow(clippy::module_inception)]
pub mod iris_config {
    use plain_reference::IrisCode;
    use rand::{
        distributions::{Bernoulli, Distribution},
        Rng,
    };

    pub fn create_database<R: Rng>(num_items: usize, rng: &mut R) -> Vec<IrisCode> {
        let mut database = Vec::with_capacity(num_items);
        for _ in 0..num_items {
            database.push(IrisCode::random_rng(rng));
        }
        database
    }

    pub fn similar_iris<R: Rng>(iris: &IrisCode, rng: &mut R) -> IrisCode {
        let mut res = IrisCode {
            code: iris.code,
            mask: iris.mask,
        };
        // flip a few bits in mask and code (like 5%)
        let dist = Bernoulli::new(0.05).unwrap();
        for mut b in res.code.as_mut_bitslice() {
            if dist.sample(rng) {
                b.set(!*b);
            }
        }
        for mut b in res.mask.as_mut_bitslice() {
            if dist.sample(rng) {
                b.set(!*b);
            }
        }

        res
    }
}
