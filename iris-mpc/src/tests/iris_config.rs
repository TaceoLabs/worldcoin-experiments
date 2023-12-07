#[allow(clippy::module_inception)]
pub mod iris_config {
    use plain_reference::IrisCode;
    use rand::Rng;

    pub fn create_database<R: Rng>(num_items: usize, rng: &mut R) -> Vec<IrisCode> {
        let mut database = Vec::with_capacity(num_items);
        for _ in 0..num_items {
            database.push(IrisCode::random_rng(rng));
        }
        database
    }
}
