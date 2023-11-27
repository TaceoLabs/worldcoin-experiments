// share x = x1 ^ x2 ^ x3 where party i has (xi, x{i+1})
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct BShare<T: Sharable> {
    pub(crate) a: T::Share,
    pub(crate) b: T::Share,
    sharetype: PhantomData<T>,
}

impl<T: Sharable> Share<T> {
    pub fn new(a: T::Share, b: T::Share) -> Self {
        Share {
            a,
            b,
            sharetype: PhantomData,
        }
    }
}
