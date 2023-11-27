// share x = x1 + x2 + x3 where party i has (xi, x{i+1})
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct AShare<T: Sharable> {
    pub(crate) a: T::Share,
    pub(crate) b: T::Share,
    sharetype: PhantomData<T>,
}

impl<T: Sharable> AShare<T> {
    pub(crate) fn new(a: T::Share, b: T::Share) -> Self {
        AShare {
            a,
            b,
            sharetype: PhantomData,
        }
    }
}
