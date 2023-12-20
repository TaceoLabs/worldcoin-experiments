use super::polynomial::Poly;
use crate::types::ring_element::RingImpl;

pub struct IrreduciblePolys {}

impl IrreduciblePolys {
    const D40: u64 = 1099522486571;
    const D41: u64 = 2199023255561;
    const D42: u64 = 4399239010919;
    const D43: u64 = 8796093022297;
    const D44: u64 = 17592203542555;
    const D45: u64 = 35184373323841;
    const D46: u64 = 70368755859457;
    const D47: u64 = 140737488355361;
    const D48: u64 = 281475018792329;
    const D49: u64 = 562949953422687;
    const D50: u64 = 1125900847118165;
    const D51: u64 = 2251799813788225;
    const D52: u64 = 4503600141354131;
    const D53: u64 = 9007199254741063;
    const D54: u64 = 18014423912784023;
    const D55: u64 = 36028797018967697;
    const D56: u64 = 72057603773459229;
    const D57: u64 = 144115188078554495;
    const D58: u64 = 288230378958036459;
    const D59: u64 = 576460752303423611;
    const D60: u64 = 1152981527954067773;
    const D61: u64 = 2305843009213693991;
    const D62: u64 = 4611686024857219139;
    const D63: u64 = 9223372036884368159;

    fn get_inner(d: usize) -> u64 {
        match d {
            40 => Self::D40,
            41 => Self::D41,
            42 => Self::D42,
            43 => Self::D43,
            44 => Self::D44,
            45 => Self::D45,
            46 => Self::D46,
            47 => Self::D47,
            48 => Self::D48,
            49 => Self::D49,
            50 => Self::D50,
            51 => Self::D51,
            52 => Self::D52,
            53 => Self::D53,
            54 => Self::D54,
            55 => Self::D55,
            56 => Self::D56,
            57 => Self::D57,
            58 => Self::D58,
            59 => Self::D59,
            60 => Self::D60,
            61 => Self::D61,
            62 => Self::D62,
            63 => Self::D63,
            _ => panic!("d must be between 40 and 63"),
        }
    }

    pub fn get<R: RingImpl>(d: usize) -> Poly<R> {
        let mut poly = Self::get_inner(d);
        let mut vec = Vec::with_capacity(d + 1);
        for _ in 0..=d {
            let bit = poly & 1 == 1;
            vec.push(R::from(bit));
            poly >>= 1;
        }
        Poly::from_vec(vec)
    }
}
