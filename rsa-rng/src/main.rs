use std::io::{stdin, stdout, BufRead, Write};

use crypto_bigint::{modular::{MontyForm, MontyParams}, rand_core::CryptoRngCore, BitOps, Concat, NonZero, Odd, RandomMod, Split, Uint, U256};
use crypto_primes::generate_prime_with_rng;
use rand::RngCore;

fn main() {
    let mut rng = RsaRng::<{U256::LIMBS}>::new(&mut rand::thread_rng());
    dbg!(rng.next_u64());
}

pub struct RsaRng<const LIMBS: usize = 125> {
    x: MontyForm<LIMBS>
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> RsaRng<LIMBS>
where // awful generics \/
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>
{
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let p: Uint<LIMBS> = generate_prime_with_rng(rng, Uint::<LIMBS>::BITS / 2);
        let q: Uint<LIMBS> = generate_prime_with_rng(rng, Uint::<LIMBS>::BITS / 2);

        let n = p * q;

        let x = Uint::<LIMBS>::random_mod(rng, &NonZero::new(n).unwrap());
        let monty_params: MontyParams<LIMBS> = MontyParams::new(Odd::new(n).unwrap());

        RsaRng {
            x: MontyForm::new(&x, monty_params)
        }
    }
}

impl<const LIMBS: usize> RngCore for RsaRng<LIMBS>  {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let e = Uint::<LIMBS>::from_u64(65537);

        for byte in dest {
            *byte = 0;
            for _ in 0..8 {
                *byte *= 2;
                if self.x.as_montgomery().bit(0).into() {
                    *byte += 1;
                }

                self.x = self.x.pow(&e);
            }
        }
    }

    fn next_u32(&mut self) -> u32 {
        let mut arr = [0;4];
        self.fill_bytes(arr.as_mut_slice());
        u32::from_le_bytes(arr)
    }

    fn next_u64(&mut self) -> u64 {
        let mut arr = [0;8];
        self.fill_bytes(arr.as_mut_slice());
        u64::from_le_bytes(arr)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest); Ok(())
    }
}

#[allow(unused)]
fn proof_of_concept() -> anyhow::Result<()> {
    type U = crypto_bigint::U1024;

    let mut rng = rand::rngs::OsRng;

    let mut stdin = stdin().lock().lines();

    print!("prime bit count: "); stdout().flush()?;
    let prime_bits: u32 = stdin.next().unwrap()?.parse()?;
    println!();

    let p: U = generate_prime_with_rng(&mut rng, prime_bits);
    let q: U = generate_prime_with_rng(&mut rng, prime_bits);

    let n = p * q;
    let phi_n = (p - U::ONE) * (q - U::ONE);

    let x = U::random_mod(&mut rng, &NonZero::new(n).unwrap());

    println!("p={p}\nq={q}\nn={n}\nphi_n={phi_n}\nx={x}\n\n");

    let e = U::from_u64(65537); // 2 ^ 16 + 1

    print!("output bit count: "); stdout().flush()?;
    let output_bits: u32 = stdin.next().unwrap()?.parse()?;
    println!();

    let monty_params = MontyParams::new(Odd::<U>::new(n).unwrap());
    let mut x = MontyForm::new(&x, monty_params);

    let mut output = U::ZERO;
    for i in 0..output_bits {
        output.set_bit(i, x.as_montgomery().bit(0).into());

        x = x.pow(&e);
    }

    println!("{output}");

    Ok(())
}
