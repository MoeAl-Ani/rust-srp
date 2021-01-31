#![crate_name = "bigint_helper"]
use num_bigint::{ToBigInt, RandBigInt};
use num::{BigUint, Num};
use std::io::ErrorKind;

pub fn generate_random_256bit_bigint() -> BigUint {
    let mut rng = rand::thread_rng();
    rng.gen_biguint(256)
}

pub fn convert_to_bigint(data: &[u8], radix: u32) -> Result<BigUint, std::io::Error> {
    if radix == 10 {
        Ok(BigUint::parse_bytes(data, 10).unwrap())
    } else if radix == 16 {
        Ok(BigUint::from_str_radix(hex::encode_upper(data).as_str(), 16).unwrap())
    } else {
        Err(std::io::Error::new(ErrorKind::InvalidInput, "wrong radix provided!"))
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use num::{BigInt, Num};
    use crate::helper::hash_helper;
    use sha2::Sha256;
    use std::io::Error;

    #[test]
    fn test_generate_random() {
        let random = generate_random_256bit_bigint();
    }

    #[test]
    fn test_convert_to_bigint_base10() {
        let num = convert_to_bigint(b"2", 10);
        match num {
            Ok(num) => {
                assert_eq!(&[2], num.to_bytes_be().as_slice())
            }
            Err(err) => {
                println!("{}", err)
            }
        }
    }

    #[test]
    fn test_convert_to_bigint_base16() {
        let num = convert_to_bigint(b"A", 16);
        match num {
            Ok(num) => {
                assert_eq!(&[65], num.to_bytes_be().as_slice())
            }
            Err(err) => {
                println!("{}", err)
            }
        }
    }

    #[test]
    fn test_convert_to_bigint_base100() {
        let num = convert_to_bigint(b"A", 100);
        match num {
            Ok(_) => {
                println!("ok")
            }
            Err(err) => {
                println!("{}", err)
            }
        }
    }
}