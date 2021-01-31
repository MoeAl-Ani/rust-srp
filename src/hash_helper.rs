#[allow(dead_code)]
use sha2::{Digest};
use sha2::digest::Output;

/// generic hashing function returns generic array
///
/// # Arguments
/// * `args` - var number of &[u8]
///
pub fn hash<D: Digest>(args: &[&[u8]]) -> Output<D> {
    let mut hasher = D::new();
    for arg in args {
        hasher.update(arg);
    }
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use crate::hash_helper::hash;

    #[test]
    fn test_hashing() {
        let hash = hash::<sha2::Sha256>(&[b"hello world"]);
        assert_eq!(&hash[..], &[185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233])
    }

    #[test]
    fn test_hashing_bigint() {
        let byte_array = hash::<sha2::Sha256>(&[b"12345678"]);
        let _hash = hex::encode_upper(&byte_array[..]);
    }
}