#[allow(dead_code)]
mod hash_helper;
pub mod bigint_helper;

use std::borrow::Borrow;
use std::ops::{Add, Mul};

use num::{BigUint, Zero};
use sha2::Sha256;
use bigint_helper::{convert_to_bigint};


use std::io::{Error, ErrorKind};
use crate::hash_helper::hash;

#[derive(Debug)]
pub struct SrpConfig {
    n: BigUint,
    g: BigUint,
}

impl SrpConfig {
    fn new(n: BigUint, g: BigUint) -> Self {
        SrpConfig {
            n,
            g
        }
    }
}

/// Computes the SRP-6 multiplier k = H(N | g)
///
/// <p>Specification: RFC 5054.
/// # Arguments
///
/// * `SrpConfig` - srp configuration {n, g}
///
/// @return The resulting multiplier 'k'.
fn compute_k(config: &SrpConfig) -> BigUint {
    let k = hash::<Sha256>(&[config.n.to_bytes_be().as_slice(), config.g.to_bytes_be().as_slice()]);
    bigint_helper::convert_to_bigint(k.as_slice(), 16).unwrap()
}

/// Computes x = H(s | H(P))
///
/// <p>Note that this method differs from the RFC 5054 recommendation
/// which includes the user identity 'I', i.e. x = H(s | H(I | ":" | P))
///
/// # Arguments
///
/// * `salt` - small random unsigned salt
/// * `password` - the client password
///
/// @return The resulting 'x' value.
pub fn compute_x(salt: &BigUint, password: &str) -> BigUint {
    let x = hash::<Sha256>(&[salt.to_bytes_be().as_slice(), password.as_bytes()]);
    bigint_helper::convert_to_bigint(x.as_slice(), 16).unwrap()
}

/// Computes the random scrambling parameter u = H(A|B)
///
/// <p>Specification: RFC 5054.
///
/// # Arguments
///
/// * `public_a` - The public client value 'A'
/// * `public_b` - The public server value 'B'
///
/// @return The resulting 'u' value.
fn compute_u(public_a: &BigUint, public_b: &BigUint) -> BigUint {
    let hash = hash::<Sha256>(&[public_a.to_bytes_be().as_slice(), public_b.to_bytes_be().as_slice()]);
    bigint_helper::convert_to_bigint(hash.as_slice(), 16).unwrap()
}

/// Computes a verifier v = g^x (mod N)
///
/// <p>Specification: RFC 5054.
///
/// # Arguments
///
/// * `SrpConfig` - srp configuration {n, g}
/// * `x` - private password key
///
/// @return The resulting verifier 'v'.
pub fn compute_v(srp_config: &SrpConfig, x: &BigUint) -> BigUint {
    srp_config.g.modpow(x, &srp_config.n)
}

#[derive(Debug)]
pub struct SrpServer {
    srp_config: SrpConfig,
    srp_state: SrpState,
    username: Option<String>,
    salt: Option<BigUint>,
    verifier: Option<BigUint>,
    public_b: Option<BigUint>,
    u: Option<BigUint>,
    public_a: BigUint,
    ks: Option<BigUint>
}

impl SrpServer {
    pub fn new(public_a: BigUint, n: BigUint, g: BigUint) -> Self {
        let config = SrpConfig::new(n,g);
        if (public_a.clone() % &config.n).is_zero() {
            panic!("bad auth!");
        }
        SrpServer {
            srp_config: config,
            srp_state: SrpState::Init,
            username: None,
            salt: None,
            verifier: None,
            public_b: None,
            u: None,
            public_a,
            ks: None
        }
    }

    pub fn step_1(&mut self, username: String, salt: BigUint, verifier: BigUint) -> Result<BigUint, Error> {
        if !self.srp_state.eq(&SrpState::Init) {
            return Err(Error::new(ErrorKind::InvalidData, "wrong state!"))
        }
        let k = compute_k(&self.srp_config);
        let private_b = bigint_helper::generate_random_256bit_bigint();
        let public_b = (k.clone() * verifier.clone()) + self.srp_config.g.modpow(&private_b, &self.srp_config.n);
        self.username = Some(username);
        self.salt = Some(salt);
        self.verifier = Some(verifier.clone());
        self.u = Some(compute_u(&self.public_a, public_b.borrow()));
        self.public_b = Some(public_b);
        // Steve: SSteve = (Av^u)^b = (g^av^u)^b = [g^a(g^x)^u]^b = (g^(a + ux))^b = (g^b)^(a + ux)
        let ks = self.public_a.clone().mul(&verifier.modpow(&self.u.clone().unwrap(), &self.srp_config.n)).modpow(&private_b, &self.srp_config.n);
        let ks = bigint_helper::convert_to_bigint(hash::<Sha256>(&[ks.clone().to_bytes_be().as_slice()]).as_slice(), 16);
        match ks {
            Ok(ks) => {
                self.ks = Some(ks);
            }
            Err(err) => {
                println!("error converting to big int for ks {}", err);
                self.ks = Some(bigint_helper::generate_random_256bit_bigint());
            }
        }
        self.srp_state = SrpState::Step1;
        Ok(self.public_b.clone().unwrap())
    }

    pub fn step_2(mut self, m1: BigUint) -> Result<BigUint, Error> {
        if !self.srp_state.eq(&SrpState::Step1) {
            return Err(Error::new(ErrorKind::InvalidData, "wrong state!"));
        }
        let m1_computed = self.compute_m1()?;
        if !m1.eq(&m1_computed) {
            return Err(Error::new(ErrorKind::InvalidData, "bad client credentials!"));
        }
        self.srp_state = SrpState::Step2;
        Ok(self.compute_m2(m1)?)
    }

    fn compute_m1(&mut self) -> Result<BigUint, Error> {
        let m1= hash::<Sha256>(&[
            self.public_a.clone().to_bytes_be().as_slice(),
            self.public_b.clone().unwrap().to_bytes_be().as_slice(),
            self.ks.clone().unwrap().to_bytes_be().as_slice()
        ]);
        convert_to_bigint(m1.as_slice(), 16)
    }

    fn compute_m2(&mut self, m1: BigUint) -> Result<BigUint, Error> {
        let m_1 = hash::<Sha256>(&[
            self.public_a.borrow().to_bytes_be().as_slice(),
            m1.to_bytes_be().as_slice(),
            self.ks.clone().unwrap().to_bytes_be().as_slice()
        ]);
        convert_to_bigint(m_1.as_slice(), 16)
    }

}

#[derive(Debug)]
pub struct SrpClient {
    srp_config: SrpConfig,
    srp_state: SrpState,
    username: Option<String>,
    password: Option<String>,
    salt: Option<BigUint>,
    private_a: Option<BigUint>,
    public_a: Option<BigUint>,
    u: Option<BigUint>,
    public_b: Option<BigUint>,
    kc: Option<BigUint>,
    m1: Option<BigUint>
}

impl SrpClient {
    pub fn new(n: BigUint, g:BigUint) -> Self {
        SrpClient {
            srp_config: SrpConfig::new(n,g),
            srp_state: SrpState::Init,
            username: None,
            password: None,
            salt: None,
            private_a: None,
            public_a: None,
            u: None,
            public_b: None,
            kc: None,
            m1: None

        }
    }

    pub fn step_1(&mut self, username: String, password: String) -> Result<BigUint, Error> {
        if !self.srp_state.eq(&SrpState::Init) {
            return Err(Error::new(ErrorKind::InvalidData, "wrong state!"));
        }
        self.username = Some(username);
        self.password = Some(password);
        // compute A
        let private_a = bigint_helper::generate_random_256bit_bigint();
        let a = self.srp_config.g.modpow(&private_a, &self.srp_config.n);
        self.private_a = Some(private_a);
        self.public_a = Some(a.clone());
        self.srp_state = SrpState::Step1;
        Ok(a)
    }

    pub fn step_2(&mut self, salt: BigUint, public_b: BigUint) -> Result<BigUint, Error> {
        if !self.srp_state.eq(&SrpState::Step1) {
            panic!("bad srp state!")
        }
        let u = compute_u(&self.public_a.as_mut().unwrap(), &public_b);
        if public_b.clone().is_zero() || u.clone().is_zero() {
            panic!("bad client auth!");
        }
        self.u = Some(compute_u(&self.public_a.as_mut().unwrap(), &public_b));
        self.salt = Some(salt.clone());
        self.public_b = Some(public_b.clone());
        let x = compute_x(&salt, self.username.clone().unwrap().as_str());
        let k = compute_k(&self.srp_config);
        // Carol: SCarol = (B − kg^x)^(a + ux) = (kv + gb − kg^x)^(a + ux) = (kg^x − kg^x + g^b)^(a + ux) = (g^b)^(a + ux)
        let sc = (public_b - (self.srp_config.g.clone().modpow(&x, &self.srp_config.n)) * k)
            .modpow(&(self.private_a.clone().unwrap().add(&u.mul(&x))), &self.srp_config.n);
        let kc = bigint_helper::convert_to_bigint(hash::<Sha256>(&[sc.borrow().to_bytes_be().as_slice()]).as_slice(), 16).unwrap();
        println!("kc = {}", kc.to_string());
        self.kc = Some(kc);
        let m_1 = self.compute_m1()?;
        self.m1 = Some(m_1.clone());
        self.srp_state = SrpState::Step2;
        Ok(m_1)
    }

    pub fn step_3(mut self, m2: BigUint) -> Result<(), Error> {
        if !self.srp_state.eq(&SrpState::Step2) {
            return Err(Error::new(ErrorKind::InvalidData, "wrong state!"));
        }
        let computed_m2 = self.compute_m2(self.m1.clone().unwrap())?;
        if !m2.eq(&computed_m2) {
            return Err(Error::new(ErrorKind::InvalidData, "bad credentials!"));
        }
        Ok(())
    }


    fn compute_m1(&mut self) -> Result<BigUint, Error> {
        let m_1 = hash::<Sha256>(&[
            self.public_a.clone().unwrap().clone().to_bytes_be().as_slice(),
            self.public_b.clone().unwrap().clone().to_bytes_be().as_slice(),
            self.kc.clone().unwrap().clone().to_bytes_be().as_slice()]);
        convert_to_bigint(m_1.as_slice(), 16)
    }

    fn compute_m2(&mut self, m1: BigUint) -> Result<BigUint, Error> {
        let m_1 = hash::<Sha256>(&[
            self.public_a.clone().unwrap().to_bytes_be().as_slice(),
            m1.to_bytes_be().as_slice(),
            self.kc.clone().unwrap().to_bytes_be().as_slice()
        ]);
        convert_to_bigint(m_1.as_slice(), 16)
    }
}

#[derive(Debug, PartialEq)]
pub enum SrpState {
    Init, Step1, Step2
}

#[cfg(test)]
mod tests {
    use core::iter;

    use rand::{Rng, thread_rng};
    use rand::distributions::Alphanumeric;

    use super::*;

    #[test]
    fn test_srp_config() {
        let n = BigUint::parse_bytes(b"B97F8C656C3DF7179C2B805BBCB3A0DC4B0B6926BF66D0A3C63CF6015625CAF9A4DB4BBE7EB34253FAB0E475A6ACFAE49FD5F22C47A71B5532911B69FE7DF4F8ACEE2F7785D75866CF6D213286FC7EBBBE3BE411ECFA10A70F0C8463DC1182C6F9B6F7666C8691B3D1AB6FD78E9CBF8AAE719EA75CA02BE87AE445C698BF0413", 16).unwrap();
        let g = BigUint::parse_bytes(b"2", 10).unwrap();
        let config = SrpConfig::new(n,g);
        println!("{:?}", config);
    }

    #[test]
    fn test_srp_generate_verifier() {
        let salt = bigint_helper::generate_random_256bit_bigint();
        let x = compute_x(&salt,"pass123");
        println!("private key = {:?}", x);
        let n = BigUint::parse_bytes(b"B97F8C656C3DF7179C2B805BBCB3A0DC4B0B6926BF66D0A3C63CF6015625CAF9A4DB4BBE7EB34253FAB0E475A6ACFAE49FD5F22C47A71B5532911B69FE7DF4F8ACEE2F7785D75866CF6D213286FC7EBBBE3BE411ECFA10A70F0C8463DC1182C6F9B6F7666C8691B3D1AB6FD78E9CBF8AAE719EA75CA02BE87AE445C698BF0413", 16).unwrap();
        let g = BigUint::parse_bytes(b"2", 10).unwrap();
        let verifier = compute_v(&SrpConfig::new(n,g),&x);
        println!("verifier = {:?}", verifier)
    }

    #[test]
    fn test_srp_client_server() {
        let mut users = vec![];
        let mut rng = thread_rng();
        for _ in 0..10 {
            let salt = bigint_helper::generate_random_256bit_bigint();
            let identity: String = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(7)
                .collect();
            let password: String = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(7)
                .collect();

            let x = compute_x(&salt, identity.as_str());
            let n = BigUint::parse_bytes(b"B97F8C656C3DF7179C2B805BBCB3A0DC4B0B6926BF66D0A3C63CF6015625CAF9A4DB4BBE7EB34253FAB0E475A6ACFAE49FD5F22C47A71B5532911B69FE7DF4F8ACEE2F7785D75866CF6D213286FC7EBBBE3BE411ECFA10A70F0C8463DC1182C6F9B6F7666C8691B3D1AB6FD78E9CBF8AAE719EA75CA02BE87AE445C698BF0413", 16).unwrap();
            let g = BigUint::parse_bytes(b"2", 10).unwrap();
            let verifier = compute_v(&SrpConfig::new(n,g), &x);
            users.push(User {
                salt,
                verifier,
                username: identity,
                password
            })
        }

        for user in users {
            let n = BigUint::parse_bytes(b"B97F8C656C3DF7179C2B805BBCB3A0DC4B0B6926BF66D0A3C63CF6015625CAF9A4DB4BBE7EB34253FAB0E475A6ACFAE49FD5F22C47A71B5532911B69FE7DF4F8ACEE2F7785D75866CF6D213286FC7EBBBE3BE411ECFA10A70F0C8463DC1182C6F9B6F7666C8691B3D1AB6FD78E9CBF8AAE719EA75CA02BE87AE445C698BF0413", 16).unwrap();
            let g = BigUint::parse_bytes(b"2", 10).unwrap();
            let mut client = SrpClient::new(n.clone(),g.clone());
            // do client step 1
            let a = client.step_1(user.username.clone(), user.password.clone());
            match a {
                Ok(a) => {
                    // send (A, I) to server
                    let mut server = SrpServer::new(a, n.clone(), g.clone());
                    // do server step 1
                    let b = server.step_1(user.username.clone(), user.salt.clone(), user.verifier.clone());
                    match b {
                        Ok(b) => {
                            // server send salt and b
                            // client step 2
                            let m_1 = client.step_2(user.salt.clone(), b.clone());
                            match m_1 {
                                Ok(m_1) => {
                                    // server step 2
                                    let m_2 = server.step_2(m_1);
                                    match m_2 {
                                        Ok(m_2) => {
                                            match client.step_3(m_2) {
                                                Ok(_) => {}
                                                Err(err) => {
                                                    panic!("{}", err);
                                                }
                                            };
                                        }
                                        Err(err) => {
                                            panic!("{}", err);
                                        }
                                    }
                                }
                                Err(err) => {
                                    panic!("{}", err);
                                }
                            }

                        }
                        Err(err) => {
                            panic!("{}", err);
                        }
                    }
                }
                Err(err) => {
                    panic!("{}", err);
                }
            }

        }
    }

    struct User {
        username: String,
        password: String,
        salt: BigUint,
        verifier: BigUint
    }
}


