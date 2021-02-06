# SRP (secure remote password)
Implementation based on the [RFC5054](https://tools.ietf.org/html/rfc5054) specification. See also the SRP description at [Wikipedia](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol).

Only SHA-256 is currently supported, others are planned in the future.

## Usage
Add the library to your `cargo.toml`:
```bash
[dependencies]
...
rust-srp = "0.1.8"
...
```

## Routines
High-level description of the client-server interaction. An example can also be found from the test case [test_srp_client_server](https://github.com/MoeAl-Ani/rust-srp/blob/1c18186881eeea73cc32ee9a985bcbd84df848ab/src/lib.rs#L321).

### Client routine
```rust
let n = <bigint>;
let g = <bigint>;
// Create the client
let mut client = SrpClient::new(n.clone(), g.clone());
// Create public key (A, bigint)
let a = client.step_1(<username>.clone(), <password>.clone());
// Create a client evidence (M1, bigint)
let m_1 = client.step_2(<salt>.clone(), b.clone());
// Validate server evidence (M2, bigint).
// Note: At this point the client is no longer usable, as it has passed its ownership to the function.
client.step_3(m_2)
```

### Server routine
```rust
let n = <bigint>;
let g = <bigint>;
// Create server with the public client key A
let mut server = SrpServer::new(a, n.clone(), g.clone());
// Create public key B by locating the SRP params for user identity I
let b = server.step_1(<username>.clone(), <salt>.clone(), <verifier>.clone());
// Validate client evidence M1, and create server evidence M2.
// Note: At this point the server is no longer valid, as it has passed its ownership to the function.
let m_2 = server.step_2(m_1);
// If M1 is valid, then from the server's point of view, client is now authenticated
```