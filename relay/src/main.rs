//! Pizzini stateless relay.
//!
//! Hard rules:
//! - No persistent state about clients or messages.
//! - No clearnet bind. Listens on a Tor onion address only.
//! - No logging that survives a process restart.

fn main() {
    println!("pizzini-relay {}: not yet implemented", env!("CARGO_PKG_VERSION"));
}
