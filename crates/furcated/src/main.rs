//! The Furcate node agent, as the open daemon. Everything is in the library;
//! an edition that adds to it registers an extension and calls the same entry
//! point from its own binary.

fn main() -> anyhow::Result<()> {
    furcated::main()
}
