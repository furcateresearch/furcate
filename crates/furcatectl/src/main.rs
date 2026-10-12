//! The operator's tool, as the open edition. Everything is in the library; an
//! edition that adds commands registers them and calls the same entry point
//! from its own binary.

fn main() {
    furcatectl::main()
}
