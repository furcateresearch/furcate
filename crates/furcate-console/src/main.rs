//! The console, as the open edition. Everything is in the library; an edition
//! that adds to it registers an extension and calls the same entry point from
//! its own binary.

fn main() {
    furcate_console::main()
}
