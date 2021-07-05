# Embedded Rust Debugger
This is a debugger for embedded rust code.
It is in an early state so it doesn't work for a lot of different microcontrollers.

This debugger is an example of how my debugging [library](https://github.com/Blinningjr/rust-debug) can be used.

## Use
Start by cloning the repository, then use it by running.
```
cargo run <ELF-FILE>
```
or
```
cargo run -- -m server
```

To see the available commands type `help` in the CLI.


## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

