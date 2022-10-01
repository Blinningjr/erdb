# Embedded Rust Debugger (ERDB)

A debugger for rust on embedded systems.

ERDB currently only work on Linux.
It is only tested on a `STM32F411RETx` dev board.

## Features
* Flash target.
* Continue, halt, step, and reset program.
* Set and clear hardware breakpoints.
* Print variables, registers, MCU status, and more.
* Print stack trace.
* Disassemble machine code.

## Installation

```sh
cargo install --path .
```

## Crate rust-debug

ERDB is built using the debug crate [rust-debug](https://github.com/Blinningjr/rust-debug).
Therefore, this is a great example of how to use that crate.

## License

Licensed under either of

* Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
* MIT license
   ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

