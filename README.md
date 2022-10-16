# Embedded Rust Debugger (erdb)

A debugger for rust on embedded systems.

Erdb currently only work on Linux.
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

## Using

Erdb has the two following modes:

* CLI mode - Starts a TUI in the terminal.
* Server mode - Starts a DAP server.

Erdb will start in CLI mode by default.
More information on the two modes in the subsections bellow.

### CLI Mode

Start erdb with the following command:

```shell
erdb
```

Erdb requires the $3$ following configurations:
 * `chip` - Type of chip, example `STM32F411RETx`.
* `work-directory` - The absolute path to the root of the project directory.
* `elf-file` - The absolute path to the compiled binary/elf file.

Which can be set using the `config` command.


But, the easiest way to use erdb, is to make a shell script that starts erdb and sets all $3$ configurations. It would look something like this:

```shell
#!/bin/bash
erdb --chip STM32F411RETx \
--work-directory /home/niklas/exjobb/nucleo64-rtic-examples \
--binary-file-path /home/niklas/exjobb/nucleo64-rtic-examples/target/thumbv7em-none-eabi/debug/nucleo-rtic-blinking-led
```

### Server Mode

TODO

## Crate rust-debug

Erdb is built using the debug crate [rust-debug](https://github.com/Blinningjr/rust-debug).
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

