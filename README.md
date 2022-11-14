# ifconfig

> Returns some information about _your_ internet connection.

## Development setup

You need to have Rust instanlled. See [Rust Getting started](https://www.rust-lang.org/fr/learn/get-started) for more information.

```sh
cargo build
```

## Release History

* 0.4.0
  * CHANGED: switched from Tide and Async-std to Axum and Tokio
  * UPDATED: updated dependencies libraries
  * UPDATED: IP database updated to November 2022
  * FIXED: a template bug in the rendered HTML page
* 0.3.0
  * First public release version
