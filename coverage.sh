#!/bin/sh

#export CARGO_INCREMENTAL=0
#export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
#export RUSTDOCFLAGS="-Cpanic=abort"
export RUSTFLAGS="-C instrument-coverage"

rm *.profraw lcov.info
export LLVM_PROFILE_FILE="coverage-%p-%m.profraw"
#cargo build
cargo test

#grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing --ignore "*cargo*" -o ./target/debug/coverage
grcov . --binary-path ./target/debug/ -s . -t lcov --branch --ignore-not-existing --ignore "*cargo*" -o ./lcov.info
