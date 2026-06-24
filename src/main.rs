#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2018_idioms)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::upper_case_acronyms)]

use std::{ffi::c_uint, mem};

mod args;
mod bindings;
mod set_1;
mod set_2;
mod utils;

pub fn print_challenge(ch: u8, title: &str, inputs: &[&str], outputs: &[&str]) {
    println!("▸ Challenge {ch}: {title}");

    println!("  input:");
    for input in inputs {
        println!("    {input}");
    }

    println!("  output:");
    for output in outputs {
        println!("    {output}");
    }
}

const CHALLENGES: &[&[fn()]] = &[
    &[
        set_1::challenge_1::run,
        set_1::challenge_2::run,
        set_1::challenge_3::run,
        set_1::challenge_4::run,
        set_1::challenge_5::run,
        set_1::challenge_6::run,
        set_1::challenge_7::run,
        set_1::challenge_8::run,
    ],
    &[
        set_2::challenge_1::run,
        set_2::challenge_2::run,
        set_2::challenge_3::run,
    ],
];

fn main() {
    let args = args::Args::parse();

    let mut seed: c_uint = 0;
    unsafe {
        bindings::getrandom((&raw mut seed).cast(), mem::size_of::<c_uint>(), 0);
        bindings::srand(seed);
    }

    CHALLENGES
        .get(args.set - 1)
        .unwrap_or_else(|| {
            report_err!(&args.program, "set '{}' unimplemented", args.set);
            std::process::exit(1);
        })
        .get(args.challenge - 1)
        .unwrap_or_else(|| {
            report_err!(
                &args.program,
                "challenge '{}' unimplemented",
                args.challenge
            );
            std::process::exit(1);
        })();
}
