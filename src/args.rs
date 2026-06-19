use std::{env, process};

#[macro_export]
macro_rules! report_err {
    ($program:expr, $($arg:tt)+) => {{
        eprintln!("\x1b[1;1m{}\x1b[0m: \x1b[1;31merror:\x1b[0m {}", $program, format!($($arg)+));
    }};
}

#[derive(Debug, Default)]
pub struct Args {
    pub program: String,
    pub set: usize,
    pub challenge: usize,
}

impl Args {
    #[must_use]
    pub fn parse() -> Self {
        let mut args = Self::default();
        let mut os_args = env::args().peekable();

        args.program = os_args.next().unwrap_or_else(|| "cryptopals".into());

        while let Some(arg) = os_args.peek() {
            if arg.starts_with('-') {
                let flag_name = os_args
                    .next()
                    .expect("next argument was peeked and should be present");

                if let Some(flag) = PROGRAM_FLAGS
                    .iter()
                    .find(|flag| !flag_name.is_empty() && flag.names.contains(&flag_name.as_str()))
                {
                    match flag.names {
                        ["-s", "--set"] => {
                            if let Some(s) = os_args.next()
                                && let Ok(s) = s.parse::<usize>()
                            {
                                args.set = s;
                            } else {
                                report_err!(&args.program, "invalid set number");
                                print_usage(&args.program);
                            }
                        }
                        ["-c", "--challenge"] => {
                            if let Some(c) = os_args.next()
                                && let Ok(c) = c.parse::<usize>()
                            {
                                args.challenge = c;
                            } else {
                                report_err!(&args.program, "invalid challenge number");
                                print_usage(&args.program);
                            }
                        }
                        _ => {
                            if let Some(run) = flag.run {
                                run(&args.program);
                            }
                        }
                    }
                } else {
                    report_err!(&args.program, "invalid flag: '{flag_name}'");
                    print_usage(&args.program);
                }
            } else {
                report_err!(&args.program, "invalid argument: '{arg}'");
                print_usage(&args.program);
            }
        }

        if args.set == 0 || args.challenge == 0 {
            print_usage(&args.program);
        }

        args
    }
}

struct Flag {
    names: [&'static str; 2],
    description: &'static str,
    run: Option<fn(&str) -> !>,
}

const PROGRAM_FLAGS: &[Flag] = &[
    Flag {
        names: ["-s", "--set"],
        description: "            set containing the challenge.",
        run: None,
    },
    Flag {
        names: ["-c", "--challenge"],
        description: "      challenge to execute.",
        run: None,
    },
    Flag {
        names: ["-h", "--help"],
        description: "           print this summary.",
        run: Some(print_usage),
    },
];

fn print_usage(program: &str) -> ! {
    eprintln!("\x1b[1;1musage:\x1b[0m");
    eprintln!("   {program} -s <set> -c <challenge>");
    eprintln!("\x1b[1;1moptions:\x1b[0m");

    for flag in PROGRAM_FLAGS {
        eprintln!("   {}{}", flag.names.join(", "), flag.description);
    }

    process::exit(1);
}
