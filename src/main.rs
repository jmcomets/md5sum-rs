extern crate clap;
extern crate md5;

#[macro_use]
extern crate nom;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io;
use std::iter::FromIterator;
use std::process;

use clap::{Arg, App};

use nom::{is_hex_digit, rest};

const HELP: &'static str =
r#"Usage: md5sum [OPTION]... [FILE]...
Print or check MD5 (128-bit) checksums.

With no FILE, or when FILE is -, read standard input.

  -c, --check          read MD5 sums from the FILEs and check them

The following five options are useful only when verifying checksums:
      --ignore-missing  don't fail or report status for missing files
      --quiet          don't print OK for each successfully verified file
      --status         don't output anything, status code shows success
      --strict         exit non-zero for improperly formatted checksum lines
  -w, --warn           warn about improperly formatted checksum lines

      --help     display this help and exit
      --version  output version information and exit

The sums are computed as described in RFC 1321. When checking, the input
should be a former output of this program. The default mode is to print a
line with checksum, a space and name for each FILE."#;

fn app() -> App<'static, 'static> {
    App::new("md5sum")
        .version("0.1.0")
        .author("Jean-Marie C. <jean.marie.comets@gmail.com>")
        .about("Print or check MD5 (128-bit) checksums.")
        .help(HELP)
        .arg(Arg::with_name("file")
             .multiple(true)
             .takes_value(true))
        .arg(Arg::with_name("check")
             .short("c")
             .long("check")
             .help("read MD5 sums from the FILEs and check them"))
        .arg(Arg::with_name("ignore_missing")
             .long("ignore-missing")
             .help("don't fail or report status for missing files"))
        .arg(Arg::with_name("quiet")
             .long("quiet")
             .help("don't print OK for each successfully verified file"))
        .arg(Arg::with_name("status")
             .long("status")
             .help("don't output anything, status code shows success"))
        .arg(Arg::with_name("strict")
             .long("strict")
             .help("exit non-zero for improperly formatted checksum lines"))
        .arg(Arg::with_name("warn")
             .short("w")
             .long("warn")
             .help("warn about improperly formatted checksum lines"))
}

const STDIN_NAME: &'static str = "-";

fn main() {
    let matches = app().get_matches();

    let filenames = matches.values_of("file")
        .map(Vec::from_iter)
        .unwrap_or(vec![STDIN_NAME]);

    // flags
    let check = matches.is_present("check");
    let ignore_missing = matches.is_present("ignore_missing");
    let quiet = matches.is_present("quiet");
    let status = matches.is_present("status");
    let strict = matches.is_present("strict");
    let warn = matches.is_present("warn");

    macro_rules! print_err {
        ($fmt:tt$(, $arg:expr)*) => {
            if !quiet {
                eprintln!($fmt, $( $arg, )*);
            }
        }
    }

    macro_rules! exit_err {
        ($fmt:tt$(, $arg:expr)*) => {
            eprintln!($fmt, $( $arg, )*);
            process::exit(1);
        }
    }

    if check {
        let mut failed = vec![];
        for filename in filenames {
            read(filename, |r| {
                for line in r.lines() {
                    use MD5Check::*;

                    let md5check = line
                        .map(|line| md5sum_check(&line))
                        .unwrap_or_else(|e| ReadError(filename.to_string(), e));

                    match md5check {
                        MatchSuccess => {
                            println!("{}: OK", filename);
                        }
                        MatchFailed(filename) => {
                            if !status {
                                print_err!("{}: FAILED", filename);
                            }

                            failed.push(filename.to_string());
                        }
                        BadFormat => {
                            if strict {
                                exit_err!("ERROR: line badly formatted");
                            } else if warn {
                                print_err!("WARNING: line badly formatted");
                            }
                        }
                        ReadError(filename, _) => {
                            if ignore_missing {
                                exit_err!("FAILED: coult not read {}", filename);
                            }
                        }
                    }
                }

                Ok(())
            }).unwrap_or_else(|_| {
                if ignore_missing {
                    exit_err!("FAILED: coult not read {}", filename);
                }
            });
        }

        //println!("md5sum: src/main.rs: no properly formatted MD5 checksum lines found");

        if failed.len() > 0 {
            let suffix = if failed.len() > 1 { "s" } else { "" };
            print_err!("md5sum: WARNING: {} computed checksum{} did NOT match", failed.len(), suffix);
            process::exit(1);
        }
    } else {
        for filename in filenames {
            let sum = read_md5sum(filename)
                .unwrap_or_else(|e| {
                    print_err!("Error when reading \"{}\": {:?}", filename, e);
                    process::exit(1);
                });

            println!("{:x}  {}", sum, filename);
        }
    }
}

fn is_hex_str(hs: &str) -> bool {
    hs.bytes().all(|h| is_hex_digit(h))
}

named!(md5sum_output<&str>, verify!(take_str!(32), is_hex_str));

named!(md5sum_line<(&str, &str)>, do_parse!(
        sum:      md5sum_output >> char!(' ') >>
        prefix:   alt!(char!(' ') | char!('*'))>>
        filename: map_res!(rest, ::std::str::from_utf8) >>
        (sum, filename)
    ));

fn read_md5sum_line(line: &str) -> Option<(&str, &str)> {
    md5sum_line(line.as_bytes()).to_full_result().ok()
}

enum MD5Check {
    MatchSuccess,
    MatchFailed(String),
    BadFormat,
    ReadError(String, io::Error),
}

fn md5sum_check(line: &str) -> MD5Check {
    use MD5Check::*;

    match read_md5sum_line(&line) {
        Some((expected, filename)) => {
            md5sum_expect(filename, expected)
        }
        None => {
            BadFormat
        }
    }
}

fn md5sum_expect(filename: &str, expected: &str) -> MD5Check {
    use MD5Check::*;

    match read_md5sum(filename) {
        Ok(sum) => {
            let reached = format!("{:x}", sum);
            if expected != reached {
                MatchFailed(filename.to_string())
            } else {
                MatchSuccess
            }
        }
        Err(e) => {
            ReadError(filename.to_string(), e)
        }
    }
}

fn read_md5sum(filename: &str) -> io::Result<md5::Digest> {
    read(filename, |r| md5sum(r))
}

fn read<F, T>(filename: &str, mut read_fn: F) -> io::Result<T>
    where F: FnMut(&mut BufRead) -> io::Result<T>
{
    let stdin = io::stdin();

    macro_rules! boxed_bufread {
        ($e:expr) => {
            Box::new($e) as Box<BufRead>
        }
    }

    let mut reader = {
        if filename == STDIN_NAME {
            boxed_bufread!(stdin.lock())
        } else {
            let file = File::open(filename).map(BufReader::new)?;
            boxed_bufread!(file)
        }
    };

    read_fn(&mut reader)
}

fn md5sum<R: BufRead>(mut reader: R) -> io::Result<md5::Digest> {
    let mut c = md5::Context::new();

    loop {
        let nb_bytes_read = {
            let bytes = reader.fill_buf()?;

            // EOF -> compute md5
            if bytes.is_empty() {
                return Ok(c.compute());
            }

            c.consume(bytes);

            bytes.len()
        };

        reader.consume(nb_bytes_read);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_validate_checksum_lines() {
        let valid_lines = vec![
            ("262d61a1b7a6df20a71b36563a78cd3b  Cargo.toml",  Some(("262d61a1b7a6df20a71b36563a78cd3b", "Cargo.toml"))),
            ("9e1f74e2cd32f1da3bf795607ddd0366  src/main.rs", Some(("9e1f74e2cd32f1da3bf795607ddd0366", "src/main.rs"))),
            ("9e1f74e2cd32f1da3bf795607ddd0366 *src/lib.rs",  Some(("9e1f74e2cd32f1da3bf795607ddd0366", "src/lib.rs"))),
            ];

        for (line, expected) in valid_lines {
            assert_eq!(expected, read_md5sum_line(line));
        }

        let invalid_lines = vec![
            " 9e1f74e2cd32f1da3bf795607ddd0366  src/main.rs",
            " e1f74e2cd32f1da3bf795607ddd0366  src/main.rs",
            "9e1f74e2cd32f1da3bf795607ddd03664 src/main.rs",
            "9e1f74e2cd32f1da3bf795607ddd0366 -src/main.rs",
            "9e1f74e2cd32f1da3bf795607ddd0366 src/main.rs",
            "9e1f74e2cd32f1da3bf795607ddd0366 src/main.rs ",
        ];

        for line in invalid_lines {
            assert_eq!(None, read_md5sum_line(line));
        }
    }
}
