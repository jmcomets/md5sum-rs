extern crate clap;
extern crate md5;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io;
use std::iter::FromIterator;
use std::process;

use clap::{Arg, App};

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
        .arg(Arg::with_name("FILE")
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

    let filenames = matches.values_of("FILE")
        .map(Vec::from_iter)
        .unwrap_or(vec![STDIN_NAME]);

    let stdin = io::stdin();

    for filename in filenames {
        let mut reader = {
            macro_rules! boxed_bufread {
                ($e:expr) => {
                    Box::new($e) as Box<BufRead>
                }
            }

            if filename == STDIN_NAME {
                boxed_bufread!(stdin.lock())
            } else {
                let file = File::open(&filename)
                    .map(BufReader::new)
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to open {}: {:?}", &filename, e);
                        process::exit(1);
                    });
                boxed_bufread!(file)
            }
        };

        let sum = md5sum(&mut reader);

        println!("{:x}  {}", sum, filename);
    }
}

fn md5sum<R: BufRead>(mut reader: R) -> md5::Digest {
    let mut c = md5::Context::new();

    loop {
        let nb_bytes_read = {
            let bytes = reader.fill_buf()
                .unwrap_or_else(|e| {
                    eprintln!("Failed reading buffer: {:?}", e);
                    process::exit(1);
                });

            // EOF -> compute md5
            if bytes.is_empty() {
                return c.compute();
            }

            c.consume(bytes);

            bytes.len()
        };

        reader.consume(nb_bytes_read);
    }
}
