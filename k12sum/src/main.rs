use anyhow::{bail, Context, Result};
use clap::{App, Arg};
use kangarootwelve_xkcp::{Hasher, OutputReader, RATE};
use std::cmp;
use std::fs::File;
use std::io;
use std::io::prelude::*;

const FILE_ARG: &str = "file";
const LENGTH_ARG: &str = "length";
const NO_NAMES_ARG: &str = "no-names";
const RAW_ARG: &str = "raw";
const CUSTOM_ARG: &str = "custom";
const MMAP_ARG: &str = "mmap";

fn clap_parse_argv() -> clap::ArgMatches<'static> {
    App::new("k12sum")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(Arg::with_name(FILE_ARG).multiple(true))
        .arg(
            Arg::with_name(LENGTH_ARG)
                .long(LENGTH_ARG)
                .short("l")
                .takes_value(true)
                .value_name("LEN")
                .help(
                    "The number of output bytes, prior to hex\n\
                     encoding (default 32)",
                ),
        )
        .arg(
            Arg::with_name(NO_NAMES_ARG)
                .long(NO_NAMES_ARG)
                .help("Omits filenames in the output"),
        )
        .arg(Arg::with_name(RAW_ARG).long(RAW_ARG).help(
            "Writes raw output bytes to stdout, rather than hex.\n\
             --no-names is implied. In this case, only a single\n\
             input is allowed.",
        ))
        .arg(
            Arg::with_name(CUSTOM_ARG)
                .long(CUSTOM_ARG)
                .takes_value(true)
                .value_name("STR")
                .help("The optional customization string"),
        )
        .arg(
            Arg::with_name(MMAP_ARG)
                .long(MMAP_ARG)
                .help("Reads the input using memory mapping"),
        )
        .get_matches()
}

// 64 KiB is the minimum needed to use AVX-512.
fn copy_wide(mut reader: impl Read, hasher: &mut Hasher) -> io::Result<u64> {
    let mut buffer = [0; 65536];
    let mut total = 0;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                hasher.update(&buffer[..n]);
                total += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn hash_reader(reader: impl Read, customization: &[u8]) -> Result<OutputReader> {
    let mut hasher = Hasher::new();
    copy_wide(reader, &mut hasher)?;
    Ok(hasher.finalize_custom_xof(customization))
}

fn mmap_file(file: &File) -> Result<memmap::Mmap> {
    let metadata = file.metadata()?;
    let file_size = metadata.len();
    if !metadata.is_file() {
        bail!("not a real file")
    } else if file_size > isize::max_value() as u64 {
        // https://github.com/danburkert/memmap-rs/issues/69
        bail!("too long to safely map")
    } else if file_size == 0 {
        // https://github.com/danburkert/memmap-rs/issues/72
        bail!("cannot mmap empty file")
    } else {
        // Explicitly set the length of the memory map, so that filesystem
        // changes can't race to violate the invariants we just checked.
        let mmap = unsafe {
            memmap::MmapOptions::new()
                .len(file_size as usize)
                .map(&file)?
        };
        Ok(mmap)
    }
}

fn hash_mmap(file: &File, customization: &[u8]) -> Result<OutputReader> {
    let mmap = mmap_file(file).context("mmap failed")?;
    let mut hasher = Hasher::new();
    hasher.update(&mmap);
    Ok(hasher.finalize_custom_xof(customization))
}

fn write_hex_output(mut output: OutputReader, mut len: u64) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    // Encoding multiples of the byte rate is most efficient.
    let mut block = [0; RATE];
    while len > 0 {
        output.squeeze(&mut block);
        let hex_str = hex::encode(&block[..]);
        let take_bytes = cmp::min(len, block.len() as u64);
        stdout.write_all(&hex_str.as_bytes()[..2 * take_bytes as usize])?;
        len -= take_bytes;
    }
    Ok(())
}

fn write_raw_output(output: OutputReader, len: u64) -> Result<()> {
    let mut output = output.take(len);
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    std::io::copy(&mut output, &mut stdout)?;

    Ok(())
}

// Errors from this function get handled by the file loop and printed per-file.
fn hash_file(
    filepath: &std::ffi::OsStr,
    customization: &[u8],
    use_mmap: bool,
) -> Result<OutputReader> {
    let file = File::open(filepath)?;
    if use_mmap {
        hash_mmap(&file, customization)
    } else {
        hash_reader(file, customization)
    }
}

fn main() -> Result<()> {
    let args = clap_parse_argv();
    let output_len = if let Some(length) = args.value_of(LENGTH_ARG) {
        length.parse::<u64>().context("Failed to parse length.")?
    } else {
        32
    };
    let print_names = !args.is_present(NO_NAMES_ARG);
    let raw_output = args.is_present(RAW_ARG);
    let customization = args.value_of(CUSTOM_ARG).unwrap_or("").as_bytes();
    let use_mmap = args.is_present(MMAP_ARG);

    let mut did_error = false;
    if let Some(files) = args.values_of_os(FILE_ARG) {
        if raw_output && files.len() > 1 {
            bail!("k12sum: Only one filename can be provided when using --raw");
        }
        for filepath in files {
            let filepath_str = filepath.to_string_lossy();
            match hash_file(filepath, customization, use_mmap) {
                Ok(output) => {
                    if raw_output {
                        write_raw_output(output, output_len)?;
                    } else {
                        write_hex_output(output, output_len)?;
                        if print_names {
                            println!("  {}", filepath_str);
                        } else {
                            println!();
                        }
                    }
                }
                Err(e) => {
                    did_error = true;
                    eprintln!("k12sum: {}: {}", filepath_str, e);
                }
            }
        }
    } else {
        if use_mmap {
            bail!("k12sum: cannot use --mmap with standard input");
        }
        let stdin = std::io::stdin();
        let stdin = stdin.lock();
        let output = hash_reader(stdin, customization)?;
        if raw_output {
            write_raw_output(output, output_len)?;
        } else {
            write_hex_output(output, output_len)?;
            println!();
        }
    }
    std::process::exit(if did_error { 1 } else { 0 });
}
