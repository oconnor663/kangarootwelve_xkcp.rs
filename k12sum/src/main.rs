use anyhow::{Result, bail, ensure};
use clap::Parser;
use std::cmp;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

const NAME: &str = "k12sum";

#[derive(Parser)]
#[command(version, max_term_width(100))]
struct Args {
    /// Files to hash, or checkfiles to check
    ///
    /// When no file is given, or when - is given, read standard input.
    file: Vec<PathBuf>,

    /// The number of output bytes, before hex encoding
    #[arg(short, long, default_value_t = 32, value_name("LEN"))]
    length: u64,

    /// The optional customization string
    ///
    /// Cannot be used with --keyed.
    #[arg(long, value_name("STR"))]
    custom: Option<String>,

    /// Enable memory mapping
    #[arg(long)]
    mmap: bool,

    /// Omit filenames in the output
    #[arg(long)]
    no_names: bool,

    /// Write raw output bytes to stdout, rather than hex
    ///
    /// --no-names is implied. In this case, only a single input is allowed.
    #[arg(long)]
    raw: bool,

    /// Read K12 sums from the [FILE]s and check them
    #[arg(
        short,
        long,
        conflicts_with("custom"),
        conflicts_with("length"),
        conflicts_with("raw"),
        conflicts_with("no_names")
    )]
    check: bool,

    /// Skip printing OK for each checked file
    ///
    /// Must be used with --check.
    #[arg(long, requires("check"))]
    quiet: bool,
}

enum Input {
    Mmap(io::Cursor<memmap::Mmap>),
    File(File),
    Stdin,
}

impl Input {
    // Open an input file, using mmap if appropriate. "-" means stdin. Note
    // that this convention applies both to command line arguments, and to
    // filepaths that appear in a checkfile.
    fn open(path: &Path, args: &Args) -> Result<Self> {
        if path == Path::new("-") {
            if args.mmap {
                bail!("cannot use --mmap with standard input");
            }
            return Ok(Self::Stdin);
        }
        let file = File::open(path)?;
        if args.mmap {
            let mmap = mmap_file(&file)?;
            return Ok(Self::Mmap(io::Cursor::new(mmap)));
        }
        Ok(Self::File(file))
    }

    fn hash(&mut self, args: &Args) -> Result<kangarootwelve_xkcp::OutputReader> {
        let mut hasher = kangarootwelve_xkcp::Hasher::new();
        match self {
            Self::Mmap(cursor) => {
                hasher.update(cursor.get_ref());
            }
            Self::File(file) => {
                copy_wide(file, &mut hasher)?;
            }
            Self::Stdin => {
                let stdin = io::stdin();
                let lock = stdin.lock();
                copy_wide(lock, &mut hasher)?;
            }
        }
        Ok(hasher.finalize_custom_xof(args.custom.as_ref().map(String::as_bytes).unwrap_or(&[])))
    }
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Mmap(cursor) => cursor.read(buf),
            Self::File(file) => file.read(buf),
            Self::Stdin => io::stdin().read(buf),
        }
    }
}

// 64 KiB is the minimum needed to use AVX-512.
fn copy_wide(mut reader: impl Read, hasher: &mut kangarootwelve_xkcp::Hasher) -> io::Result<u64> {
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

fn write_hex_output(mut output: kangarootwelve_xkcp::OutputReader, args: &Args) -> Result<()> {
    // Encoding multiples of the rate is most efficient.
    let mut len = args.length;
    let mut block = [0; kangarootwelve_xkcp::RATE];
    while len > 0 {
        output.squeeze(&mut block);
        let hex_str = hex::encode(&block[..]);
        let take_bytes = cmp::min(len, block.len() as u64);
        print!("{}", &hex_str[..2 * take_bytes as usize]);
        len -= take_bytes;
    }
    Ok(())
}

fn write_raw_output(output: kangarootwelve_xkcp::OutputReader, args: &Args) -> Result<()> {
    let mut output = output.take(args.length);
    let stdout = std::io::stdout();
    let mut handler = stdout.lock();
    std::io::copy(&mut output, &mut handler)?;

    Ok(())
}

struct FilepathString {
    filepath_string: String,
    is_escaped: bool,
}

// returns (string, did_escape)
fn filepath_to_string(filepath: &Path) -> FilepathString {
    let unicode_cow = filepath.to_string_lossy();
    let mut filepath_string = unicode_cow.to_string();
    // If we're on Windows, normalize backslashes to forward slashes. This
    // avoids a lot of ugly escaping in the common case, and it makes
    // checkfiles created on Windows more likely to be portable to Unix. It
    // also allows us to set a blanket "no backslashes allowed in checkfiles on
    // Windows" rule, rather than allowing a Unix backslash to potentially get
    // interpreted as a directory separator on Windows.
    if cfg!(windows) {
        filepath_string = filepath_string.replace('\\', "/");
    }
    let mut is_escaped = false;
    if filepath_string.contains('\\') || filepath_string.contains('\n') {
        filepath_string = filepath_string.replace('\\', "\\\\").replace('\n', "\\n");
        is_escaped = true;
    }
    FilepathString {
        filepath_string,
        is_escaped,
    }
}

fn hex_half_byte(c: char) -> Result<u8> {
    // The hex characters in the hash must be lowercase for now, though we
    // could support uppercase too if we wanted to.
    if '0' <= c && c <= '9' {
        return Ok(c as u8 - '0' as u8);
    }
    if 'a' <= c && c <= 'f' {
        return Ok(c as u8 - 'a' as u8 + 10);
    }
    bail!("Invalid hex");
}

// The `check` command is a security tool. That means it's much better for a
// check to fail more often than it should (a false negative), than for a check
// to ever succeed when it shouldn't (a false positive). By forbidding certain
// characters in checked filepaths, we avoid a class of false positives where
// two different filepaths can get confused with each other.
fn check_for_invalid_characters(utf8_path: &str) -> Result<()> {
    // Null characters in paths should never happen, but they can result in a
    // path getting silently truncated on Unix.
    if utf8_path.contains('\0') {
        bail!("Null character in path");
    }
    // Because we convert invalid UTF-8 sequences in paths to the Unicode
    // replacement character, multiple different invalid paths can map to the
    // same UTF-8 string.
    if utf8_path.contains('�') {
        bail!("Unicode replacement character in path");
    }
    // We normalize all Windows backslashes to forward slashes in our output,
    // so the only natural way to get a backslash in a checkfile on Windows is
    // to construct it on Unix and copy it over. (Or of course you could just
    // doctor it by hand.) To avoid confusing this with a directory separator,
    // we forbid backslashes entirely on Windows. Note that this check comes
    // after unescaping has been done.
    if cfg!(windows) && utf8_path.contains('\\') {
        bail!("Backslash in path");
    }
    Ok(())
}

fn unescape(mut path: &str) -> Result<String> {
    let mut unescaped = String::with_capacity(2 * path.len());
    while let Some(i) = path.find('\\') {
        ensure!(i < path.len() - 1, "Invalid backslash escape");
        unescaped.push_str(&path[..i]);
        match path[i + 1..].chars().next().unwrap() {
            // Anything other than a recognized escape sequence is an error.
            'n' => unescaped.push_str("\n"),
            '\\' => unescaped.push_str("\\"),
            _ => bail!("Invalid backslash escape"),
        }
        path = &path[i + 2..];
    }
    unescaped.push_str(path);
    Ok(unescaped)
}

#[derive(Debug)]
struct ParsedCheckLine {
    file_string: String,
    is_escaped: bool,
    file_path: PathBuf,
    expected_hash: kangarootwelve_xkcp::Hash,
}

fn parse_check_line(mut line: &str) -> Result<ParsedCheckLine> {
    // Trim off the trailing newline, if any.
    line = line.trim_end_matches('\n');
    // If there's a backslash at the front of the line, that means we need to
    // unescape the path below. This matches the behavior of e.g. md5sum.
    let first = if let Some(c) = line.chars().next() {
        c
    } else {
        bail!("Empty line");
    };
    let mut is_escaped = false;
    if first == '\\' {
        is_escaped = true;
        line = &line[1..];
    }
    // The front of the line must be a hash of the usual length, followed by
    // two spaces. The hex characters in the hash must be lowercase for now,
    // though we could support uppercase too if we wanted to.
    let hash_hex_len = 64;
    let num_spaces = 2;
    let prefix_len = hash_hex_len + num_spaces;
    ensure!(line.len() > prefix_len, "Short line");
    ensure!(
        line.chars().take(prefix_len).all(|c| c.is_ascii()),
        "Non-ASCII prefix"
    );
    ensure!(&line[hash_hex_len..][..2] == "  ", "Invalid space");
    // Decode the hash hex.
    let mut hash_bytes = [0; 32];
    let mut hex_chars = line[..hash_hex_len].chars();
    for byte in &mut hash_bytes {
        let high_char = hex_chars.next().unwrap();
        let low_char = hex_chars.next().unwrap();
        *byte = 16 * hex_half_byte(high_char)? + hex_half_byte(low_char)?;
    }
    let expected_hash: kangarootwelve_xkcp::Hash = hash_bytes.into();
    let file_string = line[prefix_len..].to_string();
    let file_path_string = if is_escaped {
        // If we detected a backslash at the start of the line earlier, now we
        // need to unescape backslashes and newlines.
        unescape(&file_string)?
    } else {
        file_string.clone().into()
    };
    check_for_invalid_characters(&file_path_string)?;
    Ok(ParsedCheckLine {
        file_string,
        is_escaped,
        file_path: file_path_string.into(),
        expected_hash,
    })
}

fn hash_one_input(path: &Path, args: &Args) -> Result<()> {
    let mut input = Input::open(path, args)?;
    let output = input.hash(args)?;
    if args.raw {
        write_raw_output(output, args)?;
        return Ok(());
    }
    if args.no_names {
        write_hex_output(output, args)?;
        println!();
        return Ok(());
    }
    let FilepathString {
        filepath_string,
        is_escaped,
    } = filepath_to_string(path);
    if is_escaped {
        print!("\\");
    }
    write_hex_output(output, args)?;
    println!("  {}", filepath_string);
    Ok(())
}

// Returns true for success. Having a boolean return value here, instead of
// passing down the some_file_failed reference, makes it less likely that we
// might forget to set it in some error condition.
fn check_one_line(line: &str, args: &Args) -> bool {
    let parse_result = parse_check_line(&line);
    let ParsedCheckLine {
        file_string,
        is_escaped,
        file_path,
        expected_hash,
    } = match parse_result {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("{}: {}", NAME, e);
            return false;
        }
    };
    let file_string = if is_escaped {
        "\\".to_string() + &file_string
    } else {
        file_string
    };
    let hash_result: Result<kangarootwelve_xkcp::Hash> = Input::open(&file_path, args)
        .and_then(|mut input| input.hash(args))
        .map(|mut hash_output| {
            let mut found_hash_bytes = [0; 32];
            hash_output.squeeze(&mut found_hash_bytes);
            found_hash_bytes.into()
        });
    let found_hash: kangarootwelve_xkcp::Hash = match hash_result {
        Ok(hash) => hash,
        Err(e) => {
            println!("{}: FAILED ({})", file_string, e);
            return false;
        }
    };
    // This is a constant-time comparison.
    if expected_hash == found_hash {
        if !args.quiet {
            println!("{}: OK", file_string);
        }
        true
    } else {
        println!("{}: FAILED", file_string);
        false
    }
}

fn check_one_checkfile(path: &Path, args: &Args, some_file_failed: &mut bool) -> Result<()> {
    let checkfile_input = Input::open(path, args)?;
    let mut bufreader = io::BufReader::new(checkfile_input);
    let mut line = String::new();
    loop {
        line.clear();
        let n = bufreader.read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        // check_one_line() prints errors and turns them into a success=false
        // return, so it doesn't return a Result.
        let success = check_one_line(&line, args);
        if !success {
            *some_file_failed = true;
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut some_file_failed = false;
    let file_args = if !args.file.is_empty() {
        args.file.clone()
    } else {
        vec!["-".into()]
    };
    if args.raw && file_args.len() > 1 {
        bail!("Only one filename can be provided when using --raw");
    }
    for path in &file_args {
        if args.check {
            // A hash mismatch or a failure to read a hashed file will be
            // printed in the checkfile loop, and will not propagate here.
            // This is similar to the explicit error handling we do in the
            // hashing case immediately below. In these cases,
            // some_file_failed will be set to false.
            check_one_checkfile(path, &args, &mut some_file_failed)?;
        } else {
            // Errors encountered in hashing are tolerated and printed to
            // stderr. This allows e.g. `k12sum *` to print errors for
            // non-files and keep going. However, if we encounter any
            // errors we'll still return non-zero at the end.
            let result = hash_one_input(path, &args);
            if let Err(e) = result {
                some_file_failed = true;
                eprintln!("{}: {}: {}", NAME, path.to_string_lossy(), e);
            }
        }
    }
    std::process::exit(if some_file_failed { 1 } else { 0 });
}
