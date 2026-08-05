use anyhow::{Result, bail, ensure};
use clap::Parser;
use std::cmp;
use std::fs::File;
use std::io;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

const NAME: &str = "k12sum";
const MINIMUM_MMAP_SIZE: u64 = 16 * 1024; // 16 KiB

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
    #[arg(long, value_name("STR"))]
    custom: Option<String>,

    /// The maximum number of threads to use
    ///
    /// By default, this is the number of logical cores. If this flag is
    /// omitted, or if its value is 0, RAYON_NUM_THREADS is also respected.
    #[arg(long, value_name("NUM"))]
    num_threads: Option<usize>,

    /// Disable memory mapping
    ///
    /// Currently this also disables multithreading.
    #[arg(long)]
    no_mmap: bool,

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
    Mmap(io::Cursor<memmap2::Mmap>),
    File(File),
    Stdin,
}

impl Input {
    // Open an input file, using mmap if appropriate. "-" means stdin. Note
    // that this convention applies both to command line arguments, and to
    // filepaths that appear in a checkfile.
    fn open(path: &Path, args: &Args) -> Result<Self> {
        if path == Path::new("-") {
            return Ok(Self::Stdin);
        }
        let mut file = File::open(path)?;
        if !args.no_mmap {
            if let Some(mmap) = maybe_mmap_file(&mut file)? {
                return Ok(Self::Mmap(io::Cursor::new(mmap)));
            }
        }
        Ok(Self::File(file))
    }

    fn hash(&mut self, args: &Args) -> Result<kangarootwelve_xkcp::OutputReader> {
        let mut hasher = if args.no_mmap || args.num_threads == Some(1) {
            kangarootwelve_xkcp::Hasher::new()
        } else {
            kangarootwelve_xkcp::Hasher::new_rayon()
        };
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

// Try to `mmap` a file, unless it's short enough that ordinary reads are faster, currently 16 KiB.
// Return `Ok(None)` if mapping fails or if we don't attempt it. Only return `Err` for unexpected
// failures that could leave the `File` in a bad state.
//
// This function is copied from the `blake3` crate. See the comments there about safety.
fn maybe_mmap_file(file: &mut File) -> io::Result<Option<memmap2::Mmap>> {
    // Seeking is more reliable than `.metadata()` for getting the length. Either is valid for
    // regular files, but block devices sometimes report zero length despite being mappable. See
    // https://github.com/BLAKE3-team/BLAKE3/pull/487.
    use io::Seek;
    // In debug mode only, check that the cursor is at the beginning. If the seek below fails,
    // we'll leave the cursor where it is, and that can be confusing if it isn't at the beginning.
    // (This function isn't public, but this comes up in test cases.)
    if cfg!(debug_assertions) {
        if let Ok(position) = file.stream_position() {
            assert_eq!(position, 0, "initial file offset isn't at the beginning");
        }
    }
    // Seek to "16 KiB less 1 byte" from end-of-file. For short files, this will generally fail
    // with an invalid argument error and leave the cursor at the beginning. For a regular file of
    // exactly 16383 bytes, it will succeed and return 0, again leaving the cursor at the
    // beginning. For some special/device files like /dev/random, it will also return 0. In all
    // those cases, we can return without doing any extra syscalls to reset the cursor, and let the
    // caller fall back to ordinary reads.
    let seek_offset = MINIMUM_MMAP_SIZE - 1;
    let seek_target = io::SeekFrom::End(-(seek_offset as i64));
    let Ok(offset_len) = file.seek(seek_target) else {
        return Ok(None); // short or unseekable files
    };
    if offset_len == 0 {
        return Ok(None); // either exactly 16383 bytes, or e.g. /dev/random
    }
    // It's UB to produce a slice longer than `isize::MAX`. `memmap2` checks that internally, so
    // it's kind of redundant to check it here, but we need to guard the `usize` cast in any case.
    if offset_len <= isize::MAX as u64 - seek_offset {
        // We have a seekable file that's long enough to be worth mapping, but not too long to map
        // (e.g. on a 32-bit system). Try to map it. If this succeeds, we'll assume the caller
        // isn't going to do any ordinary reads, so we don't need to `rewind`.
        let mut mmap_options = memmap2::MmapOptions::new();
        mmap_options.len((offset_len + seek_offset) as usize); // checked above
        if let Ok(mmap) = unsafe { mmap_options.map(&*file) } {
            return Ok(Some(mmap));
        }
    }
    // `mmap` failed (or would've failed), so we need to `rewind` and let the caller do ordinary
    // reads. This is the only failure case where we return `Err`, since if it does fail somehow
    // (not clear if that's possible in practice), the file cursor position will be wrong.
    file.rewind()?;
    Ok(None)
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
    if filepath_string.contains(['\\', '\n', '\r']) {
        filepath_string = filepath_string
            .replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
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
            'r' => unescaped.push_str("\r"),
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
    // Trim off the trailing newlines, if any.
    line = line.trim_end_matches(['\r', '\n']);
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
        // need to unescape backslashes, newlines, and carriage returns.
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

fn check_one_checkfile(path: &Path, args: &Args, files_failed: &mut u64) -> Result<()> {
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
            // We use `files_failed > 0` to indicate a mismatch, so it's important for correctness
            // that it's impossible for this counter to overflow.
            *files_failed = files_failed.saturating_add(1);
        }
    }
}

fn main() -> Result<()> {
    // wild::args_os() is equivalent to std::env::args_os() on Unix, but on Windows it adds support
    // for globbing.
    let args = Args::parse_from(wild::args_os());
    let mut files_failed = 0u64;
    let file_args = if !args.file.is_empty() {
        args.file.clone()
    } else {
        vec!["-".into()]
    };
    if args.raw && file_args.len() > 1 {
        bail!("Only one filename can be provided when using --raw");
    }
    let mut thread_pool_builder = rayon::ThreadPoolBuilder::new();
    if let Some(num_threads) = args.num_threads {
        thread_pool_builder = thread_pool_builder.num_threads(num_threads);
    }
    let thread_pool = thread_pool_builder.build()?;
    thread_pool.install(|| {
        for path in &file_args {
            if args.check {
                // A hash mismatch or a failure to read a hashed file will be
                // printed in the checkfile loop, and will not propagate here.
                // This is similar to the explicit error handling we do in the
                // hashing case immediately below. In these cases,
                // files_failed will be incremented.
                check_one_checkfile(path, &args, &mut files_failed)?;
            } else {
                // Errors encountered in hashing are tolerated and printed to
                // stderr. This allows e.g. `k12sum *` to print errors for
                // non-files and keep going. However, if we encounter any
                // errors we'll still return non-zero at the end.
                let result = hash_one_input(path, &args);
                if let Err(e) = result {
                    files_failed = files_failed.saturating_add(1);
                    eprintln!("{}: {}: {}", NAME, path.to_string_lossy(), e);
                }
            }
        }
        if args.check && files_failed > 0 {
            eprintln!(
                "{}: WARNING: {} computed checksum{} did NOT match",
                NAME,
                files_failed,
                if files_failed == 1 { "" } else { "s" },
            );
        }
        std::process::exit(if files_failed > 0 { 1 } else { 0 });
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io;
    use std::io::prelude::*;

    #[test]
    fn test_maybe_mmap_small_files() -> io::Result<()> {
        let test_cases = [0, 1, MINIMUM_MMAP_SIZE - 2, MINIMUM_MMAP_SIZE - 1];
        for len in test_cases {
            dbg!(len);
            // Create a file smaller than 16 KiB. `maybe_mmap_file` should return `Ok(None)`.
            let input = vec![0xa5; len as usize];
            let mut f = tempfile::NamedTempFile::new()?;
            f.write_all(&input)?;
            f.flush()?;
            // We have a debug assert that the initial file offset is 0.
            f.rewind()?;
            assert!(maybe_mmap_file(f.as_file_mut())?.is_none());
            // Check that the file cursor remains at start-of-file.
            assert_eq!(f.stream_position()?, 0);
            let mut hasher = kangarootwelve_xkcp::Hasher::new();
            copy_wide(f.as_file_mut(), &mut hasher)?;
            assert_eq!(kangarootwelve_xkcp::hash(&input), hasher.finalize());
        }
        Ok(())
    }

    #[test]
    fn test_maybe_mmap_mappable_files() -> io::Result<()> {
        let test_cases = [MINIMUM_MMAP_SIZE, MINIMUM_MMAP_SIZE + 1];
        for len in test_cases {
            dbg!(len);
            // Create a file that's 16 KiB or larger. `maybe_mmap_file` should return `Ok(Some(_))`.
            let input = vec![0xa5; len as usize];
            let mut f = tempfile::NamedTempFile::new()?;
            f.write_all(&input)?;
            f.flush()?;
            // We have a debug assert that the initial file offset is 0.
            f.rewind()?;
            let Ok(Some(mmap)) = maybe_mmap_file(f.as_file_mut()) else {
                panic!("mmap failed");
            };
            // `maybe_mmap_file` doesn't `rewind` the file in this case, so we need to do that
            // ourselves.
            assert_ne!(f.stream_position()?, 0);
            f.rewind()?;
            assert_eq!(mmap[..], input[..]);
            assert_eq!(
                kangarootwelve_xkcp::hash(&input),
                kangarootwelve_xkcp::hash(&mmap),
            );
            let mut hasher = kangarootwelve_xkcp::Hasher::new();
            copy_wide(f.as_file_mut(), &mut hasher)?;
            assert_eq!(kangarootwelve_xkcp::hash(&input), hasher.finalize());
        }
        Ok(())
    }

    #[test]
    fn test_maybe_mmap_current_exe() -> io::Result<()> {
        // The current executable should always be a regular file larger than 16 KiB, so mmap
        // should ~always succeed. (A filesystem might not support mmap at all, but we don't test
        // any of those in CI.)
        let mut exe_file = File::open(std::env::current_exe()?)?;
        assert!(exe_file.metadata()?.len() > MINIMUM_MMAP_SIZE);
        let mmap = maybe_mmap_file(&mut exe_file)?.expect("maybe_mmap_file should return Some");
        // Mainly we're testing that we got `Some` above, but go ahead and read the mmap just to
        // make sure it doesn't bus fault or anything like that. `maybe_mmap_file` doesn't `rewind`
        // the file in this case, so we need to do that ourselves.
        exe_file.rewind()?;
        let mut hasher = kangarootwelve_xkcp::Hasher::new();
        copy_wide(&exe_file, &mut hasher)?;
        assert_eq!(kangarootwelve_xkcp::hash(&mmap), hasher.finalize());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_unmappable_linux() -> io::Result<()> {
        // I'm not aware of any similarly unmappable paths on macOS or Windows, so this test is
        // Linux-only for now.
        let unmappable_path = "/sys/kernel/btf/vmlinux";
        let mut unmappable_file = File::open(unmappable_path)?;
        // The file is large enough to attempt mmapping.
        assert!(unmappable_file.metadata()?.len() > MINIMUM_MMAP_SIZE);
        // We're allowed to read the file.
        assert_eq!(unmappable_file.read(&mut [0])?, 1);
        // But mmapping the file fails. (We have a debug assert that requires `rewind` here.)
        unmappable_file.rewind()?;
        unsafe { memmap2::Mmap::map(&unmappable_file) }.unwrap_err();
        // `maybe_mmap_file` swallows that error and returns `None`.
        assert!(maybe_mmap_file(&mut unmappable_file)?.is_none());
        Ok(())
    }
}
