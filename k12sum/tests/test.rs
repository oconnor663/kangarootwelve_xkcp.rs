use duct::cmd;
use kangarootwelve_xkcp::{hash, Hasher};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

pub fn k12sum_exe() -> PathBuf {
    env!("CARGO_BIN_EXE_k12sum").into()
}

#[test]
fn test_hash_one() {
    let expected = hash(b"foo");
    let output = cmd!(k12sum_exe()).stdin_bytes("foo").read().unwrap();
    assert_eq!(format!("{}  -", expected.to_hex().as_str()), output);
}

#[test]
fn test_hash_one_raw() {
    let expected = hash(b"foo");
    let output = cmd!(k12sum_exe(), "--raw")
        .stdin_bytes("foo")
        .stdout_capture()
        .run()
        .unwrap()
        .stdout;
    assert_eq!(expected.as_bytes(), output.as_slice());
}

#[test]
fn test_hash_many() {
    let dir = tempfile::tempdir().unwrap();
    let file1 = dir.path().join("file1");
    fs::write(&file1, b"foo").unwrap();
    let file2 = dir.path().join("file2");
    fs::write(&file2, b"bar").unwrap();

    let output = cmd!(k12sum_exe(), &file1, &file2).read().unwrap();
    let foo_hash = hash(b"foo");
    let bar_hash = hash(b"bar");
    let expected = format!(
        "{}  {}\n{}  {}",
        foo_hash.to_hex(),
        // account for slash normalization on Windows
        file1.to_string_lossy().replace("\\", "/"),
        bar_hash.to_hex(),
        file2.to_string_lossy().replace("\\", "/"),
    );
    assert_eq!(expected, output);

    let output_no_names = cmd!(k12sum_exe(), "--no-names", &file1, &file2)
        .read()
        .unwrap();
    let expected_no_names = format!("{}\n{}", foo_hash.to_hex(), bar_hash.to_hex());
    assert_eq!(expected_no_names, output_no_names);

    // Repeat that, with --mmap.
    let output_mmap = cmd!(k12sum_exe(), "--no-names", "--mmap", &file1, &file2)
        .read()
        .unwrap();
    assert_eq!(expected_no_names, output_mmap);
}

#[test]
fn test_customization() {
    let mut hasher = Hasher::new();
    hasher.update(b"foo");
    let expected = hasher.finalize_custom(b"bar");
    let output = cmd!(k12sum_exe(), "--custom", "bar")
        .stdin_bytes("foo")
        .read()
        .unwrap();
    assert_eq!(format!("{}  -", expected.to_hex().as_str()), output);
}

#[test]
fn test_hash_length() {
    let mut hasher = Hasher::new();
    hasher.update(b"foo");
    let mut expected = [0; 100];
    hasher.finalize_xof().squeeze(&mut expected);
    let output = cmd!(k12sum_exe(), "--length=100")
        .stdin_bytes("foo")
        .read()
        .unwrap();
    assert_eq!(format!("{}  -", hex::encode(&expected[..])), output);
}

#[test]
fn test_length_without_value_is_an_error() {
    let result = cmd!(k12sum_exe(), "--length")
        .stdin_bytes("foo")
        .stderr_capture()
        .run();
    assert!(result.is_err());
}

#[test]
fn test_raw_with_multi_files_is_an_error() {
    let f1 = tempfile::NamedTempFile::new().unwrap();
    let f2 = tempfile::NamedTempFile::new().unwrap();

    // Make sure it doesn't error with just one file
    let result = cmd!(k12sum_exe(), "--raw", f1.path())
        .stdout_capture()
        .run();
    assert!(result.is_ok());

    // Make sure it errors when both file are passed
    let result = cmd!(k12sum_exe(), "--raw", f1.path(), f2.path())
        .stderr_capture()
        .run();
    assert!(result.is_err());
}

#[test]
fn test_mmap_stdin_is_an_error() {
    let result = cmd!(k12sum_exe(), "--mmap")
        .stdin_bytes("foo")
        .stderr_capture()
        .run();
    assert!(result.is_err());
}

#[test]
#[cfg(unix)]
fn test_newline_and_backslash_escaping_on_unix() {
    let empty_hash = hash(b"").to_hex();
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("subdir")).unwrap();
    let names = [
        "abcdef",
        "abc\ndef",
        "abc\\def",
        "abc\rdef",
        "abc\r\ndef",
        "subdir/foo",
    ];
    let mut paths = Vec::new();
    for name in &names {
        let path = dir.path().join(name);
        println!("creating file at {:?}", path);
        fs::write(&path, b"").unwrap();
        paths.push(path);
    }
    let output = cmd(k12sum_exe(), &names).dir(dir.path()).read().unwrap();
    let expected = format!(
        "\
{0}  abcdef
\\{0}  abc\\ndef
\\{0}  abc\\\\def
{0}  abc\rdef
\\{0}  abc\r\\ndef
{0}  subdir/foo",
        empty_hash,
    );
    println!("output");
    println!("======");
    println!("{}", output);
    println!();
    println!("expected");
    println!("========");
    println!("{}", expected);
    println!();
    assert_eq!(expected, output);
}

#[test]
#[cfg(windows)]
fn test_slash_normalization_on_windows() {
    let empty_hash = hash(b"").to_hex();
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("subdir")).unwrap();
    // Note that filenames can't contain newlines or backslashes on Windows, so
    // we don't test escaping here. We only test forward slash and backslash as
    // directory separators.
    let names = ["abcdef", "subdir/foo", "subdir\\bar"];
    let mut paths = Vec::new();
    for name in &names {
        let path = dir.path().join(name);
        println!("creating file at {:?}", path);
        fs::write(&path, b"").unwrap();
        paths.push(path);
    }
    let output = cmd(k12sum_exe(), &names).dir(dir.path()).read().unwrap();
    let expected = format!(
        "\
{0}  abcdef
{0}  subdir/foo
{0}  subdir/bar",
        empty_hash,
    );
    println!("output");
    println!("======");
    println!("{}", output);
    println!();
    println!("expected");
    println!("========");
    println!("{}", expected);
    println!();
    assert_eq!(expected, output);
}

#[test]
#[cfg(unix)]
fn test_invalid_unicode_on_unix() {
    use std::os::unix::ffi::OsStringExt;

    let empty_hash = hash(b"").to_hex();
    let dir = tempfile::tempdir().unwrap();
    let names = ["abcdef".into(), OsString::from_vec(b"abc\xffdef".to_vec())];
    let mut paths = Vec::new();
    for name in &names {
        let path = dir.path().join(name);
        println!("creating file at {:?}", path);
        // Note: Some operating systems, macOS in particular, simply don't
        // allow invalid Unicode in filenames. On those systems, this write
        // will fail. That's fine, we'll just short-circuit this test in that
        // case. But assert that at least Linux allows this.
        let write_result = fs::write(&path, b"");
        if cfg!(target_os = "linux") {
            write_result.expect("Linux should allow invalid Unicode");
        } else if write_result.is_err() {
            return;
        }
        paths.push(path);
    }
    let output = cmd(k12sum_exe(), &names).dir(dir.path()).read().unwrap();
    let expected = format!(
        "\
{0}  abcdef
{0}  abc�def",
        empty_hash,
    );
    println!("output");
    println!("======");
    println!("{}", output);
    println!();
    println!("expected");
    println!("========");
    println!("{}", expected);
    println!();
    assert_eq!(expected, output);
}

#[test]
#[cfg(windows)]
fn test_invalid_unicode_on_windows() {
    use std::os::windows::ffi::OsStringExt;

    let empty_hash = hash(b"").to_hex();
    let dir = tempfile::tempdir().unwrap();
    let surrogate_char = 0xDC00;
    let bad_unicode_wchars = [
        'a' as u16,
        'b' as u16,
        'c' as u16,
        surrogate_char,
        'd' as u16,
        'e' as u16,
        'f' as u16,
    ];
    let bad_osstring = OsString::from_wide(&bad_unicode_wchars);
    let names = ["abcdef".into(), bad_osstring];
    let mut paths = Vec::new();
    for name in &names {
        let path = dir.path().join(name);
        println!("creating file at {:?}", path);
        fs::write(&path, b"").unwrap();
        paths.push(path);
    }
    let output = cmd(k12sum_exe(), &names).dir(dir.path()).read().unwrap();
    let expected = format!(
        "\
{0}  abcdef
{0}  abc�def",
        empty_hash,
    );
    println!("output");
    println!("======");
    println!("{}", output);
    println!();
    println!("expected");
    println!("========");
    println!("{}", expected);
    println!();
    assert_eq!(expected, output);
}

#[test]
fn test_check() {
    // Make a directory full of files, and make sure the k12sum output in that
    // directory is what we expect.
    let a_hash = hash(b"a").to_hex();
    let b_hash = hash(b"b").to_hex();
    let cd_hash = hash(b"cd").to_hex();
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a"), b"a").unwrap();
    fs::write(dir.path().join("b"), b"b").unwrap();
    fs::create_dir(dir.path().join("c")).unwrap();
    fs::write(dir.path().join("c/d"), b"cd").unwrap();
    let output = cmd!(k12sum_exe(), "a", "b", "c/d")
        .dir(dir.path())
        .stdout_capture()
        .stderr_capture()
        .run()
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let expected_checkfile = format!(
        "{}  a\n\
         {}  b\n\
         {}  c/d\n",
        a_hash, b_hash, cd_hash,
    );
    assert_eq!(expected_checkfile, stdout);
    assert_eq!("", stderr);

    // Now use the output we just validated as a checkfile, passed to stdin.
    let output = cmd!(k12sum_exe(), "--check")
        .stdin_bytes(expected_checkfile.as_bytes())
        .dir(dir.path())
        .stdout_capture()
        .stderr_capture()
        .run()
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let expected_check_output = "\
         a: OK\n\
         b: OK\n\
         c/d: OK\n";
    assert_eq!(expected_check_output, stdout);
    assert_eq!("", stderr);

    // Now pass the same checkfile twice on the command line just for fun.
    let checkfile_path = dir.path().join("checkfile");
    fs::write(&checkfile_path, &expected_checkfile).unwrap();
    let output = cmd!(k12sum_exe(), "--check", &checkfile_path, &checkfile_path)
        .dir(dir.path())
        .stdout_capture()
        .stderr_capture()
        .run()
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let mut double_check_output = String::new();
    double_check_output.push_str(&expected_check_output);
    double_check_output.push_str(&expected_check_output);
    assert_eq!(double_check_output, stdout);
    assert_eq!("", stderr);

    // Corrupt one of the files and check again.
    fs::write(dir.path().join("b"), b"CORRUPTION").unwrap();
    let output = cmd!(k12sum_exe(), "--check", &checkfile_path)
        .dir(dir.path())
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let expected_check_failure = "\
        a: OK\n\
        b: FAILED\n\
        c/d: OK\n";
    assert!(!output.status.success());
    assert_eq!(expected_check_failure, stdout);
    assert_eq!("", stderr);

    // Delete one of the files and check again.
    fs::remove_file(dir.path().join("b")).unwrap();
    let open_file_error = fs::File::open(dir.path().join("b")).unwrap_err();
    let output = cmd!(k12sum_exe(), "--check", &checkfile_path)
        .dir(dir.path())
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let expected_check_failure = format!(
        "a: OK\n\
         b: FAILED ({})\n\
         c/d: OK\n",
        open_file_error,
    );
    assert!(!output.status.success());
    assert_eq!(expected_check_failure, stdout);
    assert_eq!("", stderr);

    // Confirm that --quiet suppresses the OKs but not the FAILEDs.
    let output = cmd!(k12sum_exe(), "--check", "--quiet", &checkfile_path)
        .dir(dir.path())
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let expected_check_failure = format!("b: FAILED ({})\n", open_file_error);
    assert!(!output.status.success());
    assert_eq!(expected_check_failure, stdout);
    assert_eq!("", stderr);
}

#[test]
fn test_check_invalid_characters() {
    // Check that a null character in the path fails.
    let output = cmd!(k12sum_exe(), "--check")
        .stdin_bytes("0000000000000000000000000000000000000000000000000000000000000000  \0")
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(!output.status.success());
    assert_eq!("", stdout);
    assert_eq!("k12sum: Null character in path\n", stderr);

    // Check that a Unicode replacement character in the path fails.
    let output = cmd!(k12sum_exe(), "--check")
        .stdin_bytes("0000000000000000000000000000000000000000000000000000000000000000  �")
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(!output.status.success());
    assert_eq!("", stdout);
    assert_eq!("k12sum: Unicode replacement character in path\n", stderr);

    // Check that an invalid escape sequence in the path fails.
    let output = cmd!(k12sum_exe(), "--check")
        .stdin_bytes("\\0000000000000000000000000000000000000000000000000000000000000000  \\a")
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(!output.status.success());
    assert_eq!("", stdout);
    assert_eq!("k12sum: Invalid backslash escape\n", stderr);

    // Windows also forbids literal backslashes. Check for that if and only if
    // we're on Windows.
    if cfg!(windows) {
        let output = cmd!(k12sum_exe(), "--check")
            .stdin_bytes("0000000000000000000000000000000000000000000000000000000000000000  \\")
            .stdout_capture()
            .stderr_capture()
            .unchecked()
            .run()
            .unwrap();
        let stdout = std::str::from_utf8(&output.stdout).unwrap();
        let stderr = std::str::from_utf8(&output.stderr).unwrap();
        assert!(!output.status.success());
        assert_eq!("", stdout);
        assert_eq!("k12sum: Backslash in path\n", stderr);
    }
}

#[test]
fn test_globbing() {
    // On Unix, globbing is provided by the shell. On Windows, globbing is
    // provided by us, using the `wild` crate.
    let dir = tempfile::tempdir().unwrap();
    let file1 = dir.path().join("file1");
    fs::write(&file1, b"foo").unwrap();
    let file2 = dir.path().join("file2");
    fs::write(&file2, b"bar").unwrap();

    let foo_hash = hash(b"foo");
    let bar_hash = hash(b"bar");
    // NOTE: This assumes that the glob will be expanded in alphabetical order,
    //       to "file1 file2" rather than "file2 file1". So far, this seems to
    //       be true (guaranteed?) of Unix shell behavior, and true in practice
    //       with the `wild` crate on Windows. It's possible that this could
    //       start failing in the future, though, or on some unknown platform.
    //       If that ever happens, we'll need to relax this test somehow,
    //       probably by just testing for both possible outputs. I'm not
    //       handling that case in advance, though, because I'd prefer to hear
    //       about it if it comes up.
    let expected = format!("{}  file1\n{}  file2", foo_hash.to_hex(), bar_hash.to_hex());

    let star_command = format!("{} *", k12sum_exe().to_str().unwrap());
    let (exe, c_flag) = if cfg!(windows) {
        ("cmd.exe", "/C")
    } else {
        ("/bin/sh", "-c")
    };
    let output = cmd!(exe, c_flag, star_command)
        .dir(dir.path())
        .read()
        .unwrap();
    assert_eq!(expected, output);
}
