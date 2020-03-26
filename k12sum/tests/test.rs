use duct::cmd;
use kangarootwelve_xkcp::Hasher;
use std::fs;
use std::path::PathBuf;

pub fn k12sum_exe() -> PathBuf {
    assert_cmd::cargo::cargo_bin("k12sum")
}

#[test]
fn test_hash_one() {
    let mut hasher = Hasher::new();
    hasher.update(b"foo");
    let mut expected = [0; 32];
    hasher.finalize(&mut expected);
    let output = cmd!(k12sum_exe()).stdin_bytes("foo").read().unwrap();
    assert_eq!(hex::encode(expected), output);
}

#[test]
fn test_hash_one_raw() {
    let mut hasher = Hasher::new();
    hasher.update(b"foo");
    let mut expected = [0; 32];
    hasher.finalize(&mut expected);
    let output = cmd!(k12sum_exe(), "--raw")
        .stdin_bytes("foo")
        .stdout_capture()
        .run()
        .unwrap()
        .stdout;
    assert_eq!(expected, output.as_slice());
}

#[test]
fn test_hash_many() {
    let dir = tempfile::tempdir().unwrap();
    let file1 = dir.path().join("file1");
    fs::write(&file1, b"foo").unwrap();
    let file2 = dir.path().join("file2");
    fs::write(&file2, b"bar").unwrap();

    let output = cmd!(k12sum_exe(), &file1, &file2).read().unwrap();
    let mut foo_hasher = Hasher::new();
    foo_hasher.update(b"foo");
    let mut foo_hash = [0; 32];
    foo_hasher.finalize(&mut foo_hash);
    let mut bar_hasher = Hasher::new();
    bar_hasher.update(b"bar");
    let mut bar_hash = [0; 32];
    bar_hasher.finalize(&mut bar_hash);
    let expected = format!(
        "{}  {}\n{}  {}",
        hex::encode(&foo_hash),
        file1.to_string_lossy(),
        hex::encode(&bar_hash),
        file2.to_string_lossy(),
    );
    assert_eq!(expected, output);

    let output_no_names = cmd!(k12sum_exe(), "--no-names", &file1, &file2)
        .read()
        .unwrap();
    let expected_no_names = format!("{}\n{}", hex::encode(&foo_hash), hex::encode(&bar_hash),);
    assert_eq!(expected_no_names, output_no_names);
}

#[test]
fn test_hash_length() {
    let mut hasher = Hasher::new();
    hasher.update(b"foo");
    let mut expected = [0; 100];
    hasher.finalize(&mut expected);
    let output = cmd!(k12sum_exe(), "--length=100")
        .stdin_bytes("foo")
        .read()
        .unwrap();
    assert_eq!(hex::encode(&expected[..]), output);
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
