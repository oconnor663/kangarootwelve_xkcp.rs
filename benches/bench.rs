#![feature(test)]

extern crate test;

use rand::prelude::*;
use test::Bencher;

const KIB: usize = 1024;

// This struct randomizes two things:
// 1. The actual bytes of input.
// 2. The page offset the input starts at.
pub struct RandomInput {
    buf: Vec<u8>,
    len: usize,
    offsets: Vec<usize>,
    offset_index: usize,
}

impl RandomInput {
    pub fn new(b: &mut Bencher, len: usize) -> Self {
        b.bytes += len as u64;
        let page_size: usize = page_size::get();
        let mut buf = vec![0u8; len + page_size];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut buf);
        let mut offsets: Vec<usize> = (0..page_size).collect();
        offsets.shuffle(&mut rng);
        Self {
            buf,
            len,
            offsets,
            offset_index: 0,
        }
    }

    pub fn get(&mut self) -> &[u8] {
        let offset = self.offsets[self.offset_index];
        self.offset_index += 1;
        if self.offset_index >= self.offsets.len() {
            self.offset_index = 0;
        }
        &self.buf[offset..][..self.len]
    }
}

fn bench_atonce(b: &mut Bencher, len: usize) {
    let mut input = RandomInput::new(b, len);
    b.iter(|| kangarootwelve_xkcp::hash(input.get()));
}

#[bench]
fn bench_0001_kib(b: &mut Bencher) {
    bench_atonce(b, 1 * KIB);
}

#[bench]
fn bench_0002_kib(b: &mut Bencher) {
    bench_atonce(b, 2 * KIB);
}

#[bench]
fn bench_0004_kib(b: &mut Bencher) {
    bench_atonce(b, 4 * KIB);
}

#[bench]
fn bench_0008_kib(b: &mut Bencher) {
    bench_atonce(b, 8 * KIB);
}

#[bench]
fn bench_0016_kib(b: &mut Bencher) {
    bench_atonce(b, 16 * KIB);
}

#[bench]
fn bench_0032_kib(b: &mut Bencher) {
    bench_atonce(b, 32 * KIB);
}

#[bench]
fn bench_0064_kib(b: &mut Bencher) {
    bench_atonce(b, 64 * KIB);
}

#[bench]
fn bench_0128_kib(b: &mut Bencher) {
    bench_atonce(b, 128 * KIB);
}

#[bench]
fn bench_0256_kib(b: &mut Bencher) {
    bench_atonce(b, 256 * KIB);
}

#[bench]
fn bench_0512_kib(b: &mut Bencher) {
    bench_atonce(b, 512 * KIB);
}

#[bench]
fn bench_1024_kib(b: &mut Bencher) {
    bench_atonce(b, 1024 * KIB);
}

#[bench]
fn bench_1024_kib_k12(b: &mut Bencher) {
    let mut input = RandomInput::new(b, 1024 * KIB);
    b.iter(|| {
        use digest::{ExtendableOutput, Update, XofReader};
        let mut state = k12::KangarooTwelve::default();
        state.update(input.get());
        let mut reader = state.finalize_xof();
        let mut output = [0; 32];
        reader.read(&mut output);
        output
    });
}
