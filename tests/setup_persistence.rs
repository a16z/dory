//! Concurrent `setup` calls on a cold setup directory.
//!
//! This test changes `HOME`, so it lives in its own test binary, which runs
//! as its own process.

#![cfg(all(feature = "arkworks", feature = "disk-persistence"))]

use dory_pcs::backends::arkworks::BN254;
use dory_pcs::setup::load_setup;
use std::sync::{Arc, Barrier};
use std::thread;

/// Threads that all find no setup file generate their own setups at once.
/// Each must return the first setup saved, and none may read a partly
/// written file.
#[test]
fn concurrent_setup_agrees_on_one_file() {
    let home = std::env::temp_dir().join(format!("dory-setup-race-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    std::env::remove_var("LOCALAPPDATA");
    std::env::set_var("HOME", &home);

    let max_log_n = 6;
    let threads = 8;
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                dory_pcs::setup::<BN254>(max_log_n).0
            })
        })
        .collect();
    let setups: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    let (saved, _) = load_setup::<BN254>(max_log_n).unwrap();
    for setup in &setups {
        assert_eq!(setup.g1_vec, saved.g1_vec);
        assert_eq!(setup.g2_vec, saved.g2_vec);
        assert_eq!(setup.h1, saved.h1);
    }

    // Losing writers and the winner's link both remove their temporary files.
    let leftovers: Vec<_> = walk(&home)
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");

    std::fs::remove_dir_all(&home).unwrap();
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}
