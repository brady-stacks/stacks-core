// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use stacks_inspect::chainstate::PrivateCopy;
use stacks_inspect::cli::Cli;

static NEXT: AtomicU64 = AtomicU64::new(0);
const BLOCK_FILE: &str =
    "chainstate/blocks/0000/0000/0000000000000000000000000000000000000000000000000000000000000000";
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "stacks-recovery-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        for dir in [
            "chainstate/vm/clarity",
            "chainstate/blocks/0000/0000",
            "burnchain/sortition",
        ] {
            fs::create_dir_all(source.join(dir)).unwrap();
        }
        for file in [
            "chainstate/vm/index.sqlite",
            "chainstate/vm/clarity/marf.sqlite",
            "burnchain/sortition/marf.sqlite",
            "burnchain/burnchain.sqlite",
            "headers.sqlite",
        ] {
            let db = rusqlite::Connection::open(source.join(file)).unwrap();
            db.execute_batch(
                "CREATE TABLE retained(value TEXT); INSERT INTO retained VALUES ('original');",
            )
            .unwrap();
        }
        for file in [
            BLOCK_FILE,
            "chainstate/vm/clarity/marf.sqlite.blobs",
            "chainstate/vm/clarity/marf.sqlite-journal",
            "peer.sqlite",
            "signer.sqlite",
            "chainstate/mempool.sqlite",
            "stacker_db.sqlite",
        ] {
            fs::write(source.join(file), b"original").unwrap();
        }
        Self(root)
    }
    fn source(&self) -> PathBuf {
        self.0.join("source")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn contents(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(base: &Path, root: &Path, result: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(base, &path, result);
            } else {
                result.push((
                    path.strip_prefix(base).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                ));
            }
        }
    }
    let mut result = Vec::new();
    visit(root, root, &mut result);
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

#[test]
fn independent_copy_preserves_source_and_omits_local_state() {
    let fixture = Fixture::new();
    let before = contents(&fixture.source());
    let copy = PrivateCopy::acquire(&fixture.source(), &fixture.0, "mainnet").unwrap();
    assert_eq!(
        fs::read(
            copy.network_dir
                .join("chainstate/vm/clarity/marf.sqlite-journal")
        )
        .unwrap(),
        b"original"
    );
    for omitted in [
        "peer.sqlite",
        "signer.sqlite",
        "chainstate/mempool.sqlite",
        "stacker_db.sqlite",
    ] {
        assert!(!copy.network_dir.join(omitted).exists());
    }
    fs::write(copy.network_dir.join(BLOCK_FILE), b"changed").unwrap();
    assert_eq!(contents(&fixture.source()), before);
    let private = copy.network_dir.parent().unwrap().to_path_buf();
    drop(copy);
    assert!(!private.exists());
    assert_eq!(contents(&fixture.source()), before);
}

#[test]
fn publication_is_complete_and_does_not_replace_destination() {
    let fixture = Fixture::new();
    let before = contents(&fixture.source());
    let copy = PrivateCopy::acquire(&fixture.source(), &fixture.0, "mainnet").unwrap();
    // The fixture's arbitrary journal bytes are for acquisition, not SQLite recovery.
    fs::remove_file(
        copy.network_dir
            .join("chainstate/vm/clarity/marf.sqlite-journal"),
    )
    .unwrap();
    let output = fixture.0.join("published");
    copy.publish(&output).unwrap();
    assert_eq!(
        fs::read(output.join("mainnet").join(BLOCK_FILE)).unwrap(),
        b"original"
    );
    let copy = PrivateCopy::acquire(&fixture.source(), &fixture.0, "mainnet").unwrap();
    assert!(copy.publish(&output).is_err());
    assert_eq!(
        fs::read(output.join("mainnet").join(BLOCK_FILE)).unwrap(),
        b"original"
    );
    assert_eq!(contents(&fixture.source()), before);
}

#[test]
fn abort_before_publication_never_exposes_output() {
    let fixture = Fixture::new();
    let before = contents(&fixture.source());
    let copy = PrivateCopy::acquire(&fixture.source(), &fixture.0, "mainnet").unwrap();
    let partial = copy.network_dir.parent().unwrap().to_path_buf();
    fs::write(copy.network_dir.join(BLOCK_FILE), b"partially rewound").unwrap();
    // Leaking the owner models process death: no Drop cleanup or publication runs.
    std::mem::forget(copy);
    assert!(
        partial
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(".stacks-recovery-partial-")
    );
    assert!(!fixture.0.join("published").exists());
    assert_eq!(contents(&fixture.source()), before);
}

#[test]
fn rejects_nested_destination_and_symlink_artifacts() {
    let fixture = Fixture::new();
    assert!(PrivateCopy::acquire(&fixture.source(), &fixture.source(), "mainnet").is_err());
    let copy = PrivateCopy::acquire(&fixture.source(), &fixture.0, "mainnet").unwrap();
    assert!(copy.publish(&fixture.source().join("nested")).is_err());
    #[cfg(unix)]
    {
        let alias = fixture.0.join("source-alias");
        std::os::unix::fs::symlink(fixture.source(), &alias).unwrap();
        assert!(PrivateCopy::acquire(&alias, &fixture.0, "mainnet").is_err());
        std::os::unix::fs::symlink(
            fixture.0.join("source/headers.sqlite"),
            fixture.source().join("chainstate/blocks/alias"),
        )
        .unwrap();
        assert!(PrivateCopy::acquire(&fixture.source(), &fixture.0, "mainnet").is_err());
    }
}

#[test]
fn replay_requires_explicit_start() {
    assert!(
        Cli::try_parse_from([
            "stacks-inspect",
            "verify-chainstate",
            "--source",
            "source",
            "--replay-to",
            "id"
        ])
        .is_err()
    );
}

#[test]
fn rejects_unclassified_consensus_files_without_touching_source() {
    let fixture = Fixture::new();
    fs::write(
        fixture.source().join("chainstate/vm/signer.sqlite"),
        b"do not copy",
    )
    .unwrap();
    let before = contents(&fixture.source());
    assert!(PrivateCopy::acquire(&fixture.source(), &fixture.0, "mainnet").is_err());
    assert_eq!(contents(&fixture.source()), before);
}

#[test]
fn competing_publishers_cannot_clobber_each_other() {
    let fixture = Fixture::new();
    let before = contents(&fixture.source());
    let first = PrivateCopy::acquire(&fixture.source(), &fixture.0, "mainnet").unwrap();
    let second = PrivateCopy::acquire(&fixture.source(), &fixture.0, "mainnet").unwrap();
    for copy in [&first, &second] {
        fs::remove_file(
            copy.network_dir
                .join("chainstate/vm/clarity/marf.sqlite-journal"),
        )
        .unwrap();
    }
    fs::write(first.network_dir.join(BLOCK_FILE), b"first").unwrap();
    fs::write(second.network_dir.join(BLOCK_FILE), b"second").unwrap();
    let output = fixture.0.join("published");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other_barrier = barrier.clone();
    let other_output = output.clone();
    let thread = std::thread::spawn(move || {
        other_barrier.wait();
        first.publish(&other_output)
    });
    barrier.wait();
    let second_result = second.publish(&output);
    let first_result = thread.join().unwrap();
    assert_ne!(first_result.is_ok(), second_result.is_ok());
    let winner = fs::read(output.join("mainnet").join(BLOCK_FILE)).unwrap();
    assert_eq!(
        winner,
        if first_result.is_ok() {
            b"first".as_slice()
        } else {
            b"second".as_slice()
        }
    );
    assert_eq!(contents(&fixture.source()), before);
}
