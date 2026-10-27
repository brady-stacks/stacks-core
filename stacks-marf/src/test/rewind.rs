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

use std::collections::HashSet;
use std::io::{Seek, SeekFrom, Write};

use rusqlite::Connection;
use stacks_common::types::chainstate::StacksBlockId;
use tempfile::tempdir_in;

use crate::maintenance::{retain_roots, root_hashes, verify_roots};
use crate::{ClarityMarfTrieId, MARFOpenOpts, MARFValue, MarfConnection, MARF};

fn append(
    marf: &mut MARF<StacksBlockId>,
    parent: &StacksBlockId,
    block: &StacksBlockId,
    value: &str,
) {
    marf.begin(parent, block).unwrap();
    marf.insert("key", MARFValue::from_value(value)).unwrap();
    marf.insert(&format!("unique-{value}"), MARFValue::from_value(value))
        .unwrap();
    marf.commit().unwrap();
}

#[test]
fn forked_rewind_preserves_history_and_reappends() {
    for external in [false, true] {
        for compress in [false, true] {
            let dir = tempdir_in("/tmp").unwrap();
            let path = dir.path().join("marf.sqlite");
            let mut opts = MARFOpenOpts::default().with_compression(compress);
            opts.external_blobs = external;
            let mut marf = MARF::from_path(path.to_str().unwrap(), opts.clone()).unwrap();
            let blocks: Vec<_> = (1..=5).map(|n| StacksBlockId([n; 32])).collect();
            append(&mut marf, &StacksBlockId::sentinel(), &blocks[0], "genesis");
            append(&mut marf, &blocks[0], &blocks[1], "discarded-fork");
            append(&mut marf, &blocks[0], &blocks[2], "retained-parent");
            append(&mut marf, &blocks[1], &blocks[3], "discarded-child");
            append(&mut marf, &blocks[2], &blocks[4], "retained-tip");
            let retained = HashSet::from([blocks[0].clone(), blocks[2].clone(), blocks[4].clone()]);
            drop(marf);
            let before = root_hashes(&path, &retained).unwrap();
            let db = Connection::open(&path).unwrap();
            let ids: Vec<(u32, String)> = db.prepare("SELECT block_id, block_hash FROM marf_data WHERE block_hash IN (?1, ?2, ?3) ORDER BY block_id").unwrap()
                .query_map([&blocks[0], &blocks[2], &blocks[4]], |row| Ok((row.get(0)?, row.get(1)?))).unwrap()
                .collect::<Result<_, _>>().unwrap();
            db.execute(
                "INSERT INTO block_extension_locks VALUES (?1)",
                [&blocks[1]],
            )
            .unwrap();
            db.execute(
                "INSERT INTO mined_blocks VALUES (1, ?1, X'00')",
                [&blocks[1]],
            )
            .unwrap();
            db.execute(
                "INSERT INTO marf_data (block_hash,data,unconfirmed) VALUES (?1,X'00',1)",
                [&StacksBlockId([9; 32])],
            )
            .unwrap();
            drop(db);
            retain_roots(&path, &retained).unwrap();
            assert_eq!(before, root_hashes(&path, &retained).unwrap());
            let values = verify_roots(&path, &retained).unwrap();
            assert_eq!(
                values.into_iter().collect::<HashSet<_>>(),
                HashSet::from([
                    MARFValue::from_value("genesis"),
                    MARFValue::from_value("retained-parent"),
                    MARFValue::from_value("retained-tip")
                ])
            );
            let db = Connection::open(&path).unwrap();
            let after: Vec<(u32, String)> = db
                .prepare("SELECT block_id, block_hash FROM marf_data ORDER BY block_id")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(ids, after);
            for table in ["block_extension_locks", "mined_blocks"] {
                assert_eq!(
                    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                        .get::<_, u32>(0))
                        .unwrap(),
                    0
                );
            }
            drop(db);
            let mut marf = MARF::from_path(path.to_str().unwrap(), opts.clone()).unwrap();
            for (block, value) in [
                (&blocks[0], "genesis"),
                (&blocks[2], "retained-parent"),
                (&blocks[4], "retained-tip"),
            ] {
                assert_eq!(
                    marf.get(block, "key").unwrap(),
                    Some(MARFValue::from_value(value))
                );
                let (value, proof) = marf.get_with_proof(block, "key").unwrap().unwrap();
                let root_to_block = before
                    .iter()
                    .map(|(block, root)| (*root, block.clone()))
                    .collect();
                assert!(proof.verify(
                    &stacks_common::types::chainstate::TrieHash::from_key("key"),
                    &value,
                    &before[block],
                    &root_to_block
                ));
            }
            append(&mut marf, &blocks[4], &blocks[1], "reprocessed");
            append(&mut marf, &blocks[1], &StacksBlockId([10; 32]), "appended");
            drop(marf);
            let mut marf = MARF::from_path(path.to_str().unwrap(), opts).unwrap();
            assert_eq!(
                marf.get(&blocks[4], "key").unwrap(),
                Some(MARFValue::from_value("retained-tip"))
            );
            drop(marf);
            let mut extended = retained.clone();
            extended.insert(blocks[1].clone());
            extended.insert(StacksBlockId([10; 32]));
            verify_roots(&path, &extended).unwrap();
            assert_eq!(before, root_hashes(&path, &retained).unwrap());
        }
    }
}

#[test]
fn discarded_out_of_bounds_tail_is_not_opened() {
    let dir = tempdir_in("/tmp").unwrap();
    let path = dir.path().join("marf.sqlite");
    let (_, blocks, _) = super::marf::setup_marf(path.to_str().unwrap(), 3, 2);
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE marf_data SET external_offset = 9223372036854770000 WHERE block_hash = ?1",
        [&blocks[2]],
    )
    .unwrap();
    drop(db);
    let all: HashSet<_> = blocks.iter().cloned().collect();
    assert!(verify_roots(&path, &all).is_err());
    let prefix = HashSet::from([blocks[0].clone(), blocks[1].clone()]);
    retain_roots(&path, &prefix).unwrap();
    let mut marf = MARF::from_path(
        path.to_str().unwrap(),
        MARFOpenOpts::new(crate::storage::TrieHashCalculationMode::Deferred, true),
    )
    .unwrap();
    append(&mut marf, &blocks[1], &blocks[2], "recovered");
    drop(marf);
    verify_roots(&path, &all).unwrap();
}

#[test]
fn retained_node_hash_damage_fails() {
    let dir = tempdir_in("/tmp").unwrap();
    let path = dir.path().join("marf.sqlite");
    let (marf, blocks, _) = super::marf::setup_marf(path.to_str().unwrap(), 2, 2);
    drop(marf);
    let retained = blocks.into_iter().collect();
    let db = Connection::open(&path).unwrap();
    let offset: u64 = db
        .query_row(
            "SELECT external_offset FROM marf_data ORDER BY block_id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(db);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("{}.blobs", path.display()))
        .unwrap();
    file.seek(SeekFrom::Start(
        offset + crate::blob_layout::ROOT_NODE_OFFSET as u64,
    ))
    .unwrap();
    file.write_all(&[0; 32]).unwrap();
    drop(file);
    assert!(verify_roots(&path, &retained).is_err());
    assert!(retain_roots(&path, &retained).is_err());
}

#[test]
fn squash_floor_is_preserved_and_required() {
    let dir = tempdir_in("/tmp").unwrap();
    let source = dir.path().join("source.sqlite");
    let (marf, blocks, _) = super::marf::setup_marf(source.to_str().unwrap(), 4, 2);
    drop(marf);
    let path = dir.path().join("squashed.sqlite");
    let opts = MARFOpenOpts::new(crate::storage::TrieHashCalculationMode::Deferred, true);
    MARF::squash_to_path(
        source.to_str().unwrap(),
        path.to_str().unwrap(),
        opts.clone(),
        &blocks[2],
        2,
        "rewind-test",
    )
    .unwrap();
    let mut marf = MARF::from_path(path.to_str().unwrap(), opts).unwrap();
    append(&mut marf, &blocks[2], &blocks[3], "extension");
    drop(marf);
    assert!(retain_roots(
        &path,
        &HashSet::from([blocks[0].clone(), blocks[1].clone()])
    )
    .is_err());
    let retained: HashSet<_> = blocks[..3].iter().cloned().collect();
    let before = root_hashes(&path, &retained).unwrap();
    retain_roots(&path, &retained).unwrap();
    assert_eq!(before, root_hashes(&path, &retained).unwrap());
    verify_roots(&path, &retained).unwrap();
    let mut marf = MARF::from_path(
        path.to_str().unwrap(),
        MARFOpenOpts::new(crate::storage::TrieHashCalculationMode::Deferred, true),
    )
    .unwrap();
    assert!(marf.get(&blocks[0], "k1").is_err());
    append(&mut marf, &blocks[2], &blocks[3], "extension-reprocessed");
}

#[test]
fn retained_backpointer_dependencies_and_schema_are_required() {
    let dir = tempdir_in("/tmp").unwrap();
    let path = dir.path().join("marf.sqlite");
    let (marf, blocks, _) = super::marf::setup_marf(path.to_str().unwrap(), 3, 20);
    drop(marf);
    // The tip inherits untouched keys from its parents. Keeping only the tip
    // must not silently leave a writable MARF with dangling local block IDs.
    assert!(retain_roots(&path, &HashSet::from([blocks[2].clone()])).is_err());

    let path = dir.path().join("unknown.sqlite");
    let (marf, blocks, _) = super::marf::setup_marf(path.to_str().unwrap(), 1, 1);
    drop(marf);
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE schema_version SET version = 999", [])
        .unwrap();
    drop(db);
    assert!(retain_roots(&path, &blocks.into_iter().collect()).is_err());
}

#[test]
fn unchanged_root_hash_does_not_hide_descendant_damage() {
    let dir = tempdir_in("/tmp").unwrap();
    let path = dir.path().join("marf.sqlite");
    let (mut marf, blocks, _) = super::marf::setup_marf(path.to_str().unwrap(), 1, 20);
    let retained = blocks.iter().cloned().collect();
    let roots_before = root_hashes(&path, &retained).unwrap();
    let pointer = marf
        .with_conn(|conn| {
            conn.open_block(&blocks[0])?;
            let (root, _) = crate::trie::Trie::read_root(conn)?;
            let mut pending: Vec<_> = root
                .ptrs()
                .iter()
                .copied()
                .filter(|ptr| ptr.id() != crate::node::TrieNodeID::Empty as u8)
                .collect();
            while let Some(ptr) = pending.pop() {
                let (node, _) = conn.read_nodetype(&ptr)?;
                if node.is_leaf() {
                    return Ok(ptr.ptr());
                }
                pending.extend(
                    node.ptrs()
                        .iter()
                        .copied()
                        .filter(|ptr| ptr.id() != crate::node::TrieNodeID::Empty as u8),
                );
            }
            Err(crate::Error::NotFoundError)
        })
        .unwrap();
    drop(marf);
    let db = Connection::open(&path).unwrap();
    let offset: u64 = db
        .query_row("SELECT external_offset FROM marf_data LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    drop(db);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("{}.blobs", path.display()))
        .unwrap();
    file.seek(SeekFrom::Start(offset + pointer)).unwrap();
    file.write_all(&[0; 32]).unwrap();
    drop(file);
    assert_eq!(roots_before, root_hashes(&path, &retained).unwrap());
    assert!(verify_roots(&path, &retained).is_err());
}

#[test]
fn unknown_child_backpointer_returns_error_without_panicking() {
    use stacks_common::types::chainstate::TrieHash;

    use crate::node::TriePtr;

    let dir = tempdir_in("/tmp").unwrap();
    let path = dir.path().join("marf.sqlite");
    let mut opts = MARFOpenOpts::default().with_compression(false);
    opts.external_blobs = true;
    let mut marf = MARF::from_path(path.to_str().unwrap(), opts).unwrap();
    let block = StacksBlockId([1; 32]);
    append(&mut marf, &StacksBlockId::sentinel(), &block, "retained");
    let (mut root, hash) = marf
        .with_conn(|conn| {
            conn.open_block(&block)?;
            crate::trie::Trie::read_root(conn)
        })
        .unwrap();
    let height_chr = TrieHash::from_key(crate::marf::OWN_BLOCK_HEIGHT_KEY).0[0];
    let child = root
        .ptrs_mut()
        .iter_mut()
        .find(|ptr| !ptr.is_empty() && ptr.chr() != height_chr)
        .unwrap();
    *child = TriePtr::new_backptr(child.id(), child.chr(), child.ptr(), u32::MAX);
    drop(marf);
    let db = Connection::open(&path).unwrap();
    let offset: u64 = db
        .query_row(
            "SELECT external_offset FROM marf_data WHERE block_hash = ?1",
            [&block],
            |row| row.get(0),
        )
        .unwrap();
    drop(db);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("{}.blobs", path.display()))
        .unwrap();
    file.seek(SeekFrom::Start(
        offset + crate::blob_layout::ROOT_NODE_OFFSET as u64,
    ))
    .unwrap();
    crate::bits::write_nodetype_bytes(&mut file, &root, &hash).unwrap();
    drop(file);
    let err = verify_roots(&path, &HashSet::from([block])).unwrap_err();
    assert!(
        err.to_string()
            .contains("backpointer depends on discarded local ID"),
        "{err}"
    );
}

#[test]
fn provisional_commit_identity_is_not_application_data() {
    let dir = tempdir_in("/tmp").unwrap();
    let path = dir.path().join("marf.sqlite");
    let mut marf = MARF::from_path(path.to_str().unwrap(), MARFOpenOpts::default()).unwrap();
    let blocks: Vec<_> = (1..=3).map(|tag| StacksBlockId([tag; 32])).collect();
    let provisional = StacksBlockId([9; 32]);
    let mut parent = StacksBlockId::sentinel();
    let value = MARFValue::from_value("retained");
    for block in &blocks {
        marf.begin(&parent, &provisional).unwrap();
        marf.insert("contract-state", value.clone()).unwrap();
        marf.commit_to(block).unwrap();
        parent = block.clone();
    }
    drop(marf);
    let retained = blocks.iter().cloned().collect();
    assert_eq!(verify_roots(&path, &retained).unwrap(), vec![value.clone()]);
    let squashed = dir.path().join("squashed.sqlite");
    MARF::squash_to_path(
        path.to_str().unwrap(),
        squashed.to_str().unwrap(),
        MARFOpenOpts::default(),
        &blocks[2],
        2,
        "provisional-recovery",
    )
    .unwrap();
    retain_roots(&squashed, &retained).unwrap();
    assert_eq!(verify_roots(&squashed, &retained).unwrap(), vec![value]);
}
