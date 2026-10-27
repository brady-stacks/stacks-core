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

//! Storage-unit tests: headers use the production serializer and initialized schema.
//! These deliberately do not claim that inserted headers have passed block processing.

use clarity::vm::costs::ExecutionCost;
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksPrivateKey, TrieHash};
use stacks_common::types::{PrivateKey, StacksEpoch, StacksEpochId};
use stacks_marf::marf::{MARFOpenOpts, MARF};
use stacks_marf::{ClarityMarfTrieId, MARFValue};
use tempfile::tempdir_in;

use super::super::{check_roots, read_stacks_ancestry};
use super::*;
use crate::chainstate::nakamoto::{NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::db::testing::TestChainstateBuilder;
use crate::config::ConfigFile;
use crate::core::StacksEpochExtension;

fn config() -> Config {
    let mut config = Config::from_config_file(
        ConfigFile::from_str("[burnchain]\nmode = 'krypton'\n").unwrap(),
        false,
    )
    .unwrap();
    config.burnchain.epochs = Some(StacksEpoch::unit_test_up_to(0, StacksEpochId::Epoch20));
    config
}

fn insert_header(
    conn: &Connection,
    parent: &StacksBlockId,
    height: u64,
    tag: u8,
    signer: Option<&StacksPrivateKey>,
) -> StacksHeaderInfo {
    let mut header = NakamotoBlockHeader::empty();
    header.parent_block_id = parent.clone();
    header.chain_length = height;
    header.consensus_hash = ConsensusHash([tag; 20]);
    if let Some(key) = signer {
        header.signer_signature = vec![key.sign(header.signer_signature_hash().bits()).unwrap()];
    }
    let info = StacksHeaderInfo {
        anchored_header: header.clone().into(),
        microblock_tail: None,
        stacks_block_height: height,
        index_root: TrieHash([0; 32]),
        consensus_hash: header.consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([tag; 32]),
        burn_header_height: 100,
        burn_header_timestamp: 0,
        anchored_block_size: 0,
        burn_view: Some(header.consensus_hash.clone()),
        total_tenure_size: 0,
    };
    NakamotoChainState::insert_stacks_block_header(
        conn,
        &info,
        &header,
        None,
        &ExecutionCost::ZERO,
        &ExecutionCost::ZERO,
        true,
        1,
        0,
    )
    .unwrap();
    info
}

fn boundary(conn: &Connection, target: &StacksBlockId) -> RecoveryBoundary {
    let stacks_blocks = read_stacks_ancestry(conn, target).unwrap();
    let sortitions: Vec<_> = stacks_blocks
        .iter()
        .map(|header| {
            let mut snapshot = BlockSnapshot::empty();
            snapshot.consensus_hash = header
                .burn_view
                .as_ref()
                .unwrap_or(&header.consensus_hash)
                .clone();
            snapshot.block_height = u64::from(header.burn_header_height);
            snapshot
        })
        .collect();
    RecoveryBoundary {
        target: target.clone(),
        stacks_height: stacks_blocks[0].stacks_block_height,
        burn_tip: sortitions[0].clone(),
        stacks_blocks,
        sortitions,
    }
}

#[test]
fn schema_accepts_migration_history_but_rejects_unknown_versions() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE db_config (version TEXT NOT NULL)")
        .unwrap();
    assert!(super::super::schema(&conn, "sortition", "11").is_err());
    for version in 2..=11 {
        conn.execute("INSERT INTO db_config VALUES (?1)", [version.to_string()])
            .unwrap();
    }
    super::super::schema(&conn, "sortition", "11").unwrap();
    conn.execute("INSERT INTO db_config VALUES ('12')", [])
        .unwrap();
    assert!(super::super::schema(&conn, "sortition", "11").is_err());
    conn.execute(
        "UPDATE db_config SET version = 'invalid' WHERE version = '12'",
        [],
    )
    .unwrap();
    assert!(super::super::schema(&conn, "sortition", "11").is_err());
}

#[test]
fn verification_rejects_missing_epoch_before_canonical_reader_panics() {
    let dir = tempdir_in("/tmp").unwrap();
    let config = config();
    let burn = config.get_burnchain();
    let sortition_dir = dir.path().join("burnchain/sortition");
    std::fs::create_dir_all(sortition_dir.parent().unwrap()).unwrap();
    let sortdb = SortitionDB::connect(
        sortition_dir.to_str().unwrap(),
        burn.first_block_height,
        &burn.first_block_hash,
        u64::from(burn.first_block_timestamp),
        &config.burnchain.get_epoch_list(),
        burn.pox_constants,
        None,
        true,
        None,
    )
    .unwrap();
    sortdb.conn().execute("DELETE FROM epochs", []).unwrap();
    drop(sortdb);
    let err = super::super::verify(dir.path(), &config).unwrap_err();
    assert!(
        err.contains("Missing epoch definition for canonical burn height"),
        "{err}"
    );
}

#[test]
fn ancestry_follows_exact_parent_not_same_height_or_newer_header() {
    let chainstate = TestChainstateBuilder::new_testnet("maintenance-exact-ancestry").build();
    let conn = chainstate.db();
    let a = insert_header(conn, &FIRST_STACKS_BLOCK_ID, 1, 1, None);
    let fork = insert_header(conn, &FIRST_STACKS_BLOCK_ID, 1, 2, None);
    let target = insert_header(conn, &a.index_block_hash(), 2, 3, None);
    insert_header(conn, &fork.index_block_hash(), 2, 4, None);
    insert_header(conn, &target.index_block_hash(), 3, 5, None);
    let blocks = read_stacks_ancestry(conn, &target.index_block_hash()).unwrap();
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].index_block_hash(), target.index_block_hash());
    assert_eq!(blocks[1].index_block_hash(), a.index_block_hash());
    assert_eq!(blocks[2].stacks_block_height, 0);
}

#[test]
fn ancestry_rejects_missing_parent_and_nonconsecutive_height() {
    let chainstate = TestChainstateBuilder::new_testnet("maintenance-broken-ancestry").build();
    let conn = chainstate.db();
    let parent = insert_header(conn, &FIRST_STACKS_BLOCK_ID, 1, 1, None);
    let child = insert_header(conn, &parent.index_block_hash(), 2, 2, None);
    let gap = insert_header(conn, &parent.index_block_hash(), 3, 3, None);
    assert!(read_stacks_ancestry(conn, &gap.index_block_hash())
        .unwrap_err()
        .contains("Nonconsecutive Stacks ancestry"));
    conn.execute(
        "DELETE FROM nakamoto_block_headers WHERE index_block_hash = ?1",
        [parent.index_block_hash()],
    )
    .unwrap();
    let err = read_stacks_ancestry(conn, &child.index_block_hash()).unwrap_err();
    assert!(err.contains("Missing retained header"), "{err}");
    assert!(
        err.contains(&parent.index_block_hash().to_string()),
        "{err}"
    );
}

#[test]
fn ancestry_rejects_corrupt_encoded_header_without_panicking() {
    let chainstate = TestChainstateBuilder::new_testnet("maintenance-corrupt-header").build();
    let conn = chainstate.db();
    let target = insert_header(conn, &FIRST_STACKS_BLOCK_ID, 1, 1, None);
    conn.execute(
        "UPDATE nakamoto_block_headers SET block_size = 'not-a-number' WHERE index_block_hash = ?1",
        [target.index_block_hash()],
    )
    .unwrap();
    assert!(read_stacks_ancestry(conn, &target.index_block_hash()).is_err());
}

#[test]
fn index_rewind_reconstructs_signers_from_retained_signatures_only() {
    let chainstate = TestChainstateBuilder::new_testnet("maintenance-signer-retention").build();
    let path: String = chainstate
        .db()
        .query_row("PRAGMA database_list", [], |r| r.get(2))
        .unwrap();
    let mut signer = StacksPrivateKey::from_slice(&[1; 32]).unwrap();
    signer.set_compress_public(true);
    let mut discarded_signer = StacksPrivateKey::from_slice(&[2; 32]).unwrap();
    discarded_signer.set_compress_public(true);
    let first = insert_header(chainstate.db(), &FIRST_STACKS_BLOCK_ID, 1, 1, Some(&signer));
    let target = insert_header(
        chainstate.db(),
        &first.index_block_hash(),
        2,
        2,
        Some(&signer),
    );
    // The burn view advances a cycle; production accounting still uses the
    // tenure's election height, not this mutable burn view.
    let config = config();
    let burnchain = config.get_burnchain();
    let view = ConsensusHash([9; 20]);
    chainstate
        .db()
        .execute(
            "UPDATE nakamoto_block_headers SET burn_view = ?1 WHERE index_block_hash = ?2",
            params![view, target.index_block_hash()],
        )
        .unwrap();
    let fork = insert_header(
        chainstate.db(),
        &first.index_block_hash(),
        2,
        3,
        Some(&discarded_signer),
    );
    let mut boundary = boundary(chainstate.db(), &target.index_block_hash());
    let view_snapshot = boundary
        .sortitions
        .iter_mut()
        .find(|s| s.consensus_hash == view)
        .unwrap();
    view_snapshot.block_height = 100 + u64::from(burnchain.pox_constants.reward_cycle_length);
    assert_ne!(
        burnchain.block_height_to_reward_cycle(100),
        burnchain.block_height_to_reward_cycle(view_snapshot.block_height)
    );
    let key = StacksPublicKey::from_private(&signer).to_hex();
    let discarded_key = StacksPublicKey::from_private(&discarded_signer).to_hex();
    let cycle = config
        .get_burnchain()
        .block_height_to_reward_cycle(100)
        .unwrap();
    chainstate
        .db()
        .execute(
            "INSERT INTO signer_stats(public_key,reward_cycle,blocks_signed) VALUES (?1,?2,999)",
            params![key, cycle],
        )
        .unwrap();
    chainstate
        .db()
        .execute(
            "INSERT INTO signer_stats(public_key,reward_cycle,blocks_signed) VALUES (?1,?2,999)",
            params![discarded_key, cycle],
        )
        .unwrap();
    drop(chainstate);
    rewind_index(Path::new(&path), &boundary, &config).unwrap();
    let conn = Connection::open(&path).unwrap();
    let stats: Vec<(String, u64, u64)> = conn
        .prepare("SELECT public_key,reward_cycle,blocks_signed FROM signer_stats")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(stats, vec![(key, cycle, 2)]);
    let discarded: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM nakamoto_block_headers WHERE index_block_hash = ?1",
            [fork.index_block_hash()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(discarded, 0);
    let retained = read_stacks_ancestry(&conn, &target.index_block_hash()).unwrap();
    assert_eq!(retained.len(), 3);
    // Re-running retention must not double signer counts.
    drop(conn);
    rewind_index(Path::new(&path), &boundary, &config).unwrap();
    let conn = Connection::open(&path).unwrap();
    let count: u64 = conn
        .query_row("SELECT blocks_signed FROM signer_stats", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn root_checks_require_every_retained_root_not_just_target() {
    let dir = tempdir_in("/tmp").unwrap();
    let path = dir.path().join("roots.sqlite");
    let first = StacksBlockId([1; 32]);
    let target = StacksBlockId([2; 32]);
    let missing = StacksBlockId([3; 32]);
    let mut marf =
        MARF::<StacksBlockId>::from_path(path.to_str().unwrap(), MARFOpenOpts::default()).unwrap();
    marf.begin(&StacksBlockId::sentinel(), &first).unwrap();
    marf.insert("key", MARFValue::from_value("first")).unwrap();
    marf.commit().unwrap();
    marf.begin(&first, &target).unwrap();
    marf.insert("key", MARFValue::from_value("target")).unwrap();
    marf.commit().unwrap();
    drop(marf);
    check_roots(
        &path,
        &HashSet::from([first.clone(), target.clone()]),
        &target,
    )
    .unwrap();
    let err = check_roots(
        &path,
        &HashSet::from([first, target.clone(), missing.clone()]),
        &target,
    )
    .unwrap_err();
    assert!(err.contains("missing retained MARF root"), "{err}");
    assert!(err.contains(&missing.to_string()), "{err}");
}

#[test]
fn root_checks_enforce_real_squash_floor_and_its_fork_identity() {
    let dir = tempdir_in("/tmp").unwrap();
    let source = dir.path().join("source.sqlite");
    let squashed = dir.path().join("squashed.sqlite");
    let ids = [
        StacksBlockId([1; 32]),
        StacksBlockId([2; 32]),
        StacksBlockId([3; 32]),
    ];
    let mut marf =
        MARF::<StacksBlockId>::from_path(source.to_str().unwrap(), MARFOpenOpts::default())
            .unwrap();
    let mut parent = StacksBlockId::sentinel();
    for (height, id) in ids.iter().enumerate() {
        marf.begin(&parent, id).unwrap();
        marf.insert("key", MARFValue::from_value(&height.to_string()))
            .unwrap();
        marf.commit().unwrap();
        parent = id.clone();
    }
    drop(marf);
    MARF::<StacksBlockId>::squash_to_path(
        source.to_str().unwrap(),
        squashed.to_str().unwrap(),
        MARFOpenOpts::default(),
        &ids[2],
        2,
        "maintenance-floor-test",
    )
    .unwrap();
    check_roots(&squashed, &ids.iter().cloned().collect(), &ids[2]).unwrap();
    let err = check_roots(
        &squashed,
        &HashSet::from([ids[0].clone(), ids[1].clone()]),
        &ids[1],
    )
    .unwrap_err();
    assert!(
        err.contains("target precedes available history floor"),
        "{err}"
    );
    // A different ID at the floor height is not the retained floor.
    let fork = StacksBlockId([9; 32]);
    let err = check_roots(
        &squashed,
        &HashSet::from([ids[0].clone(), ids[1].clone(), fork.clone()]),
        &fork,
    )
    .unwrap_err();
    assert!(
        err.contains("target precedes available history floor"),
        "{err}"
    );
}

#[test]
fn clarity_metadata_retention_removes_discarded_deployment_rows() {
    let chainstate = TestChainstateBuilder::new_testnet("maintenance-metadata-retention").build();
    let index_path: String = chainstate
        .db()
        .query_row("PRAGMA database_list", [], |r| r.get(2))
        .unwrap();
    let clarity_path = Path::new(&index_path)
        .parent()
        .unwrap()
        .join("clarity/marf.sqlite");
    let retained = boundary(chainstate.db(), &FIRST_STACKS_BLOCK_ID);
    drop(chainstate);
    let conn = Connection::open(clarity_path).unwrap();
    let original: u64 = conn
        .query_row("SELECT COUNT(*) FROM metadata_table", [], |r| r.get(0))
        .unwrap();
    assert!(original > 0, "boot contracts must have real metadata");
    let discarded = StacksBlockId([0x99; 32]);
    // Copy actual boot metadata under the discarded deployment identity: the
    // storage rule is keyed by deployment block, not contract name or height.
    conn.execute("INSERT INTO metadata_table(key,blockhash,value) SELECT key,?1,value FROM metadata_table WHERE blockhash = ?2", params![discarded, &*FIRST_STACKS_BLOCK_ID]).unwrap();
    let added: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM metadata_table WHERE blockhash = ?1",
            [&discarded],
            |r| r.get(0),
        )
        .unwrap();
    assert!(added > 0);
    block_set(&conn, &retained).unwrap();
    retain(&conn, "metadata_table", "blockhash", "retained_blocks").unwrap();
    let remaining: u64 = conn
        .query_row("SELECT COUNT(*) FROM metadata_table", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, original);
    let discarded_count: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM metadata_table WHERE blockhash = ?1",
            [&discarded],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(discarded_count, 0);
}

#[test]
fn sortition_rewind_replaces_stale_canonical_tip_memos() {
    let dir = tempdir_in("/tmp").unwrap();
    let config = config();
    let burn = config.get_burnchain();
    let sortition_dir = dir.path().join("sortition");
    let sortdb = SortitionDB::connect(
        sortition_dir.to_str().unwrap(),
        burn.first_block_height,
        &burn.first_block_hash,
        u64::from(burn.first_block_timestamp),
        &config.burnchain.get_epoch_list(),
        burn.pox_constants,
        None,
        true,
        None,
    )
    .unwrap();
    drop(sortdb);
    let path = sortition_dir.join("marf.sqlite");
    let conn = Connection::open(&path).unwrap();
    let genesis = SortitionDB::get_canonical_burn_chain_tip(&conn).unwrap();
    let chainstate = TestChainstateBuilder::new_testnet("maintenance-stale-tip-memos").build();
    let mut retained = boundary(chainstate.db(), &FIRST_STACKS_BLOCK_ID);
    retained.burn_tip = genesis.clone();
    retained.sortitions = vec![genesis.clone()];
    let stale_hash = stacks_common::types::chainstate::BlockHeaderHash([9; 32]);
    let stale_consensus = ConsensusHash([9; 20]);
    // Inject an inconsistent memo that ordinary writers cannot create atomically.
    conn.pragma_update(None, "foreign_keys", false).unwrap();
    conn.execute("UPDATE snapshots SET canonical_stacks_tip_height=999, canonical_stacks_tip_hash=?1, canonical_stacks_tip_consensus_hash=?2", params![stale_hash, stale_consensus]).unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO stacks_chain_tips VALUES (?1,?2,?3,999)",
        params![genesis.sortition_id, stale_consensus, stale_hash],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO stacks_chain_tips_by_burn_view VALUES (?1,?2,?3,?4,999)",
        params![
            genesis.sortition_id,
            stale_consensus,
            genesis.consensus_hash,
            stale_hash
        ],
    )
    .unwrap();
    drop(conn);
    rewind_sortitions(&path, &retained, &config).unwrap();
    let conn = Connection::open(path).unwrap();
    let (consensus, hash) = SortitionDB::get_canonical_stacks_chain_tip_hash(&conn).unwrap();
    assert_eq!(
        StacksBlockId::new(&consensus, &hash),
        *FIRST_STACKS_BLOCK_ID
    );
    let stale_rows: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM stacks_chain_tips WHERE block_hash = ?1",
            [&stale_hash],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stale_rows, 0);
}

#[test]
fn sortition_rewind_keeps_next_arrival_above_retained_marf_watermark() {
    use crate::chainstate::burn::db::sortdb::tests::make_fork_run;

    let config = config();
    let mut db = SortitionDB::connect_test(0, &BurnchainHeaderHash([0xfe; 32])).unwrap();
    let path: String = db
        .conn()
        .query_row("PRAGMA database_list", [], |r| r.get(2))
        .unwrap();
    let genesis = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
    let main = make_fork_run(&mut db, &genesis, 2, 0);
    let chainstate = TestChainstateBuilder::new_testnet("maintenance-arrival-watermark").build();
    let mut retained = boundary(chainstate.db(), &FIRST_STACKS_BLOCK_ID);
    let mut accepted = retained.stacks_blocks[0].clone();
    let StacksBlockHeaderTypes::Epoch2(header) = &mut accepted.anchored_header else {
        panic!("expected epoch-2 genesis");
    };
    header.version = 1;
    accepted.stacks_block_height = 1;
    accepted.consensus_hash = main[0].consensus_hash.clone();
    accepted.burn_header_height = main[0].block_height.try_into().unwrap();
    let accepted_hash = accepted.anchored_header.block_hash();
    db.conn()
        .execute(
            "UPDATE snapshots SET winning_stacks_block_hash=?1 WHERE sortition_id=?2",
            params![accepted_hash, main[0].sortition_id],
        )
        .unwrap();
    {
        let mut tx = db.tx_handle_begin(&main[1].sortition_id).unwrap();
        tx.set_stacks_block_accepted(
            &main[0].consensus_hash,
            &main[0].consensus_hash,
            &accepted_hash,
            1,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    // Discarded fork arrivals raise the global SQL sequence. A later retained
    // root commits that sequence even though those blocks are not its ancestors.
    let fork = make_fork_run(&mut db, &genesis, 3, 0x80);
    for snapshot in &fork {
        let mut tx = db.tx_handle_begin(&snapshot.sortition_id).unwrap();
        tx.set_stacks_block_accepted(
            &snapshot.consensus_hash,
            &snapshot.consensus_hash,
            &snapshot.winning_stacks_block_hash,
            snapshot.block_height,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let tip = make_fork_run(&mut db, &main[1], 1, 0).pop().unwrap();
    let watermark = db
        .index_handle(&tip.sortition_id)
        .get_stacks_block_max_arrival_index()
        .unwrap();
    assert!(watermark > 2);
    retained.target = accepted.index_block_hash();
    retained.stacks_height = 1;
    retained.stacks_blocks.insert(0, accepted);
    retained.burn_tip = SortitionDB::get_block_snapshot(db.conn(), &tip.sortition_id)
        .unwrap()
        .unwrap();
    retained.sortitions = [&tip, &main[1], &main[0], &genesis]
        .into_iter()
        .map(|s| {
            SortitionDB::get_block_snapshot(db.conn(), &s.sortition_id)
                .unwrap()
                .unwrap()
        })
        .collect();
    let roots: Vec<_> = retained
        .sortitions
        .iter()
        .map(|s| (s.sortition_id.clone(), s.index_root.clone()))
        .collect();
    drop(db);
    rewind_sortitions(Path::new(&path), &retained, &config).unwrap();
    let mut db = SortitionDB::open(
        Path::new(&path).parent().unwrap().to_str().unwrap(),
        true,
        config.get_burnchain().pox_constants,
        None,
    )
    .unwrap();
    {
        let mut tx = db.tx_handle_begin(&tip.sortition_id).unwrap();
        tx.set_stacks_block_accepted(
            &main[1].consensus_hash,
            &main[1].consensus_hash,
            &main[1].winning_stacks_block_hash,
            2,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let next = SortitionDB::get_block_snapshot(db.conn(), &main[1].sortition_id)
        .unwrap()
        .unwrap();
    assert_eq!(next.arrival_index, watermark + 1);
    let tip_after = SortitionDB::get_block_snapshot(db.conn(), &tip.sortition_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        tip_after.canonical_stacks_tip_height, 2,
        "new arrival must not be skipped by the retained root"
    );
    assert_eq!(
        tip_after.canonical_stacks_tip_hash,
        main[1].winning_stacks_block_hash
    );
    for (id, root) in roots {
        assert_eq!(
            SortitionDB::get_block_snapshot(db.conn(), &id)
                .unwrap()
                .unwrap()
                .index_root,
            root
        );
    }
    assert_eq!(
        db.index_handle(&tip.sortition_id)
            .get_stacks_block_max_arrival_index()
            .unwrap(),
        watermark
    );
    let child = make_fork_run(&mut db, &tip_after, 1, 0).pop().unwrap();
    assert_eq!(
        db.index_handle(&child.sortition_id)
            .get_stacks_block_max_arrival_index()
            .unwrap(),
        watermark + 1
    );
}
