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

//! Committed progression on a disposable, recovered chainstate, without observers or signers.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksBlockId};

use super::read_stacks_ancestry;
use crate::burnchains::bitcoin::spv::SpvClient;
use crate::burnchains::db::{BurnchainBlockData, BurnchainDB};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::coordinator::{
    ChainsCoordinator, ChainsCoordinatorConfig, CoordinatorCommunication, OnChainRewardSetProvider,
};
use crate::chainstate::nakamoto::coordinator::load_nakamoto_reward_set_for_tenure;
use crate::chainstate::nakamoto::staging_blocks::NakamotoBlockObtainMethod;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::blocks::DummyEventDispatcher;
use crate::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksChainState};
use crate::chainstate::stacks::{StacksBlock, StacksMicroblock};
use crate::config::Config;
use crate::core::EMPTY_MICROBLOCK_PARENT_HASH;
use crate::net::atlas::AtlasConfig;

struct ReplayInputs(PathBuf);

impl ReplayInputs {
    fn copy_sqlite(&self, source: &Path, name: &str) -> Result<PathBuf, String> {
        let destination = self.0.join(name);
        std::fs::copy(source, &destination)
            .map_err(|e| format!("Cannot copy replay input {}: {e}", source.display()))?;
        // SQLite recovery must happen on the private copy, never on the frozen source.
        // Rebuild shared memory from the WAL; preserve hot rollback journals as well.
        for suffix in ["-wal", "-journal"] {
            let companion = source.with_file_name(format!(
                "{}{suffix}",
                source
                    .file_name()
                    .ok_or("Replay input has no file name")?
                    .to_string_lossy()
            ));
            match std::fs::metadata(&companion) {
                Ok(_) => {
                    std::fs::copy(&companion, self.0.join(format!("{name}{suffix}"))).map_err(
                        |e| format!("Cannot copy replay input {}: {e}", companion.display()),
                    )?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(format!(
                        "Cannot inspect replay input {}: {e}",
                        companion.display()
                    ))
                }
            }
        }
        let recovered =
            Connection::open_with_flags(&destination, OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(|e| format!("Cannot recover private replay input: {e}"))?;
        recovered
            .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
            .map_err(|e| format!("Cannot recover private replay input: {e}"))?;
        recovered
            .close()
            .map_err(|(_, e)| format!("Cannot close private replay input: {e}"))?;
        Ok(destination)
    }
}

impl Drop for ReplayInputs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn readonly(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("Cannot read replay input {}: {e}", path.display()))
}

fn snapshot(conn: &Connection, consensus_hash: &ConsensusHash) -> Result<BlockSnapshot, String> {
    super::read_snapshot(conn, "consensus_hash", consensus_hash)
        .map_err(|e| format!("Cannot read replay burn view {consensus_hash}: {e}"))
}

/// Load exactly the confirmed stream, including when it belongs to the retained parent.
/// The production stream loader assumes intact storage and panics on malformed bytes; offline
/// maintenance instead reports missing/corrupt payloads before invoking production admission.
fn confirmed_microblocks(
    conn: &Connection,
    block: &StacksBlock,
) -> Result<Vec<StacksMicroblock>, String> {
    if block.header.parent_microblock == EMPTY_MICROBLOCK_PARENT_HASH
        && block.header.parent_microblock_sequence == 0
    {
        return Ok(vec![]);
    }
    let mut hash = block.header.parent_microblock.clone();
    let mut stream = Vec::new();
    for sequence in (0..=block.header.parent_microblock_sequence).rev() {
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT block_data FROM staging_microblocks_data WHERE block_hash = ?1",
                [&hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("Cannot read confirmed microblock {hash}: {e}"))?
            .ok_or_else(|| format!("Missing confirmed microblock {hash}"))?;
        let microblock = StacksMicroblock::consensus_deserialize(&mut bytes.as_slice())
            .map_err(|e| format!("Invalid confirmed microblock {hash}: {e}"))?;
        if microblock.block_hash() != hash || microblock.header.sequence != sequence {
            return Err(format!(
                "Conflicting confirmed microblock {hash}, sequence {sequence}"
            ));
        }
        hash = microblock.header.prev_block.clone();
        stream.push(microblock);
        if sequence == 0 {
            if hash != block.header.parent_block {
                return Err(
                    "Confirmed microblock stream does not descend from anchored parent".into(),
                );
            }
        }
    }
    stream.reverse();
    Ok(stream)
}

/// Replay a nonempty exact successor range using production admission, coordination and commits.
/// `source` is a frozen input; `probe` must already be a separate recovered copy at `from`.
pub fn replay(
    source: &Path,
    probe: &Path,
    from: &StacksBlockId,
    to: &StacksBlockId,
    config: &Config,
) -> Result<(), String> {
    if from == to {
        return Err(
            "Replay requires a nonempty successor range; progression was not tested".into(),
        );
    }
    let source = source
        .canonicalize()
        .map_err(|e| format!("Cannot locate replay source: {e}"))?;
    let probe = probe
        .canonicalize()
        .map_err(|e| format!("Cannot locate replay probe: {e}"))?;
    if source == probe || source.starts_with(&probe) || probe.starts_with(&source) {
        return Err("Replay source and probe must be separate, non-nested directories".into());
    }
    let source_root = source.join("chainstate");
    let input_path = probe.join(".replay-input");
    std::fs::create_dir(&input_path).map_err(|e| format!("Cannot create replay inputs: {e}"))?;
    let inputs = ReplayInputs(input_path);
    let headers = readonly(&inputs.copy_sqlite(
        &StacksChainState::header_index_root_path(source_root.clone()),
        "index.sqlite",
    )?)?;
    let ancestry = read_stacks_ancestry(&headers, to)?;
    let from_index = ancestry
        .iter()
        .position(|header| header.index_block_hash() == *from)
        .ok_or_else(|| format!("Replay endpoint {to} does not descend from {from}"))?;
    if from_index == 0 {
        return Err("Replay has no successor blocks; progression was not tested".into());
    }
    let source_sortitions = readonly(&inputs.copy_sqlite(
        &source.join("burnchain/sortition/marf.sqlite"),
        "sortition.sqlite",
    )?)?;
    let source_burn = readonly(&inputs.copy_sqlite(
        &source.join("burnchain/burnchain.sqlite"),
        "burnchain.sqlite",
    )?)?;
    let source_staging = if ancestry[..from_index]
        .iter()
        .any(|header| matches!(&header.anchored_header, StacksBlockHeaderTypes::Nakamoto(_)))
    {
        let path = StacksChainState::static_get_nakamoto_staging_blocks_path(source_root.clone())
            .map_err(|e| format!("Cannot locate replay Nakamoto payloads: {e}"))?;
        let path = inputs.copy_sqlite(Path::new(&path), "nakamoto.sqlite")?;
        Some(
            StacksChainState::open_nakamoto_staging_blocks(
                path.to_str().ok_or("Non-UTF-8 replay staging input path")?,
                false,
            )
            .map_err(|e| format!("Cannot open replay Nakamoto payloads: {e}"))?,
        )
    } else {
        None
    };
    let network = config.burnchain.get_bitcoin_network().1;
    let source_headers_path = inputs.copy_sqlite(&source.join("headers.sqlite"), "spv.sqlite")?;
    let probe_headers_path = probe.join("headers.sqlite");
    let source_spv = SpvClient::new(
        source_headers_path
            .to_str()
            .ok_or("Non-UTF-8 replay SPV source path")?,
        0,
        None,
        network,
        false,
        false,
    )
    .map_err(|e| format!("Cannot read replay SPV headers: {e}"))?;
    let mut probe_spv = SpvClient::new(
        probe_headers_path
            .to_str()
            .ok_or("Non-UTF-8 replay SPV probe path")?,
        0,
        None,
        network,
        true,
        false,
    )
    .map_err(|e| format!("Cannot open replay SPV probe: {e}"))?;

    let mut burnchain = config.get_burnchain();
    burnchain.working_dir = probe
        .join("burnchain")
        .to_str()
        .ok_or("Non-UTF-8 replay burnchain path")?
        .to_owned();
    let probe_root = probe.join("chainstate");
    let root = probe_root
        .to_str()
        .ok_or("Non-UTF-8 replay chainstate path")?;
    let (chain_state_db, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        root,
        Some(config.node.get_marf_opts()),
    )
    .map_err(|e| format!("Cannot open replay chainstate: {e}"))?;
    let sortition_db = burnchain
        .open_sortition_db(true)
        .map_err(|e| format!("Cannot open replay sortitions: {e}"))?;
    let burnchain_blocks_db = burnchain
        .open_burnchain_db(true)
        .map_err(|e| format!("Cannot open replay burnchain: {e}"))?;
    let current =
        NakamotoChainState::get_canonical_block_header(chain_state_db.db(), &sortition_db)
            .map_err(|e| format!("Cannot read replay starting tip: {e}"))?
            .ok_or("Replay starting tip is missing")?;
    if current.index_block_hash() != *from {
        return Err(format!(
            "Replay probe is at {}, expected {from}",
            current.index_block_hash()
        ));
    }
    let canonical_sortition_tip = Some(
        SortitionDB::get_canonical_sortition_tip(sortition_db.conn())
            .map_err(|e| format!("Cannot read replay sortition tip: {e}"))?,
    );
    let (comms, _channels) = CoordinatorCommunication::instantiate();
    let mut coordinator: ChainsCoordinator<'_, DummyEventDispatcher, (), _, (), ()> =
        ChainsCoordinator {
            canonical_sortition_tip,
            burnchain_blocks_db,
            chain_state_db,
            sortition_db,
            burnchain,
            atlas_db: None,
            dispatcher: None,
            cost_estimator: None,
            fee_estimator: None,
            reward_set_provider: OnChainRewardSetProvider::new(),
            notifier: (),
            atlas_config: AtlasConfig::new(config.is_mainnet()),
            config: ChainsCoordinatorConfig::new(),
            refresh_stacker_db: Arc::new(AtomicBool::new(false)),
            in_nakamoto_epoch: matches!(
                &current.anchored_header,
                StacksBlockHeaderTypes::Nakamoto(_)
            ),
            comms,
        };

    for index in (0..from_index).rev() {
        let header = &ancestry[index];
        let parent = &ancestry[index + 1];
        let block_id = header.index_block_hash();
        let burn_view = snapshot(
            &source_sortitions,
            header.burn_view.as_ref().unwrap_or(&header.consensus_hash),
        )?;
        let burn_tip = coordinator
            .burnchain_blocks_db
            .get_canonical_chain_tip()
            .map_err(|e| format!("Cannot read probe burn tip: {e}"))?;
        let mut pending: Vec<BurnchainBlockData> = Vec::new();
        let mut hash = burn_view.burn_header_hash.clone();
        let mut seen = HashSet::new();
        while hash != burn_tip.block_hash {
            if !seen.insert(hash.clone()) {
                return Err(format!("Cycle in raw replay burn ancestry at {hash}"));
            }
            let block = BurnchainDB::get_burnchain_block(&source_burn, &hash)
                .map_err(|e| format!("Missing raw replay burn block {hash}: {e}"))?;
            if block.header.block_height <= burn_tip.block_height {
                return Err(format!(
                    "Replay burn view {} does not descend from probe burn tip {}",
                    burn_view.burn_header_hash, burn_tip.block_hash
                ));
            }
            if let Some(child) = pending.last() {
                if child.header.block_height.checked_sub(1) != Some(block.header.block_height) {
                    return Err(format!("Gap in raw replay burn ancestry at {hash}"));
                }
            }
            hash = block.header.parent_block_hash.clone();
            pending.push(block);
        }
        if let Some(first) = pending.last() {
            if burn_tip.block_height.checked_add(1) != Some(first.header.block_height) {
                return Err("Gap between retained and successor raw burn headers".into());
            }
        }
        for mut block in pending.into_iter().rev() {
            let spv_header = source_spv
                .read_block_header(block.header.block_height)
                .map_err(|e| {
                    format!(
                        "Cannot read replay SPV header at {}: {e}",
                        block.header.block_height
                    )
                })?
                .ok_or_else(|| {
                    format!("Missing replay SPV header at {}", block.header.block_height)
                })?;
            if BurnchainHeaderHash::from_bitcoin_hash(&spv_header.header.bitcoin_hash())
                != block.header.block_hash
            {
                return Err(format!(
                    "Replay SPV header disagrees with raw burn block {}",
                    block.header.block_hash
                ));
            }
            let parent_height = block
                .header
                .block_height
                .checked_sub(1)
                .ok_or("Cannot append a successor burn header at height zero")?;
            probe_spv
                .insert_block_headers_after(parent_height, vec![spv_header])
                .map_err(|e| {
                    format!(
                        "Cannot append replay SPV header {}: {e}",
                        block.header.block_hash
                    )
                })?;
            // Raw operations, not the source's accepted operations or processed sortition snapshots.
            block.ops.sort_by_key(|op| op.vtxindex());
            let tx = coordinator
                .burnchain_blocks_db
                .tx_begin()
                .map_err(|e| format!("Cannot begin raw replay burn import: {e}"))?;
            tx.store_burnchain_db_entry(&block.header)
                .and_then(|_| tx.store_blockstack_ops(&block.header, &block.ops))
                .map_err(|e| {
                    format!(
                        "Cannot import raw replay burn block {}: {e}",
                        block.header.block_hash
                    )
                })?;
            tx.commit()
                .map_err(|e| format!("Cannot commit raw replay burn import: {e}"))?;
            coordinator
                .handle_new_burnchain_block()
                .map_err(|e| format!("Burnchain coordination failed before {block_id}: {e:?}"))?;
        }
        match &header.anchored_header {
            StacksBlockHeaderTypes::Epoch2(_) => {
                let path = StacksChainState::blocks_path(source_root.clone())
                    .join(StacksChainState::index_block_hash_to_rel_path(&block_id));
                let block: StacksBlock = StacksChainState::consensus_load(
                    path.to_str().ok_or("Non-UTF-8 epoch-2 payload path")?,
                )
                .map_err(|e| format!("Missing or invalid replay payload {block_id}: {e}"))?;
                if block.block_hash() != header.anchored_header.block_hash() {
                    return Err(format!("Replay payload disagrees with header {block_id}"));
                }
                for microblock in confirmed_microblocks(&headers, &block)? {
                    coordinator
                        .chain_state_db
                        .preprocess_streamed_microblock(
                            &parent.consensus_hash,
                            &parent.anchored_header.block_hash(),
                            &microblock,
                        )
                        .map_err(|e| {
                            format!("Cannot admit replay microblock for {block_id}: {e}")
                        })?;
                }
                coordinator
                    .chain_state_db
                    .preprocess_anchored_block(
                        &coordinator.sortition_db.index_conn(),
                        &header.consensus_hash,
                        &block,
                        &parent.consensus_hash,
                        0,
                    )
                    .map_err(|e| format!("Cannot admit replay anchored block {block_id}: {e}"))?;
                coordinator.handle_new_stacks_block().map_err(|e| {
                    format!("Cannot commit replay anchored block {block_id}: {e:?}")
                })?;
            }
            StacksBlockHeaderTypes::Nakamoto(_) => {
                let staging = source_staging
                    .as_ref()
                    .ok_or("Missing replay staging reader")?;
                let (block, _) = staging
                    .conn()
                    .get_nakamoto_block(&block_id)
                    .map_err(|e| format!("Cannot read replay Nakamoto block {block_id}: {e}"))?
                    .ok_or_else(|| format!("Missing replay Nakamoto block {block_id}"))?;
                if block.block_id() != block_id {
                    return Err(format!(
                        "Replay Nakamoto payload disagrees with header {block_id}"
                    ));
                }
                let tenure = snapshot(
                    coordinator.sortition_db.conn(),
                    &block.header.consensus_hash,
                )?;
                let reward_set = load_nakamoto_reward_set_for_tenure(
                    &tenure,
                    &coordinator.burnchain,
                    &mut coordinator.chain_state_db,
                    &parent.index_block_hash(),
                    &coordinator.sortition_db,
                    &coordinator.reward_set_provider,
                )
                .map_err(|e| format!("Cannot load replay reward set for {block_id}: {e}"))?
                .ok_or_else(|| format!("Replay stalled: reward set unavailable for {block_id}"))?;
                let tip = coordinator
                    .canonical_sortition_tip
                    .as_ref()
                    .ok_or("Replay sortition tip missing")?;
                NakamotoChainState::accept_block(
                    &mut coordinator.chain_state_db,
                    &block,
                    &mut coordinator.sortition_db.index_handle(tip),
                    &reward_set,
                    NakamotoBlockObtainMethod::Downloaded,
                )
                .map_err(|e| format!("Cannot admit replay Nakamoto block {block_id}: {e}"))?;
                coordinator
                    .handle_new_nakamoto_stacks_block()
                    .map_err(|e| {
                        format!("Cannot commit replay Nakamoto block {block_id}: {e:?}")
                    })?;
            }
        }
        let committed = NakamotoChainState::get_canonical_block_header(
            coordinator.chain_state_db.db(),
            &coordinator.sortition_db,
        )
        .map_err(|e| format!("Cannot observe replay progress at {block_id}: {e}"))?
        .ok_or_else(|| format!("Replay made no progress at {block_id}"))?;
        if committed.index_block_hash() != block_id {
            return Err(format!(
                "Replay stalled at {}; expected committed {block_id}",
                committed.index_block_hash()
            ));
        }
    }
    let burnchain = coordinator.burnchain.clone();
    let expected_burn = coordinator
        .burnchain_blocks_db
        .get_canonical_chain_tip()
        .map_err(|e| format!("Cannot read committed replay burn tip: {e}"))?;
    drop(coordinator);
    probe_spv
        .update_chain_work()
        .map_err(|e| format!("Cannot rebuild replay SPV chain work: {e}"))?;
    drop(probe_spv);
    let (chainstate, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        root,
        Some(config.node.get_marf_opts()),
    )
    .map_err(|e| format!("Cannot reopen committed replay chainstate: {e}"))?;
    let sortdb = burnchain
        .open_sortition_db(false)
        .map_err(|e| format!("Cannot reopen committed replay sortitions: {e}"))?;
    let endpoint = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .map_err(|e| format!("Cannot read reopened replay endpoint: {e}"))?
        .ok_or("Reopened replay endpoint is missing")?;
    let burn_endpoint = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
        .map_err(|e| format!("Cannot read reopened replay burn endpoint: {e}"))?;
    let raw_burn = burnchain
        .open_burnchain_db(false)
        .map_err(|e| format!("Cannot reopen committed replay burnchain: {e}"))?
        .get_canonical_chain_tip()
        .map_err(|e| format!("Cannot read reopened raw burn tip: {e}"))?;
    let spv = SpvClient::new(
        probe_headers_path
            .to_str()
            .ok_or("Non-UTF-8 replay SPV path")?,
        0,
        None,
        network,
        false,
        false,
    )
    .map_err(|e| format!("Cannot reopen committed replay SPV headers: {e}"))?;
    let spv_tip = spv
        .read_block_header(expected_burn.block_height)
        .map_err(|e| format!("Cannot read reopened replay SPV tip: {e}"))?
        .ok_or("Reopened replay SPV tip is missing")?;
    if endpoint.index_block_hash() != *to
        || burn_endpoint.burn_header_hash != expected_burn.block_hash
        || burn_endpoint.block_height != expected_burn.block_height
        || raw_burn != expected_burn
        || spv
            .get_highest_header_height()
            .map_err(|e| format!("Cannot read reopened replay SPV height: {e}"))?
            != expected_burn.block_height
        || BurnchainHeaderHash::from_bitcoin_hash(&spv_tip.header.bitcoin_hash())
            != expected_burn.block_hash
    {
        return Err(format!(
            "Reopened replay endpoint differs from requested {to} or committed burn tip"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clarity::vm::types::PrincipalData;
    use stacks_common::types::chainstate::{BlockHeaderHash, StacksPrivateKey};

    use super::*;
    use crate::chainstate::stacks::tests::make_user_stacks_transfer;
    use crate::chainstate::stacks::TransactionAnchorMode;

    fn stream_fixture() -> (Connection, StacksBlock, Vec<StacksMicroblock>) {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE staging_microblocks_data(block_hash TEXT PRIMARY KEY, block_data BLOB NOT NULL)",
        ).unwrap();
        let key = StacksPrivateKey::from_slice(&[1; 32]).unwrap();
        let recipient = PrincipalData::parse("ST000000000000000000002AMW42H").unwrap();
        let mut tx = make_user_stacks_transfer(&key, 0, 0, &recipient, 1);
        tx.anchor_mode = TransactionAnchorMode::OffChainOnly;
        let parent_hash = BlockHeaderHash([7; 32]);
        let first = StacksMicroblock::first_unsigned(&parent_hash, vec![tx.clone()]);
        let second = StacksMicroblock::from_parent_unsigned(&first.header, vec![tx]).unwrap();
        for microblock in [&first, &second] {
            conn.execute(
                "INSERT INTO staging_microblocks_data VALUES (?1, ?2)",
                rusqlite::params![microblock.block_hash(), microblock.serialize_to_vec()],
            )
            .unwrap();
        }
        let mut block = StacksBlock::genesis_block();
        block.header.parent_block = parent_hash;
        block.header.parent_microblock = second.block_hash();
        block.header.parent_microblock_sequence = 1;
        (conn, block, vec![first, second])
    }

    #[test]
    fn confirmed_stream_is_complete_and_ordered() {
        let (conn, block, expected) = stream_fixture();
        assert_eq!(confirmed_microblocks(&conn, &block).unwrap(), expected);
    }

    #[test]
    fn confirmed_stream_rejects_missing_or_corrupt_payloads() {
        let (conn, block, stream) = stream_fixture();
        conn.execute(
            "DELETE FROM staging_microblocks_data WHERE block_hash = ?1",
            [stream[0].block_hash()],
        )
        .unwrap();
        assert!(confirmed_microblocks(&conn, &block)
            .unwrap_err()
            .contains("Missing confirmed"));
        conn.execute(
            "INSERT INTO staging_microblocks_data VALUES (?1, ?2)",
            rusqlite::params![stream[0].block_hash(), vec![0u8]],
        )
        .unwrap();
        assert!(confirmed_microblocks(&conn, &block)
            .unwrap_err()
            .contains("Invalid confirmed"));
    }

    #[test]
    fn confirmed_stream_rejects_wrong_sequence_and_parent() {
        let (conn, mut block, _) = stream_fixture();
        block.header.parent_microblock_sequence = 2;
        assert!(confirmed_microblocks(&conn, &block)
            .unwrap_err()
            .contains("Conflicting"));
        block.header.parent_microblock_sequence = 1;
        block.header.parent_block = BlockHeaderHash([8; 32]);
        assert!(confirmed_microblocks(&conn, &block)
            .unwrap_err()
            .contains("anchored parent"));
    }

    #[test]
    fn empty_replay_never_claims_progression() {
        let id = StacksBlockId([1; 32]);
        let error = replay(
            Path::new("absent-source"),
            Path::new("absent-probe"),
            &id,
            &id,
            &Config::default(),
        )
        .unwrap_err();
        assert!(error.contains("nonempty"));
        assert!(error.contains("progression was not tested"));
    }
}

#[cfg(test)]
mod wal_tests {
    use super::*;

    #[test]
    fn replay_reads_committed_wal_without_touching_source() {
        let source_dir = tempfile::tempdir_in("/tmp").unwrap();
        let probe_dir = tempfile::tempdir_in("/tmp").unwrap();
        let source = source_dir.path().join("input.sqlite");
        let writer = Connection::open(&source).unwrap();
        writer
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA wal_autocheckpoint=0;
             CREATE TABLE payload(value INTEGER);
             INSERT INTO payload VALUES (17);",
            )
            .unwrap();
        let paths = [
            source.clone(),
            source.with_extension("sqlite-wal"),
            source.with_extension("sqlite-shm"),
        ];
        let before: Vec<_> = paths
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect();
        let input_path = probe_dir.path().join("inputs");
        std::fs::create_dir(&input_path).unwrap();
        let inputs = ReplayInputs(input_path);
        let copy = inputs.copy_sqlite(&source, "input.sqlite").unwrap();
        let reader = readonly(&copy).unwrap();
        let value: i64 = reader
            .query_row("SELECT value FROM payload", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, 17);
        for (path, original) in paths.iter().zip(before) {
            assert_eq!(std::fs::read(path).unwrap(), original);
        }
    }
}
