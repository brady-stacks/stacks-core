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

use clarity::vm::database::SqliteConnection;
use clarity::vm::types::QualifiedContractIdentifier;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::SIGNER_SLOTS_PER_USER;
use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_marf::maintenance::{root_hashes, verify_roots};
use stacks_marf::{ClarityMarfTrieId, MARFValue};

use super::*;
use crate::burnchains::bitcoin::spv::SpvClient;
use crate::chainstate::coordinator::OnChainRewardSetProvider;
use crate::chainstate::nakamoto::coordinator::load_nakamoto_reward_set_for_tenure;
use crate::chainstate::nakamoto::signer_set::NakamotoSigners;
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::stacks::{
    StacksBlock, StacksMicroblock, StacksTransaction, TransactionPayload,
};
use crate::clarity_vm::clarity::ClarityConnection;
use crate::util_lib::boot::boot_code_id;

fn check_side_values(
    conn: &Connection,
    table: &str,
    key: &str,
    values: Vec<MARFValue>,
) -> Result<(), String> {
    let mut stmt = conn
        .prepare(&format!("SELECT value FROM {table} WHERE {key} = ?1"))
        .map_err(error)?;
    for hash in values {
        let value: String = stmt
            .query_row([hash.to_hex()], |r| r.get(0))
            .optional()
            .map_err(error)?
            .ok_or_else(|| format!("Missing reachable {table} value {}", hash.to_hex()))?;
        if MARFValue::from_value(&value) != hash {
            return Err(format!("Corrupt {table} value {}", hash.to_hex()));
        }
    }
    Ok(())
}

fn contracts_in(txs: &[StacksTransaction], contracts: &mut HashSet<QualifiedContractIdentifier>) {
    for tx in txs {
        if let TransactionPayload::SmartContract(contract, _) = &tx.payload {
            contracts.insert(QualifiedContractIdentifier::new(
                tx.origin_address().into(),
                contract.name.clone(),
            ));
        }
    }
}

fn verify_payloads(
    dir: &Path,
    boundary: &RecoveryBoundary,
) -> Result<HashSet<QualifiedContractIdentifier>, String> {
    let index = open(&dir.join(INDEX), false)?;
    let naka = open(&dir.join(NAKAMOTO), false)?;
    let mut contracts = HashSet::new();
    for info in &boundary.stacks_blocks {
        if info.stacks_block_height == 0 {
            continue;
        }
        let id = info.index_block_hash();
        match &info.anchored_header {
            StacksBlockHeaderTypes::Nakamoto(header) => {
                let bytes: Vec<u8> = naka.query_row("SELECT data FROM nakamoto_staging_blocks WHERE index_block_hash = ?1 AND processed = 1 AND orphaned = 0", [&id], |r| r.get(0)).optional().map_err(error)?
                    .ok_or_else(|| format!("Missing retained Nakamoto payload {id}"))?;
                let mut bytes = bytes.as_slice();
                let block = NakamotoBlock::consensus_deserialize(&mut bytes).map_err(error)?;
                if !bytes.is_empty() || &block.header != header {
                    return Err(format!("Payload/header mismatch at {id}"));
                }
                contracts_in(&block.txs, &mut contracts);
            }
            StacksBlockHeaderTypes::Epoch2(header) => {
                let path = dir
                    .join("chainstate/blocks")
                    .join(StacksChainState::index_block_hash_to_rel_path(&id));
                let file =
                    std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                let mut reader = std::io::BufReader::new(file);
                let block = StacksBlock::consensus_deserialize(&mut reader).map_err(error)?;
                if &block.header != header {
                    return Err(format!("Payload/header mismatch at {id}"));
                }
                contracts_in(&block.txs, &mut contracts);
            }
        }
    }
    for hash in retention::confirmed_microblocks(&index, boundary)? {
        let bytes: Vec<u8> = index
            .query_row(
                "SELECT block_data FROM staging_microblocks_data WHERE block_hash = ?1",
                [&hash],
                |r| r.get(0),
            )
            .map_err(error)?;
        let block =
            StacksMicroblock::consensus_deserialize(&mut bytes.as_slice()).map_err(error)?;
        contracts_in(&block.txs, &mut contracts);
    }
    Ok(contracts)
}

/// A current-state check must detect the Clarity-before-index commit window,
/// without mistaking fully committed side forks for unfinished work.
pub(super) fn verify_committed_headers(dir: &Path) -> Result<(), String> {
    let index = open(&dir.join(INDEX), false)?;
    let mut header = index
        .prepare(
            "SELECT EXISTS(SELECT 1 FROM block_headers WHERE index_block_hash = ?1 \
         UNION ALL SELECT 1 FROM nakamoto_block_headers WHERE index_block_hash = ?1)",
        )
        .map_err(error)?;
    for store in [INDEX, CLARITY] {
        let db = open(&dir.join(store), false)?;
        let mut roots = db
            .prepare("SELECT block_hash FROM marf_data WHERE unconfirmed = 0 AND block_hash != ?1")
            .map_err(error)?;
        let mut rows = roots.query([StacksBlockId::sentinel()]).map_err(error)?;
        while let Some(row) = rows.next().map_err(error)? {
            let id: StacksBlockId = row.get(0).map_err(error)?;
            if !header
                .query_row([&id], |row| row.get::<_, bool>(0))
                .map_err(error)?
            {
                return Err(format!(
                    "{store}: confirmed MARF root {id} has no committed header"
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn verify_boundary(
    dir: &Path,
    boundary: &RecoveryBoundary,
    config: &Config,
) -> Result<(), String> {
    for file in [INDEX, CLARITY, SORTITION, BURNCHAIN, SPV, NAKAMOTO] {
        integrity(&open(&dir.join(file), false)?, file)?;
    }
    let index = open(&dir.join(INDEX), false)?;
    let clarity = open(&dir.join(CLARITY), false)?;
    let sortition = open(&dir.join(SORTITION), false)?;
    snapshot::clarity::assert_source_tables_classified(&clarity).map_err(error)?;
    snapshot::blocks::assert_source_tables_classified(&open(&dir.join(NAKAMOTO), false)?)
        .map_err(error)?;
    snapshot::burnchain::assert_source_tables_classified(&open(&dir.join(BURNCHAIN), false)?)
        .map_err(error)?;
    snapshot::spv::assert_source_tables_classified(&open(&dir.join(SPV), false)?).map_err(error)?;
    retention::check_epochs(&sortition, boundary, config)?;
    let ids = retention::retained_blocks(boundary);
    let sortition_ids: HashSet<_> = boundary
        .sortitions
        .iter()
        .map(|s| s.sortition_id.clone())
        .collect();
    check_side_values(
        &index,
        "__fork_storage",
        "value_hash",
        verify_roots(&dir.join(INDEX), &ids).map_err(error)?,
    )?;
    check_side_values(
        &clarity,
        "data_table",
        "key",
        verify_roots(&dir.join(CLARITY), &ids).map_err(error)?,
    )?;
    check_side_values(
        &sortition,
        "__fork_storage",
        "value_hash",
        verify_roots(&dir.join(SORTITION), &sortition_ids).map_err(error)?,
    )?;
    let index_roots = root_hashes(&dir.join(INDEX), &ids).map_err(error)?;
    let clarity_roots = root_hashes(&dir.join(CLARITY), &ids).map_err(error)?;
    let sortition_roots = root_hashes(&dir.join(SORTITION), &sortition_ids).map_err(error)?;
    for info in &boundary.stacks_blocks {
        let id = if info.stacks_block_height == 0 {
            FIRST_STACKS_BLOCK_ID.clone()
        } else {
            info.index_block_hash()
        };
        if index_roots.get(&id) != Some(&info.index_root) {
            return Err(format!("Index root/header mismatch at {id}"));
        }
        if info.stacks_block_height != 0 {
            let state_root = match &info.anchored_header {
                StacksBlockHeaderTypes::Epoch2(h) => &h.state_index_root,
                StacksBlockHeaderTypes::Nakamoto(h) => &h.state_index_root,
            };
            if clarity_roots.get(&id) != Some(state_root) {
                return Err(format!("Clarity root/header mismatch at {id}"));
            }
        }
    }
    let burnchain = open(&dir.join(BURNCHAIN), false)?;
    let spv = SpvClient::new(
        dir.join(SPV).to_str().ok_or("Non-UTF8 SPV path")?,
        0,
        None,
        config.burnchain.get_bitcoin_network().1,
        false,
        false,
    )
    .map_err(error)?;
    for snapshot in &boundary.sortitions {
        if sortition_roots.get(&snapshot.sortition_id) != Some(&snapshot.index_root) {
            return Err(format!(
                "Sortition root mismatch at {}",
                snapshot.sortition_id
            ));
        }
        let (height, parent): (u64, stacks_common::types::chainstate::BurnchainHeaderHash) = burnchain.query_row("SELECT block_height, parent_block_hash FROM burnchain_db_block_headers WHERE block_hash = ?1", [&snapshot.burn_header_hash], |r| Ok((r.get(0)?, r.get(1)?))).optional().map_err(error)?
            .ok_or_else(|| format!("Missing retained burn header {}", snapshot.burn_header_hash))?;
        if height != snapshot.block_height
            || (!snapshot.is_initial() && parent != snapshot.parent_burn_header_hash)
        {
            return Err(format!("Burnchain header mismatch at {height}"));
        }
        let header = spv
            .read_block_header(height)
            .map_err(error)?
            .ok_or_else(|| format!("Missing SPV header {height}"))?;
        let actual = BurnchainHeaderHash::from_bitcoin_hash(&header.header.bitcoin_hash());
        if actual != snapshot.burn_header_hash {
            return Err(format!("SPV/sortition disagreement at {height}"));
        }
    }
    let canonical = SortitionDB::get_canonical_burn_chain_tip(&sortition).map_err(error)?;
    if canonical.sortition_id != boundary.burn_tip.sortition_id {
        return Err("Canonical burn tip differs from recovery boundary".into());
    }
    let (ch, bh) = SortitionDB::get_canonical_stacks_chain_tip_hash(&sortition).map_err(error)?;
    if StacksBlockId::new(&ch, &bh) != boundary.target {
        return Err("Canonical Stacks tip differs from recovery boundary".into());
    }
    let mut contracts = verify_payloads(dir, boundary)?;
    SqliteConnection::visit_metadata_keys(
        &clarity,
        |key| -> Result<(), Box<dyn std::error::Error>> {
            let (contract, _) =
                SqliteConnection::parse_metadata_key(key).ok_or("Invalid contract metadata key")?;
            contracts.insert(QualifiedContractIdentifier::parse(contract)?);
            Ok(())
        },
    )
    .map_err(error)?;
    for name in [
        "pox",
        "pox-2",
        "pox-3",
        "pox-4",
        "pox-5",
        "lockup",
        "costs",
        "costs-2",
        "costs-3",
        "costs-4",
        "cost-voting",
        "bns",
        "genesis",
        "signers",
        "signers-voting",
        "miners",
        "sip-031",
    ] {
        contracts.insert(boot_code_id(name, config.is_mainnet()));
    }
    for signer_set in 0..2 {
        for message_id in 0..SIGNER_SLOTS_PER_USER {
            contracts.insert(NakamotoSigners::make_signers_db_contract_id(
                signer_set,
                message_id,
                config.is_mainnet(),
            ));
        }
    }
    drop(index);
    drop(clarity);
    drop(sortition);
    let burn = config.get_burnchain();
    let sortdb = SortitionDB::open(
        dir.join("burnchain/sortition")
            .to_str()
            .ok_or("Non-UTF8 sortition path")?,
        false,
        burn.pox_constants.clone(),
        Some(config.node.get_marf_opts()),
    )
    .map_err(error)?;
    let (mut chainstate, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        dir.join("chainstate")
            .to_str()
            .ok_or("Non-UTF8 chainstate path")?,
        Some(config.node.get_marf_opts()),
    )
    .map_err(error)?;
    let burn_view = sortdb.index_handle(&boundary.burn_tip.sortition_id);
    chainstate
        .with_read_only_clarity_tx(&burn_view, &boundary.target, |tx| {
            tx.with_clarity_db_readonly(|db| -> Result<(), String> {
                for contract in contracts {
                    if db.get_contract_hash(&contract).map_err(error)?.is_none() {
                        continue;
                    }
                    let context = db
                        .get_contract(&contract)
                        .map_err(|e| format!("Contract {contract}: {e}"))?;
                    db.get_contract_size(&contract)
                        .map_err(|e| format!("Contract {contract}: {e}"))?;
                    db.load_contract_analysis(&contract)
                        .map_err(error)?
                        .ok_or_else(|| format!("Missing retained analysis for {contract}"))?;
                    for name in context.meta_data_var.keys() {
                        db.load_variable(&contract, name)
                            .map_err(|e| format!("Contract {contract} variable {name}: {e}"))?;
                    }
                    for name in context.meta_data_map.keys() {
                        db.load_map(&contract, name)
                            .map_err(|e| format!("Contract {contract} map {name}: {e}"))?;
                    }
                    for name in context.meta_ft.keys() {
                        db.load_ft(&contract, name)
                            .map_err(|e| format!("Contract {contract} token {name}: {e}"))?;
                    }
                    for name in context.meta_nft.keys() {
                        db.get_nft_key_type(&contract, name)
                            .map_err(|e| format!("Contract {contract} token {name}: {e}"))?;
                    }
                }
                Ok(())
            })
        })
        .ok_or("Cannot reopen retained Clarity state")??;
    let mut tenures = HashSet::new();
    let mut cycles = HashSet::new();
    let provider = OnChainRewardSetProvider::new();
    let elections: HashMap<_, _> = boundary
        .sortitions
        .iter()
        .map(|s| (&s.consensus_hash, s))
        .collect();
    for header in &boundary.stacks_blocks {
        if !matches!(header.anchored_header, StacksBlockHeaderTypes::Nakamoto(_))
            || !tenures.insert(&header.consensus_hash)
        {
            continue;
        }
        let election = elections
            .get(&header.consensus_hash)
            .ok_or("Missing retained tenure election")?;
        load_nakamoto_reward_set_for_tenure(
            election,
            &burn,
            &mut chainstate,
            &boundary.target,
            &sortdb,
            &provider,
        )
        .map_err(|e| format!("Retained tenure {} reward set: {e}", header.consensus_hash))?
        .ok_or_else(|| {
            format!(
                "Missing retained reward set for tenure {}",
                header.consensus_hash
            )
        })?;
        let cycle = burn
            .block_height_to_reward_cycle(election.block_height)
            .ok_or("Retained tenure has no reward cycle")?;
        if cycles.insert(cycle) {
            // The first Nakamoto cycle's consensus loader uses sortition
            // storage, but signer-set RPCs also require its epoch-2 SQL row.
            provider
                .read_reward_set_nakamoto(&mut chainstate, cycle, &sortdb, &boundary.target, true)
                .map_err(|e| format!("Retained signer set for cycle {cycle}: {e:?}"))?;
        }
    }
    Ok(())
}
