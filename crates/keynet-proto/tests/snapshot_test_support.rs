#![allow(dead_code)]

use keynet_proto::{
    RegionMarks, RegionPresenceOrigin, RegionPresenceStream, RegionSnapshotControl,
    RegionSnapshotDecision, RegionSnapshotDurableBatch, RegionSnapshotDurableBatchAcknowledgment,
    RegionSnapshotDurableCutReceipt, RegionSnapshotDurableStore, RegionSnapshotEffect,
    RegionSnapshotOwnerIndexOutcome, RegionSnapshotOwnerValidation,
    RegionSnapshotOwnerValidationRequest, RegionSnapshotStoreLineage,
};

pub fn control(origin: RegionPresenceOrigin) -> RegionSnapshotControl {
    control_with_id(origin, 1)
}

pub fn control_with_id(
    origin: RegionPresenceOrigin,
    control_stream_id: u64,
) -> RegionSnapshotControl {
    RegionSnapshotControl {
        stream: RegionPresenceStream {
            origin,
            is_current: true,
        },
        local_boot_epoch: 17,
        control_stream_id,
    }
}

pub fn store(durable_revision: u64) -> RegionSnapshotDurableStore {
    RegionSnapshotDurableStore {
        lineage: RegionSnapshotStoreLineage { bytes: [0x5a; 16] },
        durable_revision,
    }
}

pub fn validation_request(
    decision: &RegionSnapshotDecision,
) -> Result<RegionSnapshotOwnerValidationRequest, String> {
    decision
        .effects
        .iter()
        .find_map(|effect| match effect {
            RegionSnapshotEffect::ValidateSnapshotOwners(request) => Some(request.clone()),
            RegionSnapshotEffect::PersistDurableBatch(_)
            | RegionSnapshotEffect::RetireLocalPresence(_) => None,
        })
        .ok_or_else(|| "snapshot decision did not request exact owner validation".to_owned())
}

pub fn unique_validation(
    request: RegionSnapshotOwnerValidationRequest,
) -> RegionSnapshotOwnerValidation {
    let owner_count = request
        .previous_indexed_owner_count
        .checked_add(request.owners.len())
        .map_or(usize::MAX, |count| count);
    let index_bytes = if owner_count == 0 {
        0
    } else {
        owner_count
            .checked_mul(
                core::mem::size_of::<keynet_proto::RegionOwner>() + core::mem::size_of::<usize>(),
            )
            .and_then(|bytes| {
                bytes.checked_add(core::mem::size_of::<Vec<keynet_proto::RegionOwner>>())
            })
            .map_or(usize::MAX, |bytes| bytes)
    };
    RegionSnapshotOwnerValidation {
        request,
        outcome: RegionSnapshotOwnerIndexOutcome::Unique {
            indexed_owner_count: owner_count,
            indexed_bytes: index_bytes,
        },
    }
}

pub fn durable_batch(
    decision: &RegionSnapshotDecision,
) -> Result<RegionSnapshotDurableBatch, String> {
    decision
        .effects
        .iter()
        .find_map(|effect| match effect {
            RegionSnapshotEffect::PersistDurableBatch(batch) => Some(batch.clone()),
            RegionSnapshotEffect::ValidateSnapshotOwners(_)
            | RegionSnapshotEffect::RetireLocalPresence(_) => None,
        })
        .ok_or_else(|| "snapshot decision did not request a durable batch".to_owned())
}

pub fn acknowledgment(
    batch: &RegionSnapshotDurableBatch,
    durable_store: RegionSnapshotDurableStore,
) -> RegionSnapshotDurableBatchAcknowledgment {
    RegionSnapshotDurableBatchAcknowledgment {
        control: batch.control,
        snapshot_id: batch.snapshot_id,
        base_revision: batch.base_revision,
        marks_revision: batch.marks_revision,
        chunk_index: batch.chunk_index,
        accepted_through: batch.accepted_through,
        commitment: batch.commitment,
        durable_store,
    }
}

pub fn receipt(
    decision: &RegionSnapshotDecision,
    control: RegionSnapshotControl,
    durable_store: RegionSnapshotDurableStore,
) -> Result<RegionSnapshotDurableCutReceipt, String> {
    let stage = decision
        .staging
        .stages
        .iter()
        .find(|stage| stage.control == control)
        .ok_or_else(|| "missing final snapshot stage".to_owned())?;
    let final_chunk_index = stage
        .final_chunk_index
        .ok_or_else(|| "final snapshot stage lacks a final chunk index".to_owned())?;
    Ok(RegionSnapshotDurableCutReceipt {
        control,
        snapshot_id: stage.snapshot_id,
        base_revision: stage.base_revision,
        marks_revision: stage.marks_revision,
        accepted_through: final_chunk_index,
        cut_commitment: stage.cut_commitment,
        final_batch_commitment: stage.final_batch_commitment,
        durable_store,
    })
}

pub fn is_durable_batch_for(decision: &RegionSnapshotDecision, mark: RegionMarks) -> bool {
    durable_batch(decision).is_ok_and(|batch| batch.joins == vec![mark])
}
