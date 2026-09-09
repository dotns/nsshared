use std::collections::BTreeSet;

use super::{
    AuthenticatedRecord, CompactMember, CompactState, Error, ManagementContents, member_id,
    verify_overlay_addresses,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipEffect {
    Applied,
    NotEntitled,
    StaleIncarnation,
    StaleAdminRevision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipReduction {
    pub state: CompactState,
    pub effect: MembershipEffect,
}

impl CompactState {
    /// Revoke through the signed incarnation without affecting a later admission.
    /// Removing a current administrator changes the set and consumes one revision.
    pub fn reduce_evict(
        &self,
        record: &AuthenticatedRecord<'_>,
    ) -> Result<MembershipReduction, Error> {
        let ManagementContents::Evict(eviction) = record.contents() else {
            return Err(Error::Payload("expected eviction record"));
        };
        let mut next = self.next_record(record)?;
        if !self.entitled(&record.receipt().author_pub) {
            return Ok(MembershipReduction {
                state: next,
                effect: MembershipEffect::NotEntitled,
            });
        }
        if self
            .evicted_through
            .get(&eviction.member_pub)
            .is_some_and(|watermark| *watermark >= eviction.incarnation)
        {
            return Ok(MembershipReduction {
                state: next,
                effect: MembershipEffect::StaleIncarnation,
            });
        }
        next.evicted_through
            .insert(eviction.member_pub, eviction.incarnation);
        if self
            .members
            .get(&eviction.member_pub)
            .is_some_and(|member| member.incarnation <= eviction.incarnation)
        {
            next.members.remove(&eviction.member_pub);
            if next.admins.remove(&eviction.member_pub) {
                next.admins_revision = self
                    .admins_revision
                    .checked_add(1)
                    .ok_or(Error::Payload("admin revision overflow"))?;
            }
        }
        next.validate()?;
        Ok(MembershipReduction {
            state: next,
            effect: MembershipEffect::Applied,
        })
    }

    /// Historical membership only. Live join, relay-origin trust, durability and business
    /// readiness are separate checks. Even ineffective authenticated records consume their seq.
    pub fn reduce_add(
        &self,
        record: &AuthenticatedRecord<'_>,
    ) -> Result<MembershipReduction, Error> {
        let ManagementContents::Add(add) = record.contents() else {
            return Err(Error::Payload("expected add record"));
        };
        let mut next = self.next_record(record)?;
        verify_overlay_addresses(&add.joiner_wg, &add.joiner_addrs)?;
        verify_overlay_addresses(&add.approver_wg, &add.approver_addrs)?;
        let author = &record.receipt().author_pub;
        if !self.entitled(author)
            || self
                .members
                .get(author)
                .is_none_or(|member| member.wg_pub != add.approver_wg)
        {
            return Ok(MembershipReduction {
                state: next,
                effect: MembershipEffect::NotEntitled,
            });
        }
        if self
            .members
            .get(&add.joiner_pub)
            .is_some_and(|current| add.member_incarnation <= current.incarnation)
            || self
                .evicted_through
                .get(&add.joiner_pub)
                .is_some_and(|watermark| add.member_incarnation <= *watermark)
        {
            return Ok(MembershipReduction {
                state: next,
                effect: MembershipEffect::StaleIncarnation,
            });
        }
        if self
            .members
            .iter()
            .any(|(key, member)| key != &add.joiner_pub && member.wg_pub == add.joiner_wg)
        {
            return Err(Error::Payload(
                "add WireGuard key already belongs to another member",
            ));
        }
        next.members.insert(
            add.joiner_pub,
            CompactMember {
                wg_pub: add.joiner_wg,
                incarnation: add.member_incarnation,
            },
        );
        next.validate()?;
        Ok(MembershipReduction {
            state: next,
            effect: MembershipEffect::Applied,
        })
    }

    /// Replace the administrator set at exactly the next revision. Full keys are resolved
    /// from the preceding membership/admin state, never invented from a fingerprint.
    pub fn reduce_admins(
        &self,
        record: &AuthenticatedRecord<'_>,
    ) -> Result<MembershipReduction, Error> {
        let ManagementContents::Admins(admins) = record.contents() else {
            return Err(Error::Payload("expected admins record"));
        };
        let mut next = self.next_record(record)?;
        if !self.entitled(&record.receipt().author_pub) {
            return Ok(MembershipReduction {
                state: next,
                effect: MembershipEffect::NotEntitled,
            });
        }
        let revision = self
            .admins_revision
            .checked_add(1)
            .ok_or(Error::Payload("admin revision overflow"))?;
        if admins.admins_revision != revision {
            return Ok(MembershipReduction {
                state: next,
                effect: MembershipEffect::StaleAdminRevision,
            });
        }
        let known: BTreeSet<_> = self
            .members
            .keys()
            .chain(self.admins.iter())
            .copied()
            .collect();
        let mut desired = BTreeSet::new();
        for id in admins.admins.chunks_exact(20) {
            let mut matches = known.iter().filter(|key| member_id(key).as_slice() == id);
            let key = matches
                .next()
                .ok_or(Error::Payload("unknown administrator identity"))?;
            if matches.next().is_some() {
                return Err(Error::Payload("ambiguous administrator identity"));
            }
            desired.insert(*key);
        }
        next.admins = desired;
        next.admins_revision = revision;
        next.validate()?;
        Ok(MembershipReduction {
            state: next,
            effect: MembershipEffect::Applied,
        })
    }

    fn entitled(&self, author: &[u8; 32]) -> bool {
        self.members.contains_key(author)
            && (self.admins.is_empty() || self.admins.contains(author))
    }

    fn next_record(&self, record: &AuthenticatedRecord<'_>) -> Result<Self, Error> {
        self.validate()?;
        let seq = self
            .seq
            .checked_add(1)
            .ok_or(Error::Payload("membership sequence overflow"))?;
        if record.receipt().network_pub != self.network_pub || record.receipt().seq != seq {
            return Err(Error::Payload(
                "membership record network or sequence mismatch",
            ));
        }
        let mut next = self.clone();
        next.seq = seq;
        Ok(next)
    }
}
