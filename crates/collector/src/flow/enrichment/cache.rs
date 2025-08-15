// Copyright (C) 2025-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::flow::enrichment::{EnrichmentOperation, Scope, Weight};
use crate::flow::types::FieldRef;
use netgauze_flow_pkt::ie::Field;
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map, hash_map, BTreeMap},
    net::IpAddr,
};
use tracing::{debug, error, info, warn};

/// TODO: description
pub(crate) struct EnrichmentCache(FxHashMap<IpAddr, PeerMetadata>);

impl EnrichmentCache {
    pub(crate) fn new() -> Self {
        Self(FxHashMap::with_hasher(FxBuildHasher))
    }

    pub(crate) fn get(&self, ip: &IpAddr) -> Option<&PeerMetadata> {
        self.0.get(ip)
    }

    pub(crate) fn get_mut(&mut self, ip: &IpAddr) -> Option<&mut PeerMetadata> {
        self.0.get_mut(ip)
    }

    pub(crate) fn remove(&mut self, ip: &IpAddr) -> Option<PeerMetadata> {
        self.0.remove(ip)
    }

    // TODO: lot of testing for upserts/delete edge cases!
    pub(crate) fn apply_enrichment(&mut self, op: EnrichmentOperation) {
        match op {
            EnrichmentOperation::Upsert(ip, scope, weight, incoming_fields) => {
                self.upsert(ip, scope, weight, incoming_fields);
            }
            EnrichmentOperation::Delete(ip, scope, weight) => {
                self.delete(ip, scope, weight);
            }
        }
    }

    fn upsert(&mut self, ip: IpAddr, scope: Scope, weight: Weight, incoming_fields: Vec<Field>) {
        let peer_metadata = self.0.entry(ip).or_insert_with(|| {
            debug!("Creating new peer metadata cache entry for ip={}", ip);
            PeerMetadata {
                map: BTreeMap::new(),
            }
        });

        // Index incoming fields with FieldRef and create WeightedField entries
        let indexed_incoming: FxHashMap<FieldRef, WeightedField> =
            FieldRef::map_fields_fxhashmap_owned(&incoming_fields)
                .into_iter()
                .map(|(field_ref, field)| (field_ref, WeightedField { weight, field }))
                .collect();

        match peer_metadata.map.entry(scope.clone().into()) {
            btree_map::Entry::Occupied(mut entry) => {
                let curr_fields = entry.get_mut();

                for (field_ref, weighted_field) in indexed_incoming {
                    // Check if field with same IE already exists
                    match curr_fields.entry(field_ref) {
                        hash_map::Entry::Occupied(mut occupied) => {
                            let curr_weight = occupied.get().weight;
                            if weight >= curr_weight {
                                debug!("Replacing field[{}] in metadata for ip={}, scope={}, weight {}->{}",
                                            field_ref.ie(),
                                            ip,
                                            scope,
                                            curr_weight,
                                            weight,
                                        );
                                occupied.insert(weighted_field);
                            } else {
                                debug!("Ignoring lower weight field[{}] in metadata for ip={}, scope={}, weight: {}<{}",
                                            field_ref.ie(),
                                            ip,
                                            scope,
                                            curr_weight,
                                            weight,
                                    );
                            }
                        }
                        hash_map::Entry::Vacant(vacant) => {
                            debug!(
                                "Adding new field[{}] in metadata for ip={}, scope={}, weight={}",
                                field_ref.ie(),
                                ip,
                                scope,
                                weight
                            );
                            vacant.insert(weighted_field);
                        }
                    }
                }
            }
            btree_map::Entry::Vacant(entry) => {
                debug!(
                    "Adding new metadata for ip={}, scope={}, weight={}",
                    ip, scope, weight,
                );

                entry.insert(indexed_incoming);
            }
        }
        // TODO: remove this log
        // TODO: in the future dump to another topic also...
        debug!("Cache for {ip}: \n{}", peer_metadata)
    }

    fn delete(&mut self, ip: IpAddr, scope: Scope, weight: Weight) {
        if let Some(peer_metadata) = self.get_mut(&ip) {
            match peer_metadata.map.entry(scope.clone().into()) {
                btree_map::Entry::Occupied(mut occupied) => {
                    let current_fields = occupied.get_mut();

                    current_fields.retain(|_ie, m_fld| {
                        if m_fld.weight < weight {
                            debug!(
                                "Removing field [{:?}] for ip={}, scope={}, weight: {}>{}",
                                m_fld.field, ip, scope, weight, m_fld.weight
                            );
                            false
                        } else {
                            true
                        }
                    });

                    if current_fields.is_empty() {
                        occupied.remove();
                        debug!(
                            "Scope {:?} now empty for ip={}, removing scope entry...",
                            scope, ip
                        );

                        if peer_metadata.map.is_empty() {
                            debug!("Cache now empty for ip={}, cleaning up...", ip);
                            self.remove(&ip);
                        }
                    }
                }
                btree_map::Entry::Vacant(_) => {
                    debug!(
                        "No entry matching ip={} and scope={}, nothing to delete",
                        ip, scope
                    );
                }
            }
        } else {
            debug!("No cache entry for ip={}, nothing to delete", ip);
        }
    }
}

/// TODO: descriptin
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PeerMetadata {
    map: BTreeMap<IndexedScope, FxHashMap<FieldRef, WeightedField>>,
}
impl PeerMetadata {
    pub(crate) fn map(&self) -> &BTreeMap<IndexedScope, FxHashMap<FieldRef, WeightedField>> {
        &self.map
    }

    // TODO: do some tests/check for global and see if it's correct
    /// Return true if scope is matching with incoming
    fn scope_matches(
        scope: &IndexedScope,
        incoming_obs_id: u32,
        incoming_fields: &FxHashMap<FieldRef, &Field>,
    ) -> bool {
        if scope.obs_domain_id != 0 && scope.obs_domain_id != incoming_obs_id {
            debug!(
                "Obs domain ID mismatch: scope={}, incoming={}",
                scope.obs_domain_id, incoming_obs_id
            );
            return false;
        }

        scope.scope_fields.iter().all(|(field_ref, field)| {
            incoming_fields
                .get(field_ref)
                .is_some_and(|incoming| field == *incoming)
        })
    }

    /// Iterate through PeerMetadata and extract fields for enrichment if the scope
    /// is matching. The logic currently selects only the higher weight Field
    /// for all matching scopes.
    ///
    /// As an example, consider the following PeerMetadata entries:
    /// - Scope {obs_domain_id: 0, scope_fields: []} -> Field
    ///   samplerName("TEST1"), weight 64
    /// - Scope {obs_domain_id: 2000, scope_fields: [selectorId(1)]} -> Field
    ///   samplerName("TEST2"), weight 16
    ///
    /// Given inputs incoming_obs_id: 2000, and incoming_fields: [bytes(600),
    /// selectorId(1)] => the return will be [samplerName("TEST2")] due to
    /// the higher weight.
    pub(crate) fn get_enrichment_fields(
        &self,
        incoming_obs_id: u32,
        incoming_fields: &[Field],
    ) -> Vec<Field> {
        // Store incoming fields indexed by FieldRef (IE, index)
        let fields_map = FieldRef::map_fields_fxhashmap(incoming_fields);

        // TODO: further optimize by hashing the scope IEs (lookups where
        //       router could have 100s of VPNs e.g. would be slow otherwise)

        let mut enrichment_fields: FxHashMap<FieldRef, &WeightedField> =
            FxHashMap::with_capacity_and_hasher(16, FxBuildHasher);

        // Iterating from global to more specific scopes (thanks to BTreeMap)
        // TODO: maybe if needed further optimize by hashing the scope IEs (lookups where
        //       router could have 100s of VPNs e.g. would be slow otherwise)
        for (scope, metadata) in self.map() {
            if Self::scope_matches(&scope, incoming_obs_id, &fields_map) {
                for (field_ref, field) in metadata {
                    match enrichment_fields.entry(*field_ref) {
                        hash_map::Entry::Occupied(mut best) => {
                            // If more specific scope and weight equal =>
                            // overwrite!
                            if field.weight() >= best.get().weight() {
                                best.insert(field);
                            }
                        }
                        hash_map::Entry::Vacant(best) => {
                            best.insert(field);
                        }
                    }
                }
            }
        }

        // TODO: remove this log
        debug!("Enrichment fields:\n{}", {
            if enrichment_fields.is_empty() {
                "No enrichment fields".to_string()
            } else {
                let mut output = String::new();
                output.push_str("| FieldRef | Weight | Field |\n");
                output.push_str("|----------|--------|-------|\n");
                for (field_ref, weighted_field) in &enrichment_fields {
                    output.push_str(&format!(
                        "| {:?} | {} | {:?} |\n",
                        field_ref,
                        weighted_field.weight(),
                        weighted_field.field()
                    ));
                }
                output
            }
        });

        return enrichment_fields
            .values()
            .map(|weighted_field| weighted_field.field().clone())
            .collect::<Vec<_>>();
    }
}

/// Scope with indexed scope_fields for faster match
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct IndexedScope {
    obs_domain_id: u32,
    scope_fields: Box<[(FieldRef, Field)]>,
}

impl From<Scope> for IndexedScope {
    fn from(scope: Scope) -> Self {
        let scope_fields = scope
            .scope_fields()
            .as_ref()
            .map(|fields| FieldRef::map_fields_boxed_slice_owned(fields))
            .unwrap_or_default();

        Self {
            obs_domain_id: scope.obs_domain_id(),
            scope_fields,
        }
    }
}

impl From<&IndexedScope> for Scope {
    fn from(scope_key: &IndexedScope) -> Self {
        let scope_fields = if scope_key.scope_fields.is_empty() {
            None
        } else {
            Some(
                scope_key
                    .scope_fields
                    .iter()
                    .map(|(_, field)| field.clone())
                    .collect(),
            )
        };

        Scope::new(scope_key.obs_domain_id, scope_fields)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct WeightedField {
    weight: Weight,
    field: Field,
}
impl WeightedField {
    pub(crate) fn weight(&self) -> Weight {
        self.weight
    }
    pub(crate) fn field(&self) -> &Field {
        &self.field
    }
}
