use netgauze_flow_pkt::ie::{Field, HasIE, IE};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Serialize};

// TODO: comment and function descriptions...

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FieldRef {
    ie: IE,
    index: usize,
}
impl FieldRef {
    pub fn new(ie: IE, index: usize) -> Self {
        Self { ie, index }
    }
    pub fn ie(&self) -> IE {
        self.ie
    }
    pub fn index(&self) -> usize {
        self.index
    }

    /// Generic function that maps Field objects to FieldRef and collects into
    /// any collection
    pub fn map_fields<'a, T, F, C>(fields: &'a [Field], mut mapper_fn: F) -> C
    where
        F: FnMut(FieldRef, &'a Field) -> T,
        C: FromIterator<T>,
    {
        let mut ie_counters: FxHashMap<IE, usize> =
            FxHashMap::with_capacity_and_hasher(fields.len(), FxBuildHasher);

        fields
            .iter()
            .map(|field| {
                let ie = field.ie();
                let ie_count = ie_counters.entry(ie).or_insert(0);
                let field_ref = FieldRef::new(ie, *ie_count);
                *ie_count += 1;
                mapper_fn(field_ref, field)
            })
            .collect()
    }

    pub fn map_fields_fxhashmap(fields: &[Field]) -> FxHashMap<Self, &Field> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field))
    }

    pub fn map_fields_fxhashmap_owned(fields: &[Field]) -> FxHashMap<Self, Field> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field.clone()))
    }

    pub fn map_fields_vec(fields: &[Field]) -> Vec<(Self, &Field)> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field))
    }

    pub fn map_fields_vec_owned(fields: &[Field]) -> Vec<(Self, Field)> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field.clone()))
    }

    pub fn map_fields_boxed_slice(fields: &[Field]) -> Box<[(Self, &Field)]> {
        Self::map_fields_vec(fields).into_boxed_slice()
    }

    pub fn map_fields_boxed_slice_owned(fields: &[Field]) -> Box<[(Self, Field)]> {
        Self::map_fields_vec_owned(fields).into_boxed_slice()
    }
}
