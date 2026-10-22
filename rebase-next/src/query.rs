//! Declared local reads and authenticated revision-bound resumptions.

use crate::binding::Binding;
use std::{cmp::Reverse, collections::BinaryHeap, ops::Bound};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    local::{KV, PUBLIC, PublicRecordValue, RuntimeHeader, Store, corrupt, encode, storage, unhex},
    model::API_VERSION,
    native_codec::{self, Address, decimal, uuid_text},
    native_slice::{Attempt, Error, Result},
    tree::{self, Aggregate},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Equality {
    pub field: String,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordQuery {
    pub path: String,
    pub contract: Option<u16>,
    pub equals: Option<Equality>,
}

impl Default for RecordQuery {
    fn default() -> Self {
        Self {
            path: "records.by_id".into(),
            contract: None,
            equals: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    pub model: String,
    pub query: RecordQuery,
    pub limit: u16,
    pub visit_budget: u16,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExistsRequest {
    pub model: String,
    pub query: RecordQuery,
    pub visit_budget: u16,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub struct PageValue<B: Binding> {
    pub records: Vec<PublicRecordValue<B>>,
    pub visited: u16,
    pub exhausted: bool,
    pub cursor: Option<String>,
    #[serde(with = "decimal")]
    pub revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    api: String,
    #[serde(with = "uuid_text")]
    store: Uuid,
    model: String,
    #[serde(with = "uuid_text")]
    actor: Uuid,
    #[serde(with = "uuid_text")]
    tenant: Uuid,
    #[serde(with = "decimal")]
    revision: u64,
    query: RecordQuery,
    #[serde(with = "uuid_text")]
    after: Uuid,
}

type CursorMac = Hmac<Sha256>;

fn sign(cursor: &Cursor, header: &RuntimeHeader) -> Result<String> {
    let bytes = encode(cursor)?;
    let mut mac = CursorMac::new_from_slice(&unhex(&header.cursor_key)?)
        .map_err(|_| corrupt("cursor signing key"))?;
    mac.update(&bytes);
    Ok(format!(
        "{}.{}",
        native_codec::hex(&bytes),
        native_codec::hex(&mac.finalize().into_bytes())
    ))
}

fn parse_cursor(token: &str, header: &RuntimeHeader) -> Result<Cursor> {
    let bad = || Error::new("invalid_cursor", "cursor does not match this query/store");
    if token.len() > 4096 {
        return Err(bad());
    }
    let (payload, signature) = token.split_once('.').ok_or_else(bad)?;
    let payload = unhex(payload)?;
    let signature = unhex(signature)?;
    let mut mac = CursorMac::new_from_slice(&unhex(&header.cursor_key)?).map_err(|_| bad())?;
    mac.update(&payload);
    mac.verify_slice(&signature).map_err(|_| bad())?;
    serde_json::from_slice(&payload).map_err(|_| bad())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RootRead {
    Summary,
    Before {
        #[serde(with = "decimal")]
        at: i64,
    },
    Latest {
        #[serde(with = "decimal")]
        at: i64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootRequest {
    pub model: String,
    #[serde(with = "uuid_text")]
    pub owner: Uuid,
    pub slot: u16,
    pub read: RootRead,
}

fn next_candidate(
    range: &mut redb::Range<'_, &'static [u8], u16>,
    secured: bool,
) -> Result<Option<(Uuid, u16)>> {
    let Some(row) = range.next() else {
        return Ok(None);
    };
    let (key, code) = row.map_err(storage)?;
    let bytes = key.value();
    let offset = if secured { 18 } else { 0 };
    if bytes.len() != offset + 16 {
        return Err(corrupt("candidate index key"));
    }
    let id = Uuid::from_slice(&bytes[offset..]).map_err(|_| corrupt("candidate identity"))?;
    Ok(Some((id, code.value())))
}

impl<B: Binding> Store<B> {
    pub fn page(&self, request: &PageRequest) -> Result<PageValue<B>> {
        if !(1..=32).contains(&request.limit) || !(1..=128).contains(&request.visit_budget) {
            return Err(Error::new("invalid_input", "page/visit limits"));
        }
        if request.query.path != "records.by_id" {
            return Err(Error::new("unsupported_query", "unregistered path"));
        }
        if let Some(code) = request.query.contract {
            self.model.public_contract(code)?;
        }
        if let Some(predicate) = &request.query.equals {
            let code = request
                .query
                .contract
                .ok_or_else(|| Error::new("invalid_input", "predicate requires a contract"))?;
            self.model
                .validate_predicate(code, &predicate.field, &predicate.value)?;
        }
        let (read, meta, header) = self.read(&request.model)?;
        let scope = self.authority(&read)?;
        if request
            .query
            .contract
            .is_some_and(|c| !scope.grants.allows(c, crate::access::Action::Read))
        {
            return Err(crate::access::denied());
        }
        let after = if let Some(token) = &request.cursor {
            let cursor = parse_cursor(token, &header)?;
            if cursor.api != API_VERSION
                || cursor.store != header.store_id
                || cursor.model != self.model.identity()
                || cursor.actor != self.context.actor
                || cursor.tenant != self.context.tenant
                || cursor.query != request.query
            {
                return Err(Error::new("invalid_cursor", "cursor scope/query differs"));
            }
            if cursor.revision != meta.revision {
                return Err(Error::new(
                    "query_changed",
                    "restart after committed mutation",
                ));
            }
            Some(cursor.after)
        } else {
            None
        };
        let index = read.open_table(PUBLIC).map_err(storage)?;
        let readers = if self.secured {
            Some(read.open_table(crate::security::READERS).map_err(storage)?)
        } else {
            None
        };
        let mut streams = vec![];
        let mut partitions = vec![];
        if let Some(index) = &readers {
            let codes: Vec<_> = self
                .model
                .contracts()
                .filter(|c| {
                    c.visibility == crate::model::Visibility::Public
                        && scope.grants.allows(c.code, crate::access::Action::Read)
                        && request.query.contract.is_none_or(|code| code == c.code)
                })
                .map(|c| c.code)
                .collect();
            if scope.accessible.len().saturating_mul(codes.len())
                > crate::access::MAX_READER_STREAMS
            {
                return Err(Error::new("work_limit", "reader partition setup limit"));
            }
            for &reader in &scope.accessible {
                for &code in &codes {
                    let lower = match after {
                        Some(id) => Bound::Excluded(crate::security::reader_key(reader, code, id)),
                        None => {
                            Bound::Included(crate::security::reader_key(reader, code, Uuid::nil()))
                        }
                    };
                    let upper =
                        Bound::Included(crate::security::reader_key(reader, code, Uuid::max()));
                    streams.push(
                        index
                            .range::<&[u8]>((
                                lower.as_ref().map(Vec::as_slice),
                                upper.as_ref().map(Vec::as_slice),
                            ))
                            .map_err(storage)?,
                    );
                    partitions.push(Some(reader));
                }
            }
        } else {
            let lower = after.map_or(Bound::Unbounded, |id| {
                Bound::Excluded(id.as_bytes().to_vec())
            });
            streams.push(
                index
                    .range::<&[u8]>((lower.as_ref().map(Vec::as_slice), Bound::Unbounded))
                    .map_err(storage)?,
            );
            partitions.push(None);
        }
        let mut heads = BinaryHeap::new();
        for (stream, range) in streams.iter_mut().enumerate() {
            if let Some((id, code)) = next_candidate(range, self.secured)? {
                heads.push(Reverse((id, stream, code)));
            }
        }
        let table = read.open_table(KV).map_err(storage)?;
        let mut ws = Attempt::<_, B>::new(
            |key: &[u8]| {
                table
                    .get(key)
                    .map(|v| v.map(|v| v.value().to_vec()))
                    .map_err(storage)
            },
            10_000,
        );
        let (mut visited, mut exhausted, mut last) = (0_u16, false, None);
        let mut records = vec![];
        while visited < request.visit_budget && records.len() < usize::from(request.limit) {
            let Some(Reverse((id, stream, code))) = heads.pop() else {
                exhausted = true;
                break;
            };
            if let Some((next, next_code)) = next_candidate(&mut streams[stream], self.secured)? {
                heads.push(Reverse((next, stream, next_code)));
            }
            visited += 1;
            last = Some(id);
            let raw = ws
                .record(id)?
                .ok_or_else(|| corrupt("missing indexed record"))?;
            if partitions[stream].is_some_and(|reader| reader != raw.reader) {
                return Err(corrupt("reader index partition"));
            }
            let record = self
                .project(&scope, id, Some(raw))
                .ok_or_else(|| corrupt("unreadable index member"))?;
            if code != record.contract {
                return Err(corrupt("public index contract"));
            }
            if request.query.contract.is_some_and(|c| c != record.contract) {
                continue;
            }
            if let Some(predicate) = &request.query.equals {
                let fields = serde_json::to_value(&record.input).map_err(storage)?;
                if fields.get(&predicate.field) != Some(&predicate.value) {
                    continue;
                }
            }
            records.push(record);
        }
        // Do not visit one extra candidate merely to promise exhaustion. A page
        // ending exactly at a limit may resume once more to prove end of scope.
        let cursor = if exhausted {
            None
        } else {
            let after = last.ok_or_else(|| corrupt("nonprogressing cursor"))?;
            Some(sign(
                &Cursor {
                    api: API_VERSION.into(),
                    store: header.store_id,
                    model: self.model.identity().into(),
                    actor: self.context.actor,
                    tenant: self.context.tenant,
                    revision: meta.revision,
                    query: request.query.clone(),
                    after,
                },
                &header,
            )?)
        };
        Ok(PageValue {
            records,
            visited,
            exhausted,
            cursor,
            revision: meta.revision,
        })
    }

    pub fn exists(&self, request: &ExistsRequest) -> Result<Value> {
        let page = self.page(&PageRequest {
            model: request.model.clone(),
            query: request.query.clone(),
            limit: 1,
            visit_budget: request.visit_budget,
            cursor: request.cursor.clone(),
        })?;
        let answer = if !page.records.is_empty() {
            "yes"
        } else if page.exhausted {
            "no"
        } else {
            "unknown"
        };
        Ok(
            json!({"answer":answer,"visited":page.visited,"revision":page.revision.to_string(),
            "cursor":if answer=="unknown" {page.cursor} else {None}}),
        )
    }

    pub fn root_read(&self, request: &RootRequest) -> Result<Value> {
        let (read, meta, _) = self.read(&request.model)?;
        let scope = self.authority(&read)?;
        let table = read.open_table(KV).map_err(storage)?;
        let mut ws = Attempt::<_, B>::new(
            |key: &[u8]| {
                table
                    .get(key)
                    .map(|v| v.map(|v| v.value().to_vec()))
                    .map_err(storage)
            },
            10_000,
        );
        let owner = self
            .project(&scope, request.owner, ws.record(request.owner)?)
            .ok_or_else(|| Error::new("not_found", "root owner unavailable"))?;
        let contract = self.model.public_contract(owner.contract)?;
        let declaration = contract
            .roots
            .iter()
            .find(|r| r.slot == request.slot)
            .ok_or_else(|| Error::new("unsupported_query", "undeclared root"))?;
        let kind = match request.read {
            RootRead::Summary => "summary",
            RootRead::Before { .. } => "before",
            RootRead::Latest { .. } => "latest",
        };
        if !declaration.reads.contains(&kind) {
            return Err(Error::new("unsupported_query", "undeclared root operation"));
        }
        let address = Address::new(request.owner, request.slot);
        let root = tree::root(&mut ws, address)?;
        let value = match request.read {
            RootRead::Summary => match root.summary {
                Aggregate::Financial(s) => {
                    json!({"count":s.count,"sum":s.sum.to_string(),"complete_min":s.complete_min().to_string(),
                    "first":s.first.map(|t|t.to_string()),"last":s.last.map(|t|t.to_string())})
                }
                Aggregate::Quote(s) => {
                    json!({"count":s.count,"first":s.first.map(|t|t.to_string()),"last":s.last.map(|t|t.to_string())})
                }
            },
            RootRead::Before { at } => {
                json!({"sum":tree::prefix(&mut ws,address,Some(at))?.to_string()})
            }
            RootRead::Latest { at } => match tree::latest(&mut ws, address, at)? {
                Some((id, rate)) => {
                    if self.project(&scope, id, ws.record(id)?).is_none() {
                        return Err(Error::new(
                            "unavailable_reference",
                            "selected quote unavailable",
                        ));
                    }
                    json!({"id":id,"rate":rate.to_string()})
                }
                None => Value::Null,
            },
        };
        Ok(
            json!({"owner":request.owner,"slot":request.slot,"revision":root.revision.to_string(),
            "store_revision":meta.revision.to_string(),"value":value}),
        )
    }
}

pub type Page = PageValue<crate::binding::Calculation>;
