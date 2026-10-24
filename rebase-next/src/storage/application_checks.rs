//! Executable application conformance over real adapter transactions. These
//! trusted controls use the ordinary mutation path and are absent from RPC.
use super::{Database, ReadableTable};
use crate::{
    binding::{Binding, Calculation},
    lifecycle,
    local::{self, Mutation, Store},
    model::Prepared,
    models::{
        effect_demo::EffectDemo,
        quantity::{self, Quantity},
    },
    native_codec::{Key, StoredValue},
    native_slice::{Context, Error, Result},
    query::{RootRead, RootRequest},
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
use uuid::Uuid;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}
fn require(ok: bool, detail: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::new("application_conformance", detail))
    }
}
fn create<B: Binding>(db: Database) -> Result<Store<B>> {
    Store::create_backend_secured(
        db,
        Arc::new(Prepared::load()?),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
}
fn request<B: Binding>(store: &Store<B>, commands: Value) -> Result<Mutation> {
    serde_json::from_value(json!({"model":store.model().identity(),
        "context":store.operation_context(store.model().identity())?,
        "operation_id":Uuid::new_v4(),"commands":commands,"returning":[]}))
    .map_err(local::storage)
}
fn update<B: Binding>(store: &Store<B>, record: Uuid, set: Value) -> Result<Value> {
    let version = store
        .get(store.model().identity(), record)?
        .ok_or_else(|| Error::new("application_conformance", "missing update source"))?
        .version;
    Ok(json!({"op":"update","id":record,"if_version":version.to_string(),"set":set,"unset":[]}))
}
fn image<B: Binding>(store: &Store<B>) -> Result<Value> {
    let image = store.observe_for_verification()?;
    let expected: BTreeSet<_> = local::table_names(true).into_iter().collect();
    let actual: BTreeSet<_> = image["tables"]
        .as_object()
        .ok_or_else(|| Error::new("application_conformance", "missing table inventory"))?
        .keys()
        .cloned()
        .collect();
    require(
        image["complete"] == true && expected == actual,
        "incomplete application-table observation",
    )?;
    Ok(image)
}
fn receipt_absent<B: Binding>(store: &Store<B>, operation: Uuid) -> Result<()> {
    let read = store.db.begin_read()?;
    require(
        read.open_table(local::RECEIPTS)?
            .get(store.receipt_key(operation))?
            .is_none(),
        "rejected operation published a receipt",
    )
}
fn reject<B: Binding>(
    store: &Store<B>,
    req: &Mutation,
    code: &str,
    abort: Option<usize>,
) -> Result<()> {
    let before = image(store)?;
    let error = store
        .mutate_inner(req, &mut || Ok(Uuid::new_v4()), abort)
        .expect_err("rejection required");
    require(
        error.code == code,
        &format!("expected {code}, received {error}"),
    )?;
    require(
        image(store)? == before,
        "rejection changed application tables",
    )?;
    receipt_absent(store, req.operation_id)?;
    store.check_integrity()?;
    Ok(())
}
fn source(record: Uuid, value: &str) -> Value {
    json!({"op":"create","id":record,"contract":quantity::SOURCE,"fields":{"value":value}})
}
fn scale(record: Uuid, parent: Uuid) -> Value {
    json!({"op":"create","id":record,"contract":quantity::SCALE,"fields":{"parent":parent,"factor":{"numerator":"1","denominator":"2"},"rounding":"exact"}})
}

/// The first transaction is fully staged at the commit barrier. A competing
/// ordinary application mutation commits before the first is released.
fn race<B: Binding>(store: &Store<B>, first: &Mutation, second: &Mutation) -> Result<()> {
    let mut barrier_calls = 0;
    let mut winner = Value::Null;
    let error = store
        .mutate_controlled(
            first,
            &mut || Ok(Uuid::new_v4()),
            None,
            &mut || {
                barrier_calls += 1;
                store.mutate(second)?;
                winner = image(store)?;
                Ok(())
            },
            false,
        )
        .expect_err("stale concurrent attempt must abort");
    require(
        error.code == "transaction_conflict",
        &format!("concurrent attempt returned {error}"),
    )?;
    require(
        barrier_calls == 1,
        "application silently retried a conflict",
    )?;
    require(
        image(store)? == winner,
        "losing attempt partially published application tables",
    )?;
    receipt_absent(store, first.operation_id)?;
    require(
        store.operation_status(&second.model, &second.context, second.operation_id)?["status"]
            == "committed",
        "winner receipt absent",
    )?;
    store.check_integrity()?;
    Ok(())
}

struct TemporaryDirectory(PathBuf);
impl TemporaryDirectory {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("rebase-g7-application-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).map_err(local::storage)?;
        Ok(Self(path))
    }
}
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The factory returns the same persisted destination for repeated family names
/// and a fresh isolated destination for each new family name.
pub fn run(factory: impl Fn(&str) -> Result<Database>, concurrent: bool) -> Result<Value> {
    let mut cases = Vec::new();
    let effect = create::<EffectDemo>(factory("effects")?)?;
    let seed = request(
        &effect,
        json!([{"op":"create","id":id(100),"contract":101,"fields":{"balance":"20"}}]),
    )?;
    effect.mutate(&seed)?;
    let dispatch = |record| json!([{"op":"create","id":record,"contract":205,"fields":{"account":id(100),"units":"3","execute_at":null,"not_after":null}}]);
    for (name, abort) in [
        ("native-public-reader-abort", 2),
        ("effect-execution-abort", usize::MAX - 1),
        ("effect-due-abort", usize::MAX - 2),
        ("effect-runtime-abort", usize::MAX - 3),
        ("operation-receipt-runtime-abort", usize::MAX),
    ] {
        reject(
            &effect,
            &request(&effect, dispatch(id(101)))?,
            "injected_abort",
            Some(abort),
        )?;
        cases.push(name);
    }
    let committed = request(&effect, dispatch(id(101)))?;
    let result = effect.mutate(&committed)?;
    effect.check_integrity()?;
    let accepted = image(&effect)?;
    require(
        accepted["tables"]["effect_executions"]
            .as_array()
            .is_some_and(|v| v.len() == 1)
            && accepted["tables"]["effect_due"]
                .as_array()
                .is_some_and(|v| v.len() == 1),
        "intent and due index were not atomically published",
    )?;
    require(
        effect.mutate(&committed)?["result"] == result["result"] && image(&effect)? == accepted,
        "same-ID replay changed committed application tables",
    )?;
    cases.push("effect-intent-atomic-publication-and-replay");
    let stale = request(
        &effect,
        json!([{"op":"update","id":id(100),"if_version":"0","set":{"balance":"21"},"unset":[]}]),
    )?;
    reject(&effect, &stale, "stale_version", None)?;
    cases.push("stale-cas-preserves-complete-inventory");
    let lost = request(&effect, dispatch(id(102)))?;
    let unknown = effect
        .mutate_controlled(
            &lost,
            &mut || Ok(Uuid::new_v4()),
            None,
            &mut || Ok(()),
            true,
        )
        .expect_err("lost response must remain unknown");
    require(
        unknown.code == "outcome_unknown",
        "lost commit response classified as definite abort",
    )?;
    let after_lost = image(&effect)?;
    let status = effect.operation_status(&lost.model, &lost.context, lost.operation_id)?;
    require(
        status["status"] == "committed",
        "original-ID reconciliation did not find committed receipt",
    )?;
    require(
        effect.mutate(&lost)?["result"] == status["result"] && image(&effect)? == after_lost,
        "reconciliation replay duplicated a committed operation",
    )?;
    cases.push("lost-response-original-id-reconciliation-no-duplicate");
    let effect_model = Arc::new(Prepared::<EffectDemo>::load()?);
    drop(effect);
    let reopened = Store::<EffectDemo>::open_backend(factory("effects")?, effect_model.clone())?;
    require(
        image(&reopened)? == after_lost,
        "reopen changed complete application tables",
    )?;
    reopened.check_integrity()?;
    require(
        reopened.operation_status(&lost.model, &lost.context, lost.operation_id)? == status,
        "reopen lost original operation receipt",
    )?;
    cases.push("persistent-reopen-complete-tables-and-receipts");
    let temporary = TemporaryDirectory::new()?;
    let backup = temporary.0.join("effects.json");
    reopened.backup(&backup)?;
    lifecycle::restore_to_backend(&backup, factory("effects-restored")?, effect_model.clone())?;
    let restored = Store::<EffectDemo>::open_backend(factory("effects-restored")?, effect_model)?;
    let restored_image = image(&restored)?;
    for name in [
        "native_kv",
        "public_records",
        "reader_records",
        "authority",
        "operations",
        "local_runtime",
        "effect_facts",
        "effect_inbox",
    ] {
        require(
            restored_image["tables"][name] == after_lost["tables"][name],
            "restore changed preserved application data",
        )?;
    }
    for row in restored_image["tables"]["effect_executions"]
        .as_array()
        .expect("complete execution inventory")
    {
        let value: Value = local::decode(&local::unhex(
            row["value"].as_str().expect("encoded execution"),
        )?)?;
        require(
            value["quarantined"] == true && value["lease"].is_null(),
            "restored unresolved effect was not quarantined",
        )?;
    }
    restored.check_integrity()?;
    let populated = image(&restored)?;
    drop(restored);
    let error = lifecycle::restore_to_backend(
        &backup,
        factory("effects-restored")?,
        Arc::new(Prepared::<EffectDemo>::load()?),
    )
    .expect_err("populated restore destination must reject");
    require(
        error.code == "storage_exists",
        "populated restore destination did not reject",
    )?;
    let restored = Store::<EffectDemo>::open_backend(
        factory("effects-restored")?,
        Arc::new(Prepared::load()?),
    )?;
    require(
        image(&restored)? == populated,
        "rejected restore changed populated destination",
    )?;
    cases.push("backend-restore-quarantine-and-populated-destination-isolation");
    drop(restored);
    drop(reopened);

    let quantities = create::<Quantity>(factory("quantity")?)?;
    let plan = Quantity::fixture_plan(quantities.model(), "quantities", id(200))?;
    quantities.mutate(&request(&quantities, plan["commands"].clone())?)?;
    let qid = |name: &str| {
        Uuid::parse_str(plan["fixture"]["ids"][name].as_str().expect("fixture ID"))
            .expect("canonical fixture ID")
    };
    let change = request(
        &quantities,
        json!([update(&quantities, qid("source"), json!({"value":"18"}))?]),
    )?;
    quantities.mutate(&change)?;
    for (name, expected) in [
        ("source", "18"),
        ("left", "9"),
        ("right", "6"),
        ("join", "15"),
    ] {
        require(
            quantities
                .get(quantities.model().identity(), qid(name))?
                .expect("quantity record")
                .derived
                .expect("quantity publication")["quantity"]
                == expected,
            "quantity cascade differs from independent literal oracle",
        )?;
    }
    reject(
        &quantities,
        &request(
            &quantities,
            json!([update(&quantities, qid("source"), json!({"value":"13"}))?]),
        )?,
        "inexact",
        None,
    )?;
    quantities.check_integrity()?;
    cases.push("quantity-publication-cascade-and-inexact-rollback");
    let quantity_image = image(&quantities)?;
    let quantity_backup = temporary.0.join("quantity.json");
    quantities.backup(&quantity_backup)?;
    lifecycle::restore_to_backend(
        &quantity_backup,
        factory("quantity-restored")?,
        Arc::new(Prepared::<Quantity>::load()?),
    )?;
    let restored_quantity = Store::<Quantity>::open_backend(
        factory("quantity-restored")?,
        Arc::new(Prepared::load()?),
    )?;
    require(
        image(&restored_quantity)? == quantity_image,
        "quantity restore changed complete application tables",
    )?;
    cases.push("backup-restore-exact-complete-inventory");
    drop(restored_quantity);
    drop(quantities);

    let calculation = create::<Calculation>(factory("calculation")?)?;
    let root = id(300);
    calculation.mutate(&request(&calculation, json!([
        {"op":"create","id":root,"contract":4,"fields":{"native_unit":1}},
        {"op":"create","id":id(301),"contract":8,"fields":{"account":root,"at":"0","amount":"10"}}
    ]))?)?;
    let posting = |record| json!([{"op":"create","id":record,"contract":8,"fields":{"account":root,"at":"1","amount":"-8"}}]);
    let invalid = request(
        &calculation,
        json!([{"op":"create","id":id(302),"contract":8,"fields":{"account":root,"at":"1","amount":"-11"}}]),
    )?;
    reject(&calculation, &invalid, "invariant", None)?;
    cases.push("calculation-root-complete-time-invariant-rollback");

    if concurrent {
        race(
            &calculation,
            &request(&calculation, posting(id(302)))?,
            &request(&calculation, posting(id(303)))?,
        )?;
        let answer = calculation.root_read(&RootRequest {
            model: calculation.model().identity().into(),
            owner: root,
            slot: 2,
            read: RootRead::Summary,
        })?;
        require(
            answer["value"]["sum"] == "2",
            "same-root writers violated balance invariant",
        )?;
        cases.push("same-root-invariant-commit-barrier");
        drop(calculation);

        let competing = create::<Quantity>(factory("concurrency")?)?;
        competing.mutate(&request(&competing, json!([source(id(400), "12")]))?)?;
        race(
            &competing,
            &request(
                &competing,
                json!([update(&competing, id(400), json!({"value":"18"}))?]),
            )?,
            &request(
                &competing,
                json!([update(&competing, id(400), json!({"value":"24"}))?]),
            )?,
        )?;
        cases.push("same-record-cas-commit-barrier-no-retry");
        race(
            &competing,
            &request(&competing, json!([source(id(401), "12")]))?,
            &request(&competing, json!([source(id(401), "18")]))?,
        )?;
        cases.push("absent-public-identity-commit-barrier");
        race(
            &competing,
            &request(
                &competing,
                json!([update(&competing, id(400), json!({"value":"24"}))?]),
            )?,
            &request(
                &competing,
                json!([update(&competing, id(400), json!({"value":"30"}))?]),
            )?,
        )?;
        cases.push("no-op-write-preserves-protected-point-read");
        race(
            &competing,
            &request(
                &competing,
                json!([{"op":"delete","id":id(401),"if_version":competing.get(competing.model().identity(), id(401))?.expect("source").version.to_string()}]),
            )?,
            &request(&competing, json!([scale(id(402), id(401))]))?,
        )?;
        cases.push("reverse-reference-discovery-versus-delete-barrier");
        drop(competing);

        let authority = create::<Quantity>(factory("authority")?)?;
        authority.mutate(&request(&authority, json!([source(id(500), "12")]))?)?;
        let pending = request(
            &authority,
            json!([update(&authority, id(500), json!({"value":"18"}))?]),
        )?;
        let graph = authority.access_graph(authority.model().identity())?;
        let mut replacement: ReplaceGraph = serde_json::from_value(json!({"model":authority.model().identity(),"if_revision":graph["revision"],"graph":graph["graph"]})).map_err(local::storage)?;
        replacement.graph.principals.push(crate::access::Principal {
            id: id(599),
            kind: crate::access::PrincipalKind::User,
            parents: vec![id(1)],
            active: true,
            credential_epoch: 0,
            grants: crate::access::Grants {
                admin: true,
                contracts: Default::default(),
            },
        });
        let actor = replacement
            .graph
            .principals
            .iter_mut()
            .find(|p| p.id == id(2))
            .expect("bootstrap actor");
        actor.active = false;
        actor.credential_epoch += 1;
        let (snapshot, _, _) = authority.read(authority.model().identity())?;
        let scope = authority.authority(&snapshot)?;
        let mut winner = Value::Null;
        let mut barriers = 0;
        let error = authority
            .mutate_controlled(
                &pending,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || {
                    barriers += 1;
                    authority.replace_access(&replacement)?;
                    winner = image(&authority)?;
                    Ok(())
                },
                false,
            )
            .expect_err("revoked authority must conflict");
        require(
            error.code == "transaction_conflict" && barriers == 1,
            &format!("authority revocation returned {error}; commit barrier calls {barriers}"),
        )?;
        require(
            image(&authority)? == winner,
            "revoked attempt changed application tables",
        )?;
        receipt_absent(&authority, pending.operation_id)?;
        require(
            authority
                .get(authority.model().identity(), id(500))
                .expect_err("new read must see revocation")
                .code
                == "forbidden",
            "new snapshot ignored authority revocation",
        )?;
        let bytes = snapshot
            .open_table(local::KV)?
            .get(Key::Record(id(500)).encode())?
            .expect("old snapshot record");
        let StoredValue::Record(record) =
            crate::native_codec::decode_for::<Quantity>(&Key::Record(id(500)), bytes.value())?
        else {
            return Err(Error::new(
                "application_conformance",
                "snapshot record type",
            ));
        };
        require(
            authority.project(&scope, id(500), Some(record)).is_some(),
            "snapshot-authorized read was incorrectly retracted",
        )?;
        authority.check_integrity()?;
        cases.push("authority-revocation-barrier-and-snapshot-authorized-read");
    } else {
        drop(calculation);
    }
    Ok(
        json!({"status":"passed","cases":cases,"case_count":cases.len(),
        "concurrent_application_schedules":concurrent,
        "automatic_retries":false,
        "table_inventory":local::table_names(true),
        "limitations":["Commit barriers run overlapping real application transactions in a deterministic order; no distributed node/network fault is simulated.",
            "Before scoped coordination is accepted, global metadata can conservatively cause application conflicts; these schedules alone do not establish disjoint-root throughput.",
            "redb serialized writers use sequential application/rollback/recovery controls; overlapping optimistic schedules are inapplicable.",
            "Effect intent/restore checks do not certify external provider delivery; worker/inbox/application boundaries require their own controls."]}),
    )
}
