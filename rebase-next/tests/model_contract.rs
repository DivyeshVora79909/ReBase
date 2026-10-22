use rebase_semantic_proof::{model::PreparedModel, native_slice::Input};
use serde_json::Value;

#[test]
fn authored_fixture_bindings_agree_with_prepared_schemas() {
    let model = PreparedModel::load().unwrap();
    let mut checked = 0;
    for text in [
        include_str!("../research/fixtures/native-slice.json"),
        include_str!("../research/fixtures/causal-slice.json"),
    ] {
        let fixtures: Value = serde_json::from_str(text).unwrap();
        let mut commands: Vec<_> = fixtures["bases"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|commands| commands.as_array().unwrap())
            .collect();
        commands.extend(
            fixtures["cases"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|c| c["operations"].as_array().unwrap())
                .flat_map(|o| o["commands"].as_array().unwrap()),
        );
        for command in commands {
            if command["op"] != "create" {
                continue;
            }
            let Some(code) = command["contract"]
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
            else {
                continue;
            };
            let fields = &command["fields"];
            assert_eq!(
                model.validate(code, fields).is_ok(),
                Input::bind(code, fields.clone()).is_ok(),
                "{command}"
            );
            checked += 1;
        }
    }
    assert!(checked > 100);
}
