//! A self-contained, read-only developer artifact. Browser-native disclosure
//! controls keep the view useful without a frontend runtime or network service.

use crate::binding::Binding;
use crate::{model::Prepared, native_slice::Result};
use serde_json::Value;

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn pretty(value: &Value) -> String {
    escape(&serde_json::to_string_pretty(value).expect("JSON value"))
}

fn label<'a>(snapshot: &'a Value, id: &str) -> Option<&'a str> {
    snapshot
        .get("labels")?
        .as_object()?
        .iter()
        .find(|(_, v)| v.as_str() == Some(id))
        .map(|(k, _)| k.as_str())
}

fn disclosure(title: &str, badge: &str, value: &Value) -> String {
    format!(
        "<details><summary><span>{}</span><small>{}</small></summary><pre>{}</pre></details>",
        escape(title),
        escape(badge),
        pretty(value)
    )
}

pub fn render<B: Binding>(
    model: &Prepared<B>,
    snapshot: Option<&Value>,
    transcript: &[Value],
) -> Result<String> {
    let mut body = String::new();
    body.push_str(&format!("<header><p class=eyebrow>REBASE NEXT / DEVELOPER WORKSPACE</p><h1>Connected facts.<br>Settled together.</h1><p class=intro>Explore the model, its published values and the dependencies behind them.</p><div class=identity><span>MODEL</span><code>{}</code></div></header>",escape(model.identity())));
    body.push_str("<nav><a href=#state>Snapshot</a><a href=#model>Model</a><a href=#workflow>Workflow</a></nav><main>");
    if let Some(snapshot) = snapshot {
        let records = snapshot["records"].as_array().map_or(0, Vec::len);
        let roots = snapshot["roots"].as_array().map_or(0, Vec::len);
        let queries = snapshot["queries"].as_array().map_or(0, Vec::len);
        body.push_str(&format!("<section id=state><div class=section-title><h2>Settled snapshot</h2><span>Store {}</span></div><div class=stats><article><b>{records}</b><span>Records</span></article><article><b>{roots}</b><span>Published roots</span></article><article><b>{queries}</b><span>Active reads</span></article></div><p class=note>This trusted local snapshot includes private output roles. It carries no connection or access grant.</p>",escape(snapshot["store"].as_str().unwrap_or("—"))));
        body.push_str("<h3>Root publications</h3><div class=root-grid>");
        for root in snapshot["roots"].as_array().into_iter().flatten() {
            let id = root["root"]["id"].as_str().unwrap_or("");
            let summary = &root["summary"]["value"];
            let sum = summary["sum"].as_str().unwrap_or("—");
            body.push_str(&format!("<article class=root><span>{} / root slot {}</span><b>{}</b><code>{}</code><small>{} occurrences · token {}</small></article>",escape(label(snapshot,id).unwrap_or("Publication")),root["root"]["slot"],escape(sum),escape(id),summary["count"],escape(root["revision"].as_str().unwrap_or(""))));
        }
        body.push_str("</div><h3>Records</h3>");
        for row in snapshot["records"].as_array().into_iter().flatten() {
            let code = row["record"]["contract"].as_u64().unwrap_or(0) as u16;
            let contract = model.contract(code)?;
            let id = row["id"].as_str().unwrap_or("");
            body.push_str(&disclosure(
                &format!("{} · {}", contract.name, label(snapshot, id).unwrap_or(id)),
                if contract.visibility == crate::model::Visibility::Public {
                    "PUBLIC SOURCE"
                } else {
                    "PRIVATE"
                },
                row,
            ));
        }
        body.push_str("<h3>Active reads and output identity</h3>");
        for (key, title) in [
            ("queries", "Query descriptors"),
            ("roles", "Retained role bindings"),
        ] {
            body.push_str(&disclosure(title, "DEVELOPER", &snapshot[key]));
        }
        body.push_str("</section>");
    } else {
        body.push_str("<section id=state><h2>Offline model</h2><p>No database was opened. The declarations below describe possible participation; a connected record chooses its active roles.</p></section>");
    }
    body.push_str(&format!("<section id=model><div class=section-title><h2>The prepared model</h2><span>{} explicit contracts</span></div><p class=note>Expand a contract for its authored schema, references, roots, calculations and source locations. Public clients receive a separate catalog.</p>", model.contracts().count()));
    for contract in model.developer_catalog()["contracts"]
        .as_array()
        .into_iter()
        .flatten()
    {
        body.push_str(&disclosure(
            &format!(
                "{:02} / {}",
                contract["code"].as_u64().unwrap_or(0),
                contract["name"].as_str().unwrap_or("")
            ),
            contract["visibility"].as_str().unwrap_or(""),
            contract,
        ));
    }
    body.push_str("</section><section id=workflow><div class=section-title><h2>Operation walkthrough</h2><span>Public API</span></div>");
    if transcript.is_empty() {
        body.push_str("<p>Run the named demo to inspect its requests, confirmed results and rejected attempts here.</p>");
    }
    for step in transcript {
        let response = &step["response"];
        let badge = if response.get("error").is_some() {
            "REJECTED"
        } else {
            "CONFIRMED"
        };
        body.push_str(&disclosure(
            step["label"].as_str().unwrap_or("Operation"),
            badge,
            step,
        ));
    }
    body.push_str("</section></main><footer>ReBase Next · Local prototype · Exact values remain decimal strings</footer>");
    Ok(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>ReBase Next — Developer workspace</title><style>
*{{box-sizing:border-box}}:root{{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#19332b;background:#f5f6f0;font-synthesis:none}}body{{margin:0}}header,nav,main,footer{{max-width:1080px;margin:auto;padding-left:36px;padding-right:36px}}header{{padding-top:64px;padding-bottom:38px}}.eyebrow{{font-size:11px;letter-spacing:.19em;font-weight:750;color:#55776b}}h1{{font-size:clamp(42px,6vw,70px);line-height:1.04;letter-spacing:-.055em;font-weight:600;margin:25px 0}}.intro{{max-width:550px;color:#58675f;font-size:18px;line-height:1.5}}.identity{{margin-top:30px;display:flex;flex-wrap:wrap;gap:12px;align-items:center}}.identity span,small{{font-size:10px;letter-spacing:.05em;color:#64766c}}code{{font-family:ui-monospace,SFMono-Regular,monospace;font-size:11px;overflow-wrap:anywhere}}nav{{display:flex;gap:32px;border-top:1px solid #d8dfd5;border-bottom:1px solid #d8dfd5;padding-top:18px;padding-bottom:18px;position:sticky;top:0;background:#f5f6f0ee;backdrop-filter:blur(8px);z-index:1}}nav a{{font-size:13px;font-weight:650;color:#294c3f;text-decoration:none}}nav a:hover{{color:#159268}}section{{padding:40px 0;scroll-margin-top:60px}}section+section{{border-top:1px solid #d8dfd5}}.section-title{{display:flex;align-items:baseline;justify-content:space-between;gap:15px}}.section-title>span{{font-size:12px;color:#6e7e73}}h2{{font-size:26px;font-weight:550;letter-spacing:-.025em;margin:0 0 24px}}h3{{font-size:15px;font-weight:650;margin:28px 0 14px}}.note{{color:#69766b;line-height:1.6;font-size:13px;max-width:700px}}.stats,.root-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}.stats article{{background:#e8eee3;border-radius:13px;padding:22px}}.stats b{{display:block;font-size:35px;letter-spacing:-.05em;font-weight:500}}.stats span{{font-size:12px;color:#637560}}.root-grid{{grid-template-columns:repeat(auto-fit,minmax(230px,1fr))}}.root{{background:white;padding:20px;border:1px solid #dce4d9;border-radius:12px;display:flex;flex-direction:column;gap:10px}}.root>span{{font-size:11px;color:#607667}}.root b{{font-size:32px;font-weight:550;color:#205640}}details{{background:#fff;border:1px solid #dde4da;border-radius:9px;margin:8px 0;overflow:hidden}}summary{{display:flex;gap:12px;justify-content:space-between;align-items:center;cursor:pointer;padding:16px 18px;font-size:13px;list-style:none}}summary:before{{content:'+';font-family:monospace;color:#6a8171}}details[open]>summary:before{{content:'−'}}summary>span{{flex:1;overflow-wrap:anywhere}}summary small{{background:#eef3eb;border-radius:4px;padding:4px 7px;white-space:nowrap}}summary:hover{{background:#f6f9f3}}summary:focus-visible,a:focus-visible{{outline:2px solid #27825c;outline-offset:-3px}}pre{{margin:0;padding:20px;overflow:auto;max-height:520px;background:#f0f4ed;color:#385746;border-top:1px solid #dde4da;font-size:12px;line-height:1.7;tab-size:2}}footer{{font-size:11px;color:#7a887c;padding-top:20px;padding-bottom:40px}}@media(max-width:620px){{header,nav,main,footer{{padding-left:20px;padding-right:20px}}header{{padding-top:36px}}.stats{{gap:8px}}.stats article{{padding:15px}}.section-title{{display:block}}.section-title>span{{display:block;margin:-12px 0 22px}}summary{{padding:14px 12px;font-size:11px}}summary small{{font-size:9px}}}}@media print{{nav{{position:static}}details{{break-inside:avoid}}pre{{max-height:none}}}}
</style></head><body>{body}</body></html>"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PreparedModel;
    #[test]
    fn data_is_text_in_the_offline_artifact() {
        assert_eq!(
            escape("</script><b> & \""),
            "&lt;/script&gt;&lt;b&gt; &amp; &quot;"
        );
        let html = render(&PreparedModel::load().unwrap(), None, &[]).unwrap();
        assert!(!html.contains("<script") && !html.contains("<iframe"));
        assert!(html.contains("No database was opened"));
    }
}
