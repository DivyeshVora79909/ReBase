//! JSON-lines adapter for the independent Fraction oracle; not a server API.

use rebase_semantic_proof::{
    native_codec::decimal,
    native_slice::Result,
    values::{Rational, Rounding},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Construct {
        #[serde(with = "decimal")]
        numerator: i128,
        #[serde(with = "decimal")]
        denominator: i128,
    },
    Apply {
        rational: Rational,
        #[serde(with = "decimal")]
        amount: i128,
        rounding: Rounding,
    },
    Validate {
        rational: Rational,
    },
}

fn execute(request: Request) -> Result<Value> {
    Ok(match request {
        Request::Construct {
            numerator,
            denominator,
        } => json!({"rational":Rational::new(numerator, denominator)?}),
        Request::Apply {
            rational,
            amount,
            rounding,
        } => json!({"amount":rational.apply(amount, rounding)?.to_string()}),
        Request::Validate { rational } => json!({"rational":rational}),
    })
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let response = match serde_json::from_str::<Request>(&line?) {
            Ok(request) => match execute(request) {
                Ok(value) => json!({"ok":value}),
                Err(error) => json!({"error":error.code}),
            },
            Err(_) => json!({"error":"invalid_input"}),
        };
        serde_json::to_writer(&mut stdout, &response)?;
        writeln!(stdout)?;
    }
    stdout.flush()
}
