//! Calculation-specific resolution and arithmetic for the shared causal engine.
use crate::{
    binding::Calculation,
    causal::{Emit, ReactiveBinding, Read, Resolved, ResolvedShape},
    indexes::standard::Leaf,
    native_codec::Address,
    native_slice::{
        Calculated, Context, Error, Input, Record, Result, Workspace, required, validate_references,
    },
    time_range::{TimeBound, TimeRange},
};
use std::collections::BTreeMap;
use uuid::Uuid;
impl ReactiveBinding for Calculation {
    type Publication = ();
    type Parameters = ();
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Workspace<L>,
        context: Context,
        _id: Uuid,
        record: &Record,
    ) -> Result<Resolved<Self::Parameters>> {
        validate_references(ws, &record.input, context)?;
        let mut shape = ResolvedShape::default();
        match &record.input {
            Input::Adjustment {
                account,
                moment,
                offset,
                post,
                ..
            } => {
                let Input::Moment { at } = required(ws, *moment, 7, context)?.input else {
                    unreachable!()
                };
                let at = at
                    .checked_add(*offset)
                    .ok_or_else(|| Error::new("invalid_input", "resolved timestamp overflow"))?;
                for slot in [1, 2] {
                    shape.reads.push(Read {
                        slot,
                        root: Address::new(*account, 2),
                        range: TimeRange::before(at),
                        validate: slot == 2,
                    });
                }
                if *post {
                    shape.emits.push(Emit {
                        role: 1,
                        contract: 12,
                        root: Address::new(*account, 2),
                        at,
                    });
                }
            }
            Input::Basis {
                sources,
                account,
                at,
                feedback,
                ..
            } => {
                for (i, root) in sources.iter().enumerate() {
                    shape.reads.push(Read {
                        slot: i as u16 + 1,
                        root: Address::new(*root, 2),
                        range: TimeRange::ALL,
                        validate: false,
                    });
                }
                shape.emits.push(Emit {
                    role: 1,
                    contract: 12,
                    root: Address::new(*account, 2),
                    at: *at,
                });
                if let Some(f) = feedback {
                    shape.emits.push(Emit {
                        role: 2,
                        contract: 12,
                        root: Address::new(f.account, 2),
                        at: f.at,
                    });
                }
            }
            _ => return Err(Error::new("corrupt_state", "noncausal subscriber")),
        };
        Ok(Resolved {
            shape,
            parameters: (),
        })
    }
    fn evaluate(
        _id: Uuid,
        record: &Record,
        shape: &ResolvedShape,
        _parameters: &Self::Parameters,
        _publications: &[crate::causal::PublicationValue<Self::Publication>],
        values: &[i128],
    ) -> Result<(Calculated, BTreeMap<u16, i128>)> {
        let (derived, amount) = match &record.input {
            Input::Adjustment { target, .. } => {
                let delta = target
                    .checked_sub(values[0])
                    .ok_or_else(|| Error::new("overflow", "adjustment difference"))?;
                (
                    Calculated::Adjustment {
                        at: match shape.reads[0].range.upper {
                            TimeBound::Excluded(at) => at,
                            _ => unreachable!("adjustment read is strictly before its emission"),
                        },
                        before: values[0],
                        delta,
                    },
                    delta,
                )
            }
            Input::Basis { factor, .. } => {
                let sum = values.iter().try_fold(0i128, |a, b| {
                    a.checked_add(*b)
                        .ok_or_else(|| Error::new("overflow", "basis sum"))
                })?;
                let value = sum
                    .checked_mul(i128::from(*factor))
                    .ok_or_else(|| Error::new("overflow", "basis product"))?;
                (Calculated::Basis { value }, value)
            }
            _ => return Err(Error::new("corrupt_state", "noncausal evaluation")),
        };
        Ok((
            derived,
            shape
                .emits
                .iter()
                .map(|e| (e.role, if e.role == 2 { 0 } else { amount }))
                .collect(),
        ))
    }
    fn output_input(producer: Uuid, e: &Emit, amount: i128) -> Result<Input> {
        Ok(Input::Output {
            producer,
            role: e.role,
            account: e.root.id,
            at: e.at,
            amount,
        })
    }
    fn output_member(input: &Input) -> Result<(Address, i64, Leaf)> {
        let Input::Output {
            account,
            at,
            amount,
            ..
        } = input
        else {
            return Err(Error::new("corrupt_state", "non-output member"));
        };
        Ok((Address::new(*account, 2), *at, Leaf::Financial(*amount)))
    }
}
