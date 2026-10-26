# Agent execution modes

Select a mode by saying `subscription` or `pay as you go`. The repository's
AGENTS.md routes the agent here; no special skill or persistent account setting
is required. In another repository, copy this directory and the short selector.

This is workflow guidance researched against official OpenAI documentation on
2026-10-26. Product limits and prices can change. The workflows below are our
engineering recommendations, not provider guarantees.

| Concern | Subscription | Pay as you go / API |
| --- | --- | --- |
| Objective | Complete verified work within the available allowance and time | Complete verified work with low total cost and elapsed time |
| Main constraint | Plan-specific allowance, credits and reset windows | Billed tokens, applicable services, rate/spend limits and time |
| Useful measurement | Completed checkpoints versus allowance used | Completed checkpoints versus total charge, elapsed time and retries |
| Model choice | Respect available models and the user's choice | Respect the selected model and any client restriction |
| Execution | Coherent checkpoints, compact relevant context, focused validation | Coherent checkpoints, fewer avoidable model/tool cycles, focused validation |

Billing and execution location are separate: local Codex can use ChatGPT sign-in
or an API key. A local interface is not proof of API billing. Model selection is
also separate; a client's single-model session is a constraint to respect, not a
universal property of usage-based billing. See [authentication](https://learn.chatgpt.com/docs/auth)
and [model controls](https://learn.chatgpt.com/docs/models).

The user's current cloud subscription offers model choice and subagents; their
current API client permits one model. Apply those constraints in the matching
environment. A Git handoff or another client's memory must not impose its
execution mode on the current session.

## Shared execution rules

1. Inspect current instructions, Git status/history, the active checkpoint and
   its acceptance conditions. Resolve stale handoffs against actual source.
2. Read enough related code to understand the change. Retrieve bounded relevant
   ranges; avoid dumping entire histories, repositories or generated output.
3. Group independent reads/searches in one tool round, inspect every result,
   then make dependent decisions. Tool concurrency does not require subagents.
4. Implement a coherent slice through its required checks and documentation.
   Continue authorized work without unnecessary user turns. One pass means an
   end-to-end attempt with feedback and repairs, not a promise of one API call.
5. Keep brief progress updates. Save long logs to artifacts; surface conclusions
   and failure excerpts. Allocate output capacity before batching large reads.
6. Run the checks required by the changed behavior. After they pass, broaden or
   repeat only for a new failure, changed input or unresolved concern.
7. Record exact source/artifact identity, checks, limits and the next dependency
   at checkpoint boundaries. Use existing records instead of duplicate trackers.
8. Preserve unknown transaction outcomes, user changes and ownership rules.
   Neither mode permits guessing results, omitting acceptance, buying credits,
   changing paid settings or altering authorization.
9. Complete one changing checkpoint through its required verification, evidence,
   commit and authorized push before starting the next changing checkpoint.
   Independent read-only preparation can overlap. If interrupted, label unfinished
   work unverified; resume from the last accepted boundary without claiming success.

One user turn can contain many model requests and tool operations. A tool call
is not a reliable unit of billing or a one-to-one count of model requests.
Subagents add context, output, retries and integration work. Use delegation or
model routing when the current environment exposes and authorizes it and the
task's likely total cost, elapsed time or result quality supports it. A client
may impose a single-model restriction; check the actual client rather than
assuming one from subscription or API billing. Do not infer exact savings or
actual billing without usage measurements.

## Sources and what they establish

- [Codex pricing](https://learn.chatgpt.com/docs/pricing): included allowances
  vary with model, context and workload; API rates do not estimate included
  subscription tasks. Purchased credits have their own rate card.
- [API pricing](https://developers.openai.com/api/docs/pricing): model token
  rates and applicable tool/service charges. No rates are frozen in this guide.
- [Latency optimization](https://developers.openai.com/api/docs/guides/latency-optimization):
  both generated tokens and sequential requests contribute to latency;
  independent operations can overlap.
- [Prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching):
  eligible matching prefixes may be reused; reads and writes have model-specific
  pricing. A continuing session alone does not guarantee reuse.
- [Agent usage accounting](https://developers.openai.com/api/docs/guides/agents-api/observability):
  include reasoning, tool arguments/results, retries and subagent work when
  measuring a completed task. Reasoning is billed as output.

Use [subscription](subscription.md) or [pay as you go](pay-as-you-go.md) for the
selected operating policy. Refresh official sources when prices or limits
matter to a decision; routine coding does not require repeating this research.
