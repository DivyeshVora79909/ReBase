# Pay-as-you-go workflow

Apply the [shared rules](README.md). Optimize total elapsed time and billed cost
to a verified result. The default priority here is completing authorized work
in one sustained attempt with few avoidable round trips. More useful work per
round helps; padding a request to its maximum token capacity does not.

## What costs time and money

A useful model of API cost is:

```text
total cost = sum over all model attempts of
  (uncached input tokens * uncached rate
   + cache-read tokens * cache-read rate
   + cache-write tokens by lifetime * corresponding write rate
   + output tokens including reasoning * output rate) / 1,000,000
  + applicable tool, compute and external-service charges
```

The input categories are disjoint; do not charge cache-write tokens again as
uncached input. Use the selected model/service's actual rate card and reported
usage. Some clients expose insufficient detail for an exact charge. Do not add
reasoning twice if the reported output total already includes it.

Elapsed time follows the critical path: input processing, output generation,
sequential model/tool round trips, builds/tests, retries and user waits.
Reducing one component can increase another. A larger useful request can remove
round trips; unnecessary generation still adds tokens and time. These are
planning models, not measured costs for the current session.

## How to work

1. Check which model and delegation controls the current client exposes and
   which the user has authorized. Respect client restrictions, including a
   single-model session where applicable; do not infer them from API billing.
   Compare likely total cost, elapsed time, retries and integration before
   routing work or delegating it.
2. Before a tool round, identify independent questions it can answer together.
   Run those operations concurrently with bounded individual and total output.
   Inspect their results before dependent decisions, edits or verification.
3. Use one coherent implementation pass: understand contracts, implement, run
   required checks, repair real failures, record evidence and advance. Keep
   necessary feedback loops; do not guess an unknown API to save one lookup.
4. Keep stable instructions and useful history where possible. Reuse already
   obtained evidence instead of rereading it. Matching prefixes may reduce
   input costs, but caching is conditional and does not make calls free.
5. Keep tool results and prose concise. Store long logs in files and return
   summaries plus actionable excerpts. Use normal tools for deterministic work.
6. Start an owned long-running build/test once, retain its handle/log and wait
   at reasonable intervals while doing independent work. Avoid duplicate builds,
   busy polling and restarting healthy jobs to obtain more output.
7. Run acceptance appropriate to the source change. Reuse unchanged native
   artifacts only when their identity and required features are established.
   Finish the exact required artifact checks before marking a checkpoint done.
8. If usage is available, measure total task cost, wall time, retries and
   successful acceptance together. Request count alone does not establish a
   saving; include all subagent/tool usage when delegation is used.

API work still has token, context, rate and spend limits. This mode does not
invent a quota or abandon authorized work early. It also does not assume
unlimited spending. Honor limits the user actually supplies and surface an
external blocker with a reproducible handoff.

The cost terms come from [API pricing](https://developers.openai.com/api/docs/pricing)
and [usage accounting](https://developers.openai.com/api/docs/guides/agents-api/observability).
The request/token trade-off is supported by
[latency guidance](https://developers.openai.com/api/docs/guides/latency-optimization);
cache behavior is documented in
[prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching).

## Reusable instruction

> Pay-as-you-go mode. Use the models and delegation controls available and
> authorized in this client. Finish authorized checkpoints in one sustained
> attempt, minimizing total cost, elapsed time and avoidable repeated context
> while preserving acceptance.
> Batch independent tools, use bounded output, and keep dependent work in order.
> Optimize total time and cost to a verified result, not tokens per request.
