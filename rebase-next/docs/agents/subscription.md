# Subscription workflow

Apply the [shared rules](README.md). Optimize verified progress per allowance
while respecting the user's time. There is no universal raw-token allowance or
model multiplier: use the actual plan/dashboard when supplied or visible, and
otherwise treat the remaining allowance as unknown.

## How to work

1. Keep the selected model. If the user requests model advice, match capability
   to the task using current availability and measured results. Do not assume a
   smaller model with more retries uses less allowance overall.
2. Load the active checkpoint, relevant contracts and acceptance controls once.
   Use exact paths and source ranges for follow-up questions. Keep unrelated
   documents and inactive tool definitions out of the working context where the
   client allows that control.
3. Spend detailed analysis on semantics, transactions and difficult failures.
   Use direct tools for mechanical inventory, formatting and verification.
   Avoid repeatedly explaining an already settled implementation plan.
4. Finish each checkpoint through validation and evidence. Continue the selected
   program when authorized; do not stop early merely to conserve an imagined
   token quota or turn one coherent task into many user prompts.
5. Batch independent tool reads; run dependent mutations and acceptance in order.
   Use a single agent unless the user explicitly requests delegation. Shared
   context and repeated integration reviews also consume usage.
6. When real remaining-capacity information is available, avoid starting optional
   campaigns that would crowd out required acceptance. Preserve a precise
   handoff at any actual limit; never call incomplete work accepted.
7. Summarize behavior, evidence and unresolved obligations. If reporting usage,
   distinguish observed allowance/credits from estimates and unavailable data.

Changing speed, model or effort can affect allowance and latency. Apply only
controls actually exposed and authorized; do not silently enable a paid faster
mode. Purchased-credit use is metered too: also consider total cost using its
own rate card instead of assuming API prices apply.

The subscription limit and credit distinction is documented in
[Codex pricing](https://learn.chatgpt.com/docs/pricing). This guide deliberately
does not embed a plan's current limits or model-specific multipliers.

## Reusable instruction

> Subscription mode. Complete the authorized checkpoints with compact relevant
> context and focused acceptance. Respect my selected model, use one agent,
> batch independent tool work, and preserve evidence at checkpoint boundaries.
> Continue without repeated routine confirmation. Treat limits as unknown
> unless actually visible; keep required correctness checks.
