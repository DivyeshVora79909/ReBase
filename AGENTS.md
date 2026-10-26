# Agent workflow

The active native implementation and its tooling live in `rebase-next/`.
Read `rebase-next/AGENTS.md`, its README, and the current handoff at the top of
`rebase-next/CONTEXT.md` before continuing that work. Use the current checkout
and checkpoint evidence; historical agent memory is only a routing aid.

When the user says **subscription** or **pay as you go / API**, apply the matching
guide for the ongoing task:

- [Subscription workflow](rebase-next/docs/agents/subscription.md)
- [Pay-as-you-go workflow](rebase-next/docs/agents/pay-as-you-go.md)
- [Shared rules, comparison and sources](rebase-next/docs/agents/README.md)

Read the shared guide and only the selected mode once. Preserve the selection
across continuations unless the user changes it. If no mode is supplied, use the
shared rules without guessing account limits or billing from the interface.
These guides change work organization, not acceptance criteria or authorization.

Default to one agent. Batch independent tool operations with bounded output;
keep dependent edits, checks and Git operations sequential. Do not launch
subagents or change the user's model just to optimize usage. A current explicit
user instruction takes precedence over older model/delegation preferences.
