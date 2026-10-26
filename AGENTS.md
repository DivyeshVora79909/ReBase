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
within that client/session unless the user changes it; reassess capabilities
when moving to another environment. If no mode is supplied, use the
shared rules without guessing account limits or billing from the interface.
These guides change work organization, not acceptance criteria or authorization.

Choose models and delegation from the actual tools, limits and task needs in
the current environment. Use available, authorized model routing or subagents
when they are likely to improve total cost, elapsed time or result quality;
include their context, retries and integration in that judgment. Respect client
restrictions such as a single-model API session, without treating them as
universal properties of a billing mode. Batch independent tool operations with
bounded output; keep dependent edits, checks and Git operations sequential. Do
not invent usage costs or change paid settings.
