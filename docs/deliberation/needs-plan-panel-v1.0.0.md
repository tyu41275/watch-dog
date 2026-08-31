# Watch Dog needs-plan panel follow-up

Status: Reconciled
Date: 2026-08-31
Target: `worker:needs-plan` parent draft for `tyu41275/watch-dog`
Draft artifact: `/home/ductor-user/.ductor/host-chatter/runtime/data/tasks/a2b73024/watch-dog-needs-plan.md`

## Panel configuration

- `feasibility-skeptic` via `chatgpt_account/gpt-5.5`
- `scope-adversary` via `chatgpt_account/gpt-5.6-luna`
- `ops-adversary` via `claude/opus`

The panel was resolved from the global default adversary registry and run against the saved 202-line parent draft with read-only access to this repository checkout.

## Outcome

- `gpt-5.5` returned `revise-first` and identified one blocking defect: decomposition ordering still lived partly in prose, which is not poller-enforceable.
- `gpt-5.6-luna` returned `revise-first` with the same blocking defect and one advisory: initial decomposition should treat P1 as deferrable until P0 evidence is green.
- `claude/opus` did not complete. Dispatch failed with `Failed to authenticate: OAuth session expired and could not be refreshed`.

## Reconciled actions

The blocking panel finding is accepted and resolved in the parent draft by:

- replacing the prose-only ordering bullets with an explicit planner instruction that generated numbered children must carry literal `Blocked by tyu41275/watch-dog#N` edges; and
- enumerating the required dependency edges as planner obligations instead of narrative sequencing.

The P1 advisory is accepted as a boundary clarification and resolved in the parent draft by stating that initial decomposition does not require any P1 child issues before all P0 evidence is green.

No repo-vision change was required. The approved synthesis at commit `69381787bccc52a5c8f07464b4d1e3f8ff16475c` remains the controlling product boundary; this follow-up only tightens the parent-intake filing contract.

## Evidence

- Panel report artifact: `/home/ductor-user/.ductor/host-chatter/runtime/data/tasks/a2b73024/watch-dog-panel-report.md`
- Panel log artifact: `/home/ductor-user/.ductor/host-chatter/runtime/data/tasks/a2b73024/watch-dog-panel-report.log`
