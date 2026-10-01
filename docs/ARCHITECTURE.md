# Architecture

## Responsibility split

FlowBound-Nebius separates probabilistic reasoning from execution authority.

| Layer | Responsibility |
| --- | --- |
| NVIDIA Nemotron | repository understanding, planning, diagnosis, bounded proposals |
| Nebius Token Factory | model inference runtime |
| FlowBound authority envelope | repository, branch, revision, path, command, network and claim bounds |
| Deterministic action gate | allow, deny or escalate each proposed operation |
| Bounded executor | perform only gated filesystem/command operations |
| Independent verifier | re-read repository/test state after execution |
| Receipt layer | record requested, authorized, executed and observed states |
| Recovery path | fail closed when successor evidence is missing or inconsistent |

## Core transition

```text
Goal
  -> Repository snapshot
  -> Nemotron proposal
  -> Authority decision
  -> Bounded execution
  -> Independent re-observation
  -> Accept | Block | Escalate | Recover
```

The predecessor revision is part of authority. If the repository changes after planning and before execution, the proposal must be re-evaluated rather than applied to a different state.

## Why the gate is outside the model

The model may see malicious instructions in code, documentation, tests, issues or generated artifacts. Treating model obedience as the security boundary would allow repository content to redefine authority.

The deterministic gate therefore evaluates concrete operations independently of the model's rationale. A persuasive explanation cannot turn a denied operation into an allowed one.

## Planned v1 execution loop

1. Resolve repository and exact predecessor revision.
2. Construct a minimal authority envelope for the task.
3. Ask Nemotron to inspect only authorized context.
4. Parse a structured plan.
5. Evaluate every requested read/write/command/network operation.
6. Execute allowed operations in a sandbox.
7. Feed bounded results back to Nemotron for iterative repair.
8. Re-observe the resulting repository and test state.
9. Emit an intended-vs-observed receipt.
10. Accept only when the observed successor satisfies the declared postconditions.

## Competition proof

The judge-facing demo will run the same coding task twice:
- first with a normal bug-fix request;
- then with adversarial repository content requesting secret access and direct push.

The expected differentiator is not that the second model becomes harmless. It is that the same capable model remains useful while operations outside its authority are deterministically blocked and visibly evidenced.
