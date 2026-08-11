# The Confidential Consortium Framework [![CI](https://github.com/microsoft/CCF/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/CCF/actions/workflows/ci.yml) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/7808/badge)](https://www.bestpractices.dev/projects/7808)

The Confidential Consortium Framework (CCF) is an open-source framework for building a new category of secure, highly available, and performant applications that focus on multi-party compute and data.</p>

<p align="center">
<img alt="ccf" src="doc/_static/ccf_overview.png" width="700">
</p>

## Get Started with CCF

- Read the [CCF overview](https://microsoft.github.io/CCF/main/overview/index.html) and become familiar with the [core concepts](https://microsoft.github.io/CCF/main/overview/what_is_ccf.html)
- [Install](https://microsoft.github.io/CCF/main/build_apps/install_bin.html) CCF on Linux
- Become familiar with the CCF core developer API with the [template CCF app](https://github.com/microsoft/ccf-app-template)
- Quickly build and run [sample CCF apps](https://github.com/microsoft/ccf-app-samples)
- [Build new CCF applications](https://microsoft.github.io/CCF/main/build_apps/index.html) in TypeScript/JavaScript or C++

## Contribute

- [Contribute](https://microsoft.github.io/CCF/main/contribute) to this repository, following the [contribution guidelines](.github/CONTRIBUTING.md)
- Submit [bugs](https://github.com/microsoft/CCF/issues/new?assignees=&labels=bug&template=bug_report.md&title=) and [feature requests](https://github.com/microsoft/CCF/issues/new?assignees=&labels=enhancement&template=feature_request.md&title=)
- Start a [discussion](https://github.com/microsoft/CCF/discussions/new) to ask a question or propose an idea

## Learn More

- Browse the [documentation](https://microsoft.github.io/CCF/)
- Read the [Research Papers](https://microsoft.github.io/CCF/main/research)

## Pure Lean consistency proof and trace validation

This repository includes a pure-Lean translation of the Veil consistency model, a complete proof of its properties, and a trace validator that checks real implementation traces against the proved model. See [lean/README.md](lean/README.md) for detail.

What is proved:

- `CCFConsistency.reachableProved` establishes the complete translated property set (all 35 Veil invariants and the one safety property) for every reachable state, over abstract and potentially infinite domains. Nothing is assumed or admitted, and the build rejects any theorem depending on `sorryAx`.
- The proof is structured as a tower of inductive bundles (core, provenance, response, status, commit, closure), each preserved by all ten actions, with the remaining clauses derived as consequences.

How trace validation works:

- Model.State stores relations as Bool, so the ten canonical transition functions are executable. Trace replay calls those exact functions; there is no separate concrete state, mirrored transition, or equivalence layer.
- The trace layer is split in two. `lean/CCFConsistency/TraceInfra.lean` is model-independent and reusable: finite domains, decidable quantifiers over them, and the replay engine with its reachability theorems. `lean/CCFConsistency/Trace.lean` is CCF-specific: decidability for the model's derived predicates, the action guards, and the proof that an enabled action is a canonical `Step`.
- Guards are evaluated, not restated. Decidability for each predicate is inferred from that predicate's own definition, so there are no hand-written Boolean mirrors and no soundness lemmas to check them against. The one thing left to audit is that each guard matches the corresponding `Step` constructor, which `TraceAction.enabled_step` states and the compiler checks.
- The trace generator (lean/trace_validation.py) reuses the Veil planner (veil/trace_validation.py) to parse NDJSON traces, reconstruct unlogged ledger/view events, and emit a typed list of TraceAction constructors.
- Generated Lean modules prove reachability only: a successful replay produces `Reachable final`. The properties are proved once and for all by `reachableProved`, so there is no need to re-evaluate them at every concrete state. The generated proofs are kernel-checked and audited for transitive `sorryAx` or native-evaluation dependencies.

Quick validation commands (from the repo root):

- Validate with Veil: `python3 veil/trace_validation.py build/consistency/trace.ndjson --validate`
- Validate with pure Lean: `python3 lean/trace_validation.py build/consistency/trace.ndjson --validate`

Notes:

- Run Lean/Lake only from a native WSL filesystem (do not build under `/mnt/c`).
- On the real 73-event / 80-action trace, kernel-checked replay takes roughly half a minute, comfortably below the cost of the library build itself.

## Third-party components

We rely on several open source third-party components, attributed under [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.txt).

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](.github/CONTRIBUTING.md).
