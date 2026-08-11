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

## Formal specification

CCF's consistency and consensus protocols have TLA+ specifications in [tla/](tla/), model checked with TLC and validated against traces from the implementation.

The consistency specification additionally has a pure Lean 4 translation in [lean/](lean/), which proves all 35 invariants and the one safety property for **every** reachable state, over unbounded domains, rather than for one finite configuration. The proof is checked by Lean's kernel and the build rejects any theorem depending on `sorryAx`. The same implementation trace that TLC validates is also replayed against the Lean model, producing a kernel-checked reachability theorem.

[lean/COMPARISON.md](lean/COMPARISON.md) compares the two: line counts by category, what each approach establishes, and where each is easier to read. In short, TLA+ is considerably more concise and produces counterexamples, while the Lean development gives an unbounded guarantee and its type checking caught three malformed definitions in `ExternalHistoryInvars.tla` that had survived model checking. They are complementary rather than competing.

## Third-party components

We rely on several open source third-party components, attributed under [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.txt).

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](.github/CONTRIBUTING.md).
