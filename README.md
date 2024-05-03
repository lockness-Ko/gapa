# gapa

A faster rewrite of [capa](https://github.com/mandiant/capa/) in golang.

- [x] Proof-of-concept (PoC)
  - [x] Blazingly fast
- [x] x86/x86-64 support
- [x] PE support
- [x] ELF support
- [ ] A bunch of the standard rule features in capa (namespace, class, characteristic, etc.)
- [ ] Compiled in rules

## Running

```bash
./gapa -file ./file.ext -rule-folder /path/to/rules
```

## Installation

You need capstone and go.

Run
```bash
go build
```
to build the project

## Motivation

Capa is incredibly slow and it annoyed me. The goal of this project is to use the same rules and acheive a result faster.

## References

[capa-rules format](https://github.com/mandiant/capa-rules/blob/master/doc/format.md#api)
[gapstone](https://github.com/knightsc/gapstone)
