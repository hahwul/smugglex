+++
title = "Fuzzing"
description = "Mutation-based payload fuzzing"
+++

smugglex includes a mutation engine that generates payload variations beyond the built-in set.

## Usage

```bash
smugglex --fuzz https://target.com
```

## Reproducibility

Use `--fuzz-seed` for deterministic fuzzing:

```bash
smugglex --fuzz --fuzz-seed 1337 https://target.com
```

## Mutation Strategies

The fuzzer applies 9 mutation types:

| Strategy | Description |
|----------|-------------|
| TE whitespace | Inject whitespace in Transfer-Encoding |
| Case variation | Randomize header name casing |
| CL value mutation | Alter Content-Length values |
| Line endings | Mix `\r\n`, `\n`, `\r` |
| Junk headers | Insert random headers |
| Chunk size | Vary chunk size encoding |
| Control chars | Insert control characters |
| Header duplication | Duplicate key headers |
| Body padding | Add padding to request body |
