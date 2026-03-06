+++
title = "TE.TE"
description = "Transfer-Encoding obfuscation attacks"
+++

Both servers support `Transfer-Encoding: chunked`, but one can be tricked into ignoring it through header obfuscation. smugglex tests 40+ variations.

## Obfuscation Examples

```
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked\x00
Transfer-encoding: chunked
```

Additional techniques include whitespace injection, control characters, line wrapping, quote variations, header name casing, and duplicate headers.

## Run

```bash
smugglex -c te-te https://target.com
```

Combine with `--fuzz` for even more variations:

```bash
smugglex -c te-te --fuzz https://target.com
```
