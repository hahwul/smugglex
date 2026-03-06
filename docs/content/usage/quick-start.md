+++
title = "Quick Start"
description = "Run your first smugglex scan"
+++

## Basic Scan

```bash
smugglex https://target.com
```

## Multiple Targets

```bash
smugglex https://target1.com https://target2.com
```

## Pipe from stdin

```bash
cat urls.txt | smugglex
```

## With Specific Checks

```bash
smugglex -c cl-te,te-cl https://target.com
```

## Verbose Output

```bash
smugglex -V https://target.com
```

## Save Results to JSON

```bash
smugglex -o results.json -f json https://target.com
```

> smugglex uses POST method by default. Use `-m` to change the HTTP method.
