# AGENTS.md - AI Agent Instructions for smugglex Docs

This is the documentation site for [smugglex](https://github.com/hahwul/smugglex), an HTTP Request Smuggling scanner written in Rust.

## Site Generator

Built with [Hwaro](https://github.com/hahwul/hwaro), a static site generator written in Crystal.

## Structure

```
new_docs/
├── config.toml              # Site configuration
├── content/
│   ├── index.md             # Homepage
│   ├── usage/               # Installation, quick start, options, output
│   ├── checks/              # CL.TE, TE.CL, TE.TE, H2C, H2, CL-Edge
│   └── advanced/            # Fingerprinting, fuzzing, exploitation, pipeline
├── templates/               # Jinja2 templates
├── static/css/style.css     # Dark mode styles
├── static/js/search.js      # Search functionality
└── static/images/           # Images including hahwul.webp
```

## Commands

- `hwaro build` - Build site to `public/`
- `hwaro serve` - Dev server at localhost:3000

## Style

- Dark mode design
- Concise, technical documentation
- fmcr.hahwul.com-inspired layout
