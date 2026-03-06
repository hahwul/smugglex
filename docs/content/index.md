+++
title = "smugglex"
description = "HTTP Request Smuggling Scanner"
+++

<div class="hero-section">
  <h1>smugglex</h1>
  <p class="tagline">Fast, comprehensive HTTP Request Smuggling scanner written in Rust.</p>
  <div class="hero-badges">
    <span class="badge badge-rust">Rust</span>
    <span class="badge">MIT License</span>
    <span class="badge">CLI Tool</span>
  </div>
</div>

## What is smugglex?

smugglex detects HTTP Request Smuggling vulnerabilities by testing how front-end and back-end servers handle request boundaries. It supports CL.TE, TE.CL, TE.TE, H2C, H2, and CL-Edge attack types with timing-based detection.

## Quick Links

- **[Installation](/usage/)** -- Install via Homebrew, Cargo, or download binaries
- **[Quick Start](/usage/quick-start/)** -- Run your first scan in seconds
- **[Checks](/checks/)** -- All supported smuggling techniques
- **[Advanced](/advanced/)** -- Fingerprinting, fuzzing, and exploitation
