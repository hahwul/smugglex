+++
template = "landing.html"

[extra.hero]
title = "Welcome to Smugglex"
badge = "v0.1.0"
description = "Open-source HTTP Request Smuggling testing tool written in Rust. Detect CL.TE, TE.CL, TE.TE, H2C, and H2 smuggling vulnerabilities in web applications."
image = "/images/preview.jpg" # Background image
cta_buttons = [
    { text = "Get Started", url = "/getting-started/installation", style = "primary" },
    { text = "View on GitHub", url = "https://github.com/hahwul/smugglex", style = "secondary" },
]

[extra.features_section]
title = "Essential Features"
description = "Key features for HTTP request smuggling vulnerability detection and analysis."

[[extra.features]]
title = "Multiple Attack Vectors"
desc = "Test for CL.TE, TE.CL, TE.TE, H2C, and H2 smuggling with extensive payload variations."
icon = "fa-solid fa-network-wired"

[[extra.features]]
title = "Timing-Based Detection"
desc = "Use timing analysis to identify desynchronization vulnerabilities in web applications."
icon = "fa-solid fa-clock"

[[extra.features]]
title = "Flexible Input Modes"
desc = "Support command-line URLs, stdin pipeline, and various scanning modes for tool integration."
icon = "fa-solid fa-terminal"

[[extra.features]]
title = "Payload Export"
desc = "Export vulnerable payloads for analysis in authorized testing scenarios."
icon = "fa-solid fa-download"

[[extra.features]]
title = "High Performance"
desc = "Built with Rust and async operations for efficient concurrent scanning."
icon = "fa-solid fa-bolt"

[[extra.features]]
title = "Comprehensive Coverage"
desc = "Detect protocol-level smuggling with HTTP/1.1 and HTTP/2 support."
icon = "fa-solid fa-shield-halved"

[extra.final_cta_section]
title = "Contributing"
description = "Smugglex is open-source. Contribute by reporting bugs, suggesting features, or submitting pull requests."
button = { text = "View GitHub Repository", url = "https://github.com/hahwul/smugglex" }
+++
