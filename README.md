[![nist-rmf-ai-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/nist-rmf-ai-mcp/badges/score.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/nist-rmf-ai-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-Published-green)](https://registry.modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/nist-rmf-ai-mcp)](https://pypi.org/project/nist-rmf-ai-mcp/)

[![nist-rmf-ai-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/nist-rmf-ai-mcp/badges/card.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/nist-rmf-ai-mcp)

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/nist-rmf-ai-mcp)](https://pypi.org/project/nist-rmf-ai-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/nist-rmf-ai-mcp)](https://pypi.org/project/nist-rmf-ai-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/nist-rmf-ai-mcp)](https://github.com/CSOAI-ORG/nist-rmf-ai-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# NIST AI RMF MCP

**NIST AI Risk Management Framework (AI 100-1) implementation across all four functions: GOVERN, MAP, MEASURE, MANAGE. Risk profiling, trustworthy AI characteristics, and EU AI Act crosswalk.**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing) · [Attestation API](#attestation-api)

</div>

---

## Why This Exists

NIST AI 100-1 is the de facto AI risk management standard for US federal agencies, federal contractors, and any US-headquartered company building AI governance. Executive Order 14110 (Oct 2023) directs federal agencies to adopt the AI RMF, and procurement officers increasingly require AI RMF compliance documentation from vendors.

The framework defines four core functions (GOVERN, MAP, MEASURE, MANAGE) with 19 categories and 72 subcategories. Mapping your AI system against all of them, assessing trustworthy AI characteristics (valid, reliable, safe, secure, accountable, transparent, explainable, privacy-enhanced, fair), and crosswalking to EU AI Act for dual-jurisdiction compliance is time-intensive. This MCP automates the full assessment.

## Install

```bash
pip install nist-rmf-ai-mcp
```

## Tools

| Tool | AI RMF Reference | What it does |
|------|-----------------|--------------|
| `assess_risk_profile` | GOVERN, MAP, MEASURE, MANAGE | Full risk profile assessment across all 4 functions |
| `map_ai_impact` | MAP 1-5 | Map AI system context, impacts, and stakeholders |
| `generate_risk_controls` | MANAGE 1-4 | Generate risk response and control recommendations |
| `crosswalk_to_eu_ai_act` | AI RMF + EU AI Act | Map NIST AI RMF subcategories to EU AI Act requirements |
| `create_risk_report` | All functions | Generate a structured AI risk management report |
| `check_trustworthy_characteristics` | AI RMF Core | Evaluate against NIST trustworthy AI characteristics |
| `predict_risk_neural` | ML-assisted | Neural network risk prediction for AI systems |
| `quick_scan` | All functions | Rapid AI system risk overview |
| `framework_overview` | AI 100-1 | Full framework structure and reference guide |

## Example

```
Prompt: "Assess our healthcare diagnostic AI against the NIST AI RMF.
It analyses chest X-rays, was trained on NIH ChestX-ray14, deployed
in a US hospital network, and clinicians use it as a second opinion."

Result: Assessment across all 4 functions with findings: MAP identifies
high-impact healthcare context with patient safety implications, MEASURE
flags dataset bias risk (ChestX-ray14 demographic skew), MANAGE requires
human-in-the-loop validation controls, GOVERN needs AI governance board
oversight. Trustworthy AI assessment scores each characteristic.
```

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day — risk profile + quick scan |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations + verify URLs |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports + webhooks |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

Every Pro/Enterprise audit produces a cryptographically signed certificate:

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

Zero-dep verifier: `pip install meok-attestation-verify`

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Enterprise support: nicholas@csoai.org

## License

MIT
<!-- mcp-name: io.github.CSOAI-ORG/nist-rmf-ai-mcp -->
