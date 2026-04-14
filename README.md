# NIST AI Risk Management Framework MCP Server

> **By [MEOK AI Labs](https://meok.ai)** — Sovereign AI tools for everyone.

The first MCP server implementing NIST AI RMF 1.0 (AI 100-1) compliance assessment. Evaluate AI systems against all four core functions (GOVERN, MAP, MEASURE, MANAGE), assess trustworthy AI characteristics, generate risk controls, and crosswalk to EU AI Act articles.

Part of the **Compliance Trinity**: EU AI Act + NIST AI RMF + ISO 42001.

[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `assess_risk_profile` | Full risk assessment against NIST AI RMF GOVERN/MAP/MEASURE/MANAGE |
| `map_ai_impact` | Map AI impacts across people, organizations, and ecosystems |
| `generate_risk_controls` | Generate NIST-aligned control recommendations with priority |
| `crosswalk_to_eu_ai_act` | Map NIST RMF functions to EU AI Act articles (killer feature) |
| `create_risk_report` | Generate complete NIST AI RMF compliance report in markdown |
| `check_trustworthy_characteristics` | Evaluate against NIST's 7 trustworthy AI characteristics |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/nist-rmf-ai-mcp.git
cd nist-rmf-ai-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "nist-rmf-ai": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/nist-rmf-ai-mcp"
    }
  }
}
```

## The Crosswalk Advantage

No one else maps regulation-to-regulation as MCP tools. The `crosswalk_to_eu_ai_act` tool shows exactly where NIST RMF requirements align with EU AI Act obligations:

- **GOVERN 1.1** maps to EU AI Act Articles 9(1), 17(1), 55
- **MAP 2.2** maps to EU AI Act Articles 14, 13(3)(d)
- **MEASURE 2.11** maps to EU AI Act Articles 10(2)(f), 10(2)(g)
- 30+ detailed mappings with alignment strength ratings

## Coverage

- **19 GOVERN subcategories** across 6 categories
- **17 MAP subcategories** across 5 categories
- **19 MEASURE subcategories** across 4 categories
- **13 MANAGE subcategories** across 4 categories
- **7 Trustworthy AI characteristics** with per-question assessment
- **30+ NIST-to-EU crosswalk mappings**

## Pricing

| Plan | Price | Requests |
|------|-------|----------|
| Free | $0/mo | 10 assessments/day |
| Pro | $29/mo | Unlimited |

## Part of MEOK AI Labs

This is one of 255+ MCP servers by MEOK AI Labs. Browse all at [meok.ai](https://meok.ai) or [GitHub](https://github.com/CSOAI-ORG).

---
**MEOK AI Labs** | [meok.ai](https://meok.ai) | nicholas@meok.ai | United Kingdom
