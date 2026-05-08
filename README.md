<div align="center">

# Nist Rmf Ai MCP

**MCP server for nist rmf ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-nist-rmf-ai-mcp)](https://pypi.org/project/meok-nist-rmf-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Nist Rmf Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `assess_risk_profile` | Assess an AI system against the full NIST AI RMF 1.0 framework. |
| `map_ai_impact` | Map AI system impacts across people, organizations, and ecosystems. |
| `generate_risk_controls` | Generate NIST-aligned control recommendations for identified AI risks. |
| `crosswalk_to_eu_ai_act` | Map NIST AI RMF functions and subcategories to EU AI Act articles. |
| `create_risk_report` | Generate a complete NIST AI RMF compliance report in markdown. |
| `check_trustworthy_characteristics` | Evaluate AI system against NIST's 7 trustworthy AI characteristics. |
| `predict_risk_neural` | Neural network-based risk prediction that improves from every compliance check. |
| `neural_insights` | Get aggregate learning insights from the neural compliance model. |
| `quick_scan` | One-line system description to instant NIST AI RMF risk profile. No API key need |
| `framework_overview` | Returns the NIST AI RMF GOVERN/MAP/MEASURE/MANAGE structure. No parameters neede |

## Installation

```bash
pip install meok-nist-rmf-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "nist-rmf-ai-mcp": {
      "command": "python",
      "args": ["-m", "meok_nist_rmf_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 10 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
