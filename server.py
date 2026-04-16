#!/usr/bin/env python3
"""
NIST AI Risk Management Framework (AI RMF 1.0) MCP Server
===========================================================
By MEOK AI Labs | https://meok.ai

The first MCP server implementing NIST AI RMF 1.0 compliance assessment.
Covers all four core functions (GOVERN, MAP, MEASURE, MANAGE), trustworthy
AI characteristics, impact mapping, risk controls, and regulation crosswalks.

Reference: NIST AI 100-1 (AI Risk Management Framework 1.0, January 2023)
           NIST AI 600-1 (Generative AI Profile, July 2024)

Install: pip install mcp
Run:     python server.py
"""


import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access
from compliance_neural import ComplianceNeuralNet

_neural_net = ComplianceNeuralNet("nist-rmf-ai")

import json
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Tier authentication (connects to Stripe subscriptions)
try:
    from auth_middleware import get_tier_from_api_key, Tier, TIER_LIMITS
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False  # Runs without auth in dev mode

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

# ── Authentication ──────────────────────────────────────────────
import os as _os
_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

def _check_auth(api_key: str = "") -> str | None:
    """Check API key if MEOK_API_KEY is set. Returns error or None."""
    if _MEOK_API_KEY and api_key != _MEOK_API_KEY:
        return "Invalid API key. Get one at https://meok.ai/api-keys"
    return None


FREE_DAILY_LIMIT = 10
_usage: dict[str, list[datetime]] = defaultdict(list)


def _check_rate_limit(caller: str = "anonymous", tier: str = "free") -> Optional[str]:
    """Returns error string if rate-limited, else None."""
    if tier == "pro":
        return None
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            f"Free tier limit reached ({FREE_DAILY_LIMIT}/day). "
            "Upgrade to MEOK AI Labs Pro for unlimited access at $29/mo: "
            "https://meok.ai/mcp/nist-rmf-ai/pro"
        )
    _usage[caller].append(now)
    return None


# ---------------------------------------------------------------------------
# FastMCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "nist-rmf-ai",
    instructions=(
        "NIST AI Risk Management Framework (AI RMF 1.0) compliance server. "
        "Provides risk assessment against GOVERN/MAP/MEASURE/MANAGE functions, "
        "impact mapping, control generation, trustworthy AI evaluation, "
        "and crosswalks to EU AI Act. By MEOK AI Labs."
    ),
)

# ---------------------------------------------------------------------------
# NIST AI RMF 1.0 Knowledge Base — All Functions & Subcategories
# ---------------------------------------------------------------------------

NIST_RMF_FUNCTIONS = {
    "GOVERN": {
        "description": "Cultivate and implement a culture of risk management within organizations designing, developing, deploying, or using AI systems.",
        "subcategories": {
            "GOVERN 1": {
                "title": "Policies, processes, procedures, and practices",
                "description": "Legal and regulatory requirements involving AI are understood, managed, and documented.",
                "subcats": {
                    "GOVERN 1.1": "Legal and regulatory requirements involving AI are understood, managed, and documented.",
                    "GOVERN 1.2": "The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.",
                    "GOVERN 1.3": "Processes, procedures, and practices are in place to determine the needed level of risk management activities based on the assessed level of risk.",
                    "GOVERN 1.4": "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities.",
                    "GOVERN 1.5": "Ongoing monitoring and periodic review of the risk management process and its outcomes are planned and organizational roles and responsibilities are clearly defined.",
                    "GOVERN 1.6": "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.",
                    "GOVERN 1.7": "Processes and procedures are in place for decommissioning and phasing out AI systems safely and in a manner that does not increase risks or harms.",
                },
            },
            "GOVERN 2": {
                "title": "Accountability structures",
                "description": "Accountability structures are in place so that the appropriate teams and individuals are empowered, responsible, and trained for mapping, measuring, and managing AI risks.",
                "subcats": {
                    "GOVERN 2.1": "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams.",
                    "GOVERN 2.2": "The organization's personnel and partners receive AI risk management training to enable them to perform their duties and responsibilities consistent with related policies, procedures, and agreements.",
                    "GOVERN 2.3": "Executive leadership of the organization takes responsibility for decisions about risks associated with AI system development and deployment.",
                },
            },
            "GOVERN 3": {
                "title": "Workforce diversity, equity, inclusion, and accessibility",
                "description": "Workforce diversity, equity, inclusion, and accessibility processes are prioritized in the mapping, measuring, and managing of AI risks throughout the lifecycle.",
                "subcats": {
                    "GOVERN 3.1": "Decision-making related to mapping, measuring, and managing AI risks throughout the lifecycle is informed by a diverse team.",
                    "GOVERN 3.2": "Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems.",
                },
            },
            "GOVERN 4": {
                "title": "Organizational commitments",
                "description": "Organizational teams are committed to a culture that considers and communicates AI risk.",
                "subcats": {
                    "GOVERN 4.1": "Organizational policies and practices are in place to foster a critical thinking and safety-first mindset in the design, development, deployment, and uses of AI systems to minimize potential negative impacts.",
                    "GOVERN 4.2": "Organizational teams document the risks and potential impacts of the AI technology they design, develop, deploy, and use, and communicate about the impacts more broadly.",
                    "GOVERN 4.3": "Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.",
                },
            },
            "GOVERN 5": {
                "title": "Engagement with AI actors",
                "description": "Processes are in place for robust engagement with relevant AI actors.",
                "subcats": {
                    "GOVERN 5.1": "Organizational policies and practices are in place to collect, consider, prioritize, and integrate feedback from those external to the team that developed or deployed the AI system regarding the potential individual and societal risks associated with the AI system.",
                    "GOVERN 5.2": "Mechanisms are established to enable AI actors to regularly incorporate adjudicated feedback from relevant AI actors into system design and implementation.",
                },
            },
            "GOVERN 6": {
                "title": "Policies and procedures for third-party entities",
                "description": "Policies and procedures are in place to address AI risks and benefits arising from third-party software and data and other supply chain issues.",
                "subcats": {
                    "GOVERN 6.1": "Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third-party's intellectual property or other rights.",
                    "GOVERN 6.2": "Contingency processes are in place for third-party AI systems or components.",
                },
            },
        },
    },
    "MAP": {
        "description": "Contextualize risks for specific use cases. Identify and assess risks related to an AI system and its context of use.",
        "subcategories": {
            "MAP 1": {
                "title": "Context is established and understood",
                "description": "Context is recognized and documented for the AI system.",
                "subcats": {
                    "MAP 1.1": "Intended purposes, potentially beneficial uses, context of use, and AI system design assumptions and limitations are understood and documented. Assumptions can include parity constraints for fair outcomes, ## of training examples, ## of features, etc.",
                    "MAP 1.2": "Interdependencies between involved AI actors are mapped.",
                    "MAP 1.3": "The organization's business case or context of use, including its effects on individuals, communities, organizations, and society, is defined and documented.",
                    "MAP 1.4": "Assessment of organization, AI system, and context of use limitations is performed.",
                    "MAP 1.5": "Organizational risk tolerances are determined and documented.",
                    "MAP 1.6": "System requirements (e.g., human oversight) and resource requirements are understood and documented.",
                },
            },
            "MAP 2": {
                "title": "Categorize AI system",
                "description": "AI systems are categorized based on potential risks.",
                "subcats": {
                    "MAP 2.1": "The specific tasks and methods used to implement the tasks that the AI system will support are defined (e.g., classifiers, generative models, recommenders).",
                    "MAP 2.2": "Information about the AI system's knowledge limits and how system output may be utilized and overseen by humans is documented. Documentation includes instructions for operation and requirements for human oversight.",
                    "MAP 2.3": "Scientific integrity and TEVV (Test, Evaluation, Verification, Validation) considerations are identified and documented, including those related to experimental design, data collection and selection, and data provenance.",
                },
            },
            "MAP 3": {
                "title": "Benefits and costs of AI systems",
                "description": "Potential benefits and costs including potential impacts to individuals, groups, communities, organizations, and society are documented.",
                "subcats": {
                    "MAP 3.1": "Potential benefits and costs, including potential risks to safety and society, of the intended AI system functionality are examined and documented.",
                    "MAP 3.2": "Potential costs of not deploying the AI system are documented.",
                    "MAP 3.3": "Targeted application scope is specified and documented based on the system's capability, established context, and AI system categorization.",
                    "MAP 3.4": "Processes for operator and practitioner proficiency with AI system performance and trustworthiness — and relevant technical standards and certifications — are documented.",
                    "MAP 3.5": "Likelihood and magnitude of each identified impact (both beneficial and harmful) based on expected use, past uses of similar systems, public incident reports, feedback from those impacted, domain experts, and other relevant factors. Severity of the harms is identified and documented.",
                },
            },
            "MAP 4": {
                "title": "Risks from third-party entities",
                "description": "Risks and benefits are mapped for all components of the AI system including third-party software and data.",
                "subcats": {
                    "MAP 4.1": "Approaches for mapping AI technology and legal risks of its components — including the use of third-party data or software — are in place, followed, and documented, as are risks of infringement of a third-party's intellectual property or other rights.",
                    "MAP 4.2": "Internal risk controls for components of the AI system, including third-party AI technologies, are identified and documented.",
                },
            },
            "MAP 5": {
                "title": "Impacts to individuals, groups, communities, organizations, and society",
                "description": "Likelihood and severity of potential impacts to individuals, groups, communities, organizations, and society are established.",
                "subcats": {
                    "MAP 5.1": "Likelihood and severity of each identified impact of the AI system — positive and negative — on individuals, groups, communities, organizations, and society are established, including expected and potential impacts on historically underserved populations.",
                    "MAP 5.2": "Practices and personnel for defining, identifying, and documenting relevant post-deployment AI system risks are in place.",
                },
            },
        },
    },
    "MEASURE": {
        "description": "Employ quantitative, qualitative, or mixed-method tools and techniques to analyze, assess, benchmark, and monitor AI risk and related impacts.",
        "subcategories": {
            "MEASURE 1": {
                "title": "Appropriate methods and metrics",
                "description": "Appropriate methods and metrics are identified and applied.",
                "subcats": {
                    "MEASURE 1.1": "Approaches and metrics for measurement of AI risks enumerated during the MAP function are selected for implementation starting with the most significant AI risks. The risks or trustworthiness characteristics that will not — or cannot — be measured are properly documented.",
                    "MEASURE 1.2": "Appropriateness of AI metrics and effectiveness of existing measures are regularly assessed and updated, including reports of errors and impacts on affected communities.",
                    "MEASURE 1.3": "Internal and external expertise for the assessment of AI systems is engaged, including domain experts, users, and potentially impacted communities.",
                },
            },
            "MEASURE 2": {
                "title": "AI systems are evaluated for trustworthy characteristics",
                "description": "AI systems are evaluated for trustworthy characteristics.",
                "subcats": {
                    "MEASURE 2.1": "Test sets, metrics, and details about the tools used during test, evaluation, validation, and verification (TEVV) are documented.",
                    "MEASURE 2.2": "Evaluations involving human subjects meet applicable requirements (including human subjects protections) and are representative of the relevant population.",
                    "MEASURE 2.3": "AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions similar to deployment conditions. Measurement results regarding AI system trustworthiness in deployment conditions are documented.",
                    "MEASURE 2.4": "The functionality and behavior of the AI system and its components — as identified in the MAP function — are monitored when in production.",
                    "MEASURE 2.5": "The AI system to be deployed is demonstrated to be valid and reliable. Limitations of the AI system are documented.",
                    "MEASURE 2.6": "The AI system is evaluated for safety risks — risks to physical or psychological safety of persons — in conditions defined by the deployment environment of the AI system.",
                    "MEASURE 2.7": "AI system security and resilience — as identified in the MAP function — are evaluated and documented.",
                    "MEASURE 2.8": "Risks associated with transparency and accountability — as identified in the MAP function — are examined and documented.",
                    "MEASURE 2.9": "The AI model is explained, validated, and documented. AI system output is interpreted within its context — as identified in the MAP function — to inform responsible use and governance.",
                    "MEASURE 2.10": "Privacy risk of the AI system — as identified in the MAP function — is examined and documented.",
                    "MEASURE 2.11": "Fairness and bias — as identified in the MAP function — are evaluated and results are documented.",
                    "MEASURE 2.12": "Environmental impact and sustainability of AI model training and management activities — as identified in the MAP function — are assessed and documented.",
                    "MEASURE 2.13": "Effectiveness of the employed TEVV metrics, processes, and documentation are evaluated regularly.",
                },
            },
            "MEASURE 3": {
                "title": "Mechanisms for tracking identified AI risks",
                "description": "Mechanisms for tracking identified AI risks over time are in place.",
                "subcats": {
                    "MEASURE 3.1": "Approaches, personnel, and documentation are in place to regularly identify and track existing, unanticipated, and emergent AI risks based on factors such as intended and actual performance in deployed contexts.",
                    "MEASURE 3.2": "Risk tracking approaches are considered for settings where AI risks are difficult to assess using currently available measurement tools or methods.",
                    "MEASURE 3.3": "Feedback processes for end users and impacted communities to report problems and appeal system outcomes are established and integrated into AI system evaluation metrics.",
                },
            },
            "MEASURE 4": {
                "title": "Measurement feedback and communication",
                "description": "Feedback about efficacy of measurement is collected and communicated.",
                "subcats": {
                    "MEASURE 4.1": "Measurement approaches for identifying AI risks are connected to deployment context(s) and are informed regularly by domain experts and other end users. Measurement results are documented.",
                    "MEASURE 4.2": "Measurement results regarding AI system trustworthiness in deployment context(s) and across the AI lifecycle are informed by input from domain experts and relevant AI actors to validate, refine, and update.",
                },
            },
        },
    },
    "MANAGE": {
        "description": "Allocate risk resources to mapped and measured risks on a regular basis and as defined by the GOVERN function.",
        "subcategories": {
            "MANAGE 1": {
                "title": "AI risks are prioritized and responded to",
                "description": "AI risks based on the risk analysis of mapped and measured AI risks are prioritized, responded to, and managed.",
                "subcats": {
                    "MANAGE 1.1": "A determination is made as to whether the AI system achieves its intended purpose and stated objectives and whether its development or deployment should proceed.",
                    "MANAGE 1.2": "Treatment of documented AI risks is prioritized based on impact, likelihood, and available resources or methods.",
                    "MANAGE 1.3": "Responses to the AI risks deemed high priority, as identified by the MAP and MEASURE functions, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.",
                    "MANAGE 1.4": "Negative residual risks (remaining risks) to individuals, groups, communities, organizations, and society that are deemed tolerable in the context are documented.",
                },
            },
            "MANAGE 2": {
                "title": "Strategies to manage AI risks",
                "description": "Strategies to maximize AI benefits and minimize negative impacts are planned, prepared, implemented, documented, and informed by input from relevant AI actors.",
                "subcats": {
                    "MANAGE 2.1": "Resources required to manage AI risks are taken into account — along with viable non-AI alternative systems, approaches, or methods — to reduce the magnitude or likelihood of potential impacts.",
                    "MANAGE 2.2": "Mechanisms are in place and applied to sustain the value of deployed AI systems.",
                    "MANAGE 2.3": "Procedures are followed to respond to and recover from a previously unknown risk when it is identified.",
                    "MANAGE 2.4": "Mechanisms are in place and applied, and approaches are documented, to quantify and document the AI system's residual risk.",
                },
            },
            "MANAGE 3": {
                "title": "AI risks and benefits from third-party resources",
                "description": "AI risks and benefits from third-party resources are managed.",
                "subcats": {
                    "MANAGE 3.1": "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented.",
                    "MANAGE 3.2": "Pre-trained models which are used for development are monitored as part of AI system regular monitoring and maintenance.",
                },
            },
            "MANAGE 4": {
                "title": "Risk treatments",
                "description": "Risk treatments, including response and recovery, and communication plans are documented and monitored regularly.",
                "subcats": {
                    "MANAGE 4.1": "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management.",
                    "MANAGE 4.2": "Measurable activities for continual improvements are integrated into AI system updates and include regular engagement with interested parties, including potentially affected communities.",
                    "MANAGE 4.3": "Incidents and errors are communicated to relevant AI actors, including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented.",
                },
            },
        },
    },
}

# ---------------------------------------------------------------------------
# NIST Trustworthy AI Characteristics (AI RMF 1.0, Section 3)
# ---------------------------------------------------------------------------
TRUSTWORTHY_CHARACTERISTICS = {
    "valid_and_reliable": {
        "name": "Valid and Reliable",
        "description": "Validation is the confirmation that AI system requirements are met and fulfilled for an intended use. Reliability means the system can perform as required, without failure, for a given time interval, under given conditions.",
        "key_questions": [
            "Has the AI system been validated against requirements for its intended use?",
            "Are accuracy and performance metrics established and documented?",
            "Has the system been tested under expected deployment conditions?",
            "Are error rates measured and documented?",
            "Is there ongoing monitoring of system performance post-deployment?",
            "Are there mechanisms to detect performance degradation over time?",
            "Has the system been stress-tested with edge cases and adversarial inputs?",
        ],
        "nist_refs": ["MEASURE 2.5", "MEASURE 2.3", "MEASURE 2.4", "MAP 2.3"],
    },
    "safe": {
        "name": "Safe",
        "description": "AI systems should not endanger human life, health, property, or the environment. They should include safeguards to constrain system behavior within safe operating parameters.",
        "key_questions": [
            "Has a safety risk assessment been conducted?",
            "Are there safeguards to constrain AI system behavior?",
            "Has the system been evaluated for risks to physical safety?",
            "Are fail-safe mechanisms and human override capabilities in place?",
            "Have potential cascading failures been identified and mitigated?",
            "Is there a safety monitoring and incident response plan?",
            "Are worst-case scenarios documented with mitigation strategies?",
        ],
        "nist_refs": ["MEASURE 2.6", "MANAGE 1.3", "MANAGE 4.1", "MAP 3.1"],
    },
    "secure_and_resilient": {
        "name": "Secure and Resilient",
        "description": "AI systems need to withstand unexpected adverse events or changes in their environment or use, and maintain their functions and structure. This includes resistance to adversarial attacks, data poisoning, and model extraction.",
        "key_questions": [
            "Has the system been evaluated for adversarial robustness?",
            "Are there protections against data poisoning attacks?",
            "Has model extraction risk been assessed?",
            "Are cybersecurity best practices applied to the AI system?",
            "Is there resilience against infrastructure failures?",
            "Are incident detection and response mechanisms in place?",
            "Has supply chain security for AI components been evaluated?",
        ],
        "nist_refs": ["MEASURE 2.7", "GOVERN 6.1", "MANAGE 2.3", "MAP 4.2"],
    },
    "accountable_and_transparent": {
        "name": "Accountable and Transparent",
        "description": "Transparency reflects the extent to which information about an AI system and its outputs is available to individuals interacting with the system. Accountability presupposes transparency.",
        "key_questions": [
            "Is there clear documentation of system purpose, capabilities, and limitations?",
            "Are roles and responsibilities for AI risk management clearly defined?",
            "Is the AI system's decision-making process documented?",
            "Are users informed when they are interacting with an AI system?",
            "Is there an audit trail for AI system decisions?",
            "Are there mechanisms for external scrutiny and oversight?",
            "Is information about training data, model architecture, and performance publicly available?",
        ],
        "nist_refs": ["MEASURE 2.8", "GOVERN 1.4", "GOVERN 2.1", "MAP 1.1"],
    },
    "explainable_and_interpretable": {
        "name": "Explainable and Interpretable",
        "description": "Explainability refers to a representation of the mechanisms underlying AI systems' operation. Interpretability refers to the meaning of AI systems' output in the context of their designed functional purposes.",
        "key_questions": [
            "Can the AI system's outputs be explained to users and stakeholders?",
            "Are model explanations faithful to the actual decision process?",
            "Is the appropriate level of explainability provided for the risk level?",
            "Are there tools or methods to interpret model outputs in context?",
            "Can users understand why a particular decision or recommendation was made?",
            "Is there documentation of model limitations and known failure modes?",
            "Are explanations tested for accuracy and usefulness with end users?",
        ],
        "nist_refs": ["MEASURE 2.9", "MAP 1.1", "MAP 2.2", "GOVERN 1.4"],
    },
    "privacy_enhanced": {
        "name": "Privacy-Enhanced",
        "description": "Privacy refers to the norms and practices that help safeguard human autonomy, identity, and dignity. AI system values including freedom from intrusion, limiting observation, and the ability to control one's data.",
        "key_questions": [
            "Has a privacy impact assessment been conducted for the AI system?",
            "Are privacy-preserving techniques (differential privacy, federated learning, etc.) employed?",
            "Is personal data minimized in training and inference?",
            "Are data subjects informed about how their data is used?",
            "Are there mechanisms for consent management and data deletion?",
            "Has re-identification risk from model outputs been assessed?",
            "Is there compliance with applicable privacy regulations (GDPR, CCPA, etc.)?",
        ],
        "nist_refs": ["MEASURE 2.10", "MAP 5.1", "GOVERN 1.1", "MANAGE 1.4"],
    },
    "fair_with_harmful_bias_managed": {
        "name": "Fair with Harmful Bias Managed",
        "description": "Fairness in AI includes concerns about harmful bias. AI systems should be designed so that they are equitable, with harmful biases identified, measured, and managed throughout the AI lifecycle.",
        "key_questions": [
            "Has bias testing been conducted across relevant demographic groups?",
            "Are fairness metrics defined and measured regularly?",
            "Is training data assessed for representation and potential biases?",
            "Are there mechanisms to detect and mitigate emergent biases post-deployment?",
            "Has the AI system's impact on historically underserved populations been evaluated?",
            "Are there diverse perspectives involved in system design and evaluation?",
            "Is there a process for affected individuals to report unfair outcomes?",
        ],
        "nist_refs": ["MEASURE 2.11", "MAP 5.1", "GOVERN 3.1", "MANAGE 4.2"],
    },
}

# ---------------------------------------------------------------------------
# NIST RMF to EU AI Act Crosswalk — The Killer Feature
# ---------------------------------------------------------------------------
NIST_TO_EU_CROSSWALK = {
    "GOVERN 1.1": {
        "eu_articles": ["Article 9(1)", "Article 17(1)", "Article 55"],
        "mapping_rationale": "NIST requirement for understanding legal/regulatory requirements maps directly to EU AI Act's risk management system (Art 9), quality management system (Art 17), and obligation for providers to demonstrate compliance (Art 55).",
        "alignment_strength": "strong",
    },
    "GOVERN 1.2": {
        "eu_articles": ["Article 9(2)", "Article 15", "Article 16(a)"],
        "mapping_rationale": "Integrating trustworthy AI characteristics into policies aligns with EU AI Act's requirement for risk management to consider known and foreseeable risks (Art 9.2), accuracy/robustness/cybersecurity (Art 15), and provider obligations (Art 16a).",
        "alignment_strength": "strong",
    },
    "GOVERN 1.3": {
        "eu_articles": ["Article 6", "Article 9(1)"],
        "mapping_rationale": "Risk-proportionate management maps to EU AI Act's classification rules for high-risk AI (Art 6) and the risk management system requirement (Art 9.1).",
        "alignment_strength": "strong",
    },
    "GOVERN 1.4": {
        "eu_articles": ["Article 13", "Article 17(1)(e)"],
        "mapping_rationale": "Transparency of risk management aligns with EU AI Act transparency obligations (Art 13) and quality management documentation requirements (Art 17.1.e).",
        "alignment_strength": "moderate",
    },
    "GOVERN 1.5": {
        "eu_articles": ["Article 9(3)", "Article 72"],
        "mapping_rationale": "Ongoing monitoring maps to EU AI Act's post-market monitoring system (Art 9.3) and post-market monitoring by providers (Art 72).",
        "alignment_strength": "strong",
    },
    "GOVERN 1.6": {
        "eu_articles": ["Article 49", "Article 71"],
        "mapping_rationale": "AI system inventory maps to EU AI Act registration in EU database (Art 49) and registration obligations (Art 71).",
        "alignment_strength": "moderate",
    },
    "GOVERN 1.7": {
        "eu_articles": ["Article 20", "Article 22"],
        "mapping_rationale": "Decommissioning processes map to EU AI Act corrective actions (Art 20) and duty of information regarding non-compliant systems (Art 22).",
        "alignment_strength": "moderate",
    },
    "GOVERN 2.1": {
        "eu_articles": ["Article 17(1)(j)", "Article 26(1)"],
        "mapping_rationale": "Documented roles and responsibilities align with EU AI Act quality management personnel accountability (Art 17.1.j) and deployer obligations (Art 26.1).",
        "alignment_strength": "strong",
    },
    "GOVERN 2.2": {
        "eu_articles": ["Article 4", "Article 17(1)(k)"],
        "mapping_rationale": "AI risk management training maps to EU AI Act AI literacy obligations (Art 4) and quality management training requirements (Art 17.1.k).",
        "alignment_strength": "strong",
    },
    "GOVERN 2.3": {
        "eu_articles": ["Article 16", "Article 17(1)(a)"],
        "mapping_rationale": "Executive responsibility maps to EU AI Act provider obligations (Art 16) and quality management leadership commitment (Art 17.1.a).",
        "alignment_strength": "moderate",
    },
    "GOVERN 3.1": {
        "eu_articles": ["Article 9(4)(a)", "Article 10(2)(f)"],
        "mapping_rationale": "Diverse teams in risk management align with EU AI Act requirements considering impact on specific groups (Art 9.4.a) and data governance considering specific geographical, contextual, behavioral, or functional settings (Art 10.2.f).",
        "alignment_strength": "moderate",
    },
    "GOVERN 4.1": {
        "eu_articles": ["Article 9(2)(a)", "Article 16(a)"],
        "mapping_rationale": "Safety-first culture aligns with EU AI Act risk management for foreseeable misuse (Art 9.2.a) and provider obligations to ensure compliance (Art 16.a).",
        "alignment_strength": "moderate",
    },
    "GOVERN 4.3": {
        "eu_articles": ["Article 62", "Article 73"],
        "mapping_rationale": "Incident sharing aligns with EU AI Act reporting of serious incidents (Art 62) and market surveillance obligations (Art 73).",
        "alignment_strength": "strong",
    },
    "GOVERN 5.1": {
        "eu_articles": ["Article 9(4)", "Article 29(6)"],
        "mapping_rationale": "External stakeholder feedback maps to EU AI Act stakeholder consultation in risk management (Art 9.4) and deployer obligation to inform providers of risks (Art 29.6).",
        "alignment_strength": "moderate",
    },
    "GOVERN 6.1": {
        "eu_articles": ["Article 25", "Article 17(1)(g)"],
        "mapping_rationale": "Third-party risk management maps to EU AI Act responsibilities along the AI value chain (Art 25) and supply chain management in quality management (Art 17.1.g).",
        "alignment_strength": "strong",
    },
    "MAP 1.1": {
        "eu_articles": ["Article 9(2)", "Article 13(3)(b)(i)"],
        "mapping_rationale": "Documenting intended purposes and limitations maps to EU AI Act risk identification (Art 9.2) and instructions for use specifying intended purpose (Art 13.3.b.i).",
        "alignment_strength": "strong",
    },
    "MAP 1.5": {
        "eu_articles": ["Article 9(5)", "Article 9(7)"],
        "mapping_rationale": "Risk tolerances map to EU AI Act residual risk requirements (Art 9.5) and testing against predefined metrics (Art 9.7).",
        "alignment_strength": "strong",
    },
    "MAP 2.1": {
        "eu_articles": ["Article 11(1)", "Article 53(1)"],
        "mapping_rationale": "System task documentation maps to EU AI Act technical documentation (Art 11.1) and obligations for general-purpose AI models (Art 53.1).",
        "alignment_strength": "strong",
    },
    "MAP 2.2": {
        "eu_articles": ["Article 14", "Article 13(3)(d)"],
        "mapping_rationale": "Human oversight documentation maps to EU AI Act human oversight requirements (Art 14) and transparency about human oversight measures (Art 13.3.d).",
        "alignment_strength": "strong",
    },
    "MAP 3.1": {
        "eu_articles": ["Article 9(2)(a)", "Article 9(2)(b)"],
        "mapping_rationale": "Benefit-cost analysis maps to EU AI Act risk identification for foreseeable misuse (Art 9.2.a) and risk estimation (Art 9.2.b).",
        "alignment_strength": "moderate",
    },
    "MAP 5.1": {
        "eu_articles": ["Article 9(4)(a)", "Article 27"],
        "mapping_rationale": "Impact assessment on individuals and communities maps to EU AI Act consideration of impacts on specific groups (Art 9.4.a) and fundamental rights impact assessment (Art 27).",
        "alignment_strength": "strong",
    },
    "MEASURE 2.3": {
        "eu_articles": ["Article 9(7)", "Article 15(1)"],
        "mapping_rationale": "System performance measurement maps to EU AI Act testing against predefined metrics (Art 9.7) and accuracy, robustness, cybersecurity (Art 15.1).",
        "alignment_strength": "strong",
    },
    "MEASURE 2.5": {
        "eu_articles": ["Article 15(1)", "Article 9(7)"],
        "mapping_rationale": "Validity and reliability demonstration maps to EU AI Act accuracy requirements (Art 15.1) and system testing (Art 9.7).",
        "alignment_strength": "strong",
    },
    "MEASURE 2.6": {
        "eu_articles": ["Article 9(2)(a)", "Article 5"],
        "mapping_rationale": "Safety risk evaluation maps to EU AI Act foreseeable risk assessment (Art 9.2.a) and prohibited practices that endanger safety (Art 5).",
        "alignment_strength": "strong",
    },
    "MEASURE 2.7": {
        "eu_articles": ["Article 15(4)", "Article 15(5)"],
        "mapping_rationale": "Security and resilience evaluation maps to EU AI Act robustness against errors/faults/inconsistencies (Art 15.4) and resilience against adversarial manipulation (Art 15.5).",
        "alignment_strength": "strong",
    },
    "MEASURE 2.8": {
        "eu_articles": ["Article 13", "Article 26(5)"],
        "mapping_rationale": "Transparency and accountability risks map to EU AI Act transparency obligations (Art 13) and deployer transparency to natural persons (Art 26.5).",
        "alignment_strength": "strong",
    },
    "MEASURE 2.9": {
        "eu_articles": ["Article 13(3)(b)(ii)", "Article 13(3)(d)"],
        "mapping_rationale": "Explainability maps to EU AI Act instructions for interpreting system output (Art 13.3.b.ii) and human oversight measures (Art 13.3.d).",
        "alignment_strength": "moderate",
    },
    "MEASURE 2.10": {
        "eu_articles": ["Article 10(5)", "Recital 69"],
        "mapping_rationale": "Privacy risk examination maps to EU AI Act data protection for training data (Art 10.5) and privacy-by-design principles (Recital 69).",
        "alignment_strength": "strong",
    },
    "MEASURE 2.11": {
        "eu_articles": ["Article 10(2)(f)", "Article 10(2)(g)"],
        "mapping_rationale": "Fairness and bias evaluation maps to EU AI Act data governance for bias detection (Art 10.2.f) and gap identification in datasets (Art 10.2.g).",
        "alignment_strength": "strong",
    },
    "MEASURE 2.12": {
        "eu_articles": ["Article 53(1)(d)", "Recital 110"],
        "mapping_rationale": "Environmental impact assessment maps to EU AI Act energy consumption reporting for GPAI models (Art 53.1.d) and sustainability considerations (Recital 110).",
        "alignment_strength": "moderate",
    },
    "MANAGE 1.1": {
        "eu_articles": ["Article 9(4)(b)", "Article 6(3)"],
        "mapping_rationale": "Deployment decision-making maps to EU AI Act risk management outcomes informing decisions (Art 9.4.b) and conditions for classification exceptions (Art 6.3).",
        "alignment_strength": "moderate",
    },
    "MANAGE 1.3": {
        "eu_articles": ["Article 9(5)", "Article 9(6)"],
        "mapping_rationale": "Risk response planning maps to EU AI Act risk elimination or mitigation measures (Art 9.5) and testing post-risk-management measures (Art 9.6).",
        "alignment_strength": "strong",
    },
    "MANAGE 2.1": {
        "eu_articles": ["Article 9(5)", "Article 9(8)"],
        "mapping_rationale": "Resource allocation for risk management maps to EU AI Act risk mitigation measures (Art 9.5) and continuous risk management throughout lifecycle (Art 9.8).",
        "alignment_strength": "moderate",
    },
    "MANAGE 4.1": {
        "eu_articles": ["Article 72", "Article 62"],
        "mapping_rationale": "Post-deployment monitoring maps to EU AI Act post-market monitoring (Art 72) and serious incident reporting (Art 62).",
        "alignment_strength": "strong",
    },
    "MANAGE 4.3": {
        "eu_articles": ["Article 62", "Article 73(2)"],
        "mapping_rationale": "Incident communication maps to EU AI Act serious incident reporting (Art 62) and market surveillance information exchange (Art 73.2).",
        "alignment_strength": "strong",
    },
}

# ---------------------------------------------------------------------------
# Impact Categories for MAP function
# ---------------------------------------------------------------------------
IMPACT_CATEGORIES = {
    "people": {
        "subcategories": [
            {"name": "Physical safety", "description": "Risk of physical harm to individuals"},
            {"name": "Psychological wellbeing", "description": "Risk of psychological harm, stress, or manipulation"},
            {"name": "Civil liberties", "description": "Impact on freedom of speech, assembly, privacy, non-discrimination"},
            {"name": "Economic opportunity", "description": "Impact on employment, financial access, economic mobility"},
            {"name": "Human autonomy", "description": "Impact on individual decision-making and self-determination"},
            {"name": "Dignity", "description": "Impact on human dignity and respect"},
        ],
    },
    "organizations": {
        "subcategories": [
            {"name": "Reputational risk", "description": "Risk to organizational reputation and public trust"},
            {"name": "Legal liability", "description": "Risk of regulatory penalties, lawsuits, or enforcement actions"},
            {"name": "Operational disruption", "description": "Risk of system failures affecting operations"},
            {"name": "Financial loss", "description": "Direct and indirect financial impacts"},
            {"name": "Competitive position", "description": "Impact on market position and competitive advantage"},
            {"name": "Workforce impact", "description": "Impact on employees, skills, and organizational culture"},
        ],
    },
    "ecosystems": {
        "subcategories": [
            {"name": "Environmental impact", "description": "Energy consumption, carbon footprint, resource use"},
            {"name": "Market dynamics", "description": "Impact on market competition, barriers to entry"},
            {"name": "Democratic processes", "description": "Impact on elections, public discourse, information integrity"},
            {"name": "Social cohesion", "description": "Impact on social trust, community relationships"},
            {"name": "Knowledge ecosystem", "description": "Impact on education, research, information quality"},
            {"name": "Critical infrastructure", "description": "Dependence and impact on essential services and systems"},
        ],
    },
}

# ---------------------------------------------------------------------------
# Risk keyword matching
# ---------------------------------------------------------------------------
RISK_KEYWORDS = {
    "safety": ["medical", "health", "clinical", "autonomous vehicle", "robot", "physical", "life-critical", "safety-critical", "weapon", "defense", "military"],
    "bias_fairness": ["hiring", "recruitment", "lending", "credit", "insurance", "criminal justice", "sentencing", "recidivism", "facial recognition", "demographic", "protected class", "discrimination"],
    "privacy": ["personal data", "biometric", "health data", "financial data", "location", "surveillance", "tracking", "profiling", "behavioral", "sensitive data", "PII", "GDPR"],
    "transparency": ["black box", "opaque", "unexplainable", "decision-making", "automated decision", "scoring", "ranking", "recommendation", "content generation", "deepfake"],
    "security": ["adversarial", "attack", "poisoning", "extraction", "model theft", "prompt injection", "jailbreak", "manipulation", "cybersecurity"],
    "autonomy": ["autonomous", "self-driving", "automated", "unsupervised", "real-time", "critical decision", "human override", "control"],
    "environmental": ["energy", "compute", "training", "carbon", "GPU", "data center", "sustainability", "resource consumption"],
    "societal": ["election", "democracy", "misinformation", "disinformation", "public discourse", "polarization", "manipulation", "social media"],
}


def _score_text_against_keywords(text: str, keywords: list[str]) -> float:
    """Score how many keyword matches exist in the text."""
    text_lower = text.lower()
    matches = sum(1 for kw in keywords if kw.lower() in text_lower)
    return min(matches / max(len(keywords), 1), 1.0)


def _identify_risk_areas(description: str) -> dict[str, float]:
    """Identify risk areas from system description."""
    return {
        area: round(_score_text_against_keywords(description, keywords), 3)
        for area, keywords in RISK_KEYWORDS.items()
    }


def _determine_risk_level(score: float) -> str:
    """Convert numeric score to risk level."""
    if score >= 0.5:
        return "high"
    elif score >= 0.25:
        return "moderate"
    elif score > 0:
        return "low"
    return "minimal"


# ===========================================================================
# MCP Tools
# ===========================================================================


@mcp.tool()
def assess_risk_profile(
    system_description: str,
    system_name: str = "AI System",
    deployment_context: str = "",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Assess an AI system against the full NIST AI RMF 1.0 framework.

    Evaluates the system description against all four core functions
    (GOVERN, MAP, MEASURE, MANAGE) and their subcategories. Identifies
    risk areas, gaps in risk management, and provides actionable
    recommendations per NIST AI 100-1.

    Args:
        system_description: Detailed description of the AI system including
            purpose, data used, deployment context, and affected populations.
        system_name: Name identifier for the AI system.
        deployment_context: Additional context about deployment environment.
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Complete NIST AI RMF risk profile with per-function assessments,
        identified risks, and prioritized recommendations.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    full_text = f"{system_description} {deployment_context}"
    risk_areas = _identify_risk_areas(full_text)
    overall_risk = round(sum(risk_areas.values()) / max(len(risk_areas), 1), 3)

    # Assess each function
    function_assessments = {}
    for func_name, func_data in NIST_RMF_FUNCTIONS.items():
        subcategory_results = []
        for subcat_id, subcat_data in func_data["subcategories"].items():
            # Determine relevance of each subcategory based on system description
            subcat_relevant = False
            subcat_priority = "standard"

            subcat_text = f"{subcat_data['title']} {subcat_data['description']}"
            relevance_score = _score_text_against_keywords(
                full_text,
                subcat_text.lower().split()[:10],
            )

            if relevance_score > 0.3:
                subcat_relevant = True
                subcat_priority = "high"
            elif relevance_score > 0.1:
                subcat_relevant = True

            detailed_subcats = {}
            for detail_id, detail_desc in subcat_data["subcats"].items():
                detailed_subcats[detail_id] = {
                    "description": detail_desc,
                    "status": "requires_assessment",
                    "priority": subcat_priority if subcat_relevant else "standard",
                }

            subcategory_results.append({
                "id": subcat_id,
                "title": subcat_data["title"],
                "description": subcat_data["description"],
                "relevant": subcat_relevant,
                "priority": subcat_priority,
                "detailed_subcategories": detailed_subcats,
            })

        function_assessments[func_name] = {
            "description": func_data["description"],
            "subcategories_assessed": len(subcategory_results),
            "high_priority_count": sum(1 for s in subcategory_results if s["priority"] == "high"),
            "subcategories": subcategory_results,
        }

    # Generate priority recommendations
    recommendations = []
    if risk_areas.get("safety", 0) > 0.2:
        recommendations.append({
            "priority": "critical",
            "function": "MAP/MEASURE",
            "action": "Conduct comprehensive safety risk assessment per MEASURE 2.6. Document safety boundaries and fail-safe mechanisms.",
            "nist_refs": ["MEASURE 2.6", "MANAGE 1.3", "MAP 3.1"],
        })
    if risk_areas.get("bias_fairness", 0) > 0.2:
        recommendations.append({
            "priority": "critical",
            "function": "MEASURE/GOVERN",
            "action": "Implement bias testing across demographic groups per MEASURE 2.11. Ensure diverse team involvement per GOVERN 3.1.",
            "nist_refs": ["MEASURE 2.11", "GOVERN 3.1", "MAP 5.1"],
        })
    if risk_areas.get("privacy", 0) > 0.2:
        recommendations.append({
            "priority": "high",
            "function": "MEASURE/GOVERN",
            "action": "Conduct privacy impact assessment per MEASURE 2.10. Implement data minimization and privacy-preserving techniques.",
            "nist_refs": ["MEASURE 2.10", "GOVERN 1.1", "MAP 1.1"],
        })
    if risk_areas.get("transparency", 0) > 0.2:
        recommendations.append({
            "priority": "high",
            "function": "MEASURE/MAP",
            "action": "Document system decision-making process and provide explainability mechanisms per MEASURE 2.8 and 2.9.",
            "nist_refs": ["MEASURE 2.8", "MEASURE 2.9", "MAP 2.2"],
        })
    if risk_areas.get("security", 0) > 0.2:
        recommendations.append({
            "priority": "high",
            "function": "MEASURE/MANAGE",
            "action": "Evaluate adversarial robustness, implement security controls, and establish incident response per MEASURE 2.7.",
            "nist_refs": ["MEASURE 2.7", "MANAGE 2.3", "GOVERN 6.1"],
        })

    # Always recommend these foundational items
    recommendations.extend([
        {
            "priority": "standard",
            "function": "GOVERN",
            "action": "Establish organizational AI risk management policies and accountability structures per GOVERN 1 and GOVERN 2.",
            "nist_refs": ["GOVERN 1.1", "GOVERN 1.2", "GOVERN 2.1"],
        },
        {
            "priority": "standard",
            "function": "MAP",
            "action": "Document intended purposes, limitations, and context of use per MAP 1.1. Map third-party dependencies per MAP 4.",
            "nist_refs": ["MAP 1.1", "MAP 1.4", "MAP 4.1"],
        },
        {
            "priority": "standard",
            "function": "MANAGE",
            "action": "Establish post-deployment monitoring and incident response plans per MANAGE 4.",
            "nist_refs": ["MANAGE 4.1", "MANAGE 4.3", "MANAGE 2.3"],
        },
    ])

    return {
        "system_name": system_name,
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "framework": "NIST AI RMF 1.0 (AI 100-1)",
        "overall_risk_score": overall_risk,
        "overall_risk_level": _determine_risk_level(overall_risk),
        "risk_areas": {
            area: {"score": score, "level": _determine_risk_level(score)}
            for area, score in risk_areas.items()
        },
        "function_assessments": function_assessments,
        "recommendations": sorted(
            recommendations,
            key=lambda x: {"critical": 0, "high": 1, "standard": 2}.get(x["priority"], 3),
        ),
        "total_subcategories_assessed": sum(
            f["subcategories_assessed"] for f in function_assessments.values()
        ),
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


@mcp.tool()
def map_ai_impact(
    system_description: str,
    system_name: str = "AI System",
    affected_populations: str = "",
    deployment_scale: str = "organizational",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Map AI system impacts across people, organizations, and ecosystems.

    Rates severity and likelihood per NIST AI RMF MAP function guidelines.
    Covers MAP 3 (benefits and costs) and MAP 5 (impacts to individuals,
    groups, communities, organizations, and society).

    Args:
        system_description: Description of the AI system and its purpose.
        system_name: Name of the AI system.
        affected_populations: Description of populations affected by the system.
        deployment_scale: Scale of deployment ('individual', 'organizational',
            'national', 'global').
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Impact map with severity and likelihood ratings across all categories.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    full_text = f"{system_description} {affected_populations}"
    risk_areas = _identify_risk_areas(full_text)

    # Scale multiplier
    scale_multiplier = {
        "individual": 0.5,
        "organizational": 0.75,
        "national": 1.0,
        "global": 1.25,
    }.get(deployment_scale, 0.75)

    impact_map = {}
    for category, cat_data in IMPACT_CATEGORIES.items():
        subcategory_impacts = []
        for subcat in cat_data["subcategories"]:
            # Calculate severity based on risk areas and category relevance
            base_severity = 0.0
            if category == "people":
                base_severity = max(
                    risk_areas.get("safety", 0),
                    risk_areas.get("bias_fairness", 0),
                    risk_areas.get("privacy", 0),
                    risk_areas.get("autonomy", 0),
                )
            elif category == "organizations":
                base_severity = max(
                    risk_areas.get("security", 0),
                    risk_areas.get("transparency", 0),
                ) * 0.8
            elif category == "ecosystems":
                base_severity = max(
                    risk_areas.get("environmental", 0),
                    risk_areas.get("societal", 0),
                ) * 0.7

            # Adjust for specific subcategory keywords
            subcat_keywords = subcat["name"].lower().split() + subcat["description"].lower().split()
            subcat_relevance = _score_text_against_keywords(full_text, subcat_keywords[:8])

            severity = min(round((base_severity + subcat_relevance) * scale_multiplier, 2), 1.0)
            likelihood = min(round(severity * 0.85, 2), 1.0)  # Likelihood typically trails severity

            severity_label = "critical" if severity >= 0.7 else "high" if severity >= 0.5 else "moderate" if severity >= 0.25 else "low"
            likelihood_label = "very likely" if likelihood >= 0.7 else "likely" if likelihood >= 0.5 else "possible" if likelihood >= 0.25 else "unlikely"

            subcategory_impacts.append({
                "name": subcat["name"],
                "description": subcat["description"],
                "severity": severity,
                "severity_label": severity_label,
                "likelihood": likelihood,
                "likelihood_label": likelihood_label,
                "risk_rating": round(severity * likelihood, 3),
                "requires_mitigation": severity >= 0.5 or likelihood >= 0.5,
            })

        category_max_severity = max(s["severity"] for s in subcategory_impacts) if subcategory_impacts else 0
        impact_map[category] = {
            "overall_severity": round(category_max_severity, 2),
            "overall_level": _determine_risk_level(category_max_severity),
            "subcategories": subcategory_impacts,
            "mitigation_needed_count": sum(1 for s in subcategory_impacts if s["requires_mitigation"]),
        }

    # NIST MAP references
    nist_refs = {
        "MAP 3.1": "Document potential benefits and costs including societal risks.",
        "MAP 3.2": "Document potential costs of NOT deploying the AI system.",
        "MAP 3.5": "Assess likelihood and magnitude of each impact; document severity of harms.",
        "MAP 5.1": "Establish impact likelihood and severity on individuals, groups, communities; consider historically underserved populations.",
        "MAP 5.2": "Define practices for post-deployment risk identification.",
    }

    return {
        "system_name": system_name,
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "framework": "NIST AI RMF 1.0 — MAP Function",
        "deployment_scale": deployment_scale,
        "affected_populations": affected_populations or "Not specified",
        "impact_map": impact_map,
        "highest_impact_area": max(impact_map.items(), key=lambda x: x[1]["overall_severity"])[0],
        "total_mitigation_actions_needed": sum(
            c["mitigation_needed_count"] for c in impact_map.values()
        ),
        "nist_map_references": nist_refs,
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


@mcp.tool()
def generate_risk_controls(
    identified_risks: str,
    system_name: str = "AI System",
    risk_tolerance: str = "moderate",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Generate NIST-aligned control recommendations for identified AI risks.

    Given identified risks, produces specific control recommendations
    mapped to NIST AI RMF MANAGE function subcategories with
    implementation priority and effort estimates.

    Args:
        identified_risks: Description of identified AI risks (comma-separated
            or narrative format).
        system_name: Name of the AI system.
        risk_tolerance: Organization's risk tolerance ('low', 'moderate', 'high').
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Prioritized control recommendations with NIST RMF references.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    risk_areas = _identify_risk_areas(identified_risks)

    tolerance_multiplier = {"low": 1.5, "moderate": 1.0, "high": 0.7}.get(risk_tolerance, 1.0)

    # Control catalog mapped to risk areas
    CONTROL_CATALOG = {
        "safety": [
            {
                "control_id": "CTRL-SAF-01",
                "name": "Safety Risk Assessment",
                "description": "Conduct systematic safety risk assessment identifying hazards, exposure scenarios, and potential harms. Document all safety-critical components and failure modes.",
                "implementation": "Engage safety engineers and domain experts. Use FMEA (Failure Mode and Effects Analysis) or HAZOP methodology. Document in safety case format.",
                "nist_ref": "MEASURE 2.6",
                "effort": "high",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-SAF-02",
                "name": "Fail-Safe Mechanisms",
                "description": "Implement fail-safe defaults and graceful degradation. Ensure system fails to a safe state when errors or unexpected conditions occur.",
                "implementation": "Design fallback behaviors, implement circuit breakers, establish minimum viable safe state. Test failure scenarios.",
                "nist_ref": "MANAGE 1.3",
                "effort": "high",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-SAF-03",
                "name": "Human Override Controls",
                "description": "Implement human override capability for all safety-critical AI decisions. Ensure operators can intervene in real-time.",
                "implementation": "Design override interfaces, establish escalation procedures, train operators. Test override under time-critical conditions.",
                "nist_ref": "GOVERN 3.2",
                "effort": "medium",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-SAF-04",
                "name": "Safety Monitoring and Alerting",
                "description": "Deploy continuous monitoring for safety-relevant metrics with automated alerting when thresholds are breached.",
                "implementation": "Define safety KPIs, implement monitoring dashboards, configure alerts, establish on-call procedures.",
                "nist_ref": "MANAGE 4.1",
                "effort": "medium",
                "priority_base": 2,
            },
        ],
        "bias_fairness": [
            {
                "control_id": "CTRL-FAIR-01",
                "name": "Bias Audit Program",
                "description": "Establish regular bias auditing across demographic groups. Test for disparate impact, equal opportunity, and calibration metrics.",
                "implementation": "Select fairness metrics appropriate to context. Test across protected attributes. Document results and remediation steps.",
                "nist_ref": "MEASURE 2.11",
                "effort": "high",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-FAIR-02",
                "name": "Training Data Governance",
                "description": "Implement data governance for training datasets. Assess representation, detect label bias, and document data provenance.",
                "implementation": "Audit dataset demographics, apply sampling corrections, document known limitations. Establish data quality metrics.",
                "nist_ref": "MAP 3.4",
                "effort": "high",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-FAIR-03",
                "name": "Diverse Review Board",
                "description": "Establish diverse review board for AI system design, development, and deployment decisions.",
                "implementation": "Recruit board members from diverse backgrounds. Define review cadence and decision authority. Document review outcomes.",
                "nist_ref": "GOVERN 3.1",
                "effort": "medium",
                "priority_base": 2,
            },
            {
                "control_id": "CTRL-FAIR-04",
                "name": "Appeal and Redress Mechanism",
                "description": "Create mechanism for individuals to contest AI decisions and receive human review.",
                "implementation": "Design appeal interface, define review SLAs, train review staff, track outcomes for systemic issues.",
                "nist_ref": "MANAGE 4.1",
                "effort": "medium",
                "priority_base": 2,
            },
        ],
        "privacy": [
            {
                "control_id": "CTRL-PRIV-01",
                "name": "Privacy Impact Assessment",
                "description": "Conduct privacy impact assessment (PIA) covering data collection, processing, storage, sharing, and deletion.",
                "implementation": "Map data flows, identify privacy risks, assess legal basis, document DPIA findings. Engage Data Protection Officer.",
                "nist_ref": "MEASURE 2.10",
                "effort": "high",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-PRIV-02",
                "name": "Data Minimization",
                "description": "Minimize personal data used in AI training and inference. Apply purpose limitation and storage limitation.",
                "implementation": "Audit data fields, remove unnecessary PII, implement data retention policies, apply anonymization/pseudonymization.",
                "nist_ref": "GOVERN 1.1",
                "effort": "medium",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-PRIV-03",
                "name": "Privacy-Preserving Techniques",
                "description": "Implement privacy-preserving ML techniques such as differential privacy, federated learning, or secure computation.",
                "implementation": "Evaluate applicable techniques for the use case. Implement with privacy budget tracking. Measure utility-privacy tradeoff.",
                "nist_ref": "MEASURE 2.10",
                "effort": "high",
                "priority_base": 2,
            },
            {
                "control_id": "CTRL-PRIV-04",
                "name": "Model Output Privacy Controls",
                "description": "Assess and mitigate re-identification risk from model outputs. Prevent membership inference and model inversion attacks.",
                "implementation": "Test for memorization, apply output perturbation, limit query rates, monitor for extraction attempts.",
                "nist_ref": "MEASURE 2.7",
                "effort": "high",
                "priority_base": 2,
            },
        ],
        "transparency": [
            {
                "control_id": "CTRL-TRANS-01",
                "name": "System Documentation",
                "description": "Create comprehensive documentation of AI system purpose, capabilities, limitations, and intended use context.",
                "implementation": "Use model cards, datasheets for datasets, and system fact sheets. Publish documentation accessible to all stakeholders.",
                "nist_ref": "MEASURE 2.8",
                "effort": "medium",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-TRANS-02",
                "name": "Explainability Framework",
                "description": "Implement explainability methods appropriate to the system's risk level and audience.",
                "implementation": "Select XAI methods (SHAP, LIME, attention visualization, etc.). Validate explanations for faithfulness. User-test explanations.",
                "nist_ref": "MEASURE 2.9",
                "effort": "high",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-TRANS-03",
                "name": "AI System Disclosure",
                "description": "Ensure users and affected individuals are informed when interacting with or subject to AI system decisions.",
                "implementation": "Design clear disclosure UI/UX, provide opt-out where applicable, explain how to access human review.",
                "nist_ref": "GOVERN 1.4",
                "effort": "low",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-TRANS-04",
                "name": "Decision Audit Trail",
                "description": "Maintain auditable logs of AI system decisions with sufficient detail for post-hoc review and investigation.",
                "implementation": "Implement structured logging, define retention periods, ensure tamper-resistance, establish audit procedures.",
                "nist_ref": "MANAGE 4.1",
                "effort": "medium",
                "priority_base": 2,
            },
        ],
        "security": [
            {
                "control_id": "CTRL-SEC-01",
                "name": "Adversarial Robustness Testing",
                "description": "Test AI system against adversarial inputs, prompt injection, and other attack vectors specific to the deployment context.",
                "implementation": "Red-team the system, use adversarial example libraries, test prompt injection defenses. Document findings and mitigations.",
                "nist_ref": "MEASURE 2.7",
                "effort": "high",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-SEC-02",
                "name": "Supply Chain Security",
                "description": "Assess and secure AI supply chain including pre-trained models, libraries, training data, and third-party APIs.",
                "implementation": "Audit dependencies, verify model provenance, scan for vulnerabilities, establish approved model registry.",
                "nist_ref": "GOVERN 6.1",
                "effort": "high",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-SEC-03",
                "name": "Incident Detection and Response",
                "description": "Implement AI-specific incident detection and response capabilities.",
                "implementation": "Define AI incident taxonomy, deploy anomaly detection on model inputs/outputs, establish response playbooks.",
                "nist_ref": "MANAGE 2.3",
                "effort": "medium",
                "priority_base": 2,
            },
        ],
        "autonomy": [
            {
                "control_id": "CTRL-AUT-01",
                "name": "Human Oversight Framework",
                "description": "Establish appropriate human oversight level based on system autonomy and risk level.",
                "implementation": "Define human-in-the-loop, on-the-loop, or over-the-loop model. Document oversight procedures and escalation paths.",
                "nist_ref": "MAP 2.2",
                "effort": "medium",
                "priority_base": 1,
            },
            {
                "control_id": "CTRL-AUT-02",
                "name": "Operational Boundaries",
                "description": "Define and enforce operational design domain — conditions under which the system is validated to operate safely.",
                "implementation": "Specify input ranges, operating conditions, and acceptable performance bounds. Implement runtime boundary checks.",
                "nist_ref": "MAP 1.4",
                "effort": "medium",
                "priority_base": 1,
            },
        ],
        "environmental": [
            {
                "control_id": "CTRL-ENV-01",
                "name": "Environmental Impact Assessment",
                "description": "Measure and document energy consumption, carbon footprint, and resource usage of AI system training and deployment.",
                "implementation": "Track compute hours, estimate carbon emissions, explore efficient architectures, document in sustainability report.",
                "nist_ref": "MEASURE 2.12",
                "effort": "medium",
                "priority_base": 2,
            },
        ],
        "societal": [
            {
                "control_id": "CTRL-SOC-01",
                "name": "Societal Impact Assessment",
                "description": "Assess broad societal impacts including effects on democratic processes, social cohesion, and information integrity.",
                "implementation": "Engage civil society stakeholders, conduct scenario analysis, document potential systemic effects and mitigations.",
                "nist_ref": "MAP 5.1",
                "effort": "high",
                "priority_base": 1,
            },
        ],
    }

    controls = []
    for area, score in risk_areas.items():
        if score > 0 and area in CONTROL_CATALOG:
            for control in CONTROL_CATALOG[area]:
                adjusted_priority = max(1, round(control["priority_base"] / tolerance_multiplier))
                controls.append({
                    **control,
                    "risk_area": area,
                    "risk_score": score,
                    "adjusted_priority": adjusted_priority,
                    "priority_label": "critical" if adjusted_priority <= 1 else "high" if adjusted_priority <= 2 else "standard",
                })

    # Sort by priority then risk score
    controls.sort(key=lambda x: (x["adjusted_priority"], -x["risk_score"]))

    return {
        "system_name": system_name,
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "framework": "NIST AI RMF 1.0 — MANAGE Function Controls",
        "risk_tolerance": risk_tolerance,
        "identified_risk_areas": {
            area: {"score": score, "level": _determine_risk_level(score)}
            for area, score in risk_areas.items()
            if score > 0
        },
        "controls": controls,
        "total_controls": len(controls),
        "critical_controls": sum(1 for c in controls if c["priority_label"] == "critical"),
        "high_controls": sum(1 for c in controls if c["priority_label"] == "high"),
        "implementation_order": [c["control_id"] for c in controls[:10]],
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


@mcp.tool()
def crosswalk_to_eu_ai_act(
    nist_functions: str = "all",
    focus_area: str = "",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Map NIST AI RMF functions and subcategories to EU AI Act articles.

    This is the killer feature -- regulation-to-regulation mapping that
    shows exactly where NIST RMF requirements align with EU AI Act
    obligations. Essential for organizations complying with both frameworks.

    Args:
        nist_functions: Comma-separated NIST functions to crosswalk
            ('GOVERN', 'MAP', 'MEASURE', 'MANAGE', or 'all').
        focus_area: Optional focus area to filter mappings (e.g., 'transparency',
            'safety', 'data governance', 'human oversight').
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Detailed crosswalk mapping between NIST AI RMF and EU AI Act
        with alignment strength ratings and rationale.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    # Filter by requested functions
    if nist_functions.lower() == "all":
        requested_funcs = ["GOVERN", "MAP", "MEASURE", "MANAGE"]
    else:
        requested_funcs = [f.strip().upper() for f in nist_functions.split(",")]

    crosswalk_results = {}
    for nist_subcat, mapping in NIST_TO_EU_CROSSWALK.items():
        func_name = nist_subcat.split()[0]
        if func_name not in requested_funcs:
            continue

        # If focus_area specified, filter by relevance
        if focus_area:
            focus_lower = focus_area.lower()
            rationale_lower = mapping["mapping_rationale"].lower()
            if focus_lower not in rationale_lower and focus_lower not in nist_subcat.lower():
                continue

        # Look up the subcategory description from the main knowledge base
        subcat_desc = ""
        for func_key, func_data in NIST_RMF_FUNCTIONS.items():
            for subcat_key, subcat_data in func_data["subcategories"].items():
                for detail_key, detail_desc in subcat_data["subcats"].items():
                    if detail_key == nist_subcat:
                        subcat_desc = detail_desc
                        break

        crosswalk_results[nist_subcat] = {
            "nist_description": subcat_desc or f"NIST AI RMF subcategory {nist_subcat}",
            "eu_ai_act_articles": mapping["eu_articles"],
            "mapping_rationale": mapping["mapping_rationale"],
            "alignment_strength": mapping["alignment_strength"],
        }

    # Summary statistics
    alignment_counts = {"strong": 0, "moderate": 0, "weak": 0}
    all_eu_articles = set()
    for result in crosswalk_results.values():
        alignment_counts[result["alignment_strength"]] = alignment_counts.get(result["alignment_strength"], 0) + 1
        all_eu_articles.update(result["eu_ai_act_articles"])

    return {
        "crosswalk_title": "NIST AI RMF 1.0 to EU AI Act (Regulation 2024/1689) Crosswalk",
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "requested_functions": requested_funcs,
        "focus_area": focus_area or "all areas",
        "total_mappings": len(crosswalk_results),
        "alignment_summary": alignment_counts,
        "eu_articles_covered": sorted(all_eu_articles),
        "crosswalk": crosswalk_results,
        "methodology": (
            "Mappings are based on semantic analysis of NIST AI RMF 1.0 (AI 100-1) "
            "subcategory requirements against EU AI Act (Regulation 2024/1689) article "
            "obligations. Alignment strength reflects the degree of direct correspondence "
            "between requirements. 'Strong' indicates near-direct mapping; 'moderate' "
            "indicates partial overlap or indirect coverage."
        ),
        "disclaimer": (
            "This crosswalk is for informational purposes. Compliance with one framework "
            "does not automatically ensure compliance with the other. Organizations should "
            "conduct independent legal analysis for each jurisdiction."
        ),
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


@mcp.tool()
def create_risk_report(
    system_description: str,
    system_name: str = "AI System",
    organization: str = "",
    include_crosswalk: bool = True,
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Generate a complete NIST AI RMF compliance report in markdown.

    Produces a comprehensive report covering risk profile, impact mapping,
    trustworthy AI characteristics, control recommendations, and optional
    EU AI Act crosswalk. Suitable for executive review and regulatory filing.

    Args:
        system_description: Detailed description of the AI system.
        system_name: Name of the AI system.
        organization: Organization name for the report header.
        include_crosswalk: Whether to include EU AI Act crosswalk section.
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Complete markdown-formatted compliance report.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    risk_areas = _identify_risk_areas(system_description)
    overall_risk = round(sum(risk_areas.values()) / max(len(risk_areas), 1), 3)
    risk_level = _determine_risk_level(overall_risk)
    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Build markdown report
    report = f"""# NIST AI Risk Management Framework - Compliance Report

## System: {system_name}
**Organization:** {organization or 'Not specified'}
**Report Date:** {report_date}
**Framework:** NIST AI RMF 1.0 (AI 100-1, January 2023)
**Generated by:** MEOK AI Labs NIST RMF MCP Server

---

## 1. Executive Summary

This report assesses **{system_name}** against the NIST AI Risk Management Framework (AI RMF 1.0).
The overall risk level is **{risk_level.upper()}** (score: {overall_risk}).

### Risk Area Summary

| Risk Area | Score | Level |
|-----------|-------|-------|
"""
    for area, score in sorted(risk_areas.items(), key=lambda x: -x[1]):
        level = _determine_risk_level(score)
        report += f"| {area.replace('_', ' ').title()} | {score} | {level.upper()} |\n"

    report += f"""
---

## 2. System Description

{system_description}

---

## 3. NIST AI RMF Function Assessment

### 3.1 GOVERN - Risk Management Culture
"""
    for subcat_id, subcat_data in NIST_RMF_FUNCTIONS["GOVERN"]["subcategories"].items():
        report += f"\n**{subcat_id}: {subcat_data['title']}**\n"
        report += f"_{subcat_data['description']}_\n\n"
        for detail_id, detail_desc in list(subcat_data["subcats"].items())[:3]:
            report += f"- [ ] {detail_id}: {detail_desc}\n"
        if len(subcat_data["subcats"]) > 3:
            report += f"- _... and {len(subcat_data['subcats']) - 3} more subcategories_\n"

    report += "\n### 3.2 MAP - Risk Contextualization\n"
    for subcat_id, subcat_data in NIST_RMF_FUNCTIONS["MAP"]["subcategories"].items():
        report += f"\n**{subcat_id}: {subcat_data['title']}**\n"
        report += f"_{subcat_data['description']}_\n\n"
        for detail_id, detail_desc in list(subcat_data["subcats"].items())[:3]:
            report += f"- [ ] {detail_id}: {detail_desc}\n"
        if len(subcat_data["subcats"]) > 3:
            report += f"- _... and {len(subcat_data['subcats']) - 3} more subcategories_\n"

    report += "\n### 3.3 MEASURE - Risk Analysis\n"
    for subcat_id, subcat_data in NIST_RMF_FUNCTIONS["MEASURE"]["subcategories"].items():
        report += f"\n**{subcat_id}: {subcat_data['title']}**\n"
        report += f"_{subcat_data['description']}_\n\n"
        for detail_id, detail_desc in list(subcat_data["subcats"].items())[:3]:
            report += f"- [ ] {detail_id}: {detail_desc}\n"
        if len(subcat_data["subcats"]) > 3:
            report += f"- _... and {len(subcat_data['subcats']) - 3} more subcategories_\n"

    report += "\n### 3.4 MANAGE - Risk Response\n"
    for subcat_id, subcat_data in NIST_RMF_FUNCTIONS["MANAGE"]["subcategories"].items():
        report += f"\n**{subcat_id}: {subcat_data['title']}**\n"
        report += f"_{subcat_data['description']}_\n\n"
        for detail_id, detail_desc in list(subcat_data["subcats"].items())[:3]:
            report += f"- [ ] {detail_id}: {detail_desc}\n"
        if len(subcat_data["subcats"]) > 3:
            report += f"- _... and {len(subcat_data['subcats']) - 3} more subcategories_\n"

    report += """
---

## 4. Trustworthy AI Characteristics Assessment

"""
    for char_id, char_data in TRUSTWORTHY_CHARACTERISTICS.items():
        report += f"### {char_data['name']}\n"
        report += f"_{char_data['description']}_\n\n"
        report += "**Key Assessment Questions:**\n"
        for q in char_data["key_questions"]:
            report += f"- [ ] {q}\n"
        report += f"\n**NIST References:** {', '.join(char_data['nist_refs'])}\n\n"

    if include_crosswalk:
        report += """---

## 5. EU AI Act Crosswalk

The following maps key NIST AI RMF subcategories to corresponding EU AI Act articles.

| NIST RMF | EU AI Act Articles | Alignment |
|----------|-------------------|-----------|
"""
        for nist_subcat, mapping in sorted(NIST_TO_EU_CROSSWALK.items()):
            articles = ", ".join(mapping["eu_articles"])
            report += f"| {nist_subcat} | {articles} | {mapping['alignment_strength']} |\n"

    report += f"""
---

## 6. Recommendations

Based on the risk profile analysis, the following actions are recommended:

1. **Immediate (0-30 days):** Address any critical risk areas identified above. Establish GOVERN function baseline.
2. **Short-term (30-90 days):** Complete MAP function assessment. Begin MEASURE activities for high-risk areas.
3. **Medium-term (90-180 days):** Implement MANAGE controls. Establish ongoing monitoring.
4. **Ongoing:** Regular re-assessment, stakeholder engagement, and continuous improvement per MANAGE 4.2.

---

## 7. Report Metadata

- **Framework Version:** NIST AI RMF 1.0 (AI 100-1)
- **Supplementary:** NIST AI 600-1 (Generative AI Profile)
- **Assessment Tool:** MEOK AI Labs NIST RMF MCP Server
- **Report Generated:** {report_date}
- **Organization:** {organization or 'Not specified'}

---

*This report was generated by the NIST AI RMF MCP Server by MEOK AI Labs.
It is intended as a compliance aid and does not constitute legal advice.
Organizations should engage qualified professionals for binding compliance assessments.*

**MEOK AI Labs** | [meok.ai](https://meok.ai) | nicholas@meok.ai
"""

    return {
        "system_name": system_name,
        "report_format": "markdown",
        "report": report,
        "word_count": len(report.split()),
        "sections": 7,
        "includes_crosswalk": include_crosswalk,
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


@mcp.tool()
def check_trustworthy_characteristics(
    system_description: str,
    system_name: str = "AI System",
    responses: Optional[str] = None,
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Evaluate AI system against NIST's 7 trustworthy AI characteristics.

    Assesses the system against: Valid & Reliable, Safe, Secure & Resilient,
    Accountable & Transparent, Explainable & Interpretable, Privacy-Enhanced,
    and Fair with Harmful Bias Managed. Returns per-characteristic scores,
    gaps, and improvement recommendations.

    Args:
        system_description: Description of the AI system and its properties.
        system_name: Name of the AI system.
        responses: Optional JSON string with self-assessment responses keyed by
            characteristic ID (e.g., '{"valid_and_reliable": "We have..."}'.
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Per-characteristic assessment with scores, gaps, and recommendations.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    # Parse optional self-assessment responses
    self_responses = {}
    if responses:
        try:
            self_responses = json.loads(responses)
        except json.JSONDecodeError:
            self_responses = {}

    risk_areas = _identify_risk_areas(system_description)

    characteristic_results = {}
    for char_id, char_data in TRUSTWORTHY_CHARACTERISTICS.items():
        # Score based on keyword matching against description
        char_keywords = char_data["description"].lower().split()[:15]
        base_score = _score_text_against_keywords(system_description, char_keywords)

        # Boost score if self-assessment provided for this characteristic
        if char_id in self_responses:
            response_text = self_responses[char_id]
            response_keywords = ["implemented", "established", "documented", "tested", "monitored", "audited", "reviewed", "validated"]
            response_score = _score_text_against_keywords(response_text, response_keywords)
            base_score = min(round((base_score + response_score) / 2 + 0.1, 2), 1.0)

        # Determine risk-adjusted score
        related_risk_areas = {
            "valid_and_reliable": "safety",
            "safe": "safety",
            "secure_and_resilient": "security",
            "accountable_and_transparent": "transparency",
            "explainable_and_interpretable": "transparency",
            "privacy_enhanced": "privacy",
            "fair_with_harmful_bias_managed": "bias_fairness",
        }
        related_risk = risk_areas.get(related_risk_areas.get(char_id, ""), 0)

        # Higher risk means more scrutiny needed (lower score unless mitigations documented)
        adjusted_score = max(0, round(base_score - (related_risk * 0.3), 2))

        if adjusted_score >= 0.7:
            status = "strong"
        elif adjusted_score >= 0.4:
            status = "adequate"
        elif adjusted_score >= 0.2:
            status = "needs_improvement"
        else:
            status = "insufficient"

        # Identify gaps (questions not addressed)
        gaps = []
        for question in char_data["key_questions"]:
            q_keywords = question.lower().split()[:5]
            if _score_text_against_keywords(system_description + " " + self_responses.get(char_id, ""), q_keywords) < 0.3:
                gaps.append(question)

        characteristic_results[char_id] = {
            "name": char_data["name"],
            "score": adjusted_score,
            "status": status,
            "description": char_data["description"],
            "gaps_identified": gaps[:5],
            "gaps_count": len(gaps),
            "nist_references": char_data["nist_refs"],
            "recommendation": _get_characteristic_recommendation(char_id, status),
        }

    # Overall trustworthiness score
    scores = [r["score"] for r in characteristic_results.values()]
    overall_score = round(sum(scores) / len(scores), 3)

    return {
        "system_name": system_name,
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "framework": "NIST AI RMF 1.0 — Trustworthy AI Characteristics (Section 3)",
        "overall_trustworthiness_score": overall_score,
        "overall_status": "strong" if overall_score >= 0.7 else "adequate" if overall_score >= 0.4 else "needs_improvement" if overall_score >= 0.2 else "insufficient",
        "characteristics": characteristic_results,
        "strongest_characteristic": max(characteristic_results.items(), key=lambda x: x[1]["score"])[1]["name"],
        "weakest_characteristic": min(characteristic_results.items(), key=lambda x: x[1]["score"])[1]["name"],
        "total_gaps_identified": sum(r["gaps_count"] for r in characteristic_results.values()),
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


def _get_characteristic_recommendation(char_id: str, status: str) -> str:
    """Get targeted recommendation based on characteristic and status."""
    recommendations = {
        "valid_and_reliable": {
            "insufficient": "Urgently establish validation and testing protocols. Define accuracy metrics and conduct benchmark testing under deployment conditions.",
            "needs_improvement": "Expand testing coverage to include edge cases and stress conditions. Implement continuous performance monitoring.",
            "adequate": "Enhance monitoring for performance degradation. Document limitations more thoroughly.",
            "strong": "Maintain current practices. Consider expanding to additional deployment scenarios.",
        },
        "safe": {
            "insufficient": "Critical: Conduct immediate safety risk assessment. Implement fail-safe mechanisms and human override capabilities.",
            "needs_improvement": "Expand safety testing to cover more failure scenarios. Establish safety monitoring and incident response.",
            "adequate": "Refine safety boundaries and test edge cases. Improve incident response procedures.",
            "strong": "Maintain safety vigilance. Regular reviews of safety case and emerging risks.",
        },
        "secure_and_resilient": {
            "insufficient": "Critical: Conduct adversarial robustness testing. Implement basic cybersecurity controls. Assess supply chain risks.",
            "needs_improvement": "Expand security testing to include model-specific attacks. Implement incident detection.",
            "adequate": "Enhance adversarial testing. Implement supply chain security monitoring.",
            "strong": "Maintain security posture. Stay current with emerging AI-specific threat landscape.",
        },
        "accountable_and_transparent": {
            "insufficient": "Establish system documentation (model cards, data sheets). Define clear roles and accountability structures.",
            "needs_improvement": "Improve documentation of decision processes. Implement audit trails.",
            "adequate": "Enhance external transparency. Consider third-party audits.",
            "strong": "Maintain documentation currency. Expand stakeholder transparency initiatives.",
        },
        "explainable_and_interpretable": {
            "insufficient": "Implement basic explainability methods. Document model behavior and known limitations.",
            "needs_improvement": "Validate explanation fidelity. User-test explanations with relevant stakeholders.",
            "adequate": "Expand explanation coverage. Implement context-specific interpretation guides.",
            "strong": "Maintain explanation quality. Research emerging XAI methods for improvement.",
        },
        "privacy_enhanced": {
            "insufficient": "Urgent: Conduct privacy impact assessment. Implement data minimization. Review regulatory compliance.",
            "needs_improvement": "Explore privacy-preserving techniques. Strengthen consent mechanisms and data subject rights.",
            "adequate": "Assess re-identification risks from model outputs. Enhance privacy budget tracking.",
            "strong": "Maintain privacy controls. Monitor for emerging privacy risks from model updates.",
        },
        "fair_with_harmful_bias_managed": {
            "insufficient": "Critical: Conduct bias audit across demographic groups. Assess training data for representation gaps.",
            "needs_improvement": "Expand bias testing coverage. Implement ongoing bias monitoring post-deployment.",
            "adequate": "Enhance community engagement. Implement appeal mechanisms for affected individuals.",
            "strong": "Maintain bias monitoring. Continue diverse stakeholder engagement.",
        },
    }
    return recommendations.get(char_id, {}).get(status, "Conduct detailed assessment for this characteristic.")


# ===========================================================================
# Neural risk prediction
# ===========================================================================

@mcp.tool()
def predict_risk_neural(
    system_name: str,
    uses_biometric: bool = False,
    uses_health_data: bool = False,
    has_human_oversight: bool = True,
    affected_users: int = 0,
    sector: str = "",
    has_documentation: bool = False,
    prior_incidents: int = 0,
    api_key: str = "") -> dict:
    """Neural network-based risk prediction that improves from every compliance check."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg}
    features = _neural_net.extract_features_from_system(
        system_name=system_name, uses_biometric=uses_biometric,
        uses_health_data=uses_health_data, has_human_oversight=has_human_oversight,
        affected_users=affected_users, sector=sector, has_documentation=has_documentation,
        prior_incidents=prior_incidents,
    )
    prediction = _neural_net.predict_risk(features)
    prediction["system_name"] = system_name
    return prediction


@mcp.tool()
def neural_insights(api_key: str = "") -> dict:
    """Get aggregate learning insights from the neural compliance model."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg}
    return _neural_net.get_insights()


# ===========================================================================
# Entry point
# ===========================================================================

@mcp.tool()
def quick_scan(description: str) -> dict:
    """One-line system description to instant NIST AI RMF risk profile. No API key needed.

    Args:
        description: Brief description of your AI system (e.g. 'facial recognition for building access')

    Returns:
        Instant NIST AI RMF risk profile with identified risk areas and priority functions.
    """
    risk_areas = _identify_risk_areas(description)
    overall = round(sum(risk_areas.values()) / max(len(risk_areas), 1), 3)
    level = _determine_risk_level(overall)

    # Determine priority NIST functions
    priority_functions = []
    if risk_areas.get("safety", 0) > 0.1 or risk_areas.get("autonomy", 0) > 0.1:
        priority_functions.append("MEASURE 2.6 (Safety evaluation)")
    if risk_areas.get("bias_fairness", 0) > 0.1:
        priority_functions.append("MEASURE 2.11 (Fairness and bias)")
    if risk_areas.get("privacy", 0) > 0.1:
        priority_functions.append("MEASURE 2.10 (Privacy risk)")
    if risk_areas.get("security", 0) > 0.1:
        priority_functions.append("MEASURE 2.7 (Security and resilience)")
    if risk_areas.get("transparency", 0) > 0.1:
        priority_functions.append("MEASURE 2.8/2.9 (Transparency and explainability)")
    if not priority_functions:
        priority_functions.append("GOVERN 1 (Establish risk management policies)")

    return {
        "system": description[:120],
        "overall_risk_level": level,
        "overall_risk_score": overall,
        "risk_areas": {k: {"score": v, "level": _determine_risk_level(v)} for k, v in risk_areas.items() if v > 0},
        "priority_nist_functions": priority_functions,
        "core_functions": ["GOVERN", "MAP", "MEASURE", "MANAGE"],
        "next_step": "Use assess_risk_profile() for full NIST AI RMF assessment",
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


@mcp.tool()
def framework_overview() -> dict:
    """Returns the NIST AI RMF GOVERN/MAP/MEASURE/MANAGE structure. No parameters needed."""
    overview = {}
    for func_name, func_data in NIST_RMF_FUNCTIONS.items():
        subcats = {}
        for subcat_id, subcat_data in func_data["subcategories"].items():
            subcats[subcat_id] = {
                "title": subcat_data["title"],
                "description": subcat_data["description"],
                "detailed_count": len(subcat_data["subcats"]),
            }
        overview[func_name] = {
            "description": func_data["description"],
            "subcategory_count": len(func_data["subcategories"]),
            "subcategories": subcats,
        }

    return {
        "framework": "NIST AI Risk Management Framework 1.0 (AI 100-1)",
        "published": "January 2023",
        "publisher": "National Institute of Standards and Technology (NIST)",
        "supplementary": "NIST AI 600-1 — Generative AI Profile (July 2024)",
        "core_functions": overview,
        "trustworthy_characteristics": [
            "Valid and Reliable",
            "Safe",
            "Secure and Resilient",
            "Accountable and Transparent",
            "Explainable and Interpretable",
            "Privacy-Enhanced",
            "Fair with Harmful Bias Managed",
        ],
        "tools_available": [
            "quick_scan(description) — instant risk profile",
            "assess_risk_profile(...) — full NIST AI RMF assessment",
            "map_ai_impact(...) — impact mapping across people/orgs/ecosystems",
            "generate_risk_controls(...) — NIST-aligned control recommendations",
            "crosswalk_to_eu_ai_act(...) — NIST to EU AI Act mapping",
            "check_trustworthy_characteristics(...) — 7 trustworthy AI characteristics",
            "create_risk_report(...) — comprehensive markdown report",
        ],
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


def main():
    mcp.run()


if __name__ == "__main__":
    mcp.run()
