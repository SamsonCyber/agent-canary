"""Core data models for Agent Canary."""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .forensic.chain import ChainSeal


class Vector(str, Enum):
    FILE = "file"
    MCP_TOOL = "mcp_tool"
    API_ENDPOINT = "api_endpoint"
    ENV_VAR = "env_var"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TriggerCause(str, Enum):
    SCOPE_CREEP = "scope_creep"
    PROMPT_INJECTION = "prompt_injection"
    EMERGENT_BEHAVIOR = "emergent_behavior"
    LEGITIMATE_MISCONFIG = "legitimate_misconfig"
    UNKNOWN = "unknown"


@dataclass
class ScopeRule:
    """Defines who should and shouldn't trigger this canary."""
    deny_agents: list[str] = field(default_factory=list)
    allow_agents: list[str] = field(default_factory=list)
    deny_tasks: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def should_trigger(self, agent_id: str | None = None) -> bool:
        """Return True if this access should be considered a trigger.

        Logic:
        - If allow_agents is set: only agents NOT in the list trigger.
        - If deny_agents is set: only agents IN the list trigger.
        - If both are set: allow takes precedence (allowlisted agents never trigger).
        - If neither is set: everything triggers (universal canary).
        - If agent_id is None: triggers unless allow_agents is empty (can't match).
        """
        # Allowlisted agents are always safe
        if self.allow_agents and agent_id and agent_id in self.allow_agents:
            return False
        # If there's an allow list, anyone not on it triggers
        if self.allow_agents:
            return True
        # Deny list: only listed agents trigger
        if self.deny_agents:
            if agent_id and agent_id in self.deny_agents:
                return True
            return False
        # No lists configured: universal canary, everything triggers
        return True


@dataclass
class Canary:
    """A single canary token."""
    id: str
    vector: Vector
    name: str
    path_or_url: str
    scope: ScopeRule = field(default_factory=ScopeRule)
    template: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    active: bool = True
    # Soft boundary speech for agents (measurement / forensics). Default off.
    notice_mode: str = "off"  # off | static | stochastic
    access_count: int = 0  # successful trigger deliveries (1-based after first)

    @staticmethod
    def generate_id(vector: Vector, name: str) -> str:
        raw = f"{vector.value}:{name}:{secrets.token_hex(4)}"
        return f"{vector.value}:{hashlib.sha256(raw.encode()).hexdigest()[:8]}"


@dataclass
class ToolCall:
    """A tool call in the forensic chain."""
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    relative_time: str = ""


@dataclass
class AgentFingerprint:
    """Identity fingerprint of the triggering agent."""
    model: str | None = None
    model_confidence: float = 0.0
    framework: str | None = None
    framework_confidence: float = 0.0
    session_id: str | None = None
    system_prompt_hash: str | None = None


@dataclass
class ForensicChain:
    """Full forensic context captured at trigger time."""
    trigger_prompt: str | None = None
    reasoning_trace: str | None = None
    preceding_tool_calls: list[ToolCall] = field(default_factory=list)
    context_summary: str | None = None
    raw_args: dict[str, Any] = field(default_factory=dict)


@dataclass
class Classification:
    """Classification of the trigger event."""
    cause: TriggerCause = TriggerCause.UNKNOWN
    severity: Severity = Severity.MEDIUM
    injected_content: bool = False
    recommendations: list[str] = field(default_factory=list)


@dataclass
class TriggerEvent:
    """A complete trigger event with forensic data."""
    id: str = field(default_factory=lambda: secrets.token_hex(8))
    canary_id: str = ""
    triggered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    vector: Vector = Vector.FILE
    agent_fingerprint: AgentFingerprint = field(default_factory=AgentFingerprint)
    forensic_chain: ForensicChain = field(default_factory=ForensicChain)
    classification: Classification = field(default_factory=Classification)
    raw_request: dict[str, Any] = field(default_factory=dict)
    # Soft scope notice delivered with this trigger (None if mode off).
    scope_notice: dict[str, Any] | None = None
    # Crypto seal: hash chain + optional BIP-340 / Nostr binding.
    chain_seal: ChainSeal | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dict for JSON/logging."""
        from dataclasses import asdict

        return asdict(self)
