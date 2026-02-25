from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Literal

from pydantic import BaseModel, Field, ConfigDict


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------- Core enums ----------

class ArtifactType(str, Enum):
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    FILE_SNAPSHOT = "file_snapshot"
    RUN_MANIFEST = "run_manifest"
    FINAL_OUTPUT = "final_output"


class Verdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


# ---------- Cryptographic envelope ----------

class Signature(BaseModel):
    """
    Detached signature over canonical bytes of a payload.
    You can start with Ed25519 (recommended) and keep this stable.
    """
    model_config = ConfigDict(extra="forbid")

    alg: Literal["ed25519"] = "ed25519"
    key_id: str = Field(..., description="Identifier for the signing public key (e.g., sha256(pubkey))")
    sig_b64: str = Field(..., description="Base64 signature bytes")


class HashRef(BaseModel):
    """
    Content-addressed reference to a blob (e.g., tool result stdout, trace, file snapshot).
    """
    model_config = ConfigDict(extra="forbid")

    alg: Literal["sha256"] = "sha256"
    hex: str = Field(..., description="Hex digest of content")
    size_bytes: int = Field(..., ge=0)


# ---------- Tool execution records ----------

class ToolCall(BaseModel):
    """
    What the agent *requested*.
    """
    model_config = ConfigDict(extra="forbid")

    tool_name: str
    args: Dict[str, Any] = Field(default_factory=dict)

    # Optional: agent identity / span correlation
    agent_id: Optional[str] = None
    step_id: Optional[str] = None

    requested_at: datetime = Field(default_factory=utc_now)


class ToolResult(BaseModel):
    """
    What actually happened.
    """
    model_config = ConfigDict(extra="forbid")

    tool_name: str
    ok: bool
    exit_code: Optional[int] = None

    stdout_ref: Optional[HashRef] = None
    stderr_ref: Optional[HashRef] = None
    result_ref: Optional[HashRef] = None  # for structured JSON outputs

    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime = Field(default_factory=utc_now)

    # Correlation
    agent_id: Optional[str] = None
    step_id: Optional[str] = None
    call_id: Optional[str] = None  # stable ID produced by gateway/runner


class Receipt(BaseModel):
    """
    Verifiable 'tool execution happened' receipt.
    This is the core primitive we will use to prevent "fake tool outputs".
    """
    model_config = ConfigDict(extra="forbid")

    version: Literal["v1"] = "v1"

    receipt_id: str = Field(..., description="Unique receipt ID (uuid or hash-based)")
    artifact_type: ArtifactType = ArtifactType.TOOL_RESULT

    # Binds the receipt to a specific call + result
    tool_call: ToolCall
    tool_result: ToolResult

    # Hash of the canonical payload (we’ll define canonicalization in the signer module)
    payload_hash: HashRef

    issued_at: datetime = Field(default_factory=utc_now)
    signature: Signature


# ---------- Run-level structures ----------

class Checkpoint(BaseModel):
    """
    Optional: use this later to support 'replay' and diff-friendly CI.
    """
    model_config = ConfigDict(extra="forbid")

    name: str
    created_at: datetime = Field(default_factory=utc_now)
    workspace_ref: Optional[HashRef] = None  # tarball hash etc.
    notes: Optional[str] = None


class RunManifest(BaseModel):
    """
    The single document you can store in CI artifacts.
    It references everything else by hash, and can be signed too.
    """
    model_config = ConfigDict(extra="forbid")

    version: Literal["v1"] = "v1"
    run_id: str = Field(..., description="Unique run ID, e.g., timestamp+random")
    created_at: datetime = Field(default_factory=utc_now)

    # Inputs
    repo: Optional[str] = None
    git_sha: Optional[str] = None
    policy_id: Optional[str] = None

    # Outputs
    receipts: List[Receipt] = Field(default_factory=list)
    checkpoints: List[Checkpoint] = Field(default_factory=list)

    # Optional final model output record (hash-ref)
    final_output_ref: Optional[HashRef] = None

    # Overall assessment
    verdict: Verdict = Verdict.PASS
    notes: Optional[str] = None
