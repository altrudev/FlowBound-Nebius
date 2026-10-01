from __future__ import annotations

from enum import Enum
from fnmatch import fnmatch
from pathlib import PurePosixPath

from pydantic import BaseModel, Field, field_validator


class OperationKind(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    DEPENDENCY = "dependency"
    GIT_PUSH = "git_push"


class Operation(BaseModel):
    kind: OperationKind
    target: str
    args: tuple[str, ...] = ()


class AuthorityDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class DecisionRecord(BaseModel):
    decision: AuthorityDecision
    reason: str
    matched_rule: str | None = None


class AuthorityEnvelope(BaseModel):
    repository: str
    branch: str
    predecessor_revision: str
    read_paths: tuple[str, ...] = ()
    write_paths: tuple[str, ...] = ()
    allowed_argv_prefixes: tuple[tuple[str, ...], ...] = ()
    network_hosts: tuple[str, ...] = ()
    allow_dependency_changes: bool = False
    allow_git_push: bool = False
    denied_paths: tuple[str, ...] = (
        ".env",
        ".env.*",
        "**/.env",
        "**/.env.*",
        ".ssh/**",
        "**/.ssh/**",
    )
    claim_ceiling: str = Field(
        default="verified repository transition",
        description="Strongest claim the execution receipt may make.",
    )

    @field_validator("read_paths", "write_paths", "denied_paths", "network_hosts")
    @classmethod
    def no_blank_rules(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() for value in values):
            raise ValueError("authority rules may not be blank")
        return values

    @field_validator("allowed_argv_prefixes")
    @classmethod
    def valid_argv_prefixes(
        cls, values: tuple[tuple[str, ...], ...]
    ) -> tuple[tuple[str, ...], ...]:
        for prefix in values:
            if not prefix or any(not token.strip() for token in prefix):
                raise ValueError("argv prefixes must contain non-empty tokens")
        return values

    @staticmethod
    def _normalize_path(path: str) -> str:
        raw = path.strip().replace("\\", "/")
        if not raw:
            raise ValueError("empty paths are outside repository authority")
        if raw.startswith("/") or raw.startswith("~"):
            raise ValueError("absolute or home-relative paths are outside repository authority")
        parts = PurePosixPath(raw).parts
        if ".." in parts:
            raise ValueError("path traversal is outside repository authority")
        normalized = str(PurePosixPath(raw))
        if normalized in {".", ""}:
            raise ValueError("repository root access must be expressed by scoped rules")
        return normalized

    @staticmethod
    def _matches(path: str, patterns: tuple[str, ...]) -> str | None:
        for pattern in patterns:
            if fnmatch(path, pattern):
                return pattern
            if pattern.endswith("/**") and (
                path == pattern[:-3] or path.startswith(pattern[:-2])
            ):
                return pattern
        return None

    def decide(self, operation: Operation) -> DecisionRecord:
        if operation.kind in {OperationKind.READ, OperationKind.WRITE}:
            try:
                target = self._normalize_path(operation.target)
            except ValueError as exc:
                return DecisionRecord(
                    decision=AuthorityDecision.DENY,
                    reason=str(exc),
                )

            denied = self._matches(target, self.denied_paths)
            if denied is not None:
                return DecisionRecord(
                    decision=AuthorityDecision.DENY,
                    reason="target matches an explicit denied path",
                    matched_rule=denied,
                )

            allowed = (
                self.read_paths
                if operation.kind is OperationKind.READ
                else self.write_paths
            )
            matched = self._matches(target, allowed)
            if matched is None:
                return DecisionRecord(
                    decision=AuthorityDecision.DENY,
                    reason=f"{operation.kind.value} target is outside the authority envelope",
                )
            return DecisionRecord(
                decision=AuthorityDecision.ALLOW,
                reason="target is inside the authority envelope",
                matched_rule=matched,
            )

        if operation.kind is OperationKind.EXECUTE:
            argv = (operation.target, *operation.args)
            if any(not token.strip() for token in argv):
                return DecisionRecord(
                    decision=AuthorityDecision.DENY,
                    reason="argv tokens must be non-empty",
                )
            for prefix in self.allowed_argv_prefixes:
                if argv[: len(prefix)] == prefix:
                    return DecisionRecord(
                        decision=AuthorityDecision.ALLOW,
                        reason="argv is inside an explicitly allowed prefix; executor must use shell=False",
                        matched_rule=" ".join(prefix),
                    )
            return DecisionRecord(
                decision=AuthorityDecision.DENY,
                reason="argv is not inside an explicitly allowed command prefix",
            )

        if operation.kind is OperationKind.NETWORK:
            host = operation.target.strip().lower()
            if host in {allowed.lower() for allowed in self.network_hosts}:
                return DecisionRecord(
                    decision=AuthorityDecision.ALLOW,
                    reason="network destination is explicitly allowed",
                    matched_rule=host,
                )
            return DecisionRecord(
                decision=AuthorityDecision.DENY,
                reason="network destination is outside the authority envelope",
            )

        if operation.kind is OperationKind.DEPENDENCY:
            if self.allow_dependency_changes:
                return DecisionRecord(
                    decision=AuthorityDecision.ESCALATE,
                    reason="dependency changes require explicit review even when enabled",
                )
            return DecisionRecord(
                decision=AuthorityDecision.DENY,
                reason="dependency changes are disabled",
            )

        if operation.kind is OperationKind.GIT_PUSH:
            if self.allow_git_push:
                return DecisionRecord(
                    decision=AuthorityDecision.ESCALATE,
                    reason="git push requires explicit human confirmation",
                )
            return DecisionRecord(
                decision=AuthorityDecision.DENY,
                reason="git push is disabled",
            )

        return DecisionRecord(
            decision=AuthorityDecision.DENY,
            reason="unknown operation",
        )
