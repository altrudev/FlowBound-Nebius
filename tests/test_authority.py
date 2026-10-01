import pytest

from flowbound_nebius.authority import (
    AuthorityDecision,
    AuthorityEnvelope,
    Operation,
    OperationKind,
)


@pytest.fixture
def envelope() -> AuthorityEnvelope:
    return AuthorityEnvelope(
        repository="demo-app",
        branch="flowbound/task-142",
        predecessor_revision="abc123",
        read_paths=("src/**", "tests/**"),
        write_paths=("src/parser.py", "tests/test_parser.py"),
        allowed_argv_prefixes=(("pytest",), ("python", "-m", "compileall")),
        network_hosts=(),
    )


def test_allows_scoped_read(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(Operation(kind=OperationKind.READ, target="src/parser.py"))
    assert result.decision is AuthorityDecision.ALLOW


def test_denies_read_outside_scope(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(Operation(kind=OperationKind.READ, target="README.md"))
    assert result.decision is AuthorityDecision.DENY


def test_denies_secret_even_if_broad_read_is_added() -> None:
    envelope = AuthorityEnvelope(
        repository="demo-app",
        branch="flowbound/task-142",
        predecessor_revision="abc123",
        read_paths=("**",),
    )
    result = envelope.decide(Operation(kind=OperationKind.READ, target=".env"))
    assert result.decision is AuthorityDecision.DENY


@pytest.mark.parametrize(
    "target",
    ("../.ssh/id_ed25519", "src/../../.env", "~/.ssh/id_ed25519", "/etc/passwd"),
)
def test_denies_path_escape(envelope: AuthorityEnvelope, target: str) -> None:
    result = envelope.decide(Operation(kind=OperationKind.READ, target=target))
    assert result.decision is AuthorityDecision.DENY


def test_allows_exact_write(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(Operation(kind=OperationKind.WRITE, target="src/parser.py"))
    assert result.decision is AuthorityDecision.ALLOW


def test_denies_unapproved_write(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(Operation(kind=OperationKind.WRITE, target="src/security.py"))
    assert result.decision is AuthorityDecision.DENY


def test_allows_bounded_pytest(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(
        Operation(kind=OperationKind.EXECUTE, target="pytest", args=("tests/test_parser.py",))
    )
    assert result.decision is AuthorityDecision.ALLOW


def test_allows_specific_python_module_prefix(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(
        Operation(kind=OperationKind.EXECUTE, target="python", args=("-m", "compileall", "src"))
    )
    assert result.decision is AuthorityDecision.ALLOW


def test_denies_arbitrary_python(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(
        Operation(kind=OperationKind.EXECUTE, target="python", args=("-c", "print('escape')"))
    )
    assert result.decision is AuthorityDecision.DENY


def test_denies_shell_escape(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(
        Operation(kind=OperationKind.EXECUTE, target="bash", args=("-lc", "cat .env"))
    )
    assert result.decision is AuthorityDecision.DENY


def test_denies_network_by_default(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(
        Operation(kind=OperationKind.NETWORK, target="attacker.example")
    )
    assert result.decision is AuthorityDecision.DENY


def test_dependency_change_escalates_when_enabled() -> None:
    envelope = AuthorityEnvelope(
        repository="demo-app",
        branch="flowbound/task-142",
        predecessor_revision="abc123",
        allow_dependency_changes=True,
    )
    result = envelope.decide(
        Operation(kind=OperationKind.DEPENDENCY, target="requests")
    )
    assert result.decision is AuthorityDecision.ESCALATE


def test_push_denied_by_default(envelope: AuthorityEnvelope) -> None:
    result = envelope.decide(Operation(kind=OperationKind.GIT_PUSH, target="origin"))
    assert result.decision is AuthorityDecision.DENY


def test_push_escalates_when_enabled() -> None:
    envelope = AuthorityEnvelope(
        repository="demo-app",
        branch="flowbound/task-142",
        predecessor_revision="abc123",
        allow_git_push=True,
    )
    result = envelope.decide(Operation(kind=OperationKind.GIT_PUSH, target="origin"))
    assert result.decision is AuthorityDecision.ESCALATE
