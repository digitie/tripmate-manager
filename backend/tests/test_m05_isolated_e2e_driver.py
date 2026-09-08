from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType, ModuleType
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from kor_travel_docker_manager.services import runtime_pin_registry as pin_registry
from kor_travel_docker_manager.services.pinned_runtime_release import (
    current_pinned_runtime_release,
)
from kor_travel_docker_manager.services.runtime_execution_registry import (
    BlockedExecution,
    ExecutionIdentityV6,
    migrate_execution_registry,
)

PINNED_RUNTIME_RELEASE = current_pinned_runtime_release()


def _driver() -> ModuleType:
    path = Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py"
    spec = importlib.util.spec_from_file_location("m05_isolated_e2e_driver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pair_entry(*, revision: str, raw: bytes) -> dict[str, str]:
    canonical = json.dumps(
        json.loads(raw), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return {
        "openapi_sha256": hashlib.sha256(raw).hexdigest(),
        "runtime_operation_contract_sha256": "a" * 64,
        "source_canonical_sha256": hashlib.sha256(canonical).hexdigest(),
        "source_operation_contract_sha256": "b" * 64,
        "source_revision": revision,
    }


def test_pinvi_manager_admission_contract_requires_the_gate_and_verifier(tmp_path: Path) -> None:
    driver = _driver()
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "docker-app.sh").write_text(
            "PINVI_M05_ISOLATED_MANAGER_ADMISSION_PATH\n"
            "PINVI_M05_PINSET_SHA256\n"
            "PINVI_M05_EXECUTION_IDENTITY_SHA256\n"
            "PINVI_DOCKER_COMPOSE_EXTRA_FILE\n"
        "m05_isolated_manager_admission.py\n",
        encoding="utf-8",
    )
    (scripts / "m05_isolated_manager_admission.py").write_text(
        "pinvi-m05-isolated-manager-admission-v1\n"
        '[[ "$EUID" -eq 0 ]]\n'
        "/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 -I\n",
        encoding="utf-8",
    )

    driver._assert_pinvi_manager_admission_contract(tmp_path)

    (scripts / "m05_isolated_manager_admission.py").unlink()
    with pytest.raises(driver._PhaseError, match="pinvi_manager_admission_contract_invalid"):
        driver._assert_pinvi_manager_admission_contract(tmp_path)


def test_generated_pbkdf2_hash_verifies_the_original_value() -> None:
    value = "isolated-password"
    encoded = _driver()._pbkdf2_password_hash(value)
    scheme, iterations, salt, digest = encoded.split("$")

    assert scheme == "pbkdf2_sha256"

    def restore(item: str) -> bytes:
        return base64.urlsafe_b64decode(item + "=" * (-len(item) % 4))

    assert hashlib.pbkdf2_hmac(
        "sha256", value.encode("utf-8"), restore(salt), int(iterations)
    ) == restore(digest)


def test_terminal_registry_reason_exposes_only_allowlisted_phase() -> None:
    """registry는 다음 candidate의 보정 범위만 말하고 예외 원문은 싣지 않는다."""

    driver = _driver()

    assert (
        driver._terminal_registry_reason("map_health_transport_failed")
        == "M05 isolated one-shot terminal: map_health_transport_failed"
    )
    assert (
        driver._terminal_registry_reason("untrusted detail must never be published")
        == "M05 isolated one-shot terminal: driver_contract_failed"
    )
    assert (
        driver._terminal_registry_reason("runtime_setup_credentials")
        == "M05 isolated one-shot terminal: runtime_setup_credentials"
    )
    assert (
        driver._terminal_registry_reason("runtime_loopback_publish_invalid")
        == "M05 isolated one-shot terminal: runtime_loopback_publish_invalid"
    )


def test_runtime_setup_uses_ordered_safe_subphases() -> None:
    """setup의 ordinary exception도 raw 없이 다음 source 보정 범위로만 수렴한다."""

    driver = _driver()
    source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )
    phases = (
        "runtime_setup_ports",
        "runtime_setup_workspace",
        "runtime_setup_admission_build",
        "runtime_setup_admission_write",
        "runtime_setup_network",
        "runtime_setup_credentials",
        "runtime_setup_map_config",
        "runtime_setup_playwright_runner_image",
        "runtime_setup_pinvi_config",
    )
    positions = [source.index(f'phase = "{phase}"') for phase in phases]

    assert positions == sorted(positions)
    assert all(phase in driver._PUBLIC_TERMINAL_PHASES for phase in phases)


def test_http_json_rejects_non_loopback_url_before_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver()

    monkeypatch.setattr(
        driver._LOOPBACK_OPENER,
        "open",
        lambda *_args, **_kwargs: pytest.fail("transport must not be called"),
    )

    with pytest.raises(driver._PhaseError, match="runtime_http_url_invalid"):
        driver._http_json("http://localhost:13701/health", headers={})
    with pytest.raises(driver._PhaseError, match="runtime_http_url_invalid"):
        driver._http_json("https://127.0.0.1:13701/health", headers={})


def test_http_json_default_transport_is_proxy_free_loopback_opener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver()
    seen: list[Request] = []

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b'{"data":{}}'

    def fake_open(request: Request, *, timeout: int) -> _Response:
        assert timeout == 10
        seen.append(request)
        return _Response()

    monkeypatch.setattr(driver._LOOPBACK_OPENER, "open", fake_open)
    assert driver._http_json("http://127.0.0.1:13701/health", headers={}) == {"data": {}}
    assert len(seen) == 1


def test_http_json_emits_only_the_caller_fixed_transport_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP 원문을 저장하지 않고 다음 immutable candidate의 보정 범위만 남긴다."""

    driver = _driver()

    def fail_open(*_args: object, **_kwargs: object) -> object:
        raise URLError("transport detail must not escape")

    monkeypatch.setattr(driver._LOOPBACK_OPENER, "open", fail_open)

    with pytest.raises(driver._PhaseError, match="map_health_http_failed"):
        driver._http_json(
            "http://127.0.0.1:13701/health",
            headers={},
            failure_phase="map_health_http_failed",
        )


def test_map_health_keeps_http_status_and_loopback_transport_separate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """다음 one-shot source가 원문 없이 startup 보정 범위를 구별하게 한다."""

    driver = _driver()

    def fail_status(request: Request, **_kwargs: object) -> object:
        raise HTTPError(request.full_url, 503, "discarded", None, None)

    monkeypatch.setattr(driver._LOOPBACK_OPENER, "open", fail_status)
    with pytest.raises(driver._PhaseError, match="map_health_status_failed"):
        driver._http_json(
            "http://127.0.0.1:13701/health",
            headers={},
            failure_phase="map_health_transport_failed",
            http_error_phase="map_health_status_failed",
        )

    def fail_transport(*_args: object, **_kwargs: object) -> object:
        raise URLError("discarded")

    monkeypatch.setattr(driver._LOOPBACK_OPENER, "open", fail_transport)
    with pytest.raises(driver._PhaseError, match="map_health_transport_failed"):
        driver._http_json(
            "http://127.0.0.1:13701/health",
            headers={},
            failure_phase="map_health_transport_failed",
            http_error_phase="map_health_status_failed",
        )


def test_map_health_retries_only_a_transient_loopback_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver()
    calls = 0
    waits: list[int] = []

    def transient_health(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise driver._PhaseError("map_health_transport_failed")
        return {"data": {}}

    monkeypatch.setattr(driver, "_http_json", transient_health)
    monkeypatch.setattr(driver.time, "sleep", waits.append)

    assert driver._wait_for_map_health(url="http://127.0.0.1:13701/health") == {"data": {}}
    assert calls == 2
    assert waits == [driver.LOOPBACK_HTTP_READINESS_RETRY_SECONDS]


def test_map_health_uses_the_general_loopback_readiness_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M05 consumer는 Manager의 bounded host-loopback startup 정책을 따른다."""

    driver = _driver()
    calls = 0
    waits: list[int] = []

    def transient_until_final_attempt(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls < driver.LOOPBACK_HTTP_READINESS_ATTEMPTS:
            raise driver._PhaseError("map_health_transport_failed")
        return {"data": {}}

    monkeypatch.setattr(driver, "_http_json", transient_until_final_attempt)
    monkeypatch.setattr(driver.time, "sleep", waits.append)

    assert driver._wait_for_map_health(url="http://127.0.0.1:13701/health") == {"data": {}}
    assert calls == driver.LOOPBACK_HTTP_READINESS_ATTEMPTS
    assert waits == [driver.LOOPBACK_HTTP_READINESS_RETRY_SECONDS] * (
        driver.LOOPBACK_HTTP_READINESS_ATTEMPTS - 1
    )


def test_loopback_publish_is_verified_before_http_readiness() -> None:
    driver = _driver()
    valid = {
        "NetworkSettings": {
            "Ports": {"13701/tcp": [{"HostIp": "127.0.0.1", "HostPort": "13701"}]}
        }
    }

    driver._assert_loopback_tcp_publish(valid, container_port=13701, host_port=13701)

    invalid = {
        "NetworkSettings": {
            "Ports": {"13701/tcp": [{"HostIp": "0.0.0.0", "HostPort": "13701"}]}
        }
    }
    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_invalid"):
        driver._assert_loopback_tcp_publish(invalid, container_port=13701, host_port=13701)


def test_rendered_loopback_publish_is_checked_before_a_claim() -> None:
    driver = _driver()
    rendered = json.dumps(
        {
            "services": {
                "api": {
                    "ports": [
                        {
                            "host_ip": "127.0.0.1",
                            "protocol": "tcp",
                            "published": "31337",
                            "target": 13701,
                        }
                    ]
                }
            }
        }
    )

    driver._assert_rendered_loopback_tcp_publish(
        rendered, service="api", container_port=13701, host_port=31337
    )
    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_config_invalid"):
        driver._assert_rendered_loopback_tcp_publish(
            rendered, service="api", container_port=13701, host_port=31338
        )


def test_rendered_loopback_publish_keeps_only_safe_port_evidence(tmp_path: Path) -> None:
    driver = _driver()
    evidence = tmp_path / "rendered-loopback-publish.json"
    rendered = json.dumps(
        {
            "services": {
                "api": {
                    "ports": [
                        {
                            "host_ip": "127.0.0.1",
                            "protocol": "tcp",
                            "published": "31337",
                            "target": 13701,
                        }
                    ]
                }
            }
        }
    )

    driver._assert_rendered_loopback_tcp_publish(
        rendered,
        service="api",
        container_port=13701,
        host_port=31337,
        evidence_path=evidence,
    )

    assert json.loads(evidence.read_text(encoding="utf-8")) == {
        "container_port": 13701,
        "host_port": 31337,
        "port_count": 1,
        "ports": [
            {
                "host_ip": "127.0.0.1",
                "protocol": "tcp",
                "published": "31337",
                "target": 13701,
            }
        ],
        "service": "api",
        "version": 1,
    }


def test_rendered_loopback_publish_parse_failure_keeps_only_opt_in_bounded_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver()
    safe = tmp_path / "parse.json"
    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_config_invalid"):
        driver._assert_rendered_loopback_tcp_publish(
            "not-json",
            service="api",
            container_port=13701,
            host_port=31337,
            parse_failure_evidence_path=safe,
        )
    assert json.loads(safe.read_text(encoding="utf-8")) == {
        "kind": "compose_config_output",
        "truncated": False,
        "version": 1,
    }
    assert not safe.with_suffix(".stdout").exists()

    monkeypatch.setenv(driver._FORENSIC_CAPTURE_ENV, "1")
    forensic = tmp_path / "forensic.json"
    oversized = "x" * (driver._FORENSIC_CAPTURE_LIMIT + 1)
    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_config_invalid"):
        driver._assert_rendered_loopback_tcp_publish(
            oversized,
            service="api",
            container_port=13701,
            host_port=31337,
            parse_failure_evidence_path=forensic,
        )
    assert forensic.with_suffix(".stdout").read_bytes() == (
        b"x" * driver._FORENSIC_CAPTURE_LIMIT
    )


def test_rendered_loopback_publish_evidence_drops_unknown_or_invalid_values(
    tmp_path: Path,
) -> None:
    driver = _driver()
    evidence = tmp_path / "rendered-loopback-publish.json"
    rendered = json.dumps(
        {
            "services": {
                "api": {
                    "ports": [
                        {
                            "host_ip": "127.0.0.1",
                            "name": "untrusted-env-interpolation-value",
                            "protocol": "tcp",
                            "published": "not-a-port",
                            "target": 13701,
                            "x-unexpected": {"arbitrary": "rendered-compose-data"},
                        }
                    ]
                }
            }
        }
    )

    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_config_invalid"):
        driver._assert_rendered_loopback_tcp_publish(
            rendered,
            service="api",
            container_port=13701,
            host_port=31337,
            evidence_path=evidence,
        )

    assert json.loads(evidence.read_text(encoding="utf-8")) == {
        "container_port": 13701,
        "host_port": 31337,
        "port_count": 1,
        "ports": [
            {
                "host_ip": "127.0.0.1",
                "protocol": "tcp",
                "published": None,
                "target": 13701,
            }
        ],
        "service": "api",
        "version": 1,
    }


def test_map_health_does_not_retry_a_received_http_status_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver()
    waits: list[int] = []

    def status_failure(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise driver._PhaseError("map_health_status_failed")

    monkeypatch.setattr(driver, "_http_json", status_failure)
    monkeypatch.setattr(driver.time, "sleep", waits.append)

    with pytest.raises(driver._PhaseError, match="map_health_status_failed"):
        driver._wait_for_map_health(url="http://127.0.0.1:13701/health")
    assert waits == []


def test_pinvi_receipt_transport_phase_is_not_collapsed_into_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """receipt polling은 transport failure를 fixed caller phase로 보존한다."""

    driver = _driver()

    def fail_http(*_args: object, **_kwargs: object) -> object:
        raise driver._PhaseError("m05_pinvi_receipt_http_failed")

    monkeypatch.setattr(driver, "_http_json", fail_http)

    with pytest.raises(driver._PhaseError, match="m05_pinvi_receipt_http_failed"):
        driver._wait_for_pinvi_receipt(
            api_url="http://127.0.0.1:13701",
            opener=object(),
            event_id="00000000-0000-0000-0000-000000000000",
        )


@pytest.mark.parametrize(
    ("status", "phase"),
    [
        ("blocked", "m05_pinvi_receipt_blocked"),
        ("unexpected", "m05_pinvi_receipt_invalid"),
    ],
)
def test_pinvi_receipt_non_applied_status_is_terminal(
    monkeypatch: pytest.MonkeyPatch, status: str, phase: str
) -> None:
    """PinVi detail 계약에 없는 pending retry가 terminal 상태를 timeout으로 감추지 않는다."""

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_http_json",
        lambda *_args, **_kwargs: {"data": {"status": status}},
    )

    with pytest.raises(driver._PhaseError, match=phase):
        driver._wait_for_pinvi_receipt(
            api_url="http://127.0.0.1:13701",
            opener=object(),
            event_id="00000000-0000-0000-0000-000000000000",
        )


def test_execution_registry_gate_precedes_the_m05_ledger_claim() -> None:
    """현재 exact execution은 ledger claim 전에 terminal로 거절한다."""

    source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )

    gate = source.index("_assert_current_m05_execution_is_runnable(expected_revision)")
    ledger_directory = source.index("_LEDGER.mkdir(mode=0o700, parents=True, exist_ok=True)")
    ledger_claim = source.index("claim_m05_isolated_harness_ledger(ledger_root=_LEDGER, plan=plan)")

    assert gate < ledger_directory
    assert gate < ledger_claim


def test_execution_registry_gate_refuses_the_current_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """다른 Manager revision도 unconditional block을 실행권으로 바꾸지 못한다."""

    driver = _driver()

    class _SourceRegistry:
        pinset_sha256 = driver.PINNED_RUNTIME_RELEASE.pinset_sha256
        map_revision = driver.PINNED_RUNTIME_RELEASE.source_for("map").revision
        pinvi_revision = driver.PINNED_RUNTIME_RELEASE.source_for("pinvi").revision

    class _TerminalExecutionRegistry:
        def current_matches(self, **_kwargs: object) -> bool:
            return True

        def is_unconditionally_blocked_current(self) -> bool:
            return True

    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: _SourceRegistry())
    monkeypatch.setattr(
        driver, "load_runtime_execution_registry", lambda: _TerminalExecutionRegistry()
    )

    with pytest.raises(driver._PhaseError, match="terminal_execution_blocked"):
        driver._assert_current_m05_execution_is_runnable("a" * 40)


def test_infra_terminal_leaves_a_phase_scoped_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """인프라 phase 실패는 scoped 기록이다 — execution을 소각하지 않는다.

    종전에는 phase를 넘기지 않아 모든 terminal이 무조건 차단이 됐고, 인프라 실패가
    acceptance 실패와 같은 형벌(3-repo 회전)을 받았다. terminal 27개 중 본문 도달
    0건이 그 결과다.
    """
    driver = _driver()
    seen: dict[str, object] = {}

    class _SourceRegistry:
        pinset_sha256 = driver.PINNED_RUNTIME_RELEASE.pinset_sha256
        map_revision = driver.PINNED_RUNTIME_RELEASE.source_for("map").revision
        pinvi_revision = driver.PINNED_RUNTIME_RELEASE.source_for("pinvi").revision

    class _ExecutionRegistry:
        def current_matches(self, **_kwargs: object) -> bool:
            return True

    class _UpdatedRegistry:
        def has_block_for_current(self, *, phase: str | None = None) -> bool:
            return True

    def block(**kwargs: object) -> _UpdatedRegistry:
        seen.update(kwargs)
        return _UpdatedRegistry()

    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: _SourceRegistry())
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: _ExecutionRegistry())
    monkeypatch.setattr(driver, "block_current_execution", block)
    monkeypatch.setattr(driver, "write_runtime_execution_registry", lambda _registry: None)

    assert driver._block_terminal_m05_execution(
        "map_health_transport_failed", expected_manager_revision="a" * 40
    ) is True
    assert seen["phase"] == "map_health_transport_failed"
    assert seen["reason"] == "M05 isolated one-shot terminal: map_health_transport_failed"


@pytest.mark.parametrize(
    "phase",
    ["ledger_claim", "m04_m05_e2e", "m05_case_invalid", "m04_fixture_http_failed"],
)
def test_acceptance_terminal_stays_unconditional(
    phase: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """acceptance 본문·ledger claim 실패는 여전히 무조건 소각이다(phase=None).

    "acceptance 본문은 정확히 한 번"이라는 one-shot 성질은 phase-scoped 완화의
    대상이 아니다 — 완화되는 것은 인프라 phase뿐이다.
    """
    driver = _driver()
    seen: dict[str, object] = {}

    class _SourceRegistry:
        pinset_sha256 = driver.PINNED_RUNTIME_RELEASE.pinset_sha256
        map_revision = driver.PINNED_RUNTIME_RELEASE.source_for("map").revision
        pinvi_revision = driver.PINNED_RUNTIME_RELEASE.source_for("pinvi").revision

    class _ExecutionRegistry:
        def current_matches(self, **_kwargs: object) -> bool:
            return True

    class _UpdatedRegistry:
        def has_block_for_current(self, *, phase: str | None = None) -> bool:
            return True

        def is_unconditionally_blocked_current(self) -> bool:
            return True

    def block(**kwargs: object) -> _UpdatedRegistry:
        seen.update(kwargs)
        return _UpdatedRegistry()

    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: _SourceRegistry())
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: _ExecutionRegistry())
    monkeypatch.setattr(driver, "block_current_execution", block)
    monkeypatch.setattr(driver, "write_runtime_execution_registry", lambda _registry: None)

    assert driver._block_terminal_m05_execution(
        phase, expected_manager_revision="a" * 40
    ) is True
    assert seen["phase"] is None


@pytest.mark.parametrize(
    "phase",
    ["runtime_container_identity_invalid", "runtime_http_contract_failed"],
)
def test_body_entered_failure_is_forced_unconditional(
    phase: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """본문 진입 이후에는 인프라형 phase 이름의 실패도 무조건 소각한다(R1-S4/R2-S4).

    본문 내부 helper(_container_id 등)는 인프라형 phase로 _PhaseError를 던진다 —
    force_unconditional 없이는 그 실패가 scoped 기록으로 강등돼 mutating 본문이
    재실행될 수 있다(one-shot 위반).
    """
    driver = _driver()
    seen: dict[str, object] = {}

    class _SourceRegistry:
        pinset_sha256 = driver.PINNED_RUNTIME_RELEASE.pinset_sha256
        map_revision = driver.PINNED_RUNTIME_RELEASE.source_for("map").revision
        pinvi_revision = driver.PINNED_RUNTIME_RELEASE.source_for("pinvi").revision

    class _ExecutionRegistry:
        def current_matches(self, **_kwargs: object) -> bool:
            return True

    class _UpdatedRegistry:
        def has_block_for_current(self, *, phase: str | None = None) -> bool:
            return True

        def is_unconditionally_blocked_current(self) -> bool:
            return True

    def block(**kwargs: object) -> _UpdatedRegistry:
        seen.update(kwargs)
        return _UpdatedRegistry()

    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: _SourceRegistry())
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: _ExecutionRegistry())
    monkeypatch.setattr(driver, "block_current_execution", block)
    monkeypatch.setattr(driver, "write_runtime_execution_registry", lambda _registry: None)

    assert driver._block_terminal_m05_execution(
        phase, expected_manager_revision="a" * 40, force_unconditional=True
    ) is True
    assert seen["phase"] is None


def test_cleanup_failure_does_not_downgrade_an_unconditional_phase() -> None:
    """cleanup 실패가 본문/ledger 실패 표면을 강등하지 못한다(R1-S4).

    guard 바로 다음 실행문이 cleanup overwrite인지 소스에서 확인한다 —
    본문 진입(body_entered) 또는 무조건-급 phase에서는 overwrite가 없어야 한다.
    """
    source = (
        Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py"
    ).read_text(encoding="utf-8")
    guard = "if (\n"
    guard += "                claim_attempted\n"
    guard += "                and not body_entered\n"
    guard += "                and _terminal_block_phase(phase) is not None\n"
    guard += "            ):"
    # claim 이전에는 강등 자체가 없어야 한다 — preflight_rejected receipt가
    # driver_phase != phase가 되면 launcher가 거부해 무소비 실행이 소각된다.
    assert guard in source
    tail = source[source.index(guard) + len(guard):]
    statements = [
        line.strip()
        for line in tail.splitlines()[1:9]
        if line.strip() and not line.strip().startswith("#")
    ]
    assert statements[0] == 'phase = "runtime_cleanup_failed"'
    # 실제 실패 phase는 강등 가드 **이전**에 driver_phase로 확정돼 있어야 한다
    # (e2e6: 가드 뒤 대입이 원인 phase를 통째로 가렸다). passed 경로는
    # "completed"를 실어야 launcher의 passed 검증이 첫 PASS를 무효화하지 않는다.
    contract = 'driver_phase = "completed" if completed else phase'
    assert contract in source
    assert source.index(contract) < source.index(guard)
    assert "\n        driver_phase = phase\n" not in source


def test_preclaim_exception_writes_a_nonterminal_fixed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """unknown exception은 raw 없이 현재 admission 경계로 수렴한다."""

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(RuntimeError("discarded")),
    )
    monkeypatch.setattr(
        driver,
        "_block_terminal_m05_execution",
        lambda *_args, **_kwargs: pytest.fail("preclaim failure must not block execution"),
    )

    assert driver.main("a" * 40, tmp_path) == 1
    receipt = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))

    assert receipt["status"] == "preflight_rejected"
    assert receipt["phase"] == "admission"
    assert receipt["driver_phase"] == "admission"
    assert "discarded" not in json.dumps(receipt, sort_keys=True)


def test_cleanup_boundary_marks_ordinary_exceptions_for_fixed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cleanup의 OSError도 driver raw-output 부재로 전파하지 않는다."""

    driver = _driver()
    cleanup = (tmp_path, "m05i-test", tmp_path / "runtime.env", (tmp_path / "x.yml",), ())
    monkeypatch.setattr(
        driver,
        "_cleanup_project",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("discarded")),
    )

    assert driver._cleanup_temporary_resources(
        map_cleanup=cleanup,
        pinvi_cleanup=None,
        private_files=(),
    ) == (False, True, False)


def test_preclaim_cleanup_failure_keeps_the_receipt_launcher_acceptable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """claim 전 실패에 cleanup 딸꾹질이 겹쳐도 receipt는 여전히 수용 가능해야 한다.

    종전에는 phase가 runtime_cleanup_failed로 재작성돼 driver_phase != phase가
    됐고, launcher는 그 preflight_rejected receipt를 거부해 **아무것도 claim하지
    않은 실행을 소각**했다. 이 테스트가 그 소각 receipt를 인증하고 있었다
    (적대 리뷰 BLOCKER-2). cleanup 신호는 cleanup_failed 필드가 나른다."""

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(driver._PhaseError("admission")),
    )
    monkeypatch.setattr(
        driver,
        "_cleanup_temporary_resources",
        lambda **_kwargs: (False, True, False),
    )
    monkeypatch.setattr(driver, "_block_terminal_m05_execution", lambda *_args, **_kwargs: True)

    assert driver.main("a" * 40, tmp_path) == 1
    receipt = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))

    assert receipt["status"] == "preflight_rejected"
    # phase가 재작성되지 않아 launcher의 preflight 수용 조건을 만족한다.
    assert receipt["phase"] == "admission"
    assert receipt["driver_phase"] == receipt["phase"]
    assert receipt["execution_identity_sha256"] is not None


def test_preclaim_phase_error_does_not_attempt_a_terminal_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ledger 이전의 contract failure는 block helper 자체를 호출하지 않는다."""

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(driver._PhaseError("admission_failed")),
    )
    monkeypatch.setattr(
        driver,
        "_block_terminal_m05_execution",
        lambda *_args, **_kwargs: pytest.fail("preclaim failure must not block execution"),
    )

    assert driver.main("a" * 40, tmp_path) == 1
    receipt = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))

    assert receipt["status"] == "preflight_rejected"
    assert receipt["phase"] == "admission_failed"
    assert receipt["driver_phase"] == "admission_failed"


def test_root_launcher_checks_registry_before_creating_an_output_leaf() -> None:
    """terminal direct launch은 새 leaf·driver·ledger를 만들기 전에 끝난다."""

    launcher = (Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once").read_text(
        encoding="utf-8"
    )

    assert launcher.index('"$ktdctl" pin verify --json >/dev/null 2>&1') < launcher.index(
        'install -d -o root -g root -m 0700 "$output_dir"'
    )


def test_root_launcher_defaults_to_forensic_capture_with_explicit_opt_out() -> None:
    """원문 보존이 기본값이다 — 관측 결핍이 후보 예산을 소비했다(감사 I-2).

    4개 candidate를 태운 `ports: !reset`은 stderr 한 번이면 즉시 보였을 값이었다.
    보존 대상은 bounded stderr뿐이고 root 0600 leaf를 벗어나지 않으며, 끄는 것은
    caller environment가 아니라 명시 launcher argument로만 가능하다.
    """
    launcher = (Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once").read_text(
        encoding="utf-8"
    )

    # 열 0의 대입만 기본값이다 — 들여쓰기된 호환 분기(`  forensic_capture=1`)와
    # 구분하지 않으면 기본값을 0으로 되돌려도 이 단언이 통과한다.
    assert "\nforensic_capture=1\n" in launcher, "기본값이 보존이어야 한다"
    assert "\nforensic_capture=0\n" not in launcher
    assert '"$1" == "--no-forensic-capture"' in launcher, "명시 opt-out이 있어야 한다"
    assert "export KTDM_M05_FORENSIC_CAPTURE=1" in launcher
    assert "unset KTDM_M05_FORENSIC_CAPTURE" in launcher
    assert '"${launcher_arguments[@]}"' in launcher


def test_root_launcher_forensic_default_is_behavioral_not_textual() -> None:
    """launcher를 실제 실행(bash -x)해 기본값 대입을 트레이스로 확인한다(R2-S9).

    문구 단언은 주석/데드 브랜치로 우회된다 — 여기서는 non-root 실행의 실제
    트레이스에서 `forensic_capture=1`(기본) / `=0`(--no-forensic-capture)을 본다.
    non-root라서 launcher는 root 검사에서 exit 2로 멈춘다(driver 실행 없음).
    """
    if os.name != "posix" or os.geteuid() == 0:
        pytest.skip("non-root POSIX에서만 안전하게 실행할 수 있다")
    launcher_path = Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once"

    default_run = subprocess.run(
        ["bash", "-x", str(launcher_path), "a" * 40, "/nonexistent-m05-out"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert default_run.returncode == 2
    assert "must run as root" in default_run.stderr
    assert "+ forensic_capture=1" in default_run.stderr
    assert "+ forensic_capture=0" not in default_run.stderr

    opt_out_run = subprocess.run(
        [
            "bash",
            "-x",
            str(launcher_path),
            "--no-forensic-capture",
            "a" * 40,
            "/nonexistent-m05-out",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert opt_out_run.returncode == 2
    assert "+ forensic_capture=0" in opt_out_run.stderr


def test_root_launcher_blocks_and_writes_a_fixed_envelope_when_driver_result_is_unavailable() -> None:
    """driver raw output 부재도 terminal evidence 없이 재시도할 수 없게 고정한다."""

    launcher = (Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once").read_text(
        encoding="utf-8"
    )

    # fallback 봉투는 launcher 표식이지 receipt가 아니다 — tenant의 phase
    # 네임스페이스를 쓰지 않고 launcher 소유 키로만 결과를 말한다.
    assert '"launcher_outcome": "safe_result_unavailable"' in launcher
    assert "launcher_safe_result_unavailable" not in launcher
    assert '"$ktdctl" pin block-execution' in launcher
    assert "launcher-result.json" in launcher
    assert ">/dev/null 2>&1" in launcher[launcher.index("m05_isolated_e2e.py") :]
    assert "stderr.log" not in launcher[launcher.index("driver_status=") :]
    block_start = launcher.index("has_unconditional_terminal_execution_block() {")
    block_end = launcher.index('install -d -o root -g root -m 0700 "$output_dir"')
    block_check = launcher[block_start:block_end]
    assert "/usr/bin/python3 -I -S -c" in block_check
    assert "<<'PY'" not in block_check


def test_root_launcher_accepts_only_the_launch_snapshot_and_fixed_schema() -> None:
    """rotation race와 임의 driver envelope은 fresh candidate 근거가 될 수 없다."""

    launcher = (Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once").read_text(
        encoding="utf-8"
    )

    assert "initial_snapshot" in launcher
    assert "stable_snapshot" in launcher
    assert "post_snapshot" in launcher
    # snapshot 등가는 이제 검증을 **건너뛰는 게이트가 아니라** 진단이다 —
    # launcher가 수명 내내 global mutation lock을 쥐므로 이 창에서 회전은
    # 물리적으로 불가능하고, 값 불일치는 또 다른 관측 이상일 뿐이다.
    assert 'snapshot_changed=1' in launcher
    assert '"$post_snapshot" != "$initial_snapshot"' in launcher
    assert 'value.get("pinset_sha256") != expected_pinset' in launcher
    assert 'value.get("execution_identity_sha256") != expected_execution' in launcher
    assert 'value.get("status") not in {"passed", "blocked", "preflight_rejected"}' in launcher
    assert 'if value["status"] == "preflight_rejected"' in launcher
    # 결정 분기는 case로 통합됐다 — 각 종료값의 의미가 한 곳에 모여 있다.
    assert 'case "$receipt_validation_status" in' in launcher
    for outcome in ("  0)", "  4)", "  5)", "  3)", "  *)"):
        assert outcome in launcher, outcome
    # receipt를 못 읽으면 claim 마커로 소비 여부를 판정한다(추측으로 태우지 않는다).
    assert '[[ ! -e "$output_dir/claimed" ]]' in launcher
    # 가장 무거운 명령의 상태를 포착한다.
    assert 'block_write_status="$?"' in launcher
    assert "PREFLIGHT_REJECTED_PHASES" in launcher
    assert 'value.get("phase") not in PREFLIGHT_REJECTED_PHASES' in launcher
    # Tier 2(진단) 불일치는 소각값이 아니라 저하값으로 간다 — 행동은
    # test_tier_two_divergence_never_reaches_the_unconditional_burn_value가 덮는다.
    assert "set(value) != expected_keys" in launcher
    assert "if [[ ! -e \"$launcher_result_path\"" in launcher


def test_root_launcher_accepts_every_runtime_setup_subphase() -> None:
    """driver의 모든 public terminal phase는 launcher도 exact하게 수용한다."""

    launcher = (Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once").read_text(
        encoding="utf-8"
    )
    driver_source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )

    def frozenset_literal(source: str, name: str) -> set[str]:
        tree = ast.parse(source)
        for statement in tree.body:
            if not isinstance(statement, ast.Assign) or not any(
                isinstance(target, ast.Name) and target.id == name for target in statement.targets
            ):
                continue
            assert isinstance(statement.value, ast.Call)
            assert isinstance(statement.value.func, ast.Name)
            assert statement.value.func.id == "frozenset"
            assert len(statement.value.args) == 1
            value = ast.literal_eval(statement.value.args[0])
            assert isinstance(value, set)
            assert all(isinstance(item, str) for item in value)
            return value
        raise AssertionError(f"{name} literal was not found")

    driver_phases = frozenset_literal(driver_source, "_PUBLIC_TERMINAL_PHASES")
    launcher_start = launcher.index("PHASES = frozenset(")
    launcher_end = launcher.index("PREFLIGHT_REJECTED_PHASES =", launcher_start)
    launcher_phases = frozenset_literal(launcher[launcher_start:launcher_end], "PHASES")

    assert launcher_phases == driver_phases | {"completed"}
    # blocked receipt는 scoped 기록으로도 durable하다(R1-S1) — 무조건 기록만
    # 요구하면 launcher가 모든 인프라 실패를 fallback에서 무조건 차단으로 승격한다.
    accepted_block = 'has_any_terminal_execution_block'
    fallback = 'if ! has_unconditional_terminal_execution_block; then'
    assert accepted_block in launcher
    assert fallback in launcher
    assert launcher.index(accepted_block) < launcher.index(fallback)
    # scoped predicate는 phase 필터가 없어야 한다(identity/pinset/revision만 결박).
    any_start = launcher.index("has_any_terminal_execution_block() {")
    any_end = launcher.index("has_unconditional_terminal_execution_block() {")
    any_block = launcher[any_start:any_end]
    assert 'entry.get("phase")' not in any_block
    assert 'entry.get("execution_identity_sha256") == execution' in any_block


def test_free_ports_never_walk_into_the_ephemeral_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """busy window가 쌓여도 탐색은 30000 아래에 머물거나 ports_unavailable로 닫힌다.

    상한 가드(>= 30000 break)를 65535로 되돌리는 회귀는 이 테스트만 잡는다 —
    기본 happy-path 테스트는 offset 0에서 끝나 가드를 한 번도 실행하지 않는다.
    """

    driver = _driver()
    busy_windows = 40

    calls = {"count": 0}

    def fake_command(*args: str, **_kwargs: object) -> str:
        calls["count"] += 1
        # 앞쪽 busy_windows개 window(각 13포트)는 전부 사용 중으로 답한다.
        if calls["count"] <= busy_windows * 13:
            return "LISTEN 0 128 127.0.0.1:x"
        return ""

    monkeypatch.setattr(driver, "_command", fake_command)

    try:
        ports = driver._free_ports("f" * 32)
    except driver._PhaseError as error:
        assert error.phase == "ports_unavailable"
    else:
        assert all(20000 <= port < 30000 for port in ports.values())


def test_free_ports_uses_the_standard_ss_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver()
    commands: list[tuple[str, ...]] = []

    def fake_command(*args: str, **_kwargs: object) -> str:
        commands.append(args)
        return ""

    monkeypatch.setattr(driver, "_command", fake_command)

    ports = driver._free_ports("a" * 32)

    # 전 포트가 비-ephemeral 대역(20000-29999)이어야 한다 — ephemeral 대역은
    # listening 검사(ss -ltn)를 통과해도 outbound 선점으로 bind가 깨진다.
    assert all(20000 <= port < 30000 for port in ports.values())
    assert set(ports) == {
        "map_api",
        "map_dagster",
        "map_postgres",
        "map_rustfs",
        "map_rustfs_console",
        "pinvi_api",
        "pinvi_web",
        "pinvi_rustfs",
        "pinvi_rustfs_console",
        "pinvi_dagster",
        "pinvi_cadvisor",
        "pinvi_prometheus",
        "pinvi_grafana",
    }
    assert len(set(ports.values())) == len(ports)
    assert commands
    assert {command[0] for command in commands} == {"/usr/bin/ss"}


def test_cleanup_includes_map_fresh_init_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver()
    compose_arguments: list[tuple[str, ...]] = []
    commands: list[tuple[str, ...]] = []

    def fake_compose(*_args: object, **kwargs: object) -> str:
        arguments = kwargs["arguments"]
        assert isinstance(arguments, tuple)
        compose_arguments.append(arguments)
        return ""

    def fake_command(*args: str, **_kwargs: object) -> str:
        commands.append(args)
        return ""

    monkeypatch.setattr(driver, "_compose", fake_compose)
    monkeypatch.setattr(driver, "_command", fake_command)

    driver._cleanup_project(
        root=tmp_path,
        project="m05i-map-a" * 4,
        env_file=tmp_path / "map.env",
        files=(tmp_path / "docker-compose.yml",),
        profiles=("fresh-init",),
    )

    assert compose_arguments == [
        ("--profile", "fresh-init", "down", "--volumes", "--remove-orphans")
    ]
    assert len(commands) == 3


def test_compose_records_the_supplied_fixed_failure_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver()

    def fail_command(*_args: str, **_kwargs: object) -> str:
        raise driver._PhaseError("runtime_command_failed")

    monkeypatch.setattr(driver, "_command", fail_command)

    with pytest.raises(driver._PhaseError, match="map_postgres_start_failed") as error:
        driver._compose(
            root=tmp_path,
            project="m05i-map",
            env_file=tmp_path / "map.env",
            files=(tmp_path / "docker-compose.yml",),
            arguments=("up", "postgres"),
            failure_phase="map_postgres_start_failed",
        )

    assert error.value.diagnostic is None


def test_compose_preserves_only_the_fixed_exit_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver()

    def fail_command(*_args: str, **_kwargs: object) -> str:
        raise driver._PhaseError(
            "runtime_command_failed", diagnostic="pre_root_state_invalid"
        )

    monkeypatch.setattr(driver, "_command", fail_command)

    with pytest.raises(driver._PhaseError, match="map_fresh_init_failed") as error:
        driver._compose(
            root=tmp_path,
            project="m05i-map",
            env_file=tmp_path / "map.env",
            files=(tmp_path / "docker-compose.yml",),
            arguments=("run", "db-application-schema-fresh-300"),
            failure_phase="map_fresh_init_failed",
            failure_exit_diagnostics={45: "pre_root_state_invalid"},
        )

    assert error.value.diagnostic == "pre_root_state_invalid"


def test_command_accepts_only_a_declared_failure_exit_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver()

    monkeypatch.setattr(
        driver.subprocess,
        "run",
        lambda args, **_kwargs: subprocess.CompletedProcess(args, 45),
    )

    with pytest.raises(driver._PhaseError, match="runtime_command_failed") as error:
        driver._command(
            "/usr/bin/false", failure_exit_diagnostics={45: "pre_root_state_invalid"}
        )

    assert error.value.diagnostic == "pre_root_state_invalid"


def test_compose_config_failure_evidence_is_safe_by_default_and_forensic_on_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver()

    monkeypatch.setattr(
        driver.subprocess,
        "run",
        lambda args, **_kwargs: subprocess.CompletedProcess(
            args, 2, stdout="", stderr="exact compose parser failure\n"
        ),
    )
    safe = tmp_path / "safe.json"
    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_config_invalid"):
        driver._compose(
            root=tmp_path,
            project="m05i-map",
            env_file=tmp_path / "map.env",
            files=(tmp_path / "docker-compose.yml",),
            arguments=("config", "--format", "json"),
            failure_phase="runtime_loopback_publish_config_invalid",
            failure_evidence_path=safe,
        )
    assert json.loads(safe.read_text(encoding="utf-8")) == {
        "kind": "compose_config",
        "returncode": 2,
        "version": 1,
    }
    assert not safe.with_suffix(".stderr").exists()

    monkeypatch.setenv(driver._FORENSIC_CAPTURE_ENV, "1")
    oversized_stderr = b"x" * (driver._FORENSIC_CAPTURE_LIMIT + 1)

    class FailedCompose:
        stdout = io.BytesIO(b"")
        stderr = io.BytesIO(oversized_stderr)

        def wait(self) -> int:
            return 2

    monkeypatch.setattr(driver.subprocess, "Popen", lambda *_args, **_kwargs: FailedCompose())
    forensic = tmp_path / "forensic.json"
    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_config_invalid"):
        driver._compose(
            root=tmp_path,
            project="m05i-map",
            env_file=tmp_path / "map.env",
            files=(tmp_path / "docker-compose.yml",),
            arguments=("config", "--format", "json"),
            failure_phase="runtime_loopback_publish_config_invalid",
            failure_evidence_path=forensic,
        )
    assert forensic.with_suffix(".stderr").read_bytes() == b"x" * driver._FORENSIC_CAPTURE_LIMIT


def test_compose_config_output_is_stream_bounded_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver()
    oversized_stdout = b"x" * (driver._COMPOSE_CONFIG_OUTPUT_LIMIT + 1)

    class OversizedCompose:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(oversized_stdout)

        def wait(self) -> int:
            return 0

    monkeypatch.setattr(
        driver.subprocess, "Popen", lambda *_args, **_kwargs: OversizedCompose()
    )
    safe = tmp_path / "oversized.json"
    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_config_invalid"):
        driver._compose(
            root=tmp_path,
            project="m05i-map",
            env_file=tmp_path / "map.env",
            files=(tmp_path / "docker-compose.yml",),
            arguments=("config", "--format", "json"),
            capture=True,
            failure_phase="runtime_loopback_publish_config_invalid",
            output_evidence_path=safe,
        )
    assert json.loads(safe.read_text(encoding="utf-8")) == {
        "kind": "compose_config_output",
        "truncated": True,
        "version": 1,
    }
    assert not safe.with_suffix(".stdout").exists()

    monkeypatch.setenv(driver._FORENSIC_CAPTURE_ENV, "1")
    forensic = tmp_path / "oversized-forensic.json"
    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_config_invalid"):
        driver._compose(
            root=tmp_path,
            project="m05i-map",
            env_file=tmp_path / "map.env",
            files=(tmp_path / "docker-compose.yml",),
            arguments=("config", "--format", "json"),
            capture=True,
            failure_phase="runtime_loopback_publish_config_invalid",
            output_evidence_path=forensic,
        )
    assert forensic.with_suffix(".stdout").read_bytes() == (
        b"x" * driver._FORENSIC_CAPTURE_LIMIT
    )


def test_nonzero_compose_config_keeps_exit_evidence_when_stdout_is_oversized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver()

    class FailedOversizedCompose:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"x" * (driver._COMPOSE_CONFIG_OUTPUT_LIMIT + 1))

        def wait(self) -> int:
            return 2

    monkeypatch.setattr(
        driver.subprocess, "Popen", lambda *_args, **_kwargs: FailedOversizedCompose()
    )
    command_evidence = tmp_path / "command.json"
    output_evidence = tmp_path / "output.json"
    with pytest.raises(driver._PhaseError, match="runtime_loopback_publish_config_invalid"):
        driver._compose(
            root=tmp_path,
            project="m05i-map",
            env_file=tmp_path / "map.env",
            files=(tmp_path / "docker-compose.yml",),
            arguments=("config", "--format", "json"),
            capture=True,
            failure_phase="runtime_loopback_publish_config_invalid",
            failure_evidence_path=command_evidence,
            output_evidence_path=output_evidence,
        )
    assert json.loads(command_evidence.read_text(encoding="utf-8")) == {
        "kind": "compose_config",
        "returncode": 2,
        "version": 1,
    }
    assert not output_evidence.exists()


def test_generic_command_failure_evidence_is_safe_by_default_and_bounded_on_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver()
    safe = tmp_path / "command.json"
    driver._write_command_failure_evidence(
        safe, returncode=17, stderr=b"private command error"
    )
    assert json.loads(safe.read_text(encoding="utf-8")) == {
        "kind": "runtime_command",
        "returncode": 17,
        "version": 1,
    }
    assert not safe.with_suffix(".stderr").exists()

    monkeypatch.setenv(driver._FORENSIC_CAPTURE_ENV, "1")
    forensic = tmp_path / "command-forensic.json"
    driver._write_command_failure_evidence(
        forensic,
        returncode=17,
        stderr=b"x" * (driver._FORENSIC_CAPTURE_LIMIT + 1),
    )
    assert forensic.with_suffix(".stderr").read_bytes() == (
        b"x" * driver._FORENSIC_CAPTURE_LIMIT
    )


def test_forensic_capture_scrubs_raw_secret_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """opt-in 캡처 leaf에도 raw 비밀값은 남지 않는다(R1-S9 content-scrub).

    자식 프로세스가 비밀값을 stderr/stdout에 에코해도 _RAW_ENV_NAMES의 현재
    값은 마커로 치환된다. 크기 제한은 총량 방어일 뿐 내용 방어가 아니다.
    """
    driver = _driver()
    secret = "raw-secret-value-0123456789abcdef"
    monkeypatch.setenv("M05_PINVI_PASSWORD", secret)
    monkeypatch.setenv(driver._FORENSIC_CAPTURE_ENV, "1")

    stderr_leaf = tmp_path / "command.json"
    driver._write_command_failure_evidence(
        stderr_leaf,
        returncode=17,
        stderr=b"login failed for " + secret.encode() + b" retrying",
    )
    captured = stderr_leaf.with_suffix(".stderr").read_bytes()
    assert secret.encode() not in captured
    assert b"[scrubbed:M05_PINVI_PASSWORD]" in captured

    stdout_leaf = tmp_path / "compose-output.json"
    driver._write_compose_output_evidence(
        stdout_leaf, output="services: {password: " + secret + "}"
    )
    captured_out = stdout_leaf.with_suffix(".stdout").read_bytes()
    assert secret.encode() not in captured_out
    assert b"[scrubbed:M05_PINVI_PASSWORD]" in captured_out

    # 8바이트 미만 값은 우연 일치 훼손을 피하기 위해 치환하지 않는다.
    monkeypatch.setenv("M05_PINVI_EMAIL", "a@b.c")
    tiny = tmp_path / "tiny.json"
    driver._write_command_failure_evidence(tiny, returncode=3, stderr=b"a@b.c seen")
    assert tiny.with_suffix(".stderr").read_bytes() == b"a@b.c seen"


def test_map_fresh_diagnostic_runner_uses_exit_codes_without_output() -> None:
    driver = _driver()

    runner = driver._map_fresh_init_diagnostic_runner()
    entrypoint = driver._map_fresh_init_diagnostic_entrypoint()

    assert "print(" not in runner
    assert "sys.stderr" not in runner
    assert "FreshMigrationError" in runner
    assert "RuntimePrivilegeReconciliationError" in runner
    assert "SQLAlchemyError" in runner
    assert "CommandError" in runner
    assert "baseline_reference_invalid" not in runner
    assert "fresh 300 destination reference manifest is invalid" in runner
    assert "raise SystemExit" in runner
    assert "base64.b64decode" in entrypoint


def _map_fresh_runner_exit_code(
    driver: ModuleType, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> int:
    class FreshMigrationError(RuntimeError):
        pass

    async def migrate() -> None:
        raise error

    fake_runpy = ModuleType("runpy")
    fake_runpy.run_path = lambda *_args, **_kwargs: {
        "FreshMigrationError": FreshMigrationError,
        "_migrate": migrate,
        "_parse_args": lambda _arguments: ("migrate", None),
    }
    monkeypatch.setitem(sys.modules, "runpy", fake_runpy)

    with pytest.raises(SystemExit) as stopped:
        exec(compile(driver._map_fresh_init_diagnostic_runner(), "<runner>", "exec"))

    assert isinstance(stopped.value.code, int)
    return stopped.value.code


def test_map_fresh_diagnostic_runner_maps_exact_prefix_and_unknown_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver()

    assert _map_fresh_runner_exit_code(
        driver,
        monkeypatch,
        RuntimeError("fresh 300 destination reference manifest is invalid"),
    ) == 51
    assert _map_fresh_runner_exit_code(
        driver, monkeypatch, RuntimeError("unlisted Map runtime failure")
    ) == 48
    assert _map_fresh_runner_exit_code(driver, monkeypatch, ValueError("ignored")) == 127


def test_fixture_uses_only_dagster_runtime_dsn_and_provider_contract() -> None:
    fixture = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_fixture.py").read_text(
        encoding="utf-8"
    )
    driver_source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )
    fixture_env_start = driver_source.index("_write_private_text(\n            fixture_env,")
    fixture_env_end = driver_source.index("        # API에는", fixture_env_start)
    fixture_env = driver_source[fixture_env_start:fixture_env_end]

    assert "KOR_TRAVEL_MAP_BOOTSTRAP_PG_DSN" not in fixture
    assert "KOR_TRAVEL_MAP_BOOTSTRAP_PG_DSN" not in fixture_env
    assert "KOR_TRAVEL_MAP_PG_DSN" in fixture_env
    assert "assert_runtime_db_privilege_boundary" in fixture
    assert "AsyncKorTravelMapClient" in fixture
    assert "SET LOCAL ROLE" not in fixture
    assert "INSERT INTO" not in fixture


def test_pinvi_runtime_command_uses_bounded_generic_failure_evidence() -> None:
    source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )

    assert 'for action in ("build", "up"):' in source
    assert 'runtime / f"pinvi-runtime-{action}-error.json"' in source
    assert "_write_command_failure_evidence(" in source


def test_manager_does_not_require_pinvi_crypto_dependency() -> None:
    pyproject = (Path(__file__).resolve().parents[2] / "backend/pyproject.toml").read_text(
        encoding="utf-8"
    )

    assert "cryptography" not in pyproject


def test_pair_preflight_runs_before_the_one_shot_ledger_claim() -> None:
    """invalid source pair는 ledger를 소비하지 않아 corrected pair를 막지 않는다."""

    source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )
    pair_preflight = source.index("pair, service_openapi_sha256, service_source_revision = _pair(")
    admission_contract = source.index("_assert_pinvi_manager_admission_contract(pinvi_root)")
    ledger_claim = source.index("claim_m05_isolated_harness_ledger(ledger_root=_LEDGER, plan=plan)")

    assert pair_preflight < admission_contract < ledger_claim


def test_isolated_map_override_replaces_the_api_publish_instead_of_resetting_it() -> None:
    source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )
    override_start = source.index('            "  api:",')
    override_end = source.index('            "  frontend:",', override_start)
    api_override = source[override_start:override_end]

    assert '"    ports: !override",' in api_override
    assert '"    ports: !reset",' not in api_override


def test_isolated_map_network_allowlists_the_bridge_gateway_for_host_publish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver()
    monkeypatch.setattr(driver, "_command", lambda *_args, **_kwargs: "")

    subnet, gateway, api, frontend = driver._map_network_addresses("a" * 32)

    # /28 확장 근거는 driver의 _map_network_addresses 주석 참조(app-api join +
    # provider fixture까지 담아야 IPAM 고갈이 없다 — 2026-09-01 적대 리뷰).
    assert subnet == "172.29.170.0/28"
    # 규칙 자체를 고정한다(값 리터럴이 아니라): gateway는 첫 host, 정적
    # api/frontend는 상단 두 host — 하단은 동적 할당(postgres/rustfs 등) 몫.
    # subnet 크기가 바뀌어도 .2/.3 회귀(동적 선점 충돌)를 되박을 수 없다.
    subnet_hosts = list(ipaddress.ip_network(subnet).hosts())
    assert (gateway, api, frontend) == (
        str(subnet_hosts[0]),
        str(subnet_hosts[-1]),
        str(subnet_hosts[-2]),
    )
    assert api not in {str(host) for host in subnet_hosts[:3]}
    assert frontend not in {str(host) for host in subnet_hosts[:3]}
    source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )
    assert '"{map_gateway_ip}/32"' in source


def test_isolated_pinvi_api_uses_the_private_map_network_not_host_loopback() -> None:
    """PinVi worker의 Map service request는 loopback-only publish를 우회하지 않는다."""

    source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )
    pinvi_env_start = source.index("_write_private_text(\n            pinvi_env,")
    pinvi_env_end = source.index("        pinvi_override_lines =", pinvi_env_start)
    pinvi_env = source[pinvi_env_start:pinvi_env_end]
    override_start = source.index("        pinvi_override_lines =", pinvi_env_end)
    override_end = source.index("        _write_private_text(pinvi_override", override_start)
    override = source[override_start:override_end]

    assert 'PINVI_KOR_TRAVEL_MAP_API_BASE_URL=http://{map_api_ip}:13701' in pinvi_env
    assert 'PINVI_KOR_TRAVEL_MAP_ADMIN_BASE_URL=http://{map_api_ip}:13701' in pinvi_env
    assert "host.docker.internal:{ports['map_api']}" not in pinvi_env
    assert '"      default: {}"' in override
    assert '"      m05-map: {}"' in override
    assert '"    external: true"' in override
    assert 'f"    name: {plan.map_network}"' in override


def test_root_launcher_checks_the_m05_pair_before_creating_an_output_leaf() -> None:
    """wrong Map/PinVi provenance은 execution terminal·ledger를 소비하지 않는다."""

    launcher = (Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once").read_text(
        encoding="utf-8"
    )

    pair_preflight = launcher.index("m05_isolated_e2e.py \\")
    output_leaf = launcher.index('install -d -o root -g root -m 0700 "$output_dir"')

    assert pair_preflight < output_leaf


def test_preflight_rejects_a_pair_without_blocking_the_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """launcher preflight은 diagnostic-free failure만 반환하고 mutation을 하지 않는다."""

    driver = _driver()
    calls: list[str] = []
    monkeypatch.setattr(driver, "_validate_trusted_release", lambda _expected: calls.append("release"))
    monkeypatch.setattr(
        driver, "_assert_current_m05_execution_is_runnable", lambda _expected: calls.append("execution")
    )
    monkeypatch.setattr(
        driver,
        "_source_pair_preflight",
        lambda: (_ for _ in ()).throw(driver._PhaseError("pair_contract_invalid")),
    )

    assert driver.preflight("a" * 40) == 1
    assert calls == ["release", "execution"]


def test_driver_pair_failure_before_ledger_never_blocks_the_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """launcher preflight 뒤 source cache가 달라져도 terminal 실행권을 소비하지 않는다."""

    driver = _driver()
    calls: list[str] = []

    class _Current:
        execution_identity_sha256 = "b" * 64

    class _Execution:
        current = _Current()

    class _Plan:
        execution_identity_sha256 = "b" * 64
        labels: dict[str, str] = {}
        map_network = "test-map-network"
        map_project = "test-map-project"

    class _Pair:
        map_source_revision = "c" * 40
        pinvi_source_revision = "d" * 40

    monkeypatch.setattr(driver, "_validate_trusted_release", lambda _expected: None)
    monkeypatch.setattr(
        driver, "_assert_current_m05_execution_is_runnable", lambda _expected: _Execution()
    )
    monkeypatch.setattr(driver, "_root_directory", lambda _path: None)
    monkeypatch.setattr(driver, "_root_file", lambda _path, **_kwargs: None)
    monkeypatch.setattr(driver, "_LEDGER", tmp_path / "ledger")
    monkeypatch.setattr(driver, "M05IsolatedHarnessPlan", lambda *_args: _Plan())
    monkeypatch.setattr(
        driver,
        "_source_pair_preflight",
        lambda: (_ for _ in ()).throw(driver._PhaseError("pair_contract_invalid")),
    )
    monkeypatch.setattr(
        driver,
        "_block_terminal_m05_execution",
        lambda *_args, **_kwargs: calls.append("blocked") or True,
    )

    assert driver.main("a" * 40, tmp_path) == 1
    receipt = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))

    assert calls == []
    assert receipt["status"] == "preflight_rejected"
    assert receipt["phase"] == "pair_contract_invalid"


def _write_map_application_graph(root: Path, *, head: str = "300") -> None:
    """test double의 `map_root`에 Map application migration graph를 놓는다.

    driver는 `source_materialization` phase에서 이 파일을 읽어
    `KOR_TRAVEL_MAP_MIGRATION_EXPECTED_HEAD`를 유도한다. 종전에는 리터럴 `300`이라
    fake `map_root`가 비어 있어도 통과했지만, 그 리터럴이 곧 "Map이 migration을 하나
    더하면 API 컨테이너가 기동을 거부한다"는 뜻이었다.

    실제 materialize된 source에는 이 파일이 **항상** 있다. double을 그에 맞춘다.
    """
    package = root / "src" / "kortravelmap"
    package.mkdir(parents=True, exist_ok=True)
    (package / "_application_migration_graph.json").write_text(
        json.dumps(
            {
                "schema": "kor-travel-map.application-migration-graph.v1",
                "revisions": [{"revision": head, "down_revision": []}],
            }
        ),
        encoding="utf-8",
    )


def test_ledger_claim_attempt_failure_blocks_the_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O_EXCL create 뒤 fsync가 실패해 ledger가 남을 수 있는 경계는 fail-close한다."""

    driver = _driver()
    calls: list[str] = []

    class _Current:
        execution_identity_sha256 = "b" * 64

    class _Execution:
        current = _Current()

    class _Plan:
        execution_identity_sha256 = "b" * 64
        labels: dict[str, str] = {}
        map_network = "test-map-network"
        map_project = "test-map-project"

    class _Pair:
        map_source_revision = "c" * 40
        pinvi_source_revision = "d" * 40

    monkeypatch.setattr(driver, "_validate_trusted_release", lambda _expected: None)
    monkeypatch.setattr(
        driver,
        "_assert_playwright_runner_matches_pinned_source",
        lambda _root: None,
    )
    monkeypatch.setattr(
        driver, "_assert_current_m05_execution_is_runnable", lambda _expected: _Execution()
    )
    monkeypatch.setattr(driver, "_root_directory", lambda _path: None)
    monkeypatch.setattr(driver, "_root_file", lambda _path, **_kwargs: None)
    monkeypatch.setattr(driver, "_LEDGER", tmp_path / "ledger")
    monkeypatch.setattr(driver, "M05IsolatedHarnessPlan", lambda *_args: _Plan())
    _write_map_application_graph(tmp_path)
    monkeypatch.setattr(
        driver,
        "_source_pair_preflight",
        # `state_paths`/`values`/핀 tree도 함께 온다 — body가 일회용 실행 체크아웃을
        # 만들 때 쓴다. 이 테스트는 그 생성을 스텁하므로 통과용 값이면 된다.
        lambda: (tmp_path, tmp_path, _Pair(), "a" * 64, "b" * 40, object(), {}, "c" * 40),
    )
    # 일회용 루트는 봉인 루트와 **달라야** 한다. 같은 값을 돌려주면 실행-루트 치환을
    # 되돌려도 이 테스트가 통과한다(적대 리뷰 BLOCKER-2).
    disposable_root = tmp_path / "pinvi-run"
    disposable_root.mkdir()
    monkeypatch.setattr(
        driver, "materialize_disposable_run_worktree", lambda **_kwargs: disposable_root
    )
    monkeypatch.setattr(driver, "remove_disposable_run_worktree", lambda **_kwargs: None)
    monkeypatch.setattr(
        driver, "assert_pinned_worktree_is_still_sealed", lambda **_kwargs: None
    )
    monkeypatch.setattr(
        driver, "build_m05_isolated_manager_admission", lambda **_kwargs: {}
    )
    compose_arguments: dict[str, object] = {}

    def compose(**kwargs: object) -> str:
        compose_arguments.update(kwargs)
        return "{}"

    monkeypatch.setattr(driver, "_compose", compose)
    monkeypatch.setattr(
        driver, "_assert_rendered_loopback_tcp_publish", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        driver, "_cleanup_temporary_resources", lambda **_kwargs: (False, False, False)
    )
    monkeypatch.setattr(
        driver,
        "claim_m05_isolated_harness_ledger",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("discarded")),
    )
    monkeypatch.setattr(
        driver,
        "_block_terminal_m05_execution",
        lambda *_args, **_kwargs: calls.append("blocked") or True,
    )

    assert driver.main("a" * 40, tmp_path) == 1
    receipt = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))

    assert calls == ["blocked"]
    assert receipt["status"] == "blocked"
    assert receipt["phase"] == "ledger_claim"
    assert isinstance(compose_arguments["failure_evidence_path"], Path)
    assert compose_arguments["failure_evidence_path"].name == (
        "rendered-loopback-publish-error.json"
    )


def test_manager_writes_and_passes_the_private_pinvi_admission_not_an_environment_marker() -> None:
    driver = _driver()
    admission = Path("/private/runtime/pinvi-isolated-manager-admission.json")

    environment = driver._pinvi_manager_admission_environment(
        env_file=Path("/private/runtime/pinvi.env"),
        bootstrap_credential_file=Path("/private/runtime/pinvi-admin.json"),
        project="m05i-pinvi-" + "e" * 32,
        pinvi_source_revision="d" * 40,
        execution_identity_sha256="c" * 64,
        admission_path=admission,
        compose_extra_file=Path("/private/runtime/pinvi.override.yml"),
    )

    assert environment == {
        "PINVI_ENV_FILE": "/private/runtime/pinvi.env",
        # app-api 첫 기동부터 Map network join이 걸리도록 override를 docker-app.sh
        # compose에 겹친다 — reconciliation preflight가 startup에서 Map lease를
        # 소비하므로 override 없는 첫 up은 결정적으로 실패한다(2026-09-01 실측).
        "PINVI_DOCKER_COMPOSE_EXTRA_FILE": "/private/runtime/pinvi.override.yml",
        "PINVI_BOOTSTRAP_ADMIN_CREDENTIAL_FILE": "/private/runtime/pinvi-admin.json",
        "PINVI_DOCKER_PROJECT": "m05i-pinvi-" + "e" * 32,
        "PINVI_SOURCE_REVISION": "d" * 40,
        "PINVI_M05_ISOLATED_MANAGER_ADMISSION_PATH": str(admission),
        "PINVI_M05_PINSET_SHA256": PINNED_RUNTIME_RELEASE.pinset_sha256,
        "PINVI_M05_EXECUTION_IDENTITY_SHA256": "c" * 64,
    }
    assert "PINVI_M05_ISOLATED_MANAGER_HARNESS" not in environment
    assert environment["PINVI_BOOTSTRAP_ADMIN_CREDENTIAL_FILE"] == (
        "/private/runtime/pinvi-admin.json"
    )

    source = (Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py").read_text(
        encoding="utf-8"
    )
    admission_write = source.index("build_m05_isolated_manager_admission(plan=plan, pair=pair)")
    pinvi_up = source.index('str(pinvi_root / "scripts/docker-app.sh"),')

    assert admission_write < pinvi_up
    assert "_pinvi_manager_admission_environment(" in source
    assert '"--isolated-execution-identity-sha256"' in source
    assert "plan.execution_identity_sha256" in source
    assert "PINVI_M05_ISOLATED_MANAGER_HARNESS" not in source


def test_private_json_writer_serializes_immutable_manager_admission(tmp_path: Path) -> None:
    driver = _driver()
    admission = MappingProxyType(
        {
            "kind": "pinvi-m05-isolated-manager-admission-v1",
            "transaction_id": "a" * 32,
            "version": 1,
        }
    )
    path = tmp_path / "pinvi-isolated-manager-admission.json"

    digest = driver._write_private_json(path, admission)

    raw = path.read_bytes()
    assert json.loads(raw) == dict(admission)
    assert digest == hashlib.sha256(raw).hexdigest()


def test_driver_result_keys_match_the_launcher_expected_keys() -> None:
    """driver가 쓰는 result.json 키 집합은 launcher의 exact key-set 검증과 결합돼야 한다.

    phase 어휘는 결합 테스트가 있었지만 키는 없어서, 새 필드 추가가 receipt를
    통째로 무효화(→ scoped 실패의 무조건 승격)하는 회귀가 CI green으로 통과할
    뻔했다(적대 리뷰 critical).
    """

    root = Path(__file__).resolve().parents[2]
    driver_source = (root / "scripts/m05_isolated_e2e.py").read_text(encoding="utf-8")
    launcher = (root / "scripts/run-m05-isolated-e2e-once").read_text(encoding="utf-8")

    base_start = driver_source.index("result: dict[str, object] = {")
    base_end = driver_source.index("}", driver_source.index("(result_hashes if completed"))
    base_block = driver_source[base_start:base_end]
    driver_base_keys = {
        line.split('"')[1]
        for line in base_block.splitlines()
        if line.strip().startswith('"') and '":' in line
    }
    # 조건부 키: map_fresh_init_reason(진단), result_hashes(passed 3종).
    assert 'result["map_fresh_init_reason"]' in driver_source

    base_open = launcher.index("expected_keys = {")
    launcher_base = launcher[base_open : launcher.index("}", base_open) + 1]
    launcher_base_keys = {
        part.strip().strip('"')
        for line in launcher_base.splitlines()
        for part in line.replace("expected_keys = {", "").replace("}", "").split(",")
        if part.strip().strip('"')
    }
    assert driver_base_keys == launcher_base_keys


def test_compose_failure_phase_forwards_command_stderr_and_returncode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """failure_phase 재-fail이 stderr/returncode를 버리면 forensic 일반 증거가
    정확히 가장 실패 확률 높은 compose 경로(postgres/fresh-init)에서 침묵한다
    (적대 리뷰 major)."""

    driver = _driver()

    def fake_command(*_args: str, **_kwargs: object) -> str:
        raise driver._PhaseError(
            "runtime_command_failed", returncode=17, stderr=b"compose boom"
        )

    monkeypatch.setattr(driver, "_command", fake_command)
    with pytest.raises(driver._PhaseError) as caught:
        driver._compose(
            root=Path("/tmp"),
            project="m05i-map-" + "a" * 32,
            env_file=Path("/tmp/none.env"),
            files=(Path("/tmp/a.yml"),),
            arguments=("up", "-d"),
            failure_phase="map_postgres_start_failed",
        )
    assert caught.value.phase == "map_postgres_start_failed"
    assert caught.value.returncode == 17
    assert caught.value.stderr == b"compose boom"


def test_forensic_mode_captures_stderr_without_per_call_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """forensic env가 켜지면 opt-in 없는 _command 실패도 stderr를 싣는다."""

    driver = _driver()
    monkeypatch.setenv("KTDM_M05_FORENSIC_CAPTURE", "1")
    with pytest.raises(driver._PhaseError) as caught:
        driver._command("/usr/bin/bash", "-c", "echo boom-evidence >&2; exit 3")
    assert caught.value.phase == "runtime_command_failed"
    assert caught.value.returncode == 3
    assert caught.value.stderr is not None
    assert b"boom-evidence" in caught.value.stderr


def test_scrub_registry_covers_env_kwarg_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """os.environ에 없는 env-kwarg 비밀도 레지스트리 경유로 scrub된다
    (적대 리뷰: environ 기반 scrub은 프로덕션에서 no-op였다)."""

    driver = _driver()
    secret = "registry-secret-0123456789abcdef"
    monkeypatch.delenv("M05_PINVI_PASSWORD", raising=False)
    monkeypatch.setattr(driver, "_FORENSIC_SCRUB_VALUES", {}, raising=True)
    driver._register_forensic_scrub_environment({"M05_PINVI_PASSWORD": secret})
    scrubbed = driver._scrub_forensic_bytes(b"prefix " + secret.encode() + b" suffix")
    assert secret.encode() not in scrubbed
    assert b"[scrubbed:M05_PINVI_PASSWORD]" in scrubbed


def test_rendered_service_images_use_explicit_image_or_compose_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """이미지 참조는 rendered Compose 모델이 정본이다 — 이름 추측은 PinVi처럼
    명시 image를 쓰는 compose에서 성립하지 않고(e2e8 forensic), 컨테이너 ID
    파생은 identity 검증을 X != X로 퇴화시킨다(적대 리뷰)."""

    driver = _driver()
    rendered = {
        "services": {
            "app-api": {"image": "pinvi-api:local"},
            "app-web": {"image": "pinvi-web:local"},
            "app-dagster": {"image": "pinvi-dagster:local"},
            "plain": {},
        }
    }
    captured: dict[str, object] = {}

    def fake_compose(**kwargs: object) -> str:
        captured.update(kwargs)
        return json.dumps(rendered)

    monkeypatch.setattr(driver, "_compose", fake_compose)
    references = driver._rendered_service_images(
        root=Path("/tmp"),
        project="m05i-pinvi-" + "a" * 32,
        env_file=Path("/tmp/none.env"),
        files=(Path("/tmp/a.yml"),),
        services=("app-api", "app-web", "app-dagster", "plain"),
        profiles=("etl",),
    )
    assert references["app-api"] == "pinvi-api:local"
    assert references["plain"] == "m05i-pinvi-" + "a" * 32 + "-plain"
    assert captured["arguments"] == (
        "--profile",
        "etl",
        "config",
        "--format",
        "json",
    )


def test_app_dagster_container_is_resolved_once_with_the_etl_profile() -> None:
    """프로파일 없는 app-dagster ps는 빈 결과로 body 진입 후 무조건 소각을
    만든다 — 정확히 한 번, etl 프로파일과 함께만 조회한다(적대 리뷰 critical:
    프로파일 없는 중복 조회가 남아 있었다)."""

    source = (
        Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py"
    ).read_text(encoding="utf-8")
    occurrences = [
        index
        for index in range(len(source))
        if source.startswith('"app-dagster",\n            root=', index)
    ]
    assert len(occurrences) == 1
    window = source[occurrences[0] : occurrences[0] + 300]
    assert 'profiles=("etl",)' in window


def test_compose_model_profiles_are_derived_not_hardcoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cleanup 프로파일은 compose 모델에서 파생한다 — 상대 레포 프로파일
    이름을 Manager에 리터럴로 박으면 프로파일 추가마다 잔존 컨테이너가
    cleanup 검증을 깨뜨린다(e2e6 클래스, 범용성 지시)."""

    driver = _driver()
    captured: dict[str, object] = {}

    def fake_command(*args: str, **kwargs: object) -> str:
        captured["args"] = args
        captured.update(kwargs)
        return "etl\nobservability\n\netl\n"

    monkeypatch.setattr(driver, "_command", fake_command)
    profiles = driver._compose_model_profiles(
        root=Path("/tmp"),
        project="m05i-pinvi-" + "a" * 32,
        env_file=Path("/tmp/none.env"),
        files=(Path("/tmp/a.yml"),),
    )
    assert profiles == ("etl", "observability")
    args = captured["args"]
    assert isinstance(args, tuple)
    assert args[-2:] == ("config", "--profiles")
    # 파생 출력은 상한을 갖는다(무제한 stdout 누적 금지 — 적대 리뷰).
    assert captured["capture_output_limit"] == driver._COMPOSE_CONFIG_OUTPUT_LIMIT

    def hostile_command(*_args: str, **_kwargs: object) -> str:
        return "etl\n--rm\n"

    monkeypatch.setattr(driver, "_command", hostile_command)
    with pytest.raises(driver._PhaseError, match="runtime_inspect_invalid"):
        driver._compose_model_profiles(
            root=Path("/tmp"),
            project="m05i-pinvi-" + "a" * 32,
            env_file=Path("/tmp/none.env"),
            files=(Path("/tmp/a.yml"),),
        )

    source = (
        Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py"
    ).read_text(encoding="utf-8")
    # cleanup 등록부에 프로파일 리터럴이 되살아나지 못하게 한다.
    assert 'map_files, ("fresh-init",)' not in source
    assert 'pinvi_files, ("etl",)' not in source
    assert source.count("_compose_model_profiles(") >= 3

def _exception_sink_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, forensic: bool
) -> Path:
    driver = _driver()
    if forensic:
        monkeypatch.setenv("KTDM_M05_FORENSIC_CAPTURE", "1")
    else:
        monkeypatch.delenv("KTDM_M05_FORENSIC_CAPTURE", raising=False)
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(ValueError("boom-ordinary")),
    )
    monkeypatch.setattr(
        driver, "_cleanup_temporary_resources", lambda **_kwargs: (False, False, False)
    )
    monkeypatch.setattr(
        driver, "_block_terminal_m05_execution", lambda *_a, **_k: True
    )
    assert driver.main("a" * 40, tmp_path) == 1
    return tmp_path / "failed-admission-exception.txt"


def test_ordinary_exception_leaves_forensic_traceback_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """e2e9 클래스: 익명 ordinary exception도 forensic leaf에 traceback을 남긴다.

    파일명은 raw phase가 아니라 public phase 매핑이고, receipt에는 여전히
    phase만 실린다."""

    evidence = _exception_sink_run(tmp_path, monkeypatch, forensic=True)
    assert evidence.exists()
    text = evidence.read_bytes()
    assert b"boom-ordinary" in text
    assert b"Traceback" in text
    receipt = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert receipt["phase"] == "admission"
    assert "traceback" not in json.dumps(receipt).lower()


def test_ordinary_exception_without_forensic_leaves_no_traceback_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = _exception_sink_run(tmp_path, monkeypatch, forensic=False)
    assert not evidence.exists()


def test_traceback_evidence_write_failure_does_not_change_the_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver()
    monkeypatch.setenv("KTDM_M05_FORENSIC_CAPTURE", "1")
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(ValueError("boom-ordinary")),
    )
    monkeypatch.setattr(
        driver, "_cleanup_temporary_resources", lambda **_kwargs: (False, False, False)
    )
    monkeypatch.setattr(
        driver, "_block_terminal_m05_execution", lambda *_a, **_k: True
    )
    original_writer = driver._write_private_bytes

    def failing_evidence_writer(path: Path, raw: bytes) -> None:
        # traceback leaf 기록만 실패시키고 receipt(result.json) 기록은 살린다.
        if path.name.endswith("-exception.txt"):
            raise OSError("disk")
        original_writer(path, raw)

    monkeypatch.setattr(driver, "_write_private_bytes", failing_evidence_writer)
    assert driver.main("a" * 40, tmp_path) == 1
    assert not (tmp_path / "failed-admission-exception.txt").exists()
    receipt = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert receipt["phase"] == "admission"


def test_playwright_runner_guarantee_precedes_the_ledger_claim() -> None:
    """runner 핀 digest 존재·버전 정합 보장은 실행권 소비 **전**이어야 한다.

    claim 뒤로 밀리는 리팩터 회귀의 비용은 immutable candidate 1개 소각
    (e2e13 실측)이다. 아울러 runner 핀과 pinned playwright-core 버전의
    기계 결박이 소스에 있는지도 고정한다(적대 리뷰: 두 사람-선언 핀은
    독립적으로 어긋난다 — v1.60.0 digest vs 1.62.1 lockfile 실측)."""

    source = (
        Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py"
    ).read_text(encoding="utf-8")
    inspect_at = source.index('"image", "inspect", _PLAYWRIGHT_RUNNER_IMAGE')
    version_bind_at = source.index("/ms-playwright/.docker-info")
    claim_at = source.index("claim_m05_isolated_harness_ledger(")
    assert inspect_at < claim_at
    assert version_bind_at < claim_at
    assert "runner driverVersion != pinned playwright-core" in source


def test_manual_feature_uuid_resolves_to_text_id_via_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """승인 UUID(T-VN-32C)는 M02 provenance로 opaque TEXT id로 해석돼야 한다.

    dedup 프로시저는 feature.features.feature_id(TEXT)를 기대한다 — UUID를
    그대로 넘기면 NOT FOUND가 'proof is not eligible'로 위장한다(e2e15 실측)."""

    driver = _driver()
    feature_uuid = "01a05b4c-dc60-7444-95a4-98fde8aeb782"

    def fake_http_json(url: str, **kwargs: object) -> dict[str, object]:
        assert url.endswith(f"/v1/admin/features/{feature_uuid}/creation-provenance")
        headers = kwargs.get("headers")
        assert isinstance(headers, dict)
        # 직접 admin 호출은 proxy secret 헤더가 계약이다 — 빠지는 회귀를 고정.
        assert any("Proxy-Secret" in key for key in headers)
        assert kwargs.get("failure_phase") == "m04_map_feature_ref_resolve_failed"
        return {
            "data": {
                "feature_id": "f_manual_abc123",
                "feature_uuid": feature_uuid,
            }
        }

    monkeypatch.setattr(driver, "_http_json", fake_http_json)
    resolved = driver._resolve_manual_feature_text_id(
        admin_url="http://127.0.0.1:20001",
        proxy_secret="s" * 32,
        feature_uuid=feature_uuid,
    )
    assert resolved == "f_manual_abc123"

    def detached_http_json(url: str, **_kwargs: object) -> dict[str, object]:
        # 실제 결박 붕괴 시나리오: 형태는 유효하지만 다른 UUID가 돌아온다.
        return {
            "data": {
                "feature_id": "f_manual_abc123",
                "feature_uuid": "0e0e0e0e-0e0e-70e0-8e0e-0e0e0e0e0e0e",
            }
        }

    monkeypatch.setattr(driver, "_http_json", detached_http_json)
    with pytest.raises(driver._PhaseError, match="m04_map_approval_invalid"):
        driver._resolve_manual_feature_text_id(
            admin_url="http://127.0.0.1:20001",
            proxy_secret="s" * 32,
            feature_uuid=feature_uuid,
        )


def test_manual_feature_resolution_rejects_missing_text_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver()
    feature_uuid = "01a05b4c-dc60-7444-95a4-98fde8aeb782"
    monkeypatch.setattr(
        driver,
        "_http_json",
        lambda *_a, **_k: {"data": {"feature_id": "", "feature_uuid": feature_uuid}},
    )
    with pytest.raises(driver._PhaseError, match="m04_map_approval_invalid"):
        driver._resolve_manual_feature_text_id(
            admin_url="http://127.0.0.1:20001",
            proxy_secret="s" * 32,
            feature_uuid=feature_uuid,
        )


def test_launcher_preflight_phases_mirror_the_driver_pre_claim_set() -> None:
    """pre-claim phase 집합이 driver와 launcher에서 갈라지면, 재시도 가능한
    실패가 무조건 소각으로 승격된다(2026-09-01 full-path 시뮬레이션 적발:
    launcher는 5개만 알았고 driver는 12개 phase로 pre-claim 종료할 수 있었다).

    _PUBLIC_TERMINAL_PHASES ↔ launcher PHASES와 같은 미러 결박 규약이다."""

    root = Path(__file__).resolve().parents[2]
    driver_source = (root / "scripts/m05_isolated_e2e.py").read_text(encoding="utf-8")
    launcher = (root / "scripts/run-m05-isolated-e2e-once").read_text(encoding="utf-8")

    def literal(source: str, name: str) -> set[str]:
        start = source.index(f"{name} = frozenset(")
        end = source.index(")", source.index("}", start)) + 1
        return set(re.findall(r'"([a-z0-9_]+)"', source[start:end]))

    driver_pre_claim = literal(driver_source, "_PRE_CLAIM_PHASES")
    launcher_pre_claim = literal(launcher, "PREFLIGHT_REJECTED_PHASES")
    assert driver_pre_claim == launcher_pre_claim

    # pre-claim 집합은 공개 어휘의 부분집합이어야 하고, 무조건 소각 phase를
    # 포함해서는 안 된다(그것들은 정의상 claim 이후다).
    public = literal(driver_source, "_PUBLIC_TERMINAL_PHASES")
    assert driver_pre_claim <= public
    unconditional = literal(driver_source, "_UNCONDITIONAL_TERMINAL_PHASES")
    assert not (driver_pre_claim & unconditional)

    # 이번에 추가된 runner 이미지 보장 단계가 실제로 포함돼야 한다(#289 전제).
    assert "runtime_setup_playwright_runner_image" in driver_pre_claim

    # claim 이후에만 도달 가능한 phase는 절대 들어오면 안 된다 — 들어오면
    # "실행권 미소비" 주장을 소비 증명 phase와 함께 통과시킨다(적대 리뷰 major).
    post_claim_only = {
        # claim 바로 다음 줄에서 대입된다.
        "runtime_setup_pinvi_config",
        # 전 호출부(_compose_model_profiles/_rendered_service_images/
        # _container_inspect/map_runtime)가 claim 이후다.
        "runtime_inspect_invalid",
        # finally 강등으로만 생기며 driver_phase != phase가 되어 launcher가
        # 이미 별도로 거부한다(= 이 목록에 있으면 죽은 항목).
        "runtime_cleanup_failed",
    }
    assert not (driver_pre_claim & post_claim_only)
    claim_at = driver_source.index("claim_m05_isolated_harness_ledger(ledger_root=")
    for phase in sorted(post_claim_only - {"runtime_cleanup_failed"}):
        marker = f'"{phase}"'
        assert driver_source.index(marker, claim_at) > claim_at


def test_pinvi_receipt_wait_retries_only_the_not_yet_arrived_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Map decision commit과 PinVi worker polling 사이 창은 404다 — 그것만
    재시도하고 다른 status·blocked·계약 위반은 즉시 terminal이어야 한다.

    PinVi detail 계약의 status는 blocked|applied 두 값뿐이라 'pending' 응답은
    존재하지 않는다(적대 리뷰 — 종전 구현은 없는 상태를 재시도하고 있었다)."""

    driver = _driver()
    monkeypatch.setattr(driver.time, "sleep", lambda _s: None)
    calls = {"n": 0}

    def not_ready_then_applied(*_args: object, **kwargs: object) -> dict[str, object]:
        calls["n"] += 1
        assert kwargs.get("not_found_phase") == "m05_pinvi_receipt_not_ready"
        if calls["n"] < 3:
            raise driver._PhaseError("m05_pinvi_receipt_not_ready")
        return {"data": {"status": "applied", "receipt": {"impact_count": 3}}}

    monkeypatch.setattr(driver, "_http_json", not_ready_then_applied)
    assert (
        driver._wait_for_pinvi_receipt(
            api_url="http://127.0.0.1:20001", opener=None, event_id="e" * 32
        )
        == 3
    )
    assert calls["n"] == 3

    attempts = {"n": 0}

    def forbidden(*_args: object, **_kwargs: object) -> dict[str, object]:
        attempts["n"] += 1
        raise driver._PhaseError("m05_pinvi_receipt_http_failed")

    monkeypatch.setattr(driver, "_http_json", forbidden)
    with pytest.raises(driver._PhaseError, match="m05_pinvi_receipt_http_failed"):
        driver._wait_for_pinvi_receipt(
            api_url="http://127.0.0.1:20001", opener=None, event_id="e" * 32
        )
    assert attempts["n"] == 1

    monkeypatch.setattr(
        driver, "_http_json", lambda *_a, **_k: {"data": {"status": "blocked"}}
    )
    with pytest.raises(driver._PhaseError, match="m05_pinvi_receipt_blocked"):
        driver._wait_for_pinvi_receipt(
            api_url="http://127.0.0.1:20001", opener=None, event_id="e" * 32
        )

    source = (
        Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py"
    ).read_text(encoding="utf-8")
    assert "_PINVI_RECONCILIATION_POLL_SECONDS}" in source
    assert "_POLL_SECONDS=1" not in source


def test_free_form_diagnostic_is_omitted_from_the_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """자유형 진단은 receipt에 실리지 않고 launcher가 그 receipt를 수용해야 한다.

    종전 이 테스트는 소스 문자열과 들여쓰기를 결박해 실제 동작을 보지 않았고,
    올바른 후속 수정(phase 게이트)까지 막았다(적대 리뷰 MINOR-3)."""

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(
            driver._PhaseError(
                "source_materialization", diagnostic="map application graph unavailable"
            )
        ),
    )
    monkeypatch.setattr(
        driver,
        "_block_terminal_m05_execution",
        lambda *_a, **_k: pytest.fail("preclaim failure must not block execution"),
    )
    assert driver.main("a" * 40, tmp_path) == 1

    result_path = tmp_path / "result.json"
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    assert "map_fresh_init_reason" not in receipt
    assert receipt["phase"] == "source_materialization"
    assert _validate_receipt(result_path, driver_status=1) == 4


def test_fresh_init_reason_is_only_carried_for_a_fresh_init_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """어휘 안의 단어라도 fresh-init 실패가 아니면 싣지 않는다.

    diagnostic은 _command/_compose의 **범용** 채널이라, 다른 호출부가 겹치는
    단어를 쓰는 exit map을 넘기는 순간 무관한 실패에 fresh-init 사유가 붙는다
    (적대 리뷰 MAJOR-2)."""

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(
            driver._PhaseError("source_materialization", diagnostic="alembic_command_failed")
        ),
    )
    monkeypatch.setattr(
        driver,
        "_block_terminal_m05_execution",
        lambda *_a, **_k: pytest.fail("preclaim failure must not block execution"),
    )
    assert driver.main("a" * 40, tmp_path) == 1

    receipt = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert "map_fresh_init_reason" not in receipt


_LAUNCHER_PATH = Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once"

# launcher heredoc 경계 — 백슬래시 조립으로 리터럴 이스케이프 붕괴를 피한다.
LAUNCHER_HEREDOC_MARKER = '"$driver_status" <<' + chr(39) + "PY" + chr(39) + chr(10)
HEREDOC_TERMINATOR = chr(10) + "PY" + chr(10)



def _preclaim_phases_reachable_from_validate_trusted_release() -> set[str]:
    """_validate_trusted_release 실패로 재현 가능한 pre-claim phase 표본.

    driver를 실제로 돌려야 하므로 첫 실패 지점 하나로 전 phase를 대표시킨다 —
    receipt를 만드는 코드 경로는 phase 값과 무관하게 동일하다.
    """

    driver = _driver()
    return set(driver._PRE_CLAIM_PHASES)

# ---------------------------------------------------------------------------
# launcher receipt 검증기를 **실제로 실행**하는 행동 테스트
#
# 종전의 launcher 결합 테스트는 전부 read_text() + 부분 문자열이었다. 그래서
# driver가 만든 result.json이 launcher에 실제로 수용되는지는 **CI가 한 번도
# 확인한 적이 없다** — #293/#295와 BLOCKER-1/2가 모두 손으로 돌린 시뮬레이션에서
# 나온 이유다(적대 리뷰 MAJOR-3). 아래 테스트는 launcher heredoc에서 검증기를
# 잘라내 실제 receipt를 먹인다.
# ---------------------------------------------------------------------------


def _extract_launcher_validator() -> str:
    launcher = (
        Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once"
    ).read_text(encoding="utf-8")
    marker = LAUNCHER_HEREDOC_MARKER
    start = launcher.index(marker) + len(marker)
    end = launcher.index(HEREDOC_TERMINATOR, start)
    source = launcher[start:end]
    # 비-root 테스트에서 재사용할 수 있게 **root 소유 단언만** 완화한다.
    # 정규 파일 / 모드 0600 / nlink / 스키마 검증은 launcher 원문 그대로 남는다.
    assert "metadata.st_uid != 0" in source
    return source.replace("metadata.st_uid != 0", "False", 1)


def _validate_receipt(
    result_path: Path,
    *,
    driver_status: int,
    expected: tuple[str, str, str] | None = None,
) -> int:
    """launcher 검증기를 실제로 돌린다.

    `expected`를 주지 않으면 launch snapshot이 receipt와 일치하는 경우를
    재현한다. authority(Tier 1) 변조를 시험할 때는 **고정 기대값**을 넘겨야
    한다 — receipt에서 읽으면 변조가 기대값도 함께 바꿔 무효가 된다."""

    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    revision, pinset, execution = expected or (
        receipt["manager_source_revision"],
        receipt["pinset_sha256"],
        receipt["execution_identity_sha256"],
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            _extract_launcher_validator(),
            str(result_path),
            str(revision),
            str(pinset),
            str(execution),
            str(driver_status),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return completed.returncode


def _run_driver_failing_at(
    phase: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """`phase`에서 claim 전에 죽는 driver run을 실제로 실행한다."""

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(driver._PhaseError(phase)),
    )
    monkeypatch.setattr(
        driver,
        "_block_terminal_m05_execution",
        lambda *_a, **_k: pytest.fail("preclaim failure must not block execution"),
    )
    assert driver.main("a" * 40, tmp_path) == 1
    return tmp_path / "result.json"


@pytest.mark.parametrize(
    "phase",
    sorted(_preclaim_phases_reachable_from_validate_trusted_release()),
)
def test_every_preclaim_phase_receipt_is_accepted_as_scoped_by_the_launcher(
    phase: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """claim 전 실패는 launcher가 exit 4(무소비)로 받아야 한다.

    받지 못하면 launcher는 `ktdctl pin block-execution`으로 흘러 **아무것도
    소비하지 않은 실행을 소각**한다. driver와 launcher가 phase 집합을 서로
    미러링하고 있어도, 다른 필드가 receipt를 먼저 죽이면 그 미러는 문 앞의
    벽을 지키는 셈이다(적대 리뷰: execution identity가 null이라 열 개 phase가
    exit 4에 도달할 수 없었다)."""

    result_path = _run_driver_failing_at(phase, tmp_path, monkeypatch)
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "preflight_rejected"
    assert receipt["execution_identity_sha256"] is not None
    assert _validate_receipt(result_path, driver_status=1) == 4


def test_preclaim_receipt_with_a_cleanup_hiccup_is_not_escalated_to_a_burn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cleanup 딸꾹질이 겹쳐도 무소비 실행이 소각되면 안 된다."""

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(driver._PhaseError("admission")),
    )
    monkeypatch.setattr(driver, "_cleanup_temporary_resources", lambda **_k: (True, False, False))
    monkeypatch.setattr(driver, "_block_terminal_m05_execution", lambda *_a, **_k: True)
    assert driver.main("a" * 40, tmp_path) == 1

    result_path = tmp_path / "result.json"
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "preflight_rejected"
    assert receipt["cleanup_failed"] is True
    # cleanup_failed는 진단(Tier 2)이므로 exit 5(저하)까지만 간다 — 소각(1) 아님.
    assert _validate_receipt(result_path, driver_status=1) == 5


def test_tier_two_divergence_never_reaches_the_unconditional_burn_value(
    tmp_path: Path
) -> None:
    """진단 계층 불일치는 exit 1(정체불명 crash)로 접히면 안 된다.

    Tier 1(harness·revision·pinset·execution identity·status·transaction)이
    모두 일치하면 receipt는 이 launch의 것으로 증명된 것이고, phase 어휘를
    모른다는 이유로 "receipt가 아예 없다"와 같은 값으로 접으면 관측자의
    딸꾹질이 피관측자를 태운다(적대 리뷰 Part A)."""

    base = {
        "harness": "m05-isolated-bridge-v1",
        "manager_source_revision": "a" * 40,
        "pinset_sha256": "b" * 64,
        "execution_identity_sha256": "c" * 64,
        "status": "preflight_rejected",
        "transaction_id": "d" * 32,
        "phase": "admission",
        "driver_phase": "admission",
        "cleanup_failed": False,
    }
    for label, mutate in (
        ("unknown phase", {"phase": "totally_unknown", "driver_phase": "totally_unknown"}),
        ("extra key", {"unexpected_field": "x"}),
        ("phase mismatch", {"driver_phase": "source_materialization"}),
        ("cleanup flag", {"cleanup_failed": True}),
        ("free-form reason", {"map_fresh_init_reason": "runner driverVersion != pinned"}),
    ):
        payload = dict(base)
        payload.update(mutate)
        path = tmp_path / f"{label.replace(' ', '_')}.json"
        raw = (json.dumps(payload, sort_keys=True) + chr(10)).encode("utf-8")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, raw)
        finally:
            os.close(descriptor)
        assert _validate_receipt(path, driver_status=1) == 5, label


def test_authority_divergence_still_fails_closed(tmp_path: Path) -> None:
    """Tier 1이 어긋나면 여전히 exit 1(소각)이어야 한다 — 과도 완화 방지 가드."""

    base = {
        "harness": "m05-isolated-bridge-v1",
        "manager_source_revision": "a" * 40,
        "pinset_sha256": "b" * 64,
        "execution_identity_sha256": "c" * 64,
        "status": "preflight_rejected",
        "transaction_id": "d" * 32,
        "phase": "admission",
        "driver_phase": "admission",
        "cleanup_failed": False,
    }
    for label, mutate in (
        ("foreign harness", {"harness": "other-harness-v1"}),
        ("foreign revision", {"manager_source_revision": "e" * 40}),
        ("foreign pinset", {"pinset_sha256": "e" * 64}),
        ("null identity", {"execution_identity_sha256": None}),
        ("unknown status", {"status": "made_up"}),
        ("short transaction", {"transaction_id": "d" * 31}),
    ):
        payload = dict(base)
        payload.update(mutate)
        path = tmp_path / f"auth_{label.replace(' ', '_')}.json"
        raw = (json.dumps(payload, sort_keys=True) + chr(10)).encode("utf-8")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, raw)
        finally:
            os.close(descriptor)
        assert (
            _validate_receipt(
                path,
                driver_status=1,
                expected=(base["manager_source_revision"], base["pinset_sha256"], base["execution_identity_sha256"]),
            )
            == 1
        ), label


def test_unobservable_snapshot_still_reads_the_receipt(tmp_path: Path) -> None:
    """관측 실패는 snapshot 등가 **게이트만** 무효화해야 한다.

    종전 구현은 `|| true`로 관측 실패 신호를 지워 receipt를 읽어보지도 않고
    태웠다. 그걸 '안 태운다'로만 바꾸면 더 나쁘다 — driver가 본문 진입 뒤
    하드 크래시하면 원장에 block이 없고 `pin verify`가 '실행 가능'을 보고하며
    원장 claim은 재시도를 허용하므로, 운영자가 문서대로 재실행하면 **본문이
    두 번 돈다**(적대 리뷰 BLOCKER).

    올바른 형태는 셋 다다: 관측 실패를 회전과 구분해 알리고, receipt는 그대로
    읽고, 결박에 실패하면 종전대로 소각으로 떨어진다.
    """

    launcher = _LAUNCHER_PATH.read_text(encoding="utf-8")
    start = launcher.index("snapshot_pair() {")
    end = launcher.index('  /usr/bin/python3 -I -S - ' + chr(34), start)
    if end < start:
        raise AssertionError("관측 구간을 찾지 못했다")
    observation = launcher[start:end]

    # 잘라낸 구간이 실제로 재시도·백오프·게이트 우회를 담고 있어야 한다 —
    # 아니면 아래 스텁이 무언의 no-op을 통과시킨다.
    assert "for _attempt in 1 2; do" in observation
    assert "sleep 1" in observation
    assert "unobservable" in observation

    prelude = [
        "set -euo pipefail",
        "sleep() { :; }",
        "snapshot_runtime_pin() { if [ -f \"$FAIL\" ]; then return 1; fi; echo pin; }",
        "snapshot_runtime_execution() { if [ -f \"$FAIL\" ]; then return 1; fi; echo exec; }",
        "initial_snapshot=pin",
        "initial_execution_snapshot=exec",
        "launcher_result_path=$TMP/absent.json",
    ]
    script = tmp_path / "observe.sh"
    script.write_text(
        chr(10).join(prelude)
        + chr(10)
        + observation
        + "  echo REACHED_VALIDATOR" + chr(10)
        + "fi" + chr(10),
        encoding="utf-8",
    )

    def run(*, failing: bool) -> subprocess.CompletedProcess[str]:
        marker = tmp_path / "fail"
        if failing:
            marker.write_text("x", encoding="utf-8")
        elif marker.exists():
            marker.unlink()
        return subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env={**os.environ, "FAIL": str(marker), "TMP": str(tmp_path)},
        )

    healthy = run(failing=False)
    assert healthy.returncode == 0, healthy.stderr
    assert "REACHED_VALIDATOR" in healthy.stdout
    assert "unobservable" not in healthy.stderr

    unobservable = run(failing=True)
    # 핵심: 관측이 안 돼도 **검증기에 도달한다**. 그래야 receipt가 읽히고,
    # 결박 실패면 종전대로 소각으로 떨어진다.
    assert unobservable.returncode == 0, unobservable.stderr
    assert "REACHED_VALIDATOR" in unobservable.stdout
    # 그리고 그 사실이 회전과 구분돼 남는다.
    assert "unobservable" in unobservable.stderr


def test_snapshot_observation_failure_is_never_silently_discarded() -> None:
    """관측 함수의 실패 신호를 버리는 형태가 되돌아오면 안 된다."""

    launcher = _LAUNCHER_PATH.read_text(encoding="utf-8")
    after_driver = launcher[launcher.index('driver_status=\"$?\"') :]
    observation = after_driver[: after_driver.index('  /usr/bin/python3 -I -S - ' + chr(34))]
    # 실패를 삼키는 어떤 형태도 남아 있으면 안 된다 — `|| true`뿐 아니라
    # `|| :` / `|| echo` 같은 등가 퇴행도 잡는다(적대 리뷰 m-4).
    code = chr(10).join(
        line for line in observation.splitlines() if not line.lstrip().startswith("#")
    )
    for swallow in ("|| true", "|| :", "|| echo"):
        assert swallow not in code, swallow
    # ktdctl 호출은 락을 쥔 채 무기한 대기하면 안 된다.
    assert launcher.count(chr(39).join(['timeout 30 "$ktdctl" pin'])) >= 4


def test_directory_fsync_failure_never_changes_the_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """부차적 durability 단계의 실패가 이미 성공한 쓰기를 되돌리면 안 된다.

    종전에는 디렉터리 fsync의 OSError가 그대로 전파돼 호출부의
    `except (OSError, _PhaseError): return 1`에 걸렸다. 그러면 디스크에
    `status=passed, phase=completed` receipt가 멀쩡히 있는데 driver가 1을
    반환하고, launcher Tier 1의 `(status==passed) != (driver_status==0)`가
    걸려 **통과한 1~2시간 실행이 무조건 소각된다**.

    이 규칙의 정본은 services/secure_state_file.fsync_directory다(GM-10).
    """

    driver = _driver()
    target = tmp_path / 'receipt.json'

    real_open = driver.os.open

    def failing_directory_open(path: object, flags: int, *args: object) -> int:
        if flags & driver.os.O_DIRECTORY:
            raise OSError(5, "simulated directory open failure")
        return real_open(path, flags, *args)

    monkeypatch.setattr(driver.os, "open", failing_directory_open)
    driver._write_private_bytes(target, b"payload\\n")

    # 쓰기는 성공했고 파일은 그대로다 — 부차 단계의 실패가 아무것도 되돌리지 않는다.
    assert target.read_bytes() == b"payload\\n"

    real_fsync = driver.os.fsync
    directory_fds: list[int] = []

    def failing_directory_fsync(descriptor: int) -> None:
        if descriptor in directory_fds:
            raise OSError(5, "simulated directory fsync failure")
        real_fsync(descriptor)

    def recording_open(path: object, flags: int, *args: object) -> int:
        descriptor = real_open(path, flags, *args)
        if flags & driver.os.O_DIRECTORY:
            directory_fds.append(descriptor)
        return descriptor

    monkeypatch.setattr(driver.os, "open", recording_open)
    monkeypatch.setattr(driver.os, "fsync", failing_directory_fsync)
    second = tmp_path / 'second.json'
    driver._write_private_bytes(second, b"payload\\n")
    assert second.read_bytes() == b"payload\\n"


def test_passing_run_survives_a_directory_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """claim 마커는 receipt를 못 읽을 때의 소비 판정 근거다 — 반드시 남아야 한다."""

    source = (
        Path(__file__).resolve().parents[2] / 'scripts/m05_isolated_e2e.py'
    ).read_text(encoding="utf-8")

    # claim 직후에 마커를 남긴다 — launcher가 receipt 부재 시 이걸로
    # "실행권을 소비했는가"를 판정한다.
    claim = source.index('claim_m05_isolated_harness_ledger(ledger_root=')
    marker = source.index('_write_private_bytes(output / "claimed"')
    assert marker > claim
    tail = source[claim:marker]
    # 사이에 실패 가능한 문장이 끼면 claim과 마커가 갈라진다.
    assert "_fail(" not in tail

    launcher = _LAUNCHER_PATH.read_text(encoding='utf-8')
    assert '[[ ! -e "$output_dir/claimed" ]]' in launcher


def _rotation_contract(*, admin: str, full: str, version: int = 1) -> bytes:
    """회전 게이트가 읽는 최소 계약 봉투.

    `version`이 필수다 — 실제 계약은 항상 갖고 있고, dual-read가 그 값으로
    v1/v2를 가른다.
    """

    return json.dumps(
        {
            "map": {
                "admin": {"source_revision": admin},
                "full": {"source_revision": full},
            },
            "version": version,
        }
    ).encode("utf-8")


#: 회전 대상 Map revision이 내놓는다고 가정하는 표면 blob. 실제 파일 내용이
#: 무엇이든 상관없다 — 게이트가 보는 것은 "계약의 digest == blob의 digest"다.
#: 회전 **대상** Map revision. pinned와 다른 값이어야 게이트가 무엇에 앵커돼 있는지
#: 드러난다 — pinned로 읽어도 통과하는 구현은 이 게이트의 목적을 잃은 것이다.
_ROTATION_MAP_REVISION = "a" * 40
_ROTATION_MAP_BLOB = b'{"openapi":"3.1.0"}'
_ROTATION_MAP_DIGEST = hashlib.sha256(_ROTATION_MAP_BLOB).hexdigest()


def _rotation_contract_v2(**overrides: str) -> bytes:
    """v2 봉투 — revision 선언이 없고 네 표면의 digest만 있다."""

    digests = dict.fromkeys(
        ("admin", "full", "service", "user"), _ROTATION_MAP_DIGEST
    )
    digests.update(overrides)
    return json.dumps(
        {
            "map": {name: {"openapi_sha256": digest} for name, digest in digests.items()},
            "version": 2,
        }
    ).encode("utf-8")


def _rotation_map_blobs(
    driver, monkeypatch, *, readable: bool = True
) -> tuple[list[str], list[tuple[str, ...]]]:
    """회전 대상 Map revision의 blob 읽기를 대역으로 바꾸고 **대상을 기록**한다.

    `subprocess`를 모듈 속성으로 갈아끼운다 — 실제 `subprocess.run`을 monkeypatch
    하면 같은 인터프리터의 다른 코드까지 함께 바뀐다.

    반환하는 두 리스트는 게이트가 **무엇을** 읽었는지를 담는다. digest 비교만
    단언하면 저장소·revision·경로를 잘못 지목해도 초록이다(2차 적대 리뷰).
    """

    reads: list[str] = []
    fetches: list[tuple[str, ...]] = []

    class _Result:
        returncode = 0 if readable else 128
        stdout = _ROTATION_MAP_BLOB if readable else b""

    class _Subprocess:
        PIPE = -1
        DEVNULL = -3

        @staticmethod
        def run(args: list[str], **_kwargs: object) -> object:
            reads.append(args[-1])
            return _Result()

    monkeypatch.setattr(driver, "subprocess", _Subprocess)
    return reads, fetches


def _run_rotation_preflight(
    monkeypatch,
    *,
    map_revision: str,
    pinvi_revision: str,
    contract: bytes | None,
    capsys,
) -> tuple[int, str]:
    """실제 `rotation_preflight`를 돌리되 git만 대역으로 바꾼다."""

    driver = _driver()

    def command(*args: str, **kwargs: object) -> str:
        if "show" in args:
            if contract is None:
                raise driver._PhaseError("rotation_contract_unreadable")
            return contract.decode("utf-8")
        return ""

    monkeypatch.setattr(driver, "_command", command)
    status = driver.rotation_preflight(map_revision, pinvi_revision)
    return status, capsys.readouterr().out


def _run_rotation_preflight_v2(
    monkeypatch,
    capsys,
    *,
    contract: bytes,
    readable: bool = True,
) -> tuple[int, str, list[str], list[tuple[str, ...]]]:
    driver = _driver()
    reads, fetches = _rotation_map_blobs(driver, monkeypatch, readable=readable)

    def command(*args: str, **kwargs: object) -> str:
        if "show" in args:
            return contract.decode("utf-8")
        if "fetch" in args:
            fetches.append(args)
        return ""

    monkeypatch.setattr(driver, "_command", command)
    status = driver.rotation_preflight(_ROTATION_MAP_REVISION, "b" * 40)
    return status, capsys.readouterr().out, reads, fetches


def test_rotation_preflight_accepts_v2_when_the_digests_match_the_target_map(
    monkeypatch, capsys
) -> None:
    """게이트가 무조건 거부하는 것이 아님을 먼저 건다."""

    status, _out, reads, fetches = _run_rotation_preflight_v2(
        monkeypatch, capsys, contract=_rotation_contract_v2()
    )

    assert status == 0
    # 게이트가 **무엇을** 읽었는지까지 본다. digest 비교만 단언하면 저장소·revision·
    # 경로를 잘못 지목해도 초록이고, 그러면 회전 대상과의 결박이 사라진다.
    map_url = PINNED_RUNTIME_RELEASE.source_for("map").canonical_url
    pinvi_url = PINNED_RUNTIME_RELEASE.source_for("pinvi").canonical_url
    # 두 fetch가 각각 **자기 저장소의 회전 대상 revision**을 가져온다.
    assert [args[-2:] for args in fetches] == [
        (pinvi_url, "b" * 40),
        (map_url, _ROTATION_MAP_REVISION),
    ]
    assert reads and all(
        target.startswith(_ROTATION_MAP_REVISION + ":") for target in reads
    )
    assert {target.partition(":")[2] for target in reads} == {
        "packages/kor-travel-map-api/openapi.json",
        "packages/kor-travel-map-api/openapi.service.json",
        "packages/kor-travel-map-api/openapi.user.json",
    }


def test_rotation_preflight_refuses_v2_whose_surface_digest_differs_from_the_target_map(
    monkeypatch, capsys
) -> None:
    """v2에서 "이 계약은 저 Map을 가리킨다"를 말하는 것은 digest다.

    v1은 그것을 `map.full.source_revision` 문자열로 말했고 이 게이트는 그 문자열을
    봤다. v2가 그 선언을 걷어낸 뒤 게이트를 무조건 통과로 두면, 계약과 어긋난 Map
    revision으로의 회전이 **71분짜리 rebuild를 다 태운 뒤에야** 격리 preflight에서
    거부된다 — 이 게이트가 존재하는 바로 그 실패다(2026-09-02).

    service·user 표면까지 보는 것이 v1보다 오히려 넓다. v1의 digest 대조는 계약
    자신이 지목한 revision에 앵커돼 있어 "계약은 자기무모순이다"만 증명했다.
    """

    stale = "9" * 64
    status, out, _reads, _fetches = _run_rotation_preflight_v2(
        monkeypatch, capsys, contract=_rotation_contract_v2(user=stale)
    )

    assert status == 1
    # 두 값이 **실제로** 보여야 한다. 안 보이면 운영자가 다시 역추적한다.
    assert stale in out
    assert _ROTATION_MAP_DIGEST in out
    assert "user" in out


def test_rotation_preflight_refuses_v2_when_the_target_map_surface_is_unreadable(
    monkeypatch, capsys
) -> None:
    """표면을 못 읽으면 통과가 아니라 거부다 — 모르는 것은 괜찮은 것이 아니다."""

    status, out, _reads, _fetches = _run_rotation_preflight_v2(
        monkeypatch, capsys, contract=_rotation_contract_v2(), readable=False
    )

    assert status == 1
    assert "unreadable" in out


def test_rotation_preflight_refuses_v2_with_a_non_sha256_surface_digest(
    monkeypatch, capsys
) -> None:
    """digest가 digest가 아니면 대조 자체가 성립하지 않는다.

    길이만 보면 "z"*64 같은 값이 그대로 통과해 **digest 불일치**로 잘못 보고된다.
    운영자의 다음 행동이 다르므로(계약 오작성 vs 표면 변경) 두 경우를 함께 건다.
    """

    for broken in ("not-a-digest", "z" * 64):
        status, out, _reads, _fetches = _run_rotation_preflight_v2(
            monkeypatch, capsys, contract=_rotation_contract_v2(service=broken)
        )

        assert status == 1
        assert "sha256" in out


def test_rotation_preflight_refuses_a_v1_contract_after_the_transition(
    monkeypatch, capsys
) -> None:
    """v1 계약은 이제 거부된다 — 그리고 **어느 판인지 말한다.**

    §6이 green이 된 뒤 dual-read를 걷었다(`T-VN-PAIR-V2` §7). v1 pinset으로 재개해야
    하는 상황이 오면 그 사실이 메시지에서 바로 보여야 한다. 조용히 다른 이유로
    죽으면 운영자가 revert가 답이라는 것을 알 수 없다.
    """

    status, out = _run_rotation_preflight(
        monkeypatch,
        map_revision="a" * 40,
        pinvi_revision="b" * 40,
        contract=_rotation_contract(admin="a" * 40, full="a" * 40, version=1),
        capsys=capsys,
    )

    assert status == 1
    assert "version is unsupported: 1" in out


def test_rotation_preflight_refuses_an_unsupported_contract_version(
    monkeypatch, capsys
) -> None:
    """알 수 없는 버전은 회전하지 않는다 — 불확실할 때 원장을 바꾸지 않는다."""

    driver = _driver()

    def command(*args: str, **kwargs: object) -> str:
        if "show" in args:
            return json.dumps({"map": {}, "version": 7}).encode("utf-8").decode("utf-8")
        return ""

    monkeypatch.setattr(driver, "_command", command)

    assert driver.rotation_preflight("a" * 40, "b" * 40) == 1
    assert "unsupported" in capsys.readouterr().out


def test_rotation_preflight_refuses_an_unreadable_contract(
    monkeypatch, capsys
) -> None:
    """읽지 못하면 회전하지 않는다 — 불확실할 때 원장을 바꾸지 않는다."""

    status, out = _run_rotation_preflight(
        monkeypatch,
        map_revision="a" * 40,
        pinvi_revision="b" * 40,
        contract=None,
        capsys=capsys,
    )

    assert status == 1
    assert "unreadable" in out


def test_rotation_preflight_refuses_a_non_hex_revision(monkeypatch, capsys) -> None:
    """40-hex가 아니면 fetch조차 하지 않는다."""

    driver = _driver()
    called: list[tuple[str, ...]] = []

    def command(*args: str, **kwargs: object) -> str:
        called.append(args)
        return ""

    monkeypatch.setattr(driver, "_command", command)

    assert driver.rotation_preflight("not-hex", "b" * 40) == 1
    assert called == []



def _verify_leaf_fixture(
    tmp_path,
    driver,
    *,
    identity_in_history: bool,
    history_pinset: str | None = None,
    result_identity: str | None = None,
    binding_manager: str | None = None,
    result_manager: str | None = None,
    attestation_manager: str | None = None,
    m04_attestation_sha: str | None = None,
    ledger_claim: bool = True,
    blocked_phases: tuple[str | None, ...] = (),
    status: str = "passed",
    leaf_pinset: str | None = None,
    provenance_map_revision: str | None = None,
    m04_chain_verified: bool = True,
    provenance_identity: str | None = None,
    provenance_transaction_id: str | None = None,
    provenance_manager: str | None = None,
    provenance_pinset: str | None = None,
    binding_map_revision: str | None = None,
    pinset_blocked: bool = False,
    worktree_retained: bool = False,
    drop_binding_key: str | None = None,
):
    """`--verify-leaf`가 읽는 leaf 한 벌과 그에 맞는 registry 대역을 만든다."""

    import hashlib as _hashlib

    pinned = PINNED_RUNTIME_RELEASE
    map_revision = pinned.source_for("map").revision
    pinvi_revision = pinned.source_for("pinvi").revision
    manager_revision = "b" * 40
    # **실제 파생값**을 쓴다 — `BlockedExecution`이 (pinset, manager)에서 identity를
    # 다시 계산해 대조하므로 임의의 64자 hex로는 registry 타입을 만들 수 없다.
    identity = ExecutionIdentityV6.build(
        source_pinset_sha256=pinned.pinset_sha256,
        manager_source_revision=manager_revision,
    ).execution_identity_sha256

    # leaf는 **검증기를 돌리는 신원 소유의 group/other 닫힌 트리**여야 한다.
    # 종전 픽스처는 이 조건 없이 통과했다 — 그것이 곧 "아무 디렉터리나 통과한다"는
    # 결함의 증거였다(2026-09-07 적대 리뷰 P0).
    leaf = tmp_path / "leaf"
    (leaf / "runtime" / "m04").mkdir(parents=True)
    (leaf / "runtime" / "m05").mkdir(parents=True)
    for directory in (leaf, leaf / "runtime", leaf / "runtime/m04", leaf / "runtime/m05"):
        directory.chmod(0o700)

    transaction_id = "a1" * 16
    provenance = {
        "kind": "m05-isolated-runtime-provenance-v1",
        "map": {"source_revision": provenance_map_revision or map_revision},
        "pinvi": {"source_revision": pinvi_revision},
        # 아래 넷이 L6b가 결박하는 축이다 — 실제 provenance 문서가 들고 있는 것과
        # 같은 키다(n150 실측으로 확인).
        "execution_identity_sha256": provenance_identity or (result_identity or identity),
        "manager_source_revision": provenance_manager or result_manager or manager_revision,
        "pinset_sha256": provenance_pinset or leaf_pinset or pinned.pinset_sha256,
        "transaction_id": provenance_transaction_id or transaction_id,
    }
    attestation = {
        "payload": {
            "isolated_pinset_sha256": leaf_pinset or pinned.pinset_sha256,
            "isolated_manager_source_revision": attestation_manager or manager_revision,
            "isolated_execution_identity_sha256": identity,
            "m04_server_side_chain_verified": m04_chain_verified,
            # M04 증적을 사슬에 넣는 결박. 아래에서 실제 해시로 덮어쓴다.
            "m04_attestation_sha256": None,
        },
        "signature": "unused",
    }
    m04 = {"payload": {"scope": "isolated"}, "signature": "unused"}

    def write(path, value):
        raw = json.dumps(value).encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        return _hashlib.sha256(raw).hexdigest()

    provenance_sha = write(leaf / "runtime/isolated-runtime-provenance.json", provenance)
    m04_sha = write(leaf / "runtime/m04/m04-attestation.json", m04)
    attestation["payload"]["m04_attestation_sha256"] = (
        m04_attestation_sha or m04_sha
    )
    attestation_sha = write(leaf / "runtime/m05/attestation.json", attestation)
    (leaf / "result.json").write_bytes(
        json.dumps(
            {
                "harness": driver._HARNESS_NAME,
                "status": status,
                "phase": "completed",
                "pinset_sha256": leaf_pinset or pinned.pinset_sha256,
                "transaction_id": transaction_id,
                "disposable_run_worktree_retained": worktree_retained,
                "manager_source_revision": result_manager or manager_revision,
                "execution_identity_sha256": result_identity or identity,
                "m04_attestation_sha256": m04_sha,
                "m05_attestation_sha256": attestation_sha,
                "runtime_provenance_sha256": provenance_sha,
            }
        ).encode()
    )
    if drop_binding_key is not None:
        # **양쪽에서** 지운다. 한쪽만 지우면 두 dict가 달라져 동등성 비교가 잡으므로
        # `all(value is not None ...)` 가드의 고유 영역이 재어지지 않는다.
        raw = json.loads((leaf / "result.json").read_text(encoding="utf-8"))
        raw.pop(drop_binding_key, None)
        (leaf / "result.json").chmod(0o600)
        (leaf / "result.json").write_bytes(json.dumps(raw).encode())
        provenance.pop(drop_binding_key, None)
        provenance_sha = write(
            leaf / "runtime/isolated-runtime-provenance.json", provenance
        )
        raw["runtime_provenance_sha256"] = provenance_sha
        (leaf / "result.json").write_bytes(json.dumps(raw).encode())
    (leaf / "result.json").chmod(0o600)

    # **root-only ledger claim.** 이것이 없으면 공개값만으로 조립한 leaf와 실제 실행이
    # 만든 leaf를 구별할 수 없다. 픽스처가 claim을 직접 계산해 만들어야 이 축이
    # 실제로 재어진다 — 검증기와 planner가 같은 payload 모양을 쓰는지도 함께 걸린다.
    ledger = tmp_path / "ledger"
    ledger.mkdir(mode=0o700)
    if ledger_claim is not False:
        # **attestation 쪽 identity**를 쓴다. `result_identity or identity`로 만들면
        # result identity를 어긋내는 변이가 L9까지 함께 떨어뜨려 L5를 고립시킬 수
        # 없다(5차 적대 리뷰가 변이로 확인했다 — L5 축 전체가 생존했다).
        claim = driver._leaf_ledger_claim_name(
            manager_source_revision=result_manager or manager_revision,
            execution_identity_sha256=identity,
            pinset_sha256=pinned.pinset_sha256,
        )
        (ledger / claim).write_bytes(b"claim\n")
        (ledger / claim).chmod(0o600)

    class _Binding:
        def __init__(
            self,
            execution_identity_sha256: str,
            *,
            pinset: str | None = None,
            manager: str | None = None,
        ) -> None:
            self.execution_identity_sha256 = execution_identity_sha256
            self.source_pinset_sha256 = pinset or pinned.pinset_sha256
            self.map_revision = binding_map_revision or map_revision
            self.pinvi_revision = pinvi_revision
            self.manager_source_revision = manager or manager_revision

    class _Registry:
        # 검증 대상 leaf의 identity는 **history**에만 있고 current는 다른 값이다 —
        # Manager를 업그레이드한 뒤의 실제 상태가 정확히 이 모양이다.
        current = _Binding("d" * 64)
        history = (
            (_Binding(identity, pinset=history_pinset, manager=binding_manager),)
            if identity_in_history
            else ()
        )

        # **실제 `BlockedExecution`**을 쓴다. duck-type 스텁은 `phase` 속성이
        # 없어 scoped 기록을 표현할 수 없고, 그래서 phase 필터를 지우는 변이가
        # 원리적으로 RED가 되지 않았다(3차 적대 리뷰 P0가 그 구멍으로 들어왔다).
        blocked_executions = tuple(
            BlockedExecution(
                execution_identity_sha256=ExecutionIdentityV6.build(
                    source_pinset_sha256=pinned.pinset_sha256,
                    manager_source_revision=manager_revision,
                ).execution_identity_sha256,
                source_pinset_sha256=pinned.pinset_sha256,
                manager_source_revision=manager_revision,
                reason="integration fixture",
                blocked_at="2026-09-07T00:00:00Z",
                phase=phase,
            )
            for phase in blocked_phases
        )

        @staticmethod
        def is_unconditionally_blocked_current() -> bool:
            return False

    class _Pins:
        @staticmethod
        def is_unconditionally_blocked_pinset(_sha: str) -> bool:
            return pinset_blocked

    return leaf, manager_revision, _Registry, _Pins, ledger


def test_verify_leaf_accepts_an_identity_that_is_only_in_registry_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """검증기는 자기가 배포되기 **전에** 만들어진 leaf를 볼 수 있어야 한다.

    `current`만 보면 이 검증기를 배포하는 순간(= rebind로 새 execution identity가
    생기는 순간) 그 이전 leaf가 전부 검증 불가가 된다 — 검증기가 자기 배포 이전의
    증적을 영원히 못 보는 구조다. registry history는 append-only이고 각 binding이
    pinset·Map·PinVi revision을 함께 들고 있으므로, "그 identity가 **지금 고정된
    pair**에 결박된 것이었는가"를 다시 계산할 수 있다.
    """
    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 0
    out = capsys.readouterr().out
    assert "leaf verification PASSED" in out
    # current가 아니라는 사실은 **보고**되되 통과를 막지 않는다.
    assert "is_current=False" in out


def test_verify_leaf_refuses_an_identity_bound_to_no_pinned_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """history에도 없는 identity는 거부한다 — 넓힌 것은 '어디서 찾는가'이지 결박이 아니다."""
    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=False
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    assert "L5 execution identity" in capsys.readouterr().out


def test_verify_leaf_accepts_a_leaf_built_by_an_older_manager_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """Manager를 업그레이드해도 그 이전 leaf가 검증 가능해야 한다.

    L4를 **설치된** revision과 대조하면 L5와 똑같은 이유로 깨진다 — 이 검증기를
    배포하는 순간 설치 revision이 바뀌어 자기 배포 이전 leaf를 영원히 못 본다.
    2026-09-07 n150에서 실제로 그렇게 거부됐다(L5는 고쳤는데 L4가 같은 결함을 그대로
    들고 있었다). 정본은 그 leaf가 결박된 **registry binding**이다.
    """
    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True
    )
    # 설치된 Manager는 leaf가 만들어진 뒤 업그레이드됐다.
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: "9" * 40)

    assert driver.verify_leaf(leaf) == 0
    out = capsys.readouterr().out
    assert "leaf verification PASSED" in out
    assert "is_installed=False" in out


def test_verify_leaf_refuses_attestation_and_result_manager_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """attestation과 `result.json`이 서로 다른 Manager revision을 말하면 거부한다.

    leaf 안에서 두 문서가 갈라지는 것은 그 자체로 증적이 아니다 — L5의 identity
    축과 같은 이유다.
    """
    driver = _driver()
    # result·binding은 서로 맞고 **attestation만** 어긋나게 둔다. 그래야 이 게이트가
    # "attestation도 본다"는 사실 하나만 겨냥한다 — result만 어긋내면 binding 대조가
    # 대신 잡아서 게이트가 공허해진다(변이 검증에서 실제로 그랬다).
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, attestation_manager="7" * 40
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    assert "L4 Manager source revision" in capsys.readouterr().out


def test_verify_leaf_refuses_manager_revision_that_the_binding_denies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """leaf가 주장하는 Manager revision이 그 binding의 것과 다르면 거부한다."""
    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, binding_manager="a" * 40
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    assert "L4 Manager source revision" in capsys.readouterr().out


def test_verify_leaf_refuses_history_bound_to_another_pinset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """history에서 찾더라도 그 binding이 **지금 고정된 pair**의 것이어야 한다.

    넓힌 것은 "어디서 찾는가"이지 결박이 아니다. 다른 pinset에 결박됐던 identity를
    받아 주면 "이 leaf가 현재 고정된 pair의 증적이다"라는 통과의 뜻이 사라진다.
    """
    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, history_pinset="e" * 64
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    assert "L5 execution identity" in capsys.readouterr().out


def test_verify_leaf_refuses_attestation_and_result_identity_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """attestation과 `result.json`이 서로 다른 identity를 말하면 거부한다.

    leaf 안에서 두 문서가 갈라지는 것은 그 자체로 증적이 아니다.
    """
    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, result_identity="f" * 64
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    assert "L5 execution identity" in capsys.readouterr().out


def test_verify_leaf_recomputes_the_hash_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """`result.json`의 해시는 **다시 계산해서** 대조한다 — 적힌 값을 믿지 않는다."""
    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    target = leaf / "runtime/m05/attestation.json"
    tampered = json.loads(target.read_bytes())
    tampered["payload"]["m04_server_side_chain_verified"] = True
    tampered["signature"] = "tampered"
    target.write_bytes(json.dumps(tampered).encode())

    assert driver.verify_leaf(leaf) == 1
    assert "runtime/m05/attestation.json" in capsys.readouterr().out

def test_pair_failures_carry_a_closed_vocabulary_diagnostic() -> None:
    """`pair_contract_invalid` 15곳이 전부 진단 없이 같은 문자열만 냈다.

    2026-09-02에 그 때문에 실패 지점을 traceback으로 역추적해야 했다. 진단은
    닫힌 어휘여야 한다 — 자유 문자열을 열면 호스트 상태가 새는 경로가 된다.
    """

    import re

    driver = _driver()
    source = (
        Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py"
    ).read_text(encoding="utf-8")

    bare = re.findall(r'_fail\("pair_contract_invalid"\)', source)
    assert not bare, "진단 없는 pair_contract_invalid가 남아 있다"

    used = set(
        re.findall(
            r'_fail\(\s*"pair_contract_invalid",\s*diagnostic="([^"]+)"',
            source,
        )
    ) | set(
        re.findall(
            r'"pair_contract_invalid",\s*\n\s*diagnostic="([^"]+)",',
            source,
        )
    )
    assert used, "진단 문자열을 하나도 찾지 못했다 — 이 검사가 공허해졌다"
    assert used <= driver._PAIR_DIAGNOSTICS

    # 어휘가 **한 방향으로만** 검사되면 죽은 항목이 쌓인다. v1 분기를 걷은 뒤
    # 실제로 넷이 죽어 있었다(`T-VN-PAIR-V2` §7). allowlist의 모든 항목이 이
    # 파일 어딘가에서 실제로 발신되는지도 함께 본다.
    start = source.index("_PAIR_DIAGNOSTICS")
    end = source.index("\n)\n", start) + 3
    body = source[:start] + source[end:]
    dead = {value for value in driver._PAIR_DIAGNOSTICS if f'"{value}"' not in body}
    assert not dead, f"발신되지 않는 진단 어휘가 남아 있다: {sorted(dead)}"


def test_preflight_reports_only_allowlisted_diagnostics(monkeypatch, capsys) -> None:
    """진단은 내되 allowlist 밖 문자열은 phase만 낸다.

    이 경로는 아직 output leaf가 없어 forensic scrub 채널을 쓸 수 없다
    (leaf는 launcher가 preflight **뒤에** 만든다). 그래서 노출은 닫힌 어휘로만
    한다 — 그러지 않으면 호스트 상태가 launcher stderr로 나간다.
    """

    driver = _driver()

    def allowed() -> None:
        driver._fail(
            "pair_contract_invalid",
            diagnostic="pair source blob digest differs from the pinned release",
        )

    def leaky() -> None:
        driver._fail("pair_contract_invalid", diagnostic="/root/secret/path")

    monkeypatch.setattr(driver, "_validate_trusted_release", lambda _r: None)
    monkeypatch.setattr(
        driver, "_assert_current_m05_execution_is_runnable", lambda _r: None
    )

    monkeypatch.setattr(driver, "_source_pair_preflight", allowed)
    assert driver.preflight("a" * 40) == 1
    assert "pair source blob digest differs" in capsys.readouterr().out

    monkeypatch.setattr(driver, "_source_pair_preflight", leaky)
    assert driver.preflight("a" * 40) == 1
    leaked = capsys.readouterr().out
    assert "/root/secret/path" not in leaked
    assert "pair_contract_invalid" in leaked


def test_installer_executable_set_mirrors_the_git_index() -> None:
    """설치본의 실행 비트는 **두 곳**이 정한다 — git index와 설치 스크립트다.

    설치 스크립트는 archive의 mode를 신뢰하지 않고 전부 0644로 정규화한 뒤
    명시 목록만 0755로 되돌린다(trusted install posture, 옳다). 그래서 index에서
    executable이어도 그 목록에 없으면 설치본에서는 아니다.

    2026-09-02에 `rotate-pinned-pair`가 정확히 그렇게 무효가 됐다 — 파일은 있고
    index는 `100755`인데 설치본은 `-rw-r--r--`였고, launcher는 조용히 실행되지
    않았다. 이중 선언을 없애지는 않는다(posture가 그 명시성을 요구한다).
    대신 **index를 정본으로 삼아 미러를 강제한다.**
    """

    import re
    import subprocess

    root = Path(__file__).resolve().parents[2]
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-s", "--", "scripts"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    indexed = {
        line.split("	", 1)[1].rsplit("/", 1)[-1]
        for line in listed.splitlines()
        if line and line.split(" ", 1)[0] == "100755"
    }
    assert indexed, "index에 executable script가 없다 — 이 검사가 공허해졌다"

    installer = (root / "scripts/install-ktdm-trusted-release").read_text(
        encoding="utf-8"
    )
    granted = set(
        re.findall(
            r'chmod 0755 "\$\{STAGING\}/scripts/([^"]+)"',
            installer,
        )
    )

    assert granted == indexed, (
        "설치 스크립트의 0755 목록이 git index와 다르다 — "
        f"목록에만: {sorted(granted - indexed)}, index에만: {sorted(indexed - granted)}"
    )


def _v2_pair_entry(raw: bytes) -> dict[str, str]:
    """v2 엔트리 — `source_revision`이 **없다**."""

    entry = _pair_entry(revision="0" * 40, raw=raw)
    del entry["source_revision"]
    return entry


def _write_v2_pair(pinvi_root: Path, blobs: dict[str, bytes]) -> dict[str, object]:
    paths = {
        "admin": "packages/kor-travel-map-api/openapi.json",
        "full": "packages/kor-travel-map-api/openapi.json",
        "service": "packages/kor-travel-map-api/openapi.service.json",
        "user": "packages/kor-travel-map-api/openapi.user.json",
    }
    pair: dict[str, object] = {
        "map": {name: _v2_pair_entry(blobs[paths[name]]) for name in paths},
        "version": 2,
    }
    (pinvi_root / "contracts").mkdir(parents=True, exist_ok=True)
    (pinvi_root / "contracts/kor-travel-map-m05-pair-provenance-v1.json").write_text(
        json.dumps(pair), encoding="utf-8"
    )
    # service 릴리스 revision의 **정본** 문서. v2에서 pair 계약이 그 사본을 걷어내므로
    # 하네스는 이 문서에서 값을 읽어야 한다 — pinned Map revision을 넣으면 PinVi가
    # 부팅 시 거부한다.
    (pinvi_root / "contracts/kor-travel-map-service-provenance-v1.json").write_text(
        json.dumps({"map_release_revision": _SERVICE_RELEASE_REVISION}), encoding="utf-8"
    )
    return pair


#: 픽스처의 service 릴리스 revision. pinned Map revision과 **다른** 값이어야 이
#: 게이트가 무엇을 보는지 분명해진다 — 두 값은 재핀 주기가 달라 실제로 갈라진다.
_SERVICE_RELEASE_REVISION = "7" * 40


def test_pair_v2_anchors_every_surface_to_the_pinned_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v2는 네 표면 전부를 **릴리스**의 blob과 대조한다.

    v1에서 digest 대조는 계약이 스스로 지목한 revision에 앵커돼 있어
    "계약은 자기무모순이다"만 증명했다. service·user는 각자의 낡은 revision에서
    읽혀 릴리스와의 관계가 한 번도 확인되지 않았다. v2에서는 그 관계가
    **처음으로** 검사된다.
    """

    driver = _driver()
    pinvi_root = tmp_path / "pinvi"
    map_root = tmp_path / "map"
    map_root.mkdir()
    pinned = PINNED_RUNTIME_RELEASE.source_for("map").revision
    paths = {
        "admin": "packages/kor-travel-map-api/openapi.json",
        "full": "packages/kor-travel-map-api/openapi.json",
        "service": "packages/kor-travel-map-api/openapi.service.json",
        "user": "packages/kor-travel-map-api/openapi.user.json",
    }
    blobs = {
        path: json.dumps({"path": path}).encode() for path in set(paths.values())
    }
    pair = _write_v2_pair(pinvi_root, blobs)

    reads: list[str] = []
    fetches: list[tuple[str, ...]] = []

    def fake_command(*args: str, **_kwargs: object) -> str:
        fetches.append(args)
        return ""

    def fake_run(
        args: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        target = args[-1]
        reads.append(target)
        revision, _, path = target.partition(":")
        return subprocess.CompletedProcess(args, 0, stdout=blobs[path])

    monkeypatch.setattr(driver, "_command", fake_command)
    monkeypatch.setattr(driver.subprocess, "run", fake_run)
    actual, service_openapi_sha256, service_source_revision = driver._pair(
        pinvi_root, map_root
    )

    # 네 read 전부가 pinned revision에서 났다 — 이것이 v2의 실질이다.
    assert reads and all(target.startswith(pinned + ":") for target in reads)
    # fetch는 둘이다: 릴리스 revision과 service 표면의 릴리스 revision. 후자는
    # 대조에 쓰이지 않고 **PinVi attestation이 읽을 수 있게** 보충하는 것이다
    # (계약이 네 revision을 흩뿌리던 v1과 달리 흩어지지 않는다).
    assert {args[-1] for args in fetches} == {pinned, _SERVICE_RELEASE_REVISION}
    assert actual.map_full_openapi_sha256 == pair["map"]["full"]["openapi_sha256"]
    assert service_openapi_sha256 == pair["map"]["service"]["openapi_sha256"]
    # service 표면의 revision은 pin registry가 정하지 않는다. 그 값의 정본은 PinVi의
    # service-provenance 계약이고, `config.py`가 컨테이너 부팅 때 이 env를 그 계약과
    # 대조한다 — pinned를 넣으면 71분 rebuild 뒤 기동 실패다(적대 리뷰 P0).
    assert service_source_revision == _SERVICE_RELEASE_REVISION
    assert service_source_revision != pinned


@pytest.mark.parametrize("broken", ("z" * 40, "1" * 39, 12345, None))
def test_pair_v2_rejects_a_malformed_service_release_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, broken: object
) -> None:
    """service 릴리스 revision이 commit이 아니면 env로 흘려보내지 않는다.

    이 값은 PinVi 컨테이너의 env가 되고 PinVi가 부팅 때 자기 계약과 대조한다.
    형식 검사가 없으면 잘못된 값이 71분 rebuild 뒤에야 드러난다.
    """

    driver = _driver()
    pinvi_root = tmp_path / "pinvi"
    map_root = tmp_path / "map"
    map_root.mkdir()
    paths = {
        "admin": "packages/kor-travel-map-api/openapi.json",
        "full": "packages/kor-travel-map-api/openapi.json",
        "service": "packages/kor-travel-map-api/openapi.service.json",
        "user": "packages/kor-travel-map-api/openapi.user.json",
    }
    blobs = {path: json.dumps({"path": path}).encode() for path in set(paths.values())}
    _write_v2_pair(pinvi_root, blobs)
    (pinvi_root / "contracts/kor-travel-map-service-provenance-v1.json").write_text(
        json.dumps({"map_release_revision": broken}), encoding="utf-8"
    )

    def fake_run(
        args: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        _revision, _, path = args[-1].partition(":")
        return subprocess.CompletedProcess(args, 0, stdout=blobs[path])

    monkeypatch.setattr(driver, "_command", lambda *a, **k: "")
    monkeypatch.setattr(driver.subprocess, "run", fake_run)

    with pytest.raises(driver._PhaseError) as error:
        driver._pair(pinvi_root, map_root)

    assert error.value.diagnostic == "Map service release revision is not a 40-hex commit"


def test_pair_v2_rejects_a_declared_source_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v2가 revision을 다시 선언하면 이 전환의 목적 자체가 무효다.

    생산자를 하나로 만드는 것이 v2의 요지인데, 필드를 남겨 두면 같은 이중
    선언이 조용히 돌아온다.
    """

    driver = _driver()
    pinvi_root = tmp_path / "pinvi"
    map_root = tmp_path / "map"
    map_root.mkdir()
    raw = b'{"version":2}'
    pair = {
        "map": {name: _v2_pair_entry(raw) for name in ("admin", "full", "service", "user")},
        "version": 2,
    }
    pair["map"]["user"]["source_revision"] = "e" * 40
    (pinvi_root / "contracts").mkdir(parents=True)
    (pinvi_root / "contracts/kor-travel-map-m05-pair-provenance-v1.json").write_text(
        json.dumps(pair), encoding="utf-8"
    )
    monkeypatch.setattr(driver, "_command", lambda *_a, **_k: "")

    with pytest.raises(driver._PhaseError) as raised:
        driver._pair(pinvi_root, map_root)

    assert raised.value.phase == "pair_contract_invalid"
    # 잡는 것은 entry 스키마 검사다 — 전용 검사를 따로 두면 도달하지 못한다.
    assert raised.value.diagnostic == "pair entry schema is invalid"


def test_pair_rejects_a_v1_contract_after_the_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v1 계약은 이제 거부된다(`T-VN-PAIR-V2` §7).

    §6이 green이 된 뒤 dual-read를 걷었다. v1 pinset으로 재개해야 하면 그 커밋을
    revert하는 것이 답이고, 그 판단을 하려면 **거부가 버전 때문임이** 보여야 한다.
    """

    driver = _driver()
    pinvi_root = tmp_path / "pinvi"
    map_root = tmp_path / "map"
    map_root.mkdir()
    revision = PINNED_RUNTIME_RELEASE.source_for("map").revision
    raw = b'{"version":1}'
    pair = {
        "map": {
            name: _pair_entry(revision=revision, raw=raw)
            for name in ("admin", "full", "service", "user")
        },
        "runtime_image_digests": {},
        "version": 1,
    }
    (pinvi_root / "contracts").mkdir(parents=True)
    (pinvi_root / "contracts/kor-travel-map-m05-pair-provenance-v1.json").write_text(
        json.dumps(pair), encoding="utf-8"
    )
    monkeypatch.setattr(driver, "_command", lambda *_a, **_k: "")

    with pytest.raises(driver._PhaseError) as raised:
        driver._pair(pinvi_root, map_root)

    assert raised.value.diagnostic == "pair contract version is unsupported"


def test_pair_rejects_an_unsupported_contract_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """dual-read는 1과 2만 받는다 — 알 수 없는 버전은 fail-close다."""

    driver = _driver()
    pinvi_root = tmp_path / "pinvi"
    map_root = tmp_path / "map"
    map_root.mkdir()
    raw = b'{"version":3}'
    pair = {
        "map": {name: _v2_pair_entry(raw) for name in ("admin", "full", "service", "user")},
        "version": 3,
    }
    (pinvi_root / "contracts").mkdir(parents=True)
    (pinvi_root / "contracts/kor-travel-map-m05-pair-provenance-v1.json").write_text(
        json.dumps(pair), encoding="utf-8"
    )
    monkeypatch.setattr(driver, "_command", lambda *_a, **_k: "")

    with pytest.raises(driver._PhaseError) as raised:
        driver._pair(pinvi_root, map_root)

    assert (
        raised.value.diagnostic
        == "pair contract version is unsupported"
    )


def test_pair_v2_rejects_a_surface_that_differs_from_the_pinned_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v2에서 digest 불일치는 "계약이 릴리스와 어긋난다"는 뜻이다.

    v1의 같은 실패와 **다른 사실**이므로 진단 문자열도 달라야 한다. 같은
    문자열이 두 사실을 뜻하게 두는 것이 2026-09-02 결함 #1의 형태였다.
    """

    driver = _driver()
    pinvi_root = tmp_path / "pinvi"
    map_root = tmp_path / "map"
    map_root.mkdir()
    paths = {
        "admin": "packages/kor-travel-map-api/openapi.json",
        "full": "packages/kor-travel-map-api/openapi.json",
        "service": "packages/kor-travel-map-api/openapi.service.json",
        "user": "packages/kor-travel-map-api/openapi.user.json",
    }
    blobs = {
        path: json.dumps({"path": path}).encode() for path in set(paths.values())
    }
    pair = _write_v2_pair(pinvi_root, blobs)
    # 릴리스의 blob은 그대로인데 계약이 다른 digest를 담는다.
    pair["map"]["user"]["openapi_sha256"] = "0" * 64
    (pinvi_root / "contracts/kor-travel-map-m05-pair-provenance-v1.json").write_text(
        json.dumps(pair), encoding="utf-8"
    )

    def fake_run(
        args: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        _, _, path = args[-1].partition(":")
        return subprocess.CompletedProcess(args, 0, stdout=blobs[path])

    monkeypatch.setattr(driver, "_command", lambda *_a, **_k: "")
    monkeypatch.setattr(driver.subprocess, "run", fake_run)

    with pytest.raises(driver._PhaseError) as raised:
        driver._pair(pinvi_root, map_root)

    assert (
        raised.value.diagnostic
        == "pair source blob digest differs from the pinned release"
    )


def test_root_interrupt_is_not_swallowed_when_the_receipt_write_also_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """중단 신호는 receipt 기록이 실패해도 계속 전파돼야 한다.

    `main`의 `except Exception`은 ordinary exception을 전부 잡으므로 `finally`까지
    살아 오는 것은 BaseException뿐이고, 그것은 **일부러 안 잡은 신호**다("root
    운영자가 중단 신호를 보낼 수 있게 둔다"). 종전 코드는 `finally` 안에서
    `return 1`을 해 그 신호를 삼켰다 — 운영자가 Ctrl-C를 눌러도 하네스는 평범한
    실패처럼 1로 끝났다. return을 `finally` 밖으로 빼야 이 테스트가 통과한다.
    """

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    real_write = driver._write_private_json

    def _write(path: Path, payload: object) -> None:
        if path.name == "result.json":
            raise OSError("receipt write refused")
        real_write(path, payload)

    monkeypatch.setattr(driver, "_write_private_json", _write)

    with pytest.raises(KeyboardInterrupt):
        driver.main("a" * 40, tmp_path)


def test_a_completed_body_without_a_receipt_is_not_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """본문이 통과해도 receipt를 남기지 못했으면 exit 0이 아니다.

    이 규칙은 종전에 `finally` 안의 `return 1`이 우연히 지키고 있었다. return을
    밖으로 빼면서 규칙이 사라질 수 있었으므로 `driver_exit_code`로 꺼내 네 조합을
    전부 결박한다. 반환식에서 `receipt_write_failed`를 떨어뜨리면 첫 단언이
    빨개진다 — 앞선 시도에서 이 축을 `completed=False` 경로로만 덮었더니 변이가
    통과했다(공허한 게이트였다).
    """

    driver = _driver()

    assert driver.driver_exit_code(completed=True, receipt_write_failed=True) == 1
    assert driver.driver_exit_code(completed=True, receipt_write_failed=False) == 0
    assert driver.driver_exit_code(completed=False, receipt_write_failed=True) == 1
    assert driver.driver_exit_code(completed=False, receipt_write_failed=False) == 1


def test_main_reports_the_receipt_write_failure_through_that_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`main`이 그 규칙을 실제로 거쳐 간다 — 규칙만 있고 안 부르면 소용없다."""

    driver = _driver()
    monkeypatch.setattr(
        driver,
        "_validate_trusted_release",
        lambda _expected: (_ for _ in ()).throw(RuntimeError("discarded")),
    )
    monkeypatch.setattr(
        driver, "_block_terminal_m05_execution", lambda *_a, **_k: None
    )

    seen: list[dict[str, bool]] = []
    real_rule = driver.driver_exit_code

    def _rule(*, completed: bool, receipt_write_failed: bool) -> int:
        seen.append(
            {"completed": completed, "receipt_write_failed": receipt_write_failed}
        )
        return real_rule(
            completed=completed, receipt_write_failed=receipt_write_failed
        )

    monkeypatch.setattr(driver, "driver_exit_code", _rule)

    real_write = driver._write_private_json

    def _write(path: Path, payload: object) -> None:
        if path.name == "result.json":
            raise OSError("receipt write refused")
        real_write(path, payload)

    monkeypatch.setattr(driver, "_write_private_json", _write)

    assert driver.main("a" * 40, tmp_path) == 1
    assert seen == [{"completed": False, "receipt_write_failed": True}]
    assert not (tmp_path / "result.json").exists()


def test_verify_leaf_refuses_a_leaf_outside_the_privileged_trust_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """leaf가 특권 신원의 산물이라는 증거가 없으면 거부한다.

    종전 검증기는 leaf의 소유자·권한·symlink를 **한 번도 보지 않았다** — 그래서
    `--verify-leaf`가 사실상 아무 디렉터리나 받았고, 정의가 내건 근거 셋 중 첫째
    ("root-owned 0600 leaf")가 기계로 강제되지 않았다(2026-09-07 적대 리뷰 P0,
    두 리뷰어 독립 지적).
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)
    assert driver.verify_leaf(leaf) == 0

    # (a) 디렉터리가 group/other에 열려 있다.
    leaf.chmod(0o755)
    assert driver.verify_leaf(leaf) == 1
    assert "trusted root-owned artifact" in capsys.readouterr().out
    leaf.chmod(0o700)

    # (b) leaf가 symlink다.
    link = tmp_path / "link"
    link.symlink_to(leaf, target_is_directory=True)
    assert driver.verify_leaf(link) == 1

    # (c) 안쪽 파일이 group/other에 열려 있다.
    (leaf / "result.json").chmod(0o644)
    assert driver.verify_leaf(leaf) == 1
    (leaf / "result.json").chmod(0o600)

    # (d) 다른 신원 소유의 디렉터리(테스트는 비-root로 도므로 /etc가 그 예다).
    assert driver.verify_leaf(Path("/etc")) == 1

    # (e) 증적 하위 디렉터리가 열려 있다 — 안쪽 파일은 여전히 0600이다.
    (leaf / "runtime" / "m05").chmod(0o755)
    assert driver.verify_leaf(leaf) == 1
    (leaf / "runtime" / "m05").chmod(0o700)
    assert driver.verify_leaf(leaf) == 0

    # (f) 증적 파일에 하드링크가 있다 — 같은 inode를 다른 경로에서 계속 바꿀 수 있다.
    link = tmp_path / "hardlink.json"
    os.link(leaf / "result.json", link)
    assert driver.verify_leaf(leaf) == 1
    link.unlink()
    assert driver.verify_leaf(leaf) == 0
    capsys.readouterr()

    # (g) 소유자 대조 자체 — 검증기가 다른 신원으로 돈다고 보면 자기 leaf도 거부한다.
    monkeypatch.setattr(driver.os, "geteuid", lambda: os.getuid() + 1)
    assert driver.verify_leaf(leaf) == 1
    assert "신원의 소유가 아니다" in capsys.readouterr().out


def test_verify_leaf_requires_the_root_only_ledger_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """공개값만으로 조립한 leaf는 통과하지 못해야 한다.

    L3~L6이 대조하는 값은 전부 `-public` 사본에서 world-readable이다(n150 실측
    0644). 그래서 그것만으로는 위조 문턱이 "공개값 베끼기"에 그친다. ledger는
    root-only 0700이고 드라이버가 실행 **전에** O_EXCL로 claim을 남기므로, claim의
    실재가 특권 생산자의 실제 실행을 뜻한다.
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, ledger_claim=False
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    out = capsys.readouterr().out
    assert "FAIL L9 root-only ledger claim" in out
    assert "present=False" in out


def test_leaf_ledger_claim_name_matches_the_planner(tmp_path: Path) -> None:
    """검증기의 claim 이름 계산이 planner의 정본과 **바이트 단위로** 같아야 한다.

    두 곳이 어긋나면 L9가 조용히 항상 실패한다 — 그러면 이 축은 "아무 leaf도
    통과 못 한다"가 되어 결국 걷히게 된다. 그래서 값이 아니라 두 구현을 결박한다.
    """

    from kor_travel_docker_manager.services.m05_isolated_harness import (
        M05_ISOLATED_HARNESS_KIND,
        M05_ISOLATED_HARNESS_VERSION,
        M05IsolatedHarnessPlan,
    )

    driver = _driver()
    assert driver._HARNESS_NAME == M05_ISOLATED_HARNESS_KIND
    assert driver._HARNESS_VERSION == M05_ISOLATED_HARNESS_VERSION

    # **planner를 실제로 부른다.** 앞선 판(4차 적대 리뷰가 잡았다)은 payload와
    # 직렬화를 테스트 본문에 손으로 다시 적어 비교했다 — 결박이 아니라 세 번째
    # 손복사본이었다. planner가 키를 더하거나 separators/sort_keys/끝 개행을 바꾸면
    # 검증기와 테스트는 둘 다 초록인 채 실제 ledger 파일명만 갈라지고, L9는 소리
    # 없이 항상 FAIL이 된다.
    plan = M05IsolatedHarnessPlan(
        release=PINNED_RUNTIME_RELEASE,
        manager_source_revision="b" * 40,
        execution_identity_sha256=ExecutionIdentityV6.build(
            source_pinset_sha256=PINNED_RUNTIME_RELEASE.pinset_sha256,
            manager_source_revision="b" * 40,
        ).execution_identity_sha256,
        transaction_id="0" * 32,
    )
    assert (
        driver._leaf_ledger_claim_name(
            manager_source_revision=plan.manager_source_revision,
            execution_identity_sha256=plan.execution_identity_sha256,
            pinset_sha256=PINNED_RUNTIME_RELEASE.pinset_sha256,
        )
        == plan.ledger_filename
    )

    payload = {
        "harness": M05_ISOLATED_HARNESS_KIND,
        "manager_source_revision": "b" * 40,
        "execution_identity_sha256": "c" * 64,
        "pinset_sha256": "d" * 64,
        "version": M05_ISOLATED_HARNESS_VERSION,
    }
    expected = hashlib.sha256(
        (
            json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("ascii")
    ).hexdigest()
    assert (
        driver._leaf_ledger_claim_name(
            manager_source_revision="b" * 40,
            execution_identity_sha256="c" * 64,
            pinset_sha256="d" * 64,
        )
        == expected
    )


def test_verify_leaf_binds_the_m04_evidence_into_the_hash_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """M04 증적이 사슬 안에 있어야 한다.

    종전에는 M04 파일을 L2가 해시만 하고 **한 번도 열지 않았고**, 그것을 대신
    주장하는 L7은 payload의 자유 불리언 하나였다. m05 attestation payload가 이미
    `m04_attestation_sha256`을 들고 있으므로 그것을 L2의 재계산 값과 대조한다.
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, m04_attestation_sha="e" * 64
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    assert "FAIL L7b M04 증적이 사슬 안에 있다" in capsys.readouterr().out


def test_verify_leaf_refuses_a_leaf_whose_own_identity_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """L8은 **leaf 자신의** identity 차단을 봐야 한다.

    종전에는 `current`의 차단만 봤다. 승격 후보는 둘 다 current가 아닌 identity라,
    그 leaf가 소각됐어도 L8이 통과했다(2026-09-07 적대 리뷰 P0).
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, blocked_phases=(None,)
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    out = capsys.readouterr().out
    assert "FAIL L8" in out
    assert "leaf_execution_blocked=True" in out


def test_verify_leaf_accepts_a_leaf_whose_identity_has_only_a_phase_scoped_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """phase-scoped 기록은 소각이 아니다 — 그 뒤의 정당한 leaf가 통과해야 한다.

    `blocked_executions`는 무조건 소각과 scoped 기록을 **한 리스트에** 담고, 정본
    `is_unconditionally_blocked_current()`가 `phase is None`으로 둘을 가른다.
    execution identity는 (pinset, manager)에서 파생하므로 **Manager를 안 바꾼
    재시도는 같은 identity**다 — 인프라 phase 실패로 scoped 기록이 남은 뒤 보정해
    통과한 leaf가 정확히 이 모양이고, 필터가 없으면 그 leaf가 영원히 검증 불가가
    된다(#330이 넣은 회귀, 3차 적대 리뷰 P0).
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path,
        driver,
        identity_in_history=True,
        blocked_phases=("runtime_setup_ports",),
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 0
    assert "leaf_execution_blocked=False" in capsys.readouterr().out


def test_verify_leaf_does_not_tie_a_past_leaf_to_the_current_identity_burn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """무관한 다음 실행의 소각이 과거 증적을 무효화하지 않는다.

    L4·L5는 "Manager 업그레이드는 과거 증적을 무효화하지 않는다"를 원칙으로 세웠다.
    L8이 `current`의 소각을 보면 그 원칙이 L8에서만 깨진다 — 승격 근거가 관계없는
    실패 한 건으로 사라진다(3차 적대 리뷰 P1).
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True
    )

    class _BurnedCurrent:
        current = registry.current
        history = registry.history
        blocked_executions = registry.blocked_executions

        @staticmethod
        def is_unconditionally_blocked_current() -> bool:
            return True

    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: _BurnedCurrent)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 0
    assert "leaf_execution_blocked=False" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("kwargs", "expected_fail"),
    [
        ({"status": "failed"}, "L1 harness/status/phase"),
        ({"leaf_pinset": "f" * 64}, "L3 pinset"),
        ({"provenance_map_revision": "e" * 40}, "L6 Map/PinVi source revision"),
        ({"m04_chain_verified": False}, "L7 M04 server-side chain"),
    ],
)
def test_verify_leaf_refuses_each_remaining_axis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    kwargs: dict[str, object],
    expected_fail: str,
) -> None:
    """L1·L3·L6·L7도 각각 고립해서 잰다.

    4차 적대 리뷰가 잡았다 — 이 넷은 술어를 `True`로 바꿔도 전 테스트가 초록이었다.
    특히 **L3이 "pin이 움직이면 같은 leaf가 다시 통과하지 않는다"를 지는 축**인데,
    기존 pinset 테스트는 *binding*의 pinset만 바꿔 L5가 먼저 잡고 L3은 건드려지지
    않았다. 여기서는 leaf 쪽 pinset을 어긋내 L3만 떨어뜨린다.
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, **kwargs
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    out = capsys.readouterr().out
    assert f"FAIL {expected_fail}" in out


def test_verify_leaf_requires_the_exact_private_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """모드는 "group/other에 닫혀 있다"가 아니라 **정확히** 0600/0700이어야 한다.

    `& 0o077 == 0`만 보면 0500·0400 같은 임의의 owner-only 모드를 받는다. 드라이버가
    쓰는 것은 0600(파일)·0700(디렉터리)뿐이라 정확 대조가 맞고, 그래야
    `_secure_read_root_file`이 이미 요구하던 규율과 같아진다(4차 적대 리뷰 P1).
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)
    assert driver.verify_leaf(leaf) == 0

    # owner-only지만 0600이 아니다 — `& 0o077`로는 잡히지 않는다.
    (leaf / "result.json").chmod(0o400)
    assert driver.verify_leaf(leaf) == 1
    (leaf / "result.json").chmod(0o600)

    # 디렉터리도 마찬가지 — 0500은 owner-only지만 0700이 아니다.
    leaf.chmod(0o500)
    assert driver.verify_leaf(leaf) == 1
    leaf.chmod(0o700)
    assert driver.verify_leaf(leaf) == 0
    capsys.readouterr()


def test_verify_leaf_refuses_a_provenance_from_another_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """provenance 문서가 **이 실행의 것**이어야 한다.

    종전에는 파일을 열어 놓고 map/pinvi revision 둘만 쓰고, 그 문서가 이미 들고 있는
    `execution_identity_sha256`·`manager_source_revision`·`pinset_sha256`·
    `transaction_id` 넷을 버렸다 — 다른 실행이 만든 provenance를 끼운 leaf가 L6을
    그대로 통과했다(해시 사슬은 leaf 내부 자기정합만 본다). 4차 적대 리뷰 P1.
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, provenance_identity="9" * 64
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    assert "FAIL L6b provenance가 이 실행의 것이다" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("kwargs", "expected_fail"),
    [
        # L5 — 14축 중 유일하게 고립 게이트가 하나도 없었다(5차 적대 리뷰가 변이로
        # 확인: 술어 전체를 True로 바꿔도 21건 전부 초록이었다). 원인은 L5를
        # 떨어뜨리던 세 테스트가 전부 다른 축을 함께 떨어뜨렸고, 단언이 PASS 줄에도
        # 찍히는 문자열이라 축을 구분하지 못한 것이었다.
        ({"result_identity": "7" * 64}, "L5 execution identity"),
        ({"binding_map_revision": "8" * 40}, "L5 execution identity"),
        # L8의 pinset 절반 — execution 절반만 게이트가 있었다.
        ({"pinset_blocked": True}, "L8 terminal 아님"),
        # L6b가 존재 이유로 내세운 필드가 정작 무방비였다.
        ({"provenance_transaction_id": "b2" * 16}, "L6b provenance가 이 실행의 것이다"),
        ({"provenance_manager": "c" * 40}, "L6b provenance가 이 실행의 것이다"),
        ({"provenance_pinset": "d" * 64}, "L6b provenance가 이 실행의 것이다"),
        # L0가 재지 않는 범위를 드라이버는 receipt에 싣는데 아무 축도 안 읽었다.
        ({"worktree_retained": True}, "L0b 일회용 worktree가 남지 않았다"),
        # 양쪽에서 함께 빠지면 동등성은 통과한다 — fail-close 가드의 고유 영역이다.
        ({"drop_binding_key": "transaction_id"}, "L6b provenance가 이 실행의 것이다"),
    ],
)
def test_verify_leaf_isolates_the_axes_that_survived_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    kwargs: dict[str, object],
    expected_fail: str,
) -> None:
    """5차 적대 리뷰가 변이로 잡은 무방비 축들을 각각 고립해서 잰다.

    `transaction_id`가 특히 중요하다 — 실제 위협(같은 pinset·같은 Manager의 **다른
    실행**이 만든 provenance 끼워넣기)에서는 나머지 세 필드가 전부 같으므로
    **그 필드만이 그 공격을 잡는다**. L6b를 신설한 바로 그 PR에서 게이트 없이 들어왔다.
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, **kwargs
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    out = capsys.readouterr().out
    # **`FAIL <축>`을 단언한다.** 축 이름만 보면 PASS 줄에도 찍혀 아무것도 지키지 않는다.
    assert f"FAIL {expected_fail}" in out


def test_verify_leaf_refuses_when_the_pin_registry_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """pin registry를 못 읽으면 fail-close다 — 그 분기에도 게이트가 없었다."""

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True
    )

    def _raise() -> object:
        raise driver.RuntimePinRegistryError("registry unreadable")

    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", _raise)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    assert driver.verify_leaf(leaf) == 1
    assert "FAIL L8 terminal 아님" in capsys.readouterr().out


def test_verify_leaf_prints_its_checks_even_when_an_evidence_read_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """증적 판독 실패에서도 이미 잰 축은 인쇄돼야 한다.

    m04 파일이 거부되면 루프가 끝까지 돌아 이유가 찍히는데, m05 attestation이나
    provenance가 같은 이유로 거부되면 `hashed_bytes` KeyError로 조기 return해
    **L0·L1·L2 세 줄이 한 줄도 인쇄되지 않았다.** 3차 리뷰가 고친 "이유 없는 exit 1"이
    세 파일 중 둘에서 되살아나 있었다(5차 적대 리뷰 P1).
    """

    driver = _driver()
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "trusted_manager_source_revision", lambda: manager_revision)

    (leaf / "runtime" / "m05" / "attestation.json").chmod(0o644)
    assert driver.verify_leaf(leaf) == 1
    out = capsys.readouterr().out
    assert "FAIL L2 runtime/m05/attestation.json" in out
    assert "PASS L0 leaf 신뢰 경계" in out
    assert "0644 != 0600" in out


def test_the_provenance_producer_and_the_verifier_agree_on_the_bound_keys() -> None:
    """정본이 만드는 provenance에 검증기가 읽는 키가 전부 있어야 한다.

    생산자는 `build_m05_isolated_runtime_provenance`이고 소비자는 verify_leaf의
    L6·L6b인데, 소비자가 키를 **문자열 리터럴로 다시 적는다.** 둘을 잇는 것이 없으면
    생산자에서 키 하나를 rename해도 양쪽 테스트가 초록인 채 L6b만 영구 FAIL이 된다 —
    `test_leaf_ledger_claim_name_matches_the_planner`가 L9를 위해 막아 둔 실패 양식과
    같은 것이다(5차 적대 리뷰 P1).

    생산자를 실행하려면 image inspect 전체를 지어내야 하므로, 반환 dict의 **키**를
    `ast`로 읽어 소비자가 읽는 키 집합과 대조한다. rename은 이 방식으로 잡히고,
    값의 정합은 L6b가 런타임에 잡는다.
    """

    source = (
        Path(__file__).resolve().parents[2]
        / "backend/src/kor_travel_docker_manager/services/m05_isolated_harness.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    builder = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "build_m05_isolated_runtime_provenance"
    )
    returned = next(
        node.value
        for node in ast.walk(builder)
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
    )
    produced_keys = {
        key.value for key in returned.keys if isinstance(key, ast.Constant)
    }

    # verify_leaf의 L6·L6b가 provenance에서 읽는 키.
    consumed_keys = {
        "execution_identity_sha256",
        "manager_source_revision",
        "pinset_sha256",
        "transaction_id",
        "map",
        "pinvi",
    }
    assert consumed_keys <= produced_keys, sorted(consumed_keys - produced_keys)

    driver = _driver()
    assert set(driver._LEAF_HASHED_ARTIFACTS) == {
        "m04_attestation_sha256",
        "m05_attestation_sha256",
        "runtime_provenance_sha256",
    }


# ---------------------------------------------------------------------------
# T-VN-M05-VERIFY-RECEIPT — 검증이 durable 기록을 남긴다
# ---------------------------------------------------------------------------


def _receipts(driver: ModuleType) -> list[Path]:
    root = driver._LEDGER.parent / driver._VERIFY_RECEIPT_DIRNAME
    return sorted(root.glob("*.json")) if root.exists() else []


def _verify_leaf_patched(
    driver: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **kwargs: object
):
    leaf, manager_revision, registry, pins, ledger = _verify_leaf_fixture(
        tmp_path, driver, identity_in_history=True, **kwargs
    )
    monkeypatch.setattr(driver, "_LEDGER", ledger)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(
        driver, "trusted_manager_source_revision", lambda: manager_revision
    )
    return leaf, manager_revision, ledger


def test_verify_leaf_writes_a_root_owned_receipt_for_a_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """통과 근거가 출력 텍스트로만 남으면 재현이 불가능해진다.

    pin 회전·history 500칸 링·identity 소각 중 무엇이 먼저 와도 `--verify-leaf`를 다시
    돌려 같은 결론을 얻을 수 없다. 그래서 조문이 durable receipt를 요구한다(V1).
    """

    driver = _driver()
    leaf, _manager_revision, _ledger = _verify_leaf_patched(driver, monkeypatch, tmp_path)

    assert driver.verify_leaf(leaf) == 0

    written = _receipts(driver)
    assert len(written) == 1
    assert oct(written[0].stat().st_mode & 0o777) == "0o600"
    assert oct(written[0].parent.stat().st_mode & 0o777) == "0o700"
    payload = json.loads(written[0].read_text(encoding="utf-8"))

    assert payload["outcome"] == "passed"
    assert payload["coverage"] == "complete"
    assert payload["failed_axes"] == []

    # **축을 여기서 다시 열거하지 않는다.** 인쇄된 줄과 같아야 한다 — 그래야 축이 늘 때
    # receipt도 함께 늘고, 두 곳에 적힌 숫자가 갈리지 않는다(조문 V1의 요구).
    printed = [
        line
        for line in capsys.readouterr().out.splitlines()
        if line.startswith(("PASS ", "FAIL "))
    ]
    assert payload["axis_count"] == len(printed)
    assert [axis["name"] for axis in payload["axes"]] == [
        line.split(" — ")[0][5:] for line in printed
    ]


def test_the_receipt_carries_what_it_compared_against(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V2 — pin이 움직여 재현이 불가능해져도 **무엇과 대조했는지**는 남는다."""

    driver = _driver()
    leaf, manager_revision, ledger = _verify_leaf_patched(driver, monkeypatch, tmp_path)

    assert driver.verify_leaf(leaf) == 0
    payload = json.loads(_receipts(driver)[0].read_text(encoding="utf-8"))

    assert (
        payload["pinned_pair"]["pinset_sha256"]
        == driver.PINNED_RUNTIME_RELEASE.pinset_sha256
    )
    assert payload["pinned_pair"]["map_source_revision"]
    assert payload["pinned_pair"]["pinvi_source_revision"]
    assert payload["leaf_binding"]["binding_found"] is True
    assert payload["leaf_binding"]["binding_manager_source_revision"] == manager_revision
    assert payload["ledger_claim_name"]
    assert payload["registry_paths"]["ledger"] == str(ledger)
    # 검증기 자신도 식별돼야 한다 — 설치본과 브랜치 체크아웃이 갈릴 수 있고, 4차 리뷰가
    # 정확히 그 갈림으로 잘못된 측정을 잡았다.
    assert payload["verifier"]["verifier_script_sha256"]
    assert payload["verifier"]["installed_manager_source_revision"] == manager_revision


def test_a_rejected_leaf_still_leaves_a_receipt_with_the_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**실패도 남긴다.** 통과만 남기면 "검증한 적 없다"와 "떨어졌다"가 같아 보인다.

    가장 필요한 실패 종류가 신뢰 경계 거부다 — 종전에는 그 경로가 한 문장만 인쇄하고
    축을 하나도 남기지 않아, receipt를 붙였어도 내용이 비었을 것이다.
    """

    driver = _driver()
    leaf, _manager_revision, _ledger = _verify_leaf_patched(driver, monkeypatch, tmp_path)

    leaf.chmod(0o755)
    assert driver.verify_leaf(leaf) == 1
    leaf.chmod(0o700)

    written = _receipts(driver)
    assert len(written) == 1
    payload = json.loads(written[0].read_text(encoding="utf-8"))
    assert payload["outcome"] == "failed"
    assert payload["coverage"] == "rejected_at_trust_boundary"
    assert payload["failed_axes"] == ["L0 leaf 신뢰 경계"]
    assert "trusted root-owned artifact" in payload["axes"][0]["detail"]


def test_a_receipt_write_failure_does_not_flip_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """V4 — receipt는 근거의 기록이지 **통과 조건이 아니다.**

    그렇다고 조용히 넘어가서도 안 된다. 둘 다 잰다.
    """

    driver = _driver()
    leaf, _manager_revision, _ledger = _verify_leaf_patched(driver, monkeypatch, tmp_path)

    real_open = driver.os.open

    def _refuse(path, flags, *args, **kwargs):
        if driver._VERIFY_RECEIPT_DIRNAME in str(path):
            raise OSError("read-only filesystem")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(driver.os, "open", _refuse)
    assert driver.verify_leaf(leaf) == 0
    assert "verify receipt was not written" in capsys.readouterr().out
    assert _receipts(driver) == []


# ---------------------------------------------------------------------------
# T-VN-M05-ONESHOT-CONSUME — 성공이 execution identity를 소비한다
# ---------------------------------------------------------------------------


def _consumed_registry(driver: ModuleType):
    """**실제** registry로 소비 기록을 만든다.

    duck-type 스텁을 쓰면 `has_block_for_current`의 진짜 술어를 재지 못하고, 그러면
    phase 필터를 지우는 변이가 원리적으로 RED가 되지 않는다 — 3차 적대 리뷰 P0가 정확히
    그 구멍으로 들어왔다.
    """

    pinned = driver.PINNED_RUNTIME_RELEASE
    pins = pin_registry.build_registry(
        release_version=5,
        map_revision=pinned.source_for("map").revision,
        pinvi_revision=pinned.source_for("pinvi").revision,
        rotated_by="tester",
        reason="seed",
    )
    registry = migrate_execution_registry(
        pins=pins,
        manager_source_revision=_CONSUME_MANAGER_REVISION,
        bound_by="tester",
        reason="migrate",
    )
    return pins, registry


_CONSUME_MANAGER_REVISION = "e" * 40


def test_a_consumed_identity_cannot_run_the_body_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """성공한 identity로 acceptance 본문을 두 번 돌 수 없어야 한다.

    종전에는 성공 분기가 registry를 아예 건드리지 않아 같은 identity가 계속 runnable
    이었다(2026-09-07 실측). one-shot이 **실패에만** 걸려 있었다.
    """

    driver = _driver()
    pins, registry = _consumed_registry(driver)

    # 소비 전에는 돈다 — 이 축이 없으면 아래 거부가 "원래 안 되던 것"과 구별되지 않는다.
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    driver._assert_current_m05_execution_is_runnable(_CONSUME_MANAGER_REVISION)

    consumed = driver.block_current_execution(
        registry=registry,
        reason="acceptance consumed",
        phase=driver._CONSUMED_EXECUTION_PHASE,
    )
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: consumed)
    with pytest.raises(driver._PhaseError, match=driver._CONSUMED_EXECUTION_PHASE):
        driver._assert_current_m05_execution_is_runnable(_CONSUME_MANAGER_REVISION)


def test_a_consumed_leaf_still_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """소비된 leaf가 계속 검증돼야 한다 — 조문 3항의 요지다.

    이 축이 없으면 소비를 `phase=None`으로 바꿔도 나머지가 전부 초록이다.
    """

    driver = _driver()
    leaf, _manager_revision, _ledger = _verify_leaf_patched(
        driver,
        monkeypatch,
        tmp_path,
        blocked_phases=(driver._CONSUMED_EXECUTION_PHASE,),
    )

    assert driver.verify_leaf(leaf) == 0


def test_the_consume_phase_is_mirrored_in_both_vocabularies() -> None:
    """어휘가 갈리면 소비 기록이 `driver_contract_failed`로 둔갑한다.

    그리고 pre-claim 집합에서 빠지면, 소비 거부로 끝난 실행(아무것도 claim하지 않았다)이
    launcher에서 무조건 소각으로 승격된다.
    """

    driver = _driver()
    phase = driver._CONSUMED_EXECUTION_PHASE
    assert driver._public_terminal_phase(phase) == phase
    assert driver._terminal_block_phase(phase) == phase
    assert phase in driver._PRE_CLAIM_PHASES
    launcher = (
        Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once"
    ).read_text(encoding="utf-8")
    assert launcher.count(f'"{phase}"') == 2


def test_consume_records_the_scoped_phase_not_a_burn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """소비가 **어떤 기록으로** 남는지를 직접 잰다.

    `finally` 안에 인라인으로 두면 이 축을 잴 수 없다 — 그래서 규칙을 이름 있는 함수로
    꺼냈다(`driver_exit_code`와 같은 이유이자, 이 파일이 이미 한 번 겪은 공허한 게이트).
    """

    driver = _driver()
    pins, registry = _consumed_registry(driver)
    written: list[object] = []

    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: registry)
    monkeypatch.setattr(
        driver, "write_runtime_execution_registry", lambda updated: written.append(updated)
    )

    assert (
        driver.consume_current_m05_execution(
            expected_manager_revision=_CONSUME_MANAGER_REVISION
        )
        is True
    )
    assert len(written) == 1
    updated = written[0]
    # **소각이 아니어야 한다.** 소각이면 방금 성공한 leaf가 L8에서 죽는다.
    assert updated.is_unconditionally_blocked_current() is False
    assert [entry.phase for entry in updated.blocked_executions] == [
        driver._CONSUMED_EXECUTION_PHASE
    ]


def test_main_consumes_the_execution_only_on_the_success_branch() -> None:
    """성공 분기가 실제로 소비를 부르는지 **결박**한다.

    `main`의 `finally`를 통째로 도는 테스트는 acceptance 본문 전체를 흉내 내야 해서
    현실적이지 않다. 그래서 이 파일이 이미 쓰는 방식대로(`gate = source.index(...)`)
    호출이 **어느 분기 안에** 있는지를 소스로 확인한다. 잰다고 주장하는 것은 배선뿐이고,
    무엇이 기록되는지는 위 테스트가 실제로 잰다.
    """

    source = (
        Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py"
    ).read_text(encoding="utf-8")

    failure_branch = source.index("if not completed and claim_attempted:")
    success_branch = source.index("elif completed and claim_attempted:", failure_branch)
    consume_call = source.index(
        "consume_current_m05_execution(", success_branch
    )
    end_of_finally = source.index('for name in _RAW_ENV_NAMES:', success_branch)

    # 성공 분기 **안에** 있어야 한다.
    assert success_branch < consume_call < end_of_finally
    # 실패 분기에서는 부르지 않는다 — 실패는 소각이지 소비가 아니다.
    assert "consume_current_m05_execution(" not in source[failure_branch:success_branch]


def test_a_scoped_infra_block_does_not_look_like_consumption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**소비 검사가 다른 scoped 기록까지 삼키면 안 된다.**

    적대 리뷰가 잡은 구멍이다. `has_block_for_current(phase=...)`에서 `phase=`를 떼면
    그 술어는 **모든** 차단 기록을 잡는다(registry:254-264) — 인프라 phase로 scoped
    기록이 남은 identity가 그때부터 영구히 거부되고, 진단은 엉뚱하게
    `execution_identity_consumed`가 된다. 그것이 #330이 넣고 #331이 되돌린 회귀와
    같은 부류다.

    앞선 테스트들은 이 축을 **가려 준다** — 깨끗한 registry(기록 0건)와 소비된
    registry(소비 기록 1건)만 보여 주는데, 둘 다 `phase=` 유무로 답이 갈리지 않는다.
    갈리는 유일한 상태가 여기 있다: **소비가 아닌 scoped 기록 하나.**
    """

    driver = _driver()
    pins, registry = _consumed_registry(driver)
    infra_blocked = driver.block_current_execution(
        registry=registry,
        reason="infra phase failed",
        phase="runtime_setup_network",
    )
    assert infra_blocked.is_unconditionally_blocked_current() is False
    assert infra_blocked.has_block_for_current(phase="runtime_setup_network") is True

    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: infra_blocked)

    # 보정 후 재실행이 가능해야 한다 — phase-scoped 설계의 요지다.
    driver._assert_current_m05_execution_is_runnable(_CONSUME_MANAGER_REVISION)


def test_the_consumed_rejection_names_the_recovery_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """조문 2항 — 진단이 무엇을 해야 하는지 말한다.

    phase 이름만 내면 운영자는 "이 실행을 되살릴 수 있나"를 알 수 없다. 되살릴 수 없고
    새 identity가 필요하다는 것이 답이며, 그것을 말해야 한다.
    """

    driver = _driver()
    pins, registry = _consumed_registry(driver)
    consumed = driver.block_current_execution(
        registry=registry,
        reason="acceptance consumed",
        phase=driver._CONSUMED_EXECUTION_PHASE,
    )
    monkeypatch.setattr(driver, "load_runtime_pin_registry", lambda: pins)
    monkeypatch.setattr(driver, "load_runtime_execution_registry", lambda: consumed)

    with pytest.raises(driver._PhaseError) as refused:
        driver._assert_current_m05_execution_is_runnable(_CONSUME_MANAGER_REVISION)

    diagnostic = refused.value.diagnostic
    assert diagnostic == driver._CONSUMED_DIAGNOSTIC
    assert "rotate or rebind" in diagnostic
    # 닫힌 어휘에 있어야 preflight가 실제로 내보인다 — 없으면 조용히 삼켜진다.
    # `_PAIR_DIAGNOSTICS`가 아니라 상위 집합이다: 그쪽은 pair 실패 전용이고,
    # 그 안의 모든 문자열이 발신된다는 것을 별도 테스트가 양방향으로 결박한다.
    assert diagnostic in driver._SAFE_DIAGNOSTICS
    assert diagnostic not in driver._PAIR_DIAGNOSTICS


def test_a_failed_consume_record_leaves_a_durable_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """소비 기록 실패를 print로 말하면 운영에서는 **아무 데도 닿지 않는다.**

    launcher가 드라이버를 `>/dev/null 2>&1`로 부른다(run-m05-isolated-e2e-once). 그러면
    "소비됐다"와 "기록에 실패했다"가 같아 보이고, 그 identity가 실제로는 재실행 가능한
    채로 남는다. receipt와 같은 방식으로 durable하게 남긴다.
    """

    driver = _driver()
    monkeypatch.setattr(driver, "_LEDGER", tmp_path / "ledger")

    driver._write_consume_failure_marker("f" * 40, "a" * 64)

    root = (tmp_path / "ledger").parent / driver._CONSUME_FAILURE_DIRNAME
    written = sorted(root.glob("*.json"))
    assert len(written) == 1
    assert oct(written[0].stat().st_mode & 0o777) == "0o600"
    assert oct(root.stat().st_mode & 0o777) == "0o700"
    payload = json.loads(written[0].read_text(encoding="utf-8"))
    assert payload["execution_identity_sha256"] == "a" * 64
    assert payload["manager_source_revision"] == "f" * 40
    assert "still be runnable" in payload["consequence"]


def test_the_consume_failure_path_writes_the_marker_not_a_print() -> None:
    """marker **호출부**를 결박한다.

    앞 테스트는 `_write_consume_failure_marker`를 직접 부르므로, 호출부를 print로
    되돌려도 초록이다(변이 검증이 그것을 드러냈다). 배선을 따로 잰다 — 이 파일이
    소비 배선에 쓴 방식과 같다.
    """

    source = (
        Path(__file__).resolve().parents[2] / "scripts/m05_isolated_e2e.py"
    ).read_text(encoding="utf-8")

    guard = source.index("if not execution_consumed:")
    end_of_block = source.index("for name in _RAW_ENV_NAMES:", guard)
    block = source[guard:end_of_block]

    assert "_write_consume_failure_marker(" in block
    # print는 운영에서 `/dev/null`로 간다 — 이 경로의 보고 수단이 될 수 없다.
    assert "print(" not in block


def test_the_launcher_discards_driver_stdout_so_prints_are_not_a_channel() -> None:
    """위 두 테스트의 **전제**를 고정한다.

    launcher가 언젠가 stdout을 보존하게 바뀌면 durable marker가 과잉일 수 있다. 반대로
    지금 상태에서 print로 되돌리면 보고가 사라진다. 어느 쪽이든 이 전제가 바뀌면
    알아야 하므로 여기서 잰다.
    """

    launcher = (
        Path(__file__).resolve().parents[2] / "scripts/run-m05-isolated-e2e-once"
    ).read_text(encoding="utf-8")
    invocation = launcher.index("m05_isolated_e2e.py")
    tail = launcher[invocation : launcher.index("driver_status=", invocation)]
    assert ">/dev/null 2>&1" in tail
