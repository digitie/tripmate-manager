#!/usr/bin/env python3
"""M05 disposable bridge E2E의 root-only one-shot driver.

Docker/Playwright 원문 출력이나 secret은 result에 쓰지 않는다. 이 파일은 trusted
Manager release에서만 ``run-m05-isolated-e2e-once``를 통해 실행한다.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from collections.abc import Mapping
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    ProxyHandler,
    Request,
    build_opener,
)

from kor_travel_docker_manager.services.c6c_deployment import (
    DeploymentContractError,
    effective_environment,
)
from kor_travel_docker_manager.services.loopback_readiness import (
    LOOPBACK_HTTP_READINESS_ATTEMPTS,
    LOOPBACK_HTTP_READINESS_RETRY_SECONDS,
)
from kor_travel_docker_manager.services.m05_isolated_harness import (
    M05IsolatedHarnessPlan,
    M05IsolatedNetworkExpectation,
    M05IsolatedPairEvidence,
    M05IsolatedRuntimeExpectation,
    M05IsolatedServiceExpectation,
    assert_m05_isolated_runtime,
    build_m05_isolated_manager_admission,
    build_m05_isolated_runtime_provenance,
    claim_m05_isolated_harness_ledger,
)
from kor_travel_docker_manager.services.pinned_runtime_generation import (
    PinnedRuntimeStatePaths,
    pinned_runtime_state_paths,
)
from kor_travel_docker_manager.services.pinned_runtime_generation import (
    read_manifest as read_pinned_runtime_manifest,
)
from kor_travel_docker_manager.services.pinned_runtime_release import (
    current_pinned_runtime_release,
)
from kor_travel_docker_manager.services.pinned_runtime_sources import (
    assert_pinned_worktree_is_still_sealed,
    materialize_disposable_run_worktree,
    materialize_pinned_runtime_sources,
    remove_disposable_run_worktree,
    summarize_disposable_run_worktree,
)
from kor_travel_docker_manager.services.runtime_execution_identity import (
    ExecutionIdentityV6,
)
from kor_travel_docker_manager.services.runtime_execution_registry import (
    RuntimeExecutionRegistry,
    RuntimeExecutionRegistryError,
    block_current_execution,
    load_runtime_execution_registry,
    trusted_manager_source_revision,
    write_runtime_execution_registry,
)
from kor_travel_docker_manager.services.runtime_pin_registry import (
    RuntimePinRegistryError,
    load_runtime_pin_registry,
)

# pinned revision은 코드 상수가 아니라 root 소유 registry가 소유한다(ADR-40).
# 이 드라이버는 한 번의 격리 실행 전체가 같은 pinset에 결박돼야 하므로 모듈 로드
# 시점에 한 번만 해석한다 — 실행 도중 회전이 끼어들면 전후가 다른 pinset이 된다.
PINNED_RUNTIME_RELEASE = current_pinned_runtime_release()
_CleanupProject = tuple[Path, str, Path, tuple[Path, ...], tuple[str, ...]]
#: 실행이 쓰는 일회용 체크아웃 (role, destination, state_paths, values, evidence).
#: 봉인된 핀 트리는 여기 오지 않는다. 이 파일은 `importlib`로 `sys.modules` 등록
#: 없이 로드되므로 `@dataclass`를 쓸 수 없다 — `dataclasses`가 문자열 annotation을
#: 풀 때 `sys.modules.get(cls.__module__)`를 참조해 `None`에서 깨진다.
_DisposableRunWorktree = tuple[str, Path, PinnedRuntimeStatePaths, Mapping[str, str], Path]

_ROOT = Path("/opt/kor-travel-docker-manager")
_LEDGER = Path("/var/lib/kor-travel-docker-manager/m05-isolated-once")
_REVISION_LENGTH = 40
_RENDERED_PORT_EVIDENCE_LIMIT = 16
_SAFE_PORT_PROTOCOLS = frozenset({"tcp", "udp", "sctp"})
_FORENSIC_CAPTURE_ENV = "KTDM_M05_FORENSIC_CAPTURE"
_FORENSIC_CAPTURE_LIMIT = 256 * 1024
# PinVi reconciliation worker의 폴링 주기(초). driver가 PinVi에 주입하는 값과
# receipt 대기 창을 **같은 상수**에서 파생시킨다 — 두 곳에 따로 적으면 창이
# 주기보다 짧아져 receipt가 아직 없는 순간에 단발 실패한다(정합성 스윕 high).
_PINVI_RECONCILIATION_POLL_SECONDS = 1
# 워커가 lease→apply→ACK→receipt까지 가는 데 허용할 여유 주기 수.
_PINVI_RECEIPT_READINESS_ATTEMPTS = 30
# m04/m05 attestation이 검사·실행하는 Playwright runner의 핀 digest. body에서
# 부재가 드러나면 무조건 소각이므로, 실행권 소비 전에 존재·버전 정합을 보장한다.
# v1.63.0-noble — pinned PinVi source의 playwright-core와 driverVersion이 같아야
# 브라우저 캐시(/ms-playwright)가 적중한다(적대 리뷰 실측: 구 digest v1.60.0은
# chromium 1223만 실어 pinned 1.62.1의 1234 요구와 어긋났고, 본문 브라우저
# 기동에서 무조건 소각될 운명이었다). 정합은 아래 claim 전 검사로 기계화한다.
#
# 2026-09-07: PinVi lockfile이 1.63.0으로 올라간 뒤 이 핀만 1.62.1에 남아 격리
# e2e가 claim 전에 거부됐다. 그 거부가 **설계대로** 실행권 소비 전에 났다 —
# 게이트가 없었다면 본문 브라우저 기동에서 한 사이클을 태웠을 것이다.
_PLAYWRIGHT_RUNNER_IMAGE = "mcr.microsoft.com/playwright@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27"
# Compose config은 trusted input이라도 외부 CLI 출력이다. JSON parser에 넘기는
# 원문은 이 상한만 보관하고, 초과분도 끝까지 drain해 child pipe를 막지 않는다.
_COMPOSE_CONFIG_OUTPUT_LIMIT = 256 * 1024
_RAW_ENV_NAMES = (
    "M05_MAP_ADMIN_PROXY_SECRET",
    "M05_PINVI_EMAIL",
    "M05_PINVI_PASSWORD",
    "PINVI_M04_LIVE_EMAIL",
    "PINVI_M04_LIVE_PASSWORD",
)
_PINVI_MANAGER_ADMISSION_FILES = (
    "scripts/docker-app.sh",
    "scripts/m05_isolated_manager_admission.py",
)
_PINVI_MANAGER_ADMISSION_TOKENS = frozenset(
    {
        "PINVI_M05_ISOLATED_MANAGER_ADMISSION_PATH",
        # driver는 첫 up부터 override를 겹치는 PinVi 쪽 overlay 지원에 hard-depend
        # 한다. 지원 없는 stale pin이면 env가 조용히 무시돼 같은 timeout이 진단
        # 없이 재현되므로, 소스 텍스트 계약으로 fail-close한다.
        "PINVI_DOCKER_COMPOSE_EXTRA_FILE",
        "PINVI_M05_PINSET_SHA256",
        "PINVI_M05_EXECUTION_IDENTITY_SHA256",
        "m05_isolated_manager_admission.py",
        "pinvi-m05-isolated-manager-admission-v1",
        '[[ "$EUID" -eq 0 ]]',
        "/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 -I",
    }
)
_SAFE_SUBPROCESS_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}
# Root driver가 host loopback에만 연결할 때에도 ambient HTTP(S)_PROXY를 신뢰하지
# 않는다. PinVi cookie opener도 아래와 같은 proxy-free opener를 명시적으로 만든다.
_LOOPBACK_OPENER = build_opener(ProxyHandler({}))
_MAP_FRESH_INIT_EXIT_DIAGNOSTICS = {
    41: "migrator_dsn_missing",
    42: "image_alembic_root_invalid",
    43: "migrator_session_unverifiable",
    44: "migrator_identity_invalid",
    45: "pre_root_state_invalid",
    46: "alembic_root_result_invalid",
    47: "alembic_command_failed",
    48: "alembic_runtime_contract_failed",
    49: "database_statement_failed",
    50: "runtime_privilege_reconciliation_failed",
    51: "fresh_destination_contract_invalid",
    52: "alembic_runtime_configuration_invalid",
    53: "baseline_reference_invalid",
    54: "schema_lineage_invalid",
    55: "metadata_contract_invalid",
    127: "unclassified",
}
# result.json의 map_fresh_init_reason은 **닫힌 어휘**다 — launcher receipt
# 검증기가 FRESH_INIT_REASONS로 대조하고, 벗어나면 ValueError로 떨어져 claim
# 전 실패도 무조건 소각으로 승격된다(full-path 시뮬레이션 적발). 그런데
# _fail(diagnostic=...)은 사람이 읽는 자유형 문자열도 싣는다. 어휘는 여기서
# 한 번만 선언하고(위 exit map에서 파생), 그 밖의 값은 이 필드에 싣지 않는다.
# unclassified로 수렴시키지 않는 이유: 그 값은 "fresh-init runner가 미상 exit
# code로 죽었다"는 **다른 사실**을 뜻해서, playwright 버전 불일치 같은 무관한
# 진단에 붙이면 receipt가 거짓을 주장한다. 원문은 root 0600 forensic leaf로.
_MAP_FRESH_INIT_REASONS = frozenset(_MAP_FRESH_INIT_EXIT_DIAGNOSTICS.values())
# terminal pinset registry는 비-root도 읽는 감사 표면이다. driver의 예외 원문을
# reason에 흘리지 않고, 다음 immutable candidate의 보정 범위만 나타내는 고정 phase만
# 허용한다. 이 집합 밖의 값은 가장 좁은 안전 진단으로 수렴한다.
_PUBLIC_TERMINAL_PHASES = frozenset(
    {
        # _fail이 만드는 raw phase 중 result/driver_phase로 새어 나올 수 있는
        # 것들도 어휘에 있어야 launcher receipt 검증이 깨지지 않는다(적대 리뷰).
        "arguments_invalid",
        "runtime_command_output_too_large",
        "admission",
        "driver_contract_failed",
        "ledger_claim",
        "m04_fixture_http_failed",
        "m04_fixture_invalid",
        "m04_m05_e2e",
        "m04_map_approval_http_failed",
        "m04_map_feature_ref_resolve_failed",
        "m04_map_approval_invalid",
        "m05_case_decision_http_failed",
        "m05_case_invalid",
        "m05_case_lookup_http_failed",
        "m05_fixture_invalid",
        "m05_pinvi_receipt_blocked",
        "m05_pinvi_receipt_http_failed",
        "m05_pinvi_receipt_invalid",
        "m05_pinvi_receipt_not_ready",
        "m05_pinvi_seed_http_failed",
        "m05_pinvi_seed_invalid",
        "m05_pinvi_impact_missing",
        "map_application_start_failed",
        "map_fresh_init_failed",
        "map_health_status_failed",
        "map_health_transport_failed",
        "map_postgres_start_failed",
        "map_runtime",
        "map_subscription",
        "map_subscription_http_failed",
        "network_inspect_invalid",
        "network_subnet_unavailable",
        "pair_contract_invalid",
        "pinvi_auth_invalid",
        "pinvi_login_http_failed",
        "pinvi_manager_admission_contract_invalid",
        "pinvi_runtime",
        "ports_unavailable",
        "result_write_failed",
        "runtime_cleanup_failed",
        "runtime_command_failed",
        "runtime_container_identity_invalid",
        "runtime_directory_invalid",
        "runtime_http_contract_failed",
        "runtime_http_failed",
        "runtime_http_url_invalid",
        "runtime_image_identity_invalid",
        "runtime_inspect_invalid",
        "runtime_loopback_publish_invalid",
        "runtime_loopback_publish_config_invalid",
        "runtime_execution_block_failed",
        "runtime_execution_registry_changed",
        "runtime_execution_registry_invalid",
        "runtime_pin_registry_changed",
        "runtime_pin_registry_invalid",
        "runtime_setup",
        "runtime_setup_admission",
        "runtime_setup_admission_build",
        "runtime_setup_admission_write",
        "runtime_setup_credentials",
        "runtime_setup_map_config",
        "runtime_setup_network",
        "runtime_setup_pinvi_config",
        "runtime_setup_playwright_runner_image",
        "runtime_setup_ports",
        "runtime_setup_workspace",
        "secret_cleanup_identity_invalid",
        "source_materialization",
        "terminal_execution_blocked",
        "trusted_release_invalid",
        "trusted_release_revision_mismatch",
    }
)


class _PhaseError(RuntimeError):
    def __init__(
        self,
        phase: str,
        *,
        diagnostic: str | None = None,
        returncode: int | None = None,
        stderr: bytes | None = None,
        stdout: bytes | None = None,
        stdout_truncated: bool = False,
    ) -> None:
        super().__init__(phase)
        self.phase = phase
        self.diagnostic = diagnostic
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout
        self.stdout_truncated = stdout_truncated


def _fail(
    phase: str,
    *,
    diagnostic: str | None = None,
    returncode: int | None = None,
    stderr: bytes | None = None,
    stdout: bytes | None = None,
    stdout_truncated: bool = False,
) -> NoReturn:
    raise _PhaseError(
        phase,
        diagnostic=diagnostic,
        returncode=returncode,
        stderr=stderr,
        stdout=stdout,
        stdout_truncated=stdout_truncated,
    )


def _assert_current_m05_execution_is_runnable(
    expected_manager_revision: str,
) -> RuntimeExecutionRegistry:
    """현재 source pair와 trusted Manager 실행 결박을 mutation 전에 확인한다."""

    try:
        from kor_travel_docker_manager.services.runtime_pair_rotation import (
            require_no_pending_runtime_pair_rotation,
        )

        require_no_pending_runtime_pair_rotation()
        registry = load_runtime_pin_registry()
    except (RuntimePinRegistryError, DeploymentContractError):
        _fail("runtime_pin_registry_invalid")
    if (
        registry.pinset_sha256 != PINNED_RUNTIME_RELEASE.pinset_sha256
        or registry.map_revision != PINNED_RUNTIME_RELEASE.source_for("map").revision
        or registry.pinvi_revision != PINNED_RUNTIME_RELEASE.source_for("pinvi").revision
    ):
        _fail("runtime_pin_registry_changed")
    try:
        execution = load_runtime_execution_registry()
    except RuntimeExecutionRegistryError:
        _fail("runtime_execution_registry_invalid")
    if not execution.current_matches(
        pins=registry, manager_source_revision=expected_manager_revision
    ):
        _fail("runtime_execution_registry_changed")
    if execution.is_unconditionally_blocked_current():
        _fail("terminal_execution_blocked")
    return execution


def _terminal_registry_reason(phase: str) -> str:
    """root registry에는 고정 phase만 남겨 원문 유출을 막는다."""

    return f"M05 isolated one-shot terminal: {_public_terminal_phase(phase)}"


def _public_terminal_phase(phase: str) -> str:
    """원문 없이 이미 추적 중인 실행 경계만 public receipt에 남긴다."""

    return phase if phase in _PUBLIC_TERMINAL_PHASES else "driver_contract_failed"


#: 이 phase들의 실패만 execution을 **무조건** 소각한다 — acceptance 본문과 ledger claim
#: 자체. 나머지(runtime setup·health·admission 등 인프라 phase)는 scoped 기록으로 남고
#: 보정 후 같은 pinset에서 재실행할 수 있다. 근거: terminal 27개 중 `m04_m05_e2e` 도달
#: 0건 — 인프라 실패가 acceptance 실패와 같은 형벌(3-repo 회전)을 받아 후보 예산이
#: 본문 도달 전에 소진됐다(`ktm-m03 docs/reports/map-stall-root-cause-2026-08-31.md` §3 I-1).
_UNCONDITIONAL_TERMINAL_PHASES = frozenset({"ledger_claim", "m04_m05_e2e"})

# ledger claim **이전**에만 도달할 수 있는 phase 집합 — claim 이후에만 나오는
# phase를 넣으면 "실행권을 소비하지 않았다"고 주장하는 receipt가 소비를 증명하는
# phase를 달고 검증을 통과한다(적대 리뷰 major: runtime_setup_pinvi_config는
# claim 바로 다음 줄, runtime_inspect_invalid는 전 호출부가 claim 이후,
# runtime_cleanup_failed는 driver_phase != phase라 launcher가 별도로 거부) — 이 상태로 끝난 run은
# 실행권을 소비하지 않았으므로(`status="preflight_rejected"`) 보정 후 같은
# pinset으로 재시도할 수 있어야 한다. launcher의 PREFLIGHT_REJECTED_PHASES가
# 이 집합의 부분집합만 알고 있으면, 나머지 phase로 끝난 receipt가 검증에서
# 거절되어 fallback이 execution을 **무조건 소각**한다 — phase-scoped 설계의
# 정면 부정이다(2026-09-01 driver full-path 시뮬레이션이 적발). 두 곳이
# 갈라지지 않도록 launcher는 이 상수를 그대로 미러하고 테스트가 결박한다.
_PRE_CLAIM_PHASES = frozenset(
    {
        "admission",
        "arguments_invalid",
        "driver_contract_failed",
        "network_inspect_invalid",
        "network_subnet_unavailable",
        "pair_contract_invalid",
        "pinvi_manager_admission_contract_invalid",
        "ports_unavailable",
        "result_write_failed",
        "runtime_command_failed",
        "runtime_command_output_too_large",
        "runtime_directory_invalid",
        "runtime_execution_registry_changed",
        "runtime_execution_registry_invalid",
        "runtime_loopback_publish_config_invalid",
        "runtime_loopback_publish_invalid",
        "runtime_pin_registry_changed",
        "runtime_pin_registry_invalid",
        "runtime_setup_admission",
        "runtime_setup_admission_build",
        "runtime_setup_admission_write",
        "runtime_setup_credentials",
        "runtime_setup_map_config",
        "runtime_setup_network",
        "runtime_setup_playwright_runner_image",
        "runtime_setup_ports",
        "runtime_setup_workspace",
        "source_materialization",
        "terminal_execution_blocked",
        "trusted_release_invalid",
        "trusted_release_revision_mismatch",
    }
)


def _terminal_block_phase(public_phase: str) -> str | None:
    """무조건 차단이면 ``None``, 아니면 scoped 기록용 phase."""

    if public_phase in _UNCONDITIONAL_TERMINAL_PHASES or public_phase.startswith(
        ("m04_", "m05_")
    ):
        # acceptance 본문 내부 phase(m04_fixture_* / m05_case_* 등)도 본문 실패다 —
        # "acceptance 본문은 정확히 한 번"이라는 one-shot 성질은 그대로 지킨다.
        return None
    return public_phase


def _block_terminal_m05_execution(
    phase: str, *, expected_manager_revision: str, force_unconditional: bool = False
) -> bool:
    """terminal result를 현재 v6 execution의 block 기록과 결박한다.

    acceptance 본문 실패는 무조건 차단(phase=None), 인프라 phase 실패는 scoped
    기록이다 — execution은 보정 후 재실행 가능하되 실패 이력은 append-only로 남는다.
    ``force_unconditional``은 본문 진입 이후의 실패용이다 — 본문 내부 helper가
    인프라형 phase 이름(_container_id 등)으로 실패해도 one-shot 성질(적대 리뷰
    R1-S4/R2-S4: body-entered 실패가 scoped로 강등되는 구멍)을 지킨다.
    """
    public_phase = _public_terminal_phase(phase)
    block_phase = None if force_unconditional else _terminal_block_phase(public_phase)
    try:
        pins = load_runtime_pin_registry()
        registry = load_runtime_execution_registry()
        if not registry.current_matches(
            pins=pins, manager_source_revision=expected_manager_revision
        ):
            return False
        updated = block_current_execution(
            registry=registry,
            reason=_terminal_registry_reason(phase),
            phase=block_phase,
        )
        write_runtime_execution_registry(updated)
    except (RuntimePinRegistryError, RuntimeExecutionRegistryError):
        return False
    # 성공 판정은 "기록이 남았는가"다. scoped 기록은 무조건 차단이 아니므로
    # `is_unconditionally_blocked_current()`로 판정하면 정상 기록이 실패로 보인다.
    if block_phase is None:
        return updated.is_unconditionally_blocked_current()
    return updated.has_block_for_current(phase=public_phase)


def _root_file(path: Path, *, mode: int = 0o600) -> os.stat_result:
    data = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(data.st_mode)
        or data.st_uid != 0
        or stat.S_IMODE(data.st_mode) != mode
        or data.st_nlink != 1
    ):
        _fail("trusted_release_invalid")
    return data


def _secure_read_root_file(path: Path, *, mode: int, encoding: str, limit: int) -> str:
    """Read a root-owned immutable marker without a check/read substitution window."""

    before = _root_file(path, mode=mode)
    if not hasattr(os, "O_NOFOLLOW"):
        _fail("trusted_release_invalid")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (
            (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != 0
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_nlink != 1
        ):
            _fail("trusted_release_invalid")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                _fail("trusted_release_invalid")
        after = os.fstat(fd)
        named = path.lstat()
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or (
            named.st_dev,
            named.st_ino,
        ) != (before.st_dev, before.st_ino):
            _fail("trusted_release_invalid")
        return b"".join(chunks).decode(encoding)
    except UnicodeDecodeError:
        _fail("trusted_release_invalid")
    finally:
        os.close(fd)


def _validate_trusted_release(expected: str) -> None:
    if len(expected) != _REVISION_LENGTH or any(
        char not in "0123456789abcdef" for char in expected
    ):
        _fail("arguments_invalid")
    root = _ROOT.lstat()
    if (
        _ROOT.is_symlink()
        or not stat.S_ISDIR(root.st_mode)
        or root.st_uid != 0
        or stat.S_IMODE(root.st_mode) & 0o022
    ):
        _fail("trusted_release_invalid")
    revision_file = _ROOT / ".ktdm-source-revision"
    manifest_file = _ROOT / ".ktdm-release-manifest.json"
    revision = _secure_read_root_file(
        revision_file, mode=0o644, encoding="ascii", limit=128
    ).strip()
    try:
        manifest = json.loads(
            _secure_read_root_file(
                manifest_file, mode=0o644, encoding="utf-8", limit=1_000_000
            )
        )
    except json.JSONDecodeError:
        _fail("trusted_release_invalid")
    if (
        revision != expected
        or not isinstance(manifest, dict)
        or manifest.get("manager_source_revision") != expected
    ):
        _fail("trusted_release_revision_mismatch")


def _write_private_json(path: Path, value: Mapping[str, object]) -> str:
    raw = (
        json.dumps(dict(value), ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")
    _write_private_bytes(path, raw)
    return hashlib.sha256(raw).hexdigest()


def _write_private_bytes(path: Path, raw: bytes) -> None:
    if not raw:
        _fail("result_write_failed")
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _fail("result_write_failed")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    # 디렉터리 fsync는 **최선의 노력**이다 — 파일은 위 os.fsync(fd)로 이미
    # durable하고, 이 단계는 그 사실이 crash에서도 살아남는지에 관한 추가
    # 보장일 뿐이다. 종전에는 실패가 그대로 전파돼 호출부의
    # `except (OSError, _PhaseError): return 1`에 걸렸고, 그러면 디스크에
    # `status=passed, phase=completed` receipt가 멀쩡히 있는데 driver가 1을
    # 반환한다. launcher Tier 1의 `(status==passed) != (driver_status==0)`가
    # 걸려 exit 1 -> `pin block-execution`(phase 없음 = 무조건) ->
    # **통과한 1~2시간 실행과 후보가 영구 소각된다.**
    #
    # 이 규칙의 정본은 services/secure_state_file.fsync_directory다(GM-10):
    # "이 단계의 실패로 이미 끝난 파일 교체 자체를 실패로 되돌리면 안 된다".
    # 그 함수를 직접 쓰지 않는 이유는 여기 open이 O_DIRECTORY|O_NOFOLLOW로
    # **더 강하기** 때문이다 — 규칙만 채택하고 강한 open은 유지한다.
    try:
        directory_fd = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)


def _write_private_text(path: Path, value: str) -> None:
    _write_private_bytes(path, value.encode("utf-8"))


def _command(
    *args: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = False,
    failure_exit_diagnostics: dict[int, str] | None = None,
    capture_failure_stderr: bool = False,
    capture_output_limit: int | None = None,
) -> str:
    child_env = dict(_SAFE_SUBPROCESS_ENV)
    if env is not None:
        child_env.update(env)
    # forensic 모드에서는 **모든** 외부 명령 실패가 stderr 증거를 남길 수 있어야
    # 한다. e2e6/e2e7에서 evidence 없는 runtime_command_failed가 반복돼 원인
    # 규명에 격리 run을 회당 통으로 태웠다 — 호출부가 opt-in한 곳만 증거를
    # 남기는 설계는 이 harness의 실패 표면 전체를 덮지 못한다.
    forensic_capture = os.environ.get(_FORENSIC_CAPTURE_ENV) == "1"
    # 증거로만 쓰는 stdout 포획. 호출부가 capture를 요구하지 않았어도 forensic
    # 모드에서는 실패한 명령의 stdout을 남겨야 한다 — 2026-09-03 e2e22가
    # `M04 live UI command exited with 1`만 남기고 1시간 39분을 태웠다. Playwright는
    # **어느 spec의 어떤 단언이 깨졌는지를 stdout으로** 내는데 하네스는 stderr만
    # 잡았고, 남은 stderr에는 npm의 lifecycle 오류밖에 없었다.
    evidence_stdout = forensic_capture and not capture
    if capture_failure_stderr or forensic_capture or capture_output_limit is not None:
        stdout, returncode, stderr, stdout_bytes, stdout_truncated = _run_with_bounded_output(
            args,
            cwd=cwd,
            env=child_env,
            capture=capture or evidence_stdout,
            capture_stderr=capture_failure_stderr or forensic_capture,
            stdout_limit=(
                capture_output_limit
                if capture_output_limit is not None
                else (_FORENSIC_CAPTURE_LIMIT if evidence_stdout else None)
            ),
        )
        if evidence_stdout:
            # 반환값의 의미는 종전 그대로 둔다 — 호출부는 capture를 요구하지
            # 않았다. 증거는 stdout_bytes로만 흐른다.
            stdout = ""
            if capture_output_limit is None:
                # 증거용 상한은 **실패 사유가 아니다.** 이것을 아래
                # `runtime_command_output_too_large`로 흘리면 출력이 큰 성공
                # 명령이 실패로 뒤집힌다.
                stdout_truncated = False
    else:
        completed = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd is not None else "/",
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
        stdout = completed.stdout if capture else ""
        returncode = completed.returncode
        stderr = None
        stdout_bytes = None
        stdout_truncated = False
    if returncode != 0:
        diagnostic = (
            failure_exit_diagnostics.get(returncode)
            if failure_exit_diagnostics is not None
            else None
        )
        _fail(
            "runtime_command_failed",
            diagnostic=diagnostic,
            returncode=returncode,
            stderr=stderr,
            stdout=stdout_bytes,
        )
    if stdout_truncated:
        _fail(
            "runtime_command_output_too_large",
            stdout=stdout_bytes,
            stdout_truncated=True,
        )
    return stdout


def _run_with_bounded_output(
    args: tuple[str, ...],
    *,
    cwd: Path | None,
    env: dict[str, str],
    capture: bool,
    capture_stderr: bool,
    stdout_limit: int | None,
) -> tuple[str, int, bytes | None, bytes | None, bool]:
    """Bound captured child streams while draining every byte needed to avoid pipe stalls."""

    process = subprocess.Popen(
        list(args),
        cwd=str(cwd) if cwd is not None else "/",
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
    )
    captured_stderr = bytearray()

    def drain_stderr() -> None:
        assert process.stderr is not None
        while chunk := process.stderr.read(65_536):
            remaining = _FORENSIC_CAPTURE_LIMIT - len(captured_stderr)
            if remaining > 0:
                captured_stderr.extend(chunk[:remaining])

    reader = (
        threading.Thread(target=drain_stderr, daemon=True) if capture_stderr else None
    )
    if reader is not None:
        reader.start()
    captured_stdout = bytearray()
    stdout_truncated = False
    if capture:
        assert process.stdout is not None
        while chunk := process.stdout.read(65_536):
            if stdout_limit is None:
                captured_stdout.extend(chunk)
                continue
            remaining = stdout_limit - len(captured_stdout)
            if remaining > 0:
                captured_stdout.extend(chunk[:remaining])
            if len(chunk) > remaining:
                stdout_truncated = True
        stdout_bytes: bytes | None = bytes(captured_stdout)
        stdout = stdout_bytes.decode("utf-8", errors="replace")
    else:
        stdout = ""
        stdout_bytes = None
    returncode = process.wait()
    if reader is not None:
        reader.join()
    return stdout, returncode, bytes(captured_stderr) if capture_stderr else None, stdout_bytes, stdout_truncated


def _compose(
    *,
    root: Path,
    project: str,
    env_file: Path,
    files: tuple[Path, ...],
    arguments: tuple[str, ...],
    capture: bool = False,
    environment: dict[str, str] | None = None,
    failure_phase: str | None = None,
    failure_exit_diagnostics: dict[int, str] | None = None,
    failure_evidence_path: Path | None = None,
    output_evidence_path: Path | None = None,
) -> str:
    command = [
        "/usr/bin/docker",
        "compose",
        "--project-name",
        project,
        "--env-file",
        str(env_file),
    ]
    for item in files:
        command.extend(("--file", str(item)))
    command.extend(arguments)
    try:
        return _command(
            *command,
            cwd=root,
            env=environment,
            capture=capture,
            failure_exit_diagnostics=failure_exit_diagnostics,
            capture_failure_stderr=(
                failure_evidence_path is not None
                and os.environ.get(_FORENSIC_CAPTURE_ENV) == "1"
            ),
            capture_output_limit=(
                _COMPOSE_CONFIG_OUTPUT_LIMIT if output_evidence_path is not None else None
            ),
        )
    except _PhaseError as error:
        if failure_evidence_path is not None and error.phase == "runtime_command_failed":
            _write_compose_failure_evidence(
                failure_evidence_path,
                returncode=error.returncode,
                stderr=error.stderr,
            )
        if (
            output_evidence_path is not None
            and error.phase == "runtime_command_output_too_large"
        ):
            _write_compose_output_evidence(
                output_evidence_path,
                output=error.stdout or b"",
                truncated=error.stdout_truncated,
            )
        if failure_phase is not None and error.phase in {
            "runtime_command_failed",
            "runtime_command_output_too_large",
        }:
            _fail(
                failure_phase,
                diagnostic=error.diagnostic,
                returncode=error.returncode,
                stderr=error.stderr,
                # 증거 stdout을 여기서 떨어뜨리면 바깥 handler가 쓸 것이 없다.
                stdout=error.stdout,
            )
        raise


def _scrub_forensic_bytes(raw: bytes) -> bytes:
    """캡처 바이트에서 raw 비밀값 자체를 제거한다(적대 리뷰 R1-S9).

    크기 제한은 유출 총량만 줄일 뿐 내용을 방어하지 못한다 — 자식 프로세스가
    비밀값을 stderr/stdout에 에코하면 opt-in forensic leaf(0600 root)에 그대로
    남는다. 여기서 _RAW_ENV_NAMES의 현재 값을 마커로 치환한다. 8바이트 미만
    값은 치환하지 않는다(우연 일치로 출력이 훼손되는 것 방지 — 실제 비밀은
    전부 생성 토큰이라 그보다 길다).
    """

    for name in _RAW_ENV_NAMES:
        value = os.environ.get(name)
        if value and len(value) >= 8:
            raw = raw.replace(
                value.encode("utf-8"), b"[scrubbed:" + name.encode("ascii") + b"]"
            )
    # 이 harness의 비밀 대부분은 os.environ이 아니라 `env=` kwarg 딕셔너리로만
    # 자식에게 전달된다(적대 리뷰: environ 기반 scrub은 프로덕션에서 no-op였다).
    # 비밀을 만들어 넘기는 지점이 여기 레지스트리에 등록한다.
    for name, value in _FORENSIC_SCRUB_VALUES.items():
        if value and len(value) >= 8:
            raw = raw.replace(
                value.encode("utf-8"), b"[scrubbed:" + name.encode("ascii") + b"]"
            )
    return raw


_FORENSIC_SCRUB_VALUES: dict[str, str] = {}


def _register_forensic_scrub_environment(environment: dict[str, str]) -> None:
    """`env=` kwarg로 자식에게 넘기는 _RAW_ENV_NAMES 비밀값을 scrub 대상에 올린다."""

    for name in _RAW_ENV_NAMES:
        value = environment.get(name)
        if value:
            _FORENSIC_SCRUB_VALUES[name] = value


def _register_forensic_scrub_secrets(secrets_by_name: dict[str, str]) -> None:
    """생성 즉시 호출한다 — 등록이 늦으면 이른 phase에서 scrub이 항등이 된다.

    env dict 등록과 달리 필터가 없다: 여기 들어오는 것은 전부 이 run이 만든
    비밀이다(식별자/URL 같은 진단 가치 있는 값은 넣지 않는다).
    """

    for name, value in secrets_by_name.items():
        if value:
            _FORENSIC_SCRUB_VALUES[name] = value


def _write_compose_failure_evidence(
    path: Path, *, returncode: int | None, stderr: bytes | None
) -> None:
    """Persist fixed failure metadata; raw stderr requires an explicit root forensic opt-in."""

    if not isinstance(returncode, int) or returncode < 1 or returncode > 255:
        safe_returncode: int | None = None
    else:
        safe_returncode = returncode
    _write_private_json(
        path,
        {"kind": "compose_config", "returncode": safe_returncode, "version": 1},
    )
    if os.environ.get(_FORENSIC_CAPTURE_ENV) != "1" or stderr is None:
        return
    _write_private_bytes(
        path.with_suffix(".stderr"), _scrub_forensic_bytes(stderr)[:_FORENSIC_CAPTURE_LIMIT] or b"\n"
    )


def _write_command_failure_evidence(
    path: Path,
    *,
    returncode: int | None,
    stderr: bytes | None,
    stdout: bytes | None = None,
) -> None:
    """Persist a bounded generic external-command receipt without command or env disclosure.

    stderr뿐 아니라 **stdout도** 남긴다. 많은 러너가 진짜 진단을 stdout으로 낸다 —
    Playwright는 어느 spec의 어떤 단언이 깨졌는지를 거기 쓰고, stderr에는 npm의
    lifecycle 오류만 남는다. 2026-09-03 e2e22가 그래서 1시간 39분을 태우고
    "UI 명령이 1로 끝났다"만 남겼다. 두 스트림 모두 같은 scrub과 같은 상한을
    지나고 root 0600 leaf를 벗어나지 않는다.
    """

    if not isinstance(returncode, int) or returncode < 1 or returncode > 255:
        safe_returncode: int | None = None
    else:
        safe_returncode = returncode
    _write_private_json(
        path,
        {"kind": "runtime_command", "returncode": safe_returncode, "version": 1},
    )
    if os.environ.get(_FORENSIC_CAPTURE_ENV) != "1":
        return
    for suffix, raw in ((".stderr", stderr), (".stdout", stdout)):
        if raw is None:
            continue
        _write_private_bytes(
            path.with_suffix(suffix),
            _scrub_forensic_bytes(raw)[:_FORENSIC_CAPTURE_LIMIT] or b"\n",
        )


def _write_compose_output_evidence(
    path: Path, *, output: str | bytes, truncated: bool = False
) -> None:
    """Keep a fixed parse-failure marker; raw successful-command output remains opt-in only."""

    _write_private_json(
        path,
        {
            "kind": "compose_config_output",
            "truncated": truncated,
            "version": 1,
        },
    )
    if os.environ.get(_FORENSIC_CAPTURE_ENV) != "1":
        return
    raw = output if isinstance(output, bytes) else output.encode("utf-8", errors="replace")
    raw = _scrub_forensic_bytes(raw)[:_FORENSIC_CAPTURE_LIMIT]
    _write_private_bytes(path.with_suffix(".stdout"), raw or b"\n")


def _unlink_private(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        _fail("secret_cleanup_identity_invalid")
    path.unlink()
    # 같은 규칙(GM-10): unlink는 이미 성공했다. 디렉터리 fsync 실패를 전파하면
    # cleanup 실패로 보고돼 receipt의 cleanup_failed가 켜지고, 그 자체가
    # 실행 결과를 바꾼다 — 이미 끝난 삭제를 되돌리지도 못하면서.
    try:
        directory_fd = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)


def _root_directory(path: Path, *, mode: int = 0o700) -> None:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        _fail("runtime_directory_invalid")


def _cleanup_project(
    *,
    root: Path,
    project: str,
    env_file: Path,
    files: tuple[Path, ...],
    profiles: tuple[str, ...] = (),
) -> None:
    profile_arguments = tuple(
        item for profile in profiles for item in ("--profile", profile)
    )
    try:
        _compose(
            root=root,
            project=project,
            env_file=env_file,
            files=files,
            arguments=(*profile_arguments, "down", "--volumes", "--remove-orphans"),
        )
    except _PhaseError:
        _fail("runtime_cleanup_failed")
    remaining = _command(
        "/usr/bin/docker",
        "ps",
        "--all",
        "--quiet",
        "--filter",
        f"label=com.docker.compose.project={project}",
        capture=True,
    ).strip()
    networks = _command(
        "/usr/bin/docker",
        "network",
        "ls",
        "--quiet",
        "--filter",
        f"label=com.docker.compose.project={project}",
        capture=True,
    ).strip()
    volumes = _command(
        "/usr/bin/docker",
        "volume",
        "ls",
        "--quiet",
        "--filter",
        f"label=com.docker.compose.project={project}",
        capture=True,
    ).strip()
    if remaining or networks or volumes:
        _fail("runtime_cleanup_failed")


def _cleanup_temporary_resources(
    *,
    map_cleanup: _CleanupProject | None,
    pinvi_cleanup: _CleanupProject | None,
    private_files: tuple[Path, ...],
    disposable_run_worktree: _DisposableRunWorktree | None = None,
) -> tuple[bool, bool, bool]:
    """정상 cleanup failure와 receipt로 수렴해야 할 unexpected failure를 분리한다.

    세 번째 값은 **일회용 체크아웃이 남았는가**다. 그것은 `cleanup_failed`와 다르다 —
    아래 주석 참조.
    """

    cleanup_failed = False
    unexpected_failure = False
    run_worktree_retained = False
    for cleanup in (pinvi_cleanup, map_cleanup):
        if cleanup is None:
            continue
        try:
            _cleanup_project(
                root=cleanup[0],
                project=cleanup[1],
                env_file=cleanup[2],
                files=cleanup[3],
                profiles=cleanup[4],
            )
        except _PhaseError:
            cleanup_failed = True
        except Exception:  # noqa: BLE001 - fixed terminal receipt boundary
            unexpected_failure = True
    for path in private_files:
        try:
            _unlink_private(path)
        except _PhaseError:
            cleanup_failed = True
        except Exception:  # noqa: BLE001 - fixed terminal receipt boundary
            unexpected_failure = True
    if disposable_run_worktree is not None:
        (
            run_role,
            run_destination,
            run_state_paths,
            run_values,
            run_evidence,
        ) = disposable_run_worktree
        try:
            # **삭제 전에** 무엇이 남았는지 센다. 봉인 트리를 실행에서 뺀 뒤로는
            # gitignore 경로(`node_modules/`, `test-results/`) 쓰기를 관측하던 유일한
            # 탐지기(다음 preflight의 모드 검사)가 사라진다. 여기서 세어 두지 않으면
            # "실행이 무엇을 남겼는가"가 증거 없이 삭제된다(적대 리뷰 #3).
            _write_private_json(
                run_evidence,
                {
                    "kind": "disposable_run_worktree",
                    "version": 1,
                    "role": run_role,
                    **summarize_disposable_run_worktree(destination=run_destination),
                },
            )
        except Exception:  # noqa: BLE001, S110 - evidence-only boundary
            pass
        try:
            remove_disposable_run_worktree(
                release=PINNED_RUNTIME_RELEASE,
                state_paths=run_state_paths,
                values=run_values,
                role=run_role,
                destination=run_destination,
            )
        except Exception:  # noqa: BLE001 - fixed terminal receipt boundary
            # **`cleanup_failed`로 올리지 않는다.** 이 디렉터리는 output leaf 안의
            # 일회용 사본이고 핀 상태를 오염시키지 못한다. 그런데 종전 코드는
            # EBUSY(컨테이너 tmpfs 마운트 잔존) 하나로 통과한 1.5시간짜리 실행을
            # blocked로 뒤집고 attestation 해시를 버렸다 — 이 수정이 막으려던 바로
            # 그 손실이다(적대 리뷰 #5/MAJOR-3). 사실은 receipt 필드로 남긴다.
            run_worktree_retained = True
        for sealed_role in ("pinvi", "map"):
            try:
                # **사후조건.** 일회용 체크아웃으로 옮긴 것이 효과가 있었는지를 관측으로
                # 만든다. 이 검사가 없으면 "봉인 트리를 건드리지 않았다"는 주장이 다음
                # 실행의 preflight에서야 드러나고, 그때는 이미 한 사이클을 태운
                # 뒤다(2026-09-03·04에 실제로 그렇게 잃었다). 쓰기가 일어나는 것은 오늘
                # PinVi뿐이지만 Map 봉인 트리도 compose root이자 build context이므로
                # 둘 다 본다 — 비용은 os.walk 한 번이다(적대 리뷰 #9/MINOR-5).
                assert_pinned_worktree_is_still_sealed(
                    release=PINNED_RUNTIME_RELEASE,
                    state_paths=run_state_paths,
                    values=run_values,
                    role=sealed_role,
                )
            except Exception:  # noqa: BLE001 - fixed terminal receipt boundary
                # 이쪽은 핀 트리가 움직였다는 뜻이므로 정당하게 실행을 태운다.
                cleanup_failed = True
    return cleanup_failed, unexpected_failure, run_worktree_retained


def _random_secret() -> str:
    return secrets.token_urlsafe(36)


def _pbkdf2_password_hash(value: str) -> str:
    """Map frontend가 요구하는 portable PBKDF2 형식으로 isolated admin 비밀번호를 봉인한다."""

    import base64

    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, 310_000)
    encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return f"pbkdf2_sha256$310000${encode(salt)}${encode(digest)}"


def _map_fresh_init_diagnostic_runner() -> str:
    """Map source 오류를 원문 없이 고정 종료 코드로만 분류하는 one-shot runner."""

    error_codes = {
        "KOR_TRAVEL_MAP_MIGRATOR_PG_DSN is required": 41,
        "installed application Alembic root is unavailable": 42,
        "installed active Alembic graph head is not exactly 300": 42,
        "fresh 300 migration cannot verify migrator session": 43,
        "fresh 300 migration must connect as restricted migrator": 44,
        "fresh 300 migration requires no existing public.alembic_version table": 45,
        "fresh 300 pre-root state cannot be attested": 45,
        "fresh 300 pre-root state is not exact": 45,
        "fresh 300 migration did not produce exact raw revision 300": 46,
        "fresh 300 migration destination facet does not match baseline": 46,
    }
    runtime_error_codes = {
        "fresh 300 destination reference manifest is invalid": 51,
        "fresh 300 destination artifact map is invalid": 51,
        "fresh 300 destination facet SQL is invalid": 51,
        "fresh 300 destination facet does not match immutable reference": 51,
        "KOR_TRAVEL_MAP_ALEMBIC_USE_SCHEMA_OWNER_ROLE must be exactly true or false": 52,
        "Alembic external connection must be a SQLAlchemy Connection": 52,
        "300_schema_baseline is forward-only — older Alembic lineages are unsupported": 54,
    }
    return "\n".join(
        (
            "import asyncio",
            "import runpy",
            "module = runpy.run_path(",
            "    '/usr/local/bin/ktm-application-schema-fresh-300',",
            "    run_name='m05_map_fresh_init_diagnostic',",
            ")",
            "try:",
            "    if module['_parse_args'](['migrate']) != ('migrate', None):",
            "        raise SystemExit(127)",
            "    asyncio.run(module['_migrate']())",
            "except module['FreshMigrationError'] as error:",
            f"    raise SystemExit({error_codes!r}.get(str(error), 127))",
            "except BaseException as error:",
            "    identity = (type(error).__module__, type(error).__name__)",
            "    codes = {",
            "        ('kortravelmap.infra.runtime_privileges',",
            "         'RuntimePrivilegeReconciliationError'): 50,",
            "        ('alembic.util.exc', 'CommandError'): 47,",
            "        ('sqlalchemy.exc', 'OperationalError'): 49,",
            "        ('sqlalchemy.exc', 'ProgrammingError'): 49,",
            "        ('sqlalchemy.exc', 'SQLAlchemyError'): 49,",
            "    }",
            "    if identity == ('builtins', 'RuntimeError'):",
            "        message = str(error)",
            f"        runtime_codes = {runtime_error_codes!r}",
            "        if message in runtime_codes:",
            "            raise SystemExit(runtime_codes[message])",
            "        if message.startswith('300 baseline reference') or message.startswith(",
            "            '300 baseline application-',",
            "        ):",
            "            raise SystemExit(53)",
            "        if message.startswith('0236-to-300 ') or message.startswith(",
            "            '0236 application schema',",
            "        ) or message.startswith('generic Alembic stamp'):",
            "            raise SystemExit(54)",
            "        if message.startswith('application metadata maps') or message.startswith(",
            "            'alembic unmapped-table exclusions',",
            "        ):",
            "            raise SystemExit(55)",
            "        raise SystemExit(48)",
            "    raise SystemExit(codes.get(identity, 127))",
        )
    )


def _map_fresh_init_diagnostic_entrypoint() -> str:
    encoded = base64.b64encode(
        _map_fresh_init_diagnostic_runner().encode("utf-8")
    ).decode("ascii")
    return (
        "import base64; exec(compile(base64.b64decode("
        f"{encoded!r}), '<m05-map-fresh-init>', 'exec'))"
    )


def _free_ports(transaction: str) -> dict[str, int]:
    # host publish 포트는 kernel ephemeral 대역(기본 32768-60999) **밖**에서 고른다.
    # 아래 ss -ltn 가용성 검사는 listening 소켓만 보므로, ephemeral 대역 안의
    # 포트는 검사 통과 후 임의 outbound 연결이 로컬 포트로 선점해 Docker publish
    # bind가 확률적으로 실패한다(2026-09-01 e2e5 실측: rustfs 127.0.0.1:36464
    # address already in use). 20000-29999 대역은 이 호스트의 고정 서비스
    # (12xxx/13xxx)와도 겹치지 않는다.
    #
    # 이 전제(ephemeral 하한 > 29999)는 주석이 아니라 계약이다 — 하한을 낮춘
    # 호스트에서는 run 중반의 masked bind 실패로 되돌아가는 대신, mutation 전에
    # 결정적으로 닫는다(적대 리뷰).
    try:
        raw_range = (
            Path("/proc/sys/net/ipv4/ip_local_port_range")
            .read_text(encoding="ascii")
            .split()
        )
        ephemeral_low = int(raw_range[0])
    except (OSError, ValueError, IndexError):
        _fail("ports_unavailable")
    if ephemeral_low <= 29999:
        _fail("ports_unavailable")
    base = 20000 + (int(transaction[:8], 16) % 9000)
    names = (
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
    )
    for offset in range(1000):
        ports = {
            name: base + offset * len(names) + index for index, name in enumerate(names)
        }
        if max(ports.values()) >= 30000:
            break
        if all(
            not _command(
                "/usr/bin/ss", "-H", "-ltn", f"sport = :{port}", capture=True
            ).strip()
            for port in ports.values()
        ):
            return ports
    _fail("ports_unavailable")


def _map_network_addresses(transaction: str) -> tuple[str, str, str, str]:
    """기존 Docker subnet과 겹치지 않는 bridge gateway·Map API/BFF 주소를 고른다."""

    raw = _command(
        "/usr/bin/docker",
        "network",
        "ls",
        "--quiet",
        capture=True,
    )
    network_ids = [line for line in raw.splitlines() if len(line) == 64]
    existing: list[ipaddress.IPv4Network] = []
    if network_ids:
        inspected = _command(
            "/usr/bin/docker", "network", "inspect", *network_ids, capture=True
        )
        try:
            values = json.loads(inspected)
        except json.JSONDecodeError:
            _fail("network_inspect_invalid")
        if not isinstance(values, list):
            _fail("network_inspect_invalid")
        for value in values:
            if not isinstance(value, dict):
                _fail("network_inspect_invalid")
            ipam = value.get("IPAM")
            if not isinstance(ipam, dict) or not isinstance(ipam.get("Config"), list):
                continue
            for config in ipam["Config"]:
                if not isinstance(config, dict) or not isinstance(
                    config.get("Subnet"), str
                ):
                    continue
                try:
                    subnet = ipaddress.ip_network(config["Subnet"], strict=False)
                except ValueError:
                    continue
                if isinstance(subnet, ipaddress.IPv4Network):
                    existing.append(subnet)
    seed = int(transaction[:8], 16)
    for offset in range(224):
        # /28: gateway + Map postgres/rustfs/api/frontend + PinVi app-api join +
        # provider fixture one-shot까지 담아야 한다. /29(host 6)는 app-api join
        # 시점에 만석이라 fixture `docker run --network`가 IPAM 고갈로 죽는다
        # (적대 리뷰 계산 실측).
        candidate = ipaddress.ip_network(f"172.29.{(seed + offset) % 224}.0/28")
        if not any(candidate.overlaps(item) for item in existing):
            hosts = list(candidate.hosts())
            # 정적 주소(api/frontend)는 범위 **상단**에서 고른다. Docker IPAM은
            # 동적 할당을 하단부터 채우므로, 먼저 뜨는 postgres/rustfs가 하단
            # 주소를 가져가도 뒤에 뜨는 api/frontend의 정적 claim과 충돌하지
            # 않는다(2026-09-01 실측: !override로 정적 IP가 실제 적용되자
            # postgres가 .2를 선점해 api 기동이 결정적으로 실패했다).
            return str(candidate), str(hosts[0]), str(hosts[-1]), str(hosts[-2])
    _fail("network_subnet_unavailable")


def _http_json(
    url: str,
    *,
    headers: dict[str, str],
    body: dict[str, object] | None = None,
    opener: Any | None = None,
    failure_phase: str = "runtime_http_failed",
    http_error_phase: str | None = None,
    not_found_phase: str | None = None,
) -> dict[str, object]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        _fail("runtime_http_url_invalid")
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or not 1 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        _fail("runtime_http_url_invalid")
    encoded = (
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if body is not None
        else None
    )
    request = Request(
        url,
        data=encoded,
        headers={
            **headers,
            **({"Content-Type": "application/json"} if encoded else {}),
        },
        method="POST" if encoded else "GET",
    )
    try:
        request_opener = opener.open if opener is not None else _LOOPBACK_OPENER.open
        with request_opener(request, timeout=10) as response:
            raw = response.read(2_000_000)
    except HTTPError as error:
        # HTTP status와 loopback transport 오류를 같은 원문 없는 enum으로 합치면
        # 다음 one-shot 후보가 어느 startup 경계를 보정해야 하는지 알 수 없다.
        # 404("아직 없음")는 호출자가 요청할 때만 별도 enum으로 분리한다 —
        # 그래야 대기 루프가 404만 재시도하고 401/403/5xx는 즉시 종료한다.
        if not_found_phase is not None and error.code == 404:
            _fail(not_found_phase)
        _fail(http_error_phase or failure_phase)
    except (OSError, URLError):
        # 원문 HTTP status/body/socket error는 receipt에 기록하지 않는다. 대신 caller가
        # 고정 enum을 주면 다음 immutable candidate의 보정 범위만 식별할 수 있다.
        _fail(failure_phase)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("runtime_http_contract_failed")
    if not isinstance(value, dict):
        _fail("runtime_http_contract_failed")
    return value


def _wait_for_map_health(*, url: str) -> dict[str, object]:
    """Container health와 host loopback publish 사이의 bounded 경합만 one-shot 안에서 흡수한다.

    HTTP status와 응답 계약 오류는 즉시 terminal로 보존한다. 재시도 대상은 API container가
    healthy가 된 직후 host publish socket이 아직 수신하지 않는 transport 오류뿐이며, 원문
    socket detail은 저장하지 않는다.
    """

    for attempt in range(LOOPBACK_HTTP_READINESS_ATTEMPTS):
        try:
            return _http_json(
                url,
                headers={},
                failure_phase="map_health_transport_failed",
                http_error_phase="map_health_status_failed",
            )
        except _PhaseError as error:
            if (
                error.phase != "map_health_transport_failed"
                or attempt + 1 == LOOPBACK_HTTP_READINESS_ATTEMPTS
            ):
                raise
            time.sleep(LOOPBACK_HTTP_READINESS_RETRY_SECONDS)
    raise AssertionError("map health retry loop must return or raise")


def _data(value: dict[str, object]) -> dict[str, object]:
    data = value.get("data")
    if not isinstance(data, dict):
        _fail("runtime_http_contract_failed")
    return data


def _map_headers(secret: str) -> dict[str, str]:
    return {
        "X-Kor-Travel-Map-Admin-Proxy-Secret": secret,
        "X-Kor-Travel-Map-Actor": "m05-isolated-harness",
    }


def _pinvi_admin_opener(api_url: str, *, email: str, password: str) -> Any:
    if not email or not password:
        _fail("pinvi_auth_invalid")
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
    login = _data(
        _http_json(
            f"{api_url.rstrip('/')}/auth/login",
            headers={},
            body={"email": email, "password": password},
            opener=opener,
            failure_phase="pinvi_login_http_failed",
        )
    )
    roles = login.get("roles")
    if not isinstance(roles, list) or "admin" not in roles:
        _fail("pinvi_auth_invalid")
    return opener


def _pinvi_submit_m04_fixture(*, api_url: str, opener: Any, transaction: str) -> str:
    value = _data(
        _http_json(
            f"{api_url.rstrip('/')}/features/requests",
            headers={},
            body={
                "type": "new_place",
                "kind": "place",
                "title": f"M05 isolated manual {transaction[:12]}",
                "coord": {"lon": 127.111111, "lat": 37.511111},
                "categories": ["M05 isolated"],
                "note": "M05 isolated signed E2E fixture",
                "source": "user",
                "coord_source": "map_pick",
            },
            opener=opener,
            failure_phase="m04_fixture_http_failed",
        )
    )
    request_id = value.get("request_id")
    try:
        return str(uuid.UUID(str(request_id)))
    except (TypeError, ValueError):
        _fail("m04_fixture_invalid")


def _approve_map_request(
    *, admin_url: str, request_id: str, proxy_secret: str, manual_create_token: str
) -> str:
    value = _data(
        _http_json(
            f"{admin_url.rstrip('/')}/v1/admin/feature-requests/{request_id}/approve",
            headers={
                **_map_headers(proxy_secret),
                "Idempotency-Key": str(uuid.uuid4()),
                "X-Kor-Travel-Map-Admin-Feature-Create-Token": manual_create_token,
            },
            body={
                "category": "01070300",
                "marker_color": "P-01",
                "marker_icon": "marker",
            },
            failure_phase="m04_map_approval_http_failed",
        )
    )
    if value.get("request_id") != request_id or value.get("status") != "approved":
        _fail("m04_map_approval_invalid")
    feature_id = value.get("feature_id")
    if not isinstance(feature_id, str) or not feature_id:
        _fail("m04_map_approval_invalid")
    # T-VN-32C: 승인 응답의 feature_id는 UUID 정본이다 — canonical 형태로
    # 정규화해 URL 보간 안전성과 결박 비교의 견고성을 함께 얻는다(적대 리뷰).
    try:
        return str(uuid.UUID(feature_id))
    except ValueError:
        _fail("m04_map_approval_invalid")


def _resolve_manual_feature_text_id(
    *, admin_url: str, proxy_secret: str, feature_uuid: str
) -> str:
    """승인 응답의 UUID(T-VN-32C 정본)를 opaque TEXT feature_id로 해석한다.

    dedup 프로시저·reconciliation feed는 feature.features.feature_id(TEXT)를
    기대하는데 승인/생성 응답은 UUID를 싣는다 — 이 불일치가 e2e15에서
    'candidate Feature proof is not eligible'(NOT FOUND)로 드러났다. M02
    creation-provenance 리더가 두 식별자를 최상위에 함께 실으므로 그것으로
    해석하고, UUID 결박(feature_uuid == 요청 UUID)도 함께 검증한다.
    """

    value = _data(
        _http_json(
            f"{admin_url.rstrip('/')}/v1/admin/features/{feature_uuid}"
            "/creation-provenance",
            headers=_map_headers(proxy_secret),
            failure_phase="m04_map_feature_ref_resolve_failed",
        )
    )
    text_id = value.get("feature_id")
    if (
        not isinstance(text_id, str)
        or not text_id
        or value.get("feature_uuid") != feature_uuid
    ):
        _fail("m04_map_approval_invalid")
    return text_id


def _seed_m05_provider_fixture(
    *, map_network: str, map_env: Path, image: str, manual_feature_id: str
) -> dict[str, str]:
    raw = _command(
        "/usr/bin/docker",
        "run",
        "--rm",
        "--read-only",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,mode=1777",
        "--network",
        map_network,
        "--env-file",
        str(map_env),
        "--mount",
        f"type=bind,src={_ROOT / 'scripts/m05_isolated_fixture.py'},dst=/opt/m05_isolated_fixture.py,readonly",
        "--entrypoint",
        "/usr/local/bin/python",
        image,
        "-I",
        "-B",
        "/opt/m05_isolated_fixture.py",
        manual_feature_id,
        capture=True,
    )
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        _fail("m05_fixture_invalid")
    if not isinstance(value, dict) or set(value) != {
        "case_id",
        "manual_feature_id",
        "provider_feature_id",
    }:
        _fail("m05_fixture_invalid")
    try:
        uuid.UUID(str(value["case_id"]))
    except (TypeError, ValueError):
        _fail("m05_fixture_invalid")
    if value.get("manual_feature_id") != manual_feature_id:
        _fail("m05_fixture_invalid")
    provider_id = value.get("provider_feature_id")
    if not isinstance(provider_id, str) or not provider_id:
        _fail("m05_fixture_invalid")
    return {
        "case_id": str(value["case_id"]),
        "manual_feature_id": manual_feature_id,
        "provider_feature_id": provider_id,
    }


def _seed_pinvi_feature_reference(
    *, api_url: str, opener: object, feature_id: str
) -> int:
    """rebind가 실제로 고쳐 쓸 **사용자 참조**를 PinVi에 심는다.

    이걸 심지 않으면 impact_count가 구조적으로 0이 되고, live spec의 중심 단언이
    `expect(impacts).toHaveLength(0)`로 공허하게 참이 된다 — per-impact 단언
    본문이 한 줄도 실행되지 않은 채 게이트가 green이 난다. 즉 배관이 도는 것만
    증명하고 "사용자 참조를 고쳐 쓴다"는 M05의 존재 이유는 증명하지 못한다.

    일부러 **일상적인 사용자 경로**(POST /v1/trips → POST .../pois)를 쓴다.
    그 경로는 `feature_uuid`를 채우지 않으므로, 리바인드가 legacy 축만 있는
    행을 처리하고 두 축을 함께 복구하는지까지 같이 증명된다.

    돌려주는 값은 심은 참조 수 — 호출자가 receipt의 impact_count와 대조한다.
    """

    base = api_url.rstrip("/")
    trip = _data(
        _http_json(
            f"{base}/trips",
            headers={},
            body={"title": "M05 isolated rebind reference", "visibility": "private"},
            opener=opener,
            failure_phase="m05_pinvi_seed_http_failed",
        )
    )
    trip_id = trip.get("trip_id")
    try:
        trip_uuid = str(uuid.UUID(str(trip_id)))
    except (TypeError, ValueError):
        _fail("m05_pinvi_seed_invalid")
    poi = _data(
        _http_json(
            f"{base}/trips/{trip_uuid}/pois",
            headers={},
            body={
                "day_index": 1,
                "sort_order": "a0",
                "feature_id": feature_id,
                "feature_snapshot": {},
            },
            opener=opener,
            failure_phase="m05_pinvi_seed_http_failed",
        )
    )
    if poi.get("feature_id") != feature_id:
        _fail("m05_pinvi_seed_invalid")
    return 1


def _resolve_m05_case(
    *, admin_url: str, proxy_secret: str, case_id: str, provider_feature_id: str
) -> str:
    before = _data(
        _http_json(
            f"{admin_url.rstrip('/')}/v1/admin/manual-provider-dedup-cases/{case_id}",
            headers=_map_headers(proxy_secret),
            failure_phase="m05_case_lookup_http_failed",
        )
    )
    manual = before.get("manual_feature")
    provider = before.get("provider_feature")
    if (
        before.get("status") != "pending"
        or not isinstance(manual, dict)
        or not isinstance(provider, dict)
        or not isinstance(before.get("evidence_fingerprint"), str)
        or type(manual.get("row_revision")) is not int
        or type(provider.get("row_revision")) is not int
        or provider.get("feature_id") != provider_feature_id
    ):
        _fail("m05_case_invalid")
    decision = _data(
        _http_json(
            f"{admin_url.rstrip('/')}/v1/admin/manual-provider-dedup-cases/{case_id}/decisions",
            headers={
                **_map_headers(proxy_secret),
                "Idempotency-Key": str(uuid.uuid4()),
            },
            body={
                "decision": "merged",
                "expected_case_fingerprint": before["evidence_fingerprint"],
                "expected_manual_row_revision": manual["row_revision"],
                "expected_provider_row_revision": provider["row_revision"],
                "survivor_feature_id": provider_feature_id,
                "reason": "M05 isolated signed E2E rebind",
            },
            failure_phase="m05_case_decision_http_failed",
        )
    )
    if decision.get("outcome") != "merged":
        _fail("m05_case_invalid")
    event_id = decision.get("event_id")
    try:
        return str(uuid.UUID(str(event_id)))
    except (TypeError, ValueError):
        _fail("m05_case_invalid")


def _wait_for_pinvi_receipt(*, api_url: str, opener: Any, event_id: str) -> int:
    """PinVi detail 계약의 `applied`만 성공으로 수용하고 나머지는 즉시 종료한다.

    Map decision commit과 PinVi worker의 다음 polling 사이에는 receipt도
    delivery-attempt row도 없는 창이 있고, 그 창에서 PinVi detail 라우트는
    **404**를 준다(schemas: status는 blocked|applied 두 값뿐이라 'pending'
    응답은 존재하지 않는다 — 적대 리뷰). 종전 구현은 이름과 달리 단발
    GET이라 그 창에 걸리면 즉시 실패했다. 재시도 대상은 404 하나이고
    401/403/5xx·transport 오류·blocked·계약 위반은 여전히 즉시 terminal이다.
    """

    endpoint = (
        f"{api_url.rstrip('/')}/admin/feature-reference-reconciliations/{event_id}"
    )
    for attempt in range(_PINVI_RECEIPT_READINESS_ATTEMPTS):
        try:
            data = _data(
                _http_json(
                    endpoint,
                    headers={},
                    opener=opener,
                    failure_phase="m05_pinvi_receipt_http_failed",
                    not_found_phase="m05_pinvi_receipt_not_ready",
                )
            )
            break
        except _PhaseError as error:
            if (
                error.phase != "m05_pinvi_receipt_not_ready"
                or attempt + 1 == _PINVI_RECEIPT_READINESS_ATTEMPTS
            ):
                raise
            time.sleep(_PINVI_RECONCILIATION_POLL_SECONDS)
    status = data.get("status")
    if status == "blocked":
        _fail("m05_pinvi_receipt_blocked")
    if status != "applied":
        _fail("m05_pinvi_receipt_invalid")
    receipt = data.get("receipt")
    if not isinstance(receipt, dict):
        _fail("m05_pinvi_receipt_invalid")
    impact_count = receipt.get("impact_count")
    if type(impact_count) is not int or impact_count < 0:
        _fail("m05_pinvi_receipt_invalid")
    return impact_count


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


# `pair_contract_invalid`를 내는 지점이 15곳인데 전부 진단 없이 같은 문자열만
# 냈다. 2026-09-02에 그 때문에 실패 지점을 traceback으로 역추적해야 했다 —
# 71분짜리 rebuild를 태운 **뒤에** 몇 초 만에 거부당하고도 이유를 몰랐다.
#
# 이 트랙의 확립된 절차대로 원문을 노출하는 대신 **비밀 없는 고정 어휘**를 둔다.
# 값은 전부 이 파일이 쓴 상수라 호스트 상태·경로·비밀을 담지 않는다.
#: preflight가 stdout으로 낼 수 있는 source-materialization 문구의 접두.
#:
#: `pinned_runtime_sources`의 `DeploymentContractError`는 전부 이 접두로 시작하는
#: **컴파일 시점 리터럴**이다 — 호스트 상태나 경로가 섞일 수 없다. 문구를 열거하지
#: 않고 접두로 거르므로, 새 문구가 생겨도 이 상수가 뒤처지지 않는다.
_SOURCE_DIAGNOSTIC_PREFIX = "pinned runtime source "

_PAIR_DIAGNOSTICS: frozenset[str] = frozenset(
    {
        "pair contract is unreadable",
        "pair contract envelope schema is invalid",
        "pair entry schema is invalid",
        "pair digest field is not sha256",
        "pair source blob is unreadable at the contract revision",
        "pair source blob is not canonical json",
        "pair source canonical digest differs from the contract",
        "pair service entry is invalid",
        "pair contract version is unsupported",
        "pair source blob digest differs from the pinned release",
        "Map service provenance contract is unreadable",
        "Map service release revision is not a 40-hex commit",
        # `_source_pair_preflight`가 이미 쓰던 셋. 같은 phase를 내므로 같은
        # 어휘에 들어와야 preflight가 이것도 내보인다.
        "committed pinned-runtime generation manifest unavailable",
        "committed generation pinset differs from the current release",
        "derived application head differs from the committed generation",
    }
)


def _sha256_text(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        _fail("pair_contract_invalid", diagnostic="pair digest field is not sha256")
    return value


#: 이 파일이 인용하는 `T-VN-PAIR-V2`의 정본 문서는 **Map 저장소**의
#: `docs/tasks-acceptance.md` 같은 이름 절이다(v1 분기를 언제 뗄지가 §7에 있다).
#: PinVi가 vendoring하는 pair 계약의 저장소 내 경로.
_PAIR_CONTRACT_PATH = "contracts/kor-travel-map-m05-pair-provenance-v1.json"

#: service 표면의 릴리스 revision **정본**. PinVi `config.py`가 컨테이너 부팅 때
#: 이 값과 env를 대조하므로, 하네스가 env에 넣는 값도 여기서 나와야 한다.
_SERVICE_PROVENANCE_PATH = "contracts/kor-travel-map-service-provenance-v1.json"


def _service_release_revision(pinvi_root: Path) -> str:
    """service 릴리스 revision을 그 값의 정본 문서에서 읽는다."""

    try:
        document = json.loads(
            (pinvi_root / _SERVICE_PROVENANCE_PATH).read_text(encoding="utf-8")
        )
        revision = document["map_release_revision"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        _fail(
            "pair_contract_invalid",
            diagnostic="Map service provenance contract is unreadable",
        )
    if (
        not isinstance(revision, str)
        or len(revision) != _REVISION_LENGTH
        or any(char not in "0123456789abcdef" for char in revision)
    ):
        _fail(
            "pair_contract_invalid",
            diagnostic="Map service release revision is not a 40-hex commit",
        )
    return revision

#: pair 계약의 네 표면이 Map source의 어느 파일에서 나오는지. 격리 e2e의 `_pair`와
#: 회전 preflight가 **같은 한 곳**에서 읽는다 — 두 곳에 따로 적으면 표면이 늘 때
#: 한쪽만 늘어난다(`AGENTS.md` DO NOT 15).
_PAIR_SURFACE_PATHS = {
    "admin": "packages/kor-travel-map-api/openapi.json",
    "full": "packages/kor-travel-map-api/openapi.json",
    "service": "packages/kor-travel-map-api/openapi.service.json",
    "user": "packages/kor-travel-map-api/openapi.user.json",
}


def _pair(pinvi_root: Path, map_root: Path) -> tuple[M05IsolatedPairEvidence, str, str]:
    """PinVi가 vendoring한 M05 pair를 Map pinned Git blob까지 직접 대조한다."""

    path = pinvi_root / _PAIR_CONTRACT_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        mapping = value["map"]
        full = mapping["full"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        _fail("pair_contract_invalid", diagnostic="pair contract is unreadable")
    expected_entry_keys = {
        "openapi_sha256",
        "runtime_operation_contract_sha256",
        "source_canonical_sha256",
        "source_operation_contract_sha256",
        "source_revision",
    }
    # **v2만 읽는다.** dual-read는 두 저장소를 동시에 바꿀 수 없어서 둔 이행
    # 장치였고 그 이행이 끝났다 — 2026-09-07 pinset `b229446a`에서 회전 → rebuild
    # → 격리 M05 e2e가 `status: passed`로 닫혔다(`T-VN-PAIR-V2` §6; 정본 문서는
    # Map 저장소 `docs/tasks-acceptance.md`의 같은 이름 절이다). 판을 둘 유지하는
    # 것 자체가 "어느 판을 받는가"의 두 번째 선언이라 여기서 걷는다.
    #
    # v2의 요지: `source_revision`과 `runtime_image_digests`를 계약에서 걷어낸다.
    # 두 값의 생산자는 pin registry 하나여야 하는데 계약이 두 번째로 선언하고
    # 있었고, 그 때문에 Map 문서 한 줄이 PinVi 커밋 → 새 pinset → 71분 rebuild를
    # 불렀다(2026-09-01 이후 12건, 그중 10건은 상류 OpenAPI가 바이트 동일).
    #
    # v1 pinset으로 재개해야 하면 이 커밋을 revert한다 — 그것이 되돌리는 방법이다.
    version = value.get("version") if isinstance(value, dict) else None
    if version != 2:
        _fail(
            "pair_contract_invalid",
            diagnostic="pair contract version is unsupported",
        )
    # v2는 digest만 담는다. `runtime_image_digests`도 없다 — 격리 경로는 이미
    # Manager receipt의 실측 image ID로 전량 대체하고 있었고, 그 값은 두 pinset
    # 낡은 채 방치돼 있었다.
    expected_envelope = {"map", "version"}
    entry_keys = expected_entry_keys - {"source_revision"}
    if (
        not isinstance(value, dict)
        or set(value) != expected_envelope
        or not isinstance(mapping, dict)
        or set(mapping) != {"admin", "full", "service", "user"}
        or not isinstance(full, dict)
        or set(full) != entry_keys
    ):
        _fail(
            "pair_contract_invalid",
            diagnostic="pair contract envelope schema is invalid",
        )
    pinned_map_revision = PINNED_RUNTIME_RELEASE.source_for("map").revision
    revisions: set[str] = set()
    for name in ("admin", "full", "service", "user"):
        entry = mapping.get(name)
        if not isinstance(entry, dict) or set(entry) != entry_keys:
            _fail("pair_contract_invalid", diagnostic="pair entry schema is invalid")
        _sha256_text(entry.get("openapi_sha256"))
        _sha256_text(entry.get("runtime_operation_contract_sha256"))
        _sha256_text(entry.get("source_canonical_sha256"))
        _sha256_text(entry.get("source_operation_contract_sha256"))
        # `source_revision` 재선언은 위 `set(entry) != entry_keys`가 이미 잡는다 —
        # entry_keys가 그 키를 빼고 만들어지기 때문이다. 종전에는 여기에 전용
        # 검사가 하나 더 있었지만 **도달할 수 없었다**(변이 검증에서 드러났다).
    # 앵커는 pinned revision 하나다. 이것이 이 전환의 실질이다 — v1에서 digest
    # 대조는 **계약이 스스로 지목한 revision**에 앵커돼 있어 "계약은
    # 자기무모순이다"만 증명했다. 이제 네 entry 전부가 릴리스의 blob과 대조되므로
    # service·user 표면이 릴리스에 결박된다.
    revisions.add(pinned_map_revision)
    # PinVi attestation은 service 표면을 **그 표면의 릴리스 revision**에서
    # 읽는다(`_surface_revisions`). 그 object가 checkout에 없으면 하네스가 다 돌고
    # 난 뒤 `git show`에서 죽는다 — 여기서 함께 보충한다.
    revisions.add(_service_release_revision(pinvi_root))
    map_hash = _sha256_text(full.get("openapi_sha256"))
    # v1에는 여기 두 검사가 더 있었다 — 계약이 선언한 revision이 릴리스와 같은지,
    # 그리고 admin/full이 서로 같은지. v2에는 그 선언 자체가 없어 두 모순이
    # **구조적으로 존재할 수 없다.** 없앤 것은 검사가 아니라 검사가 필요했던
    # 이유다(위 entry 루프가 `source_revision` 재선언을 거부한다).
    # M05 source attestation은 pair가 지정한 admin/full/service/user Git blob 모두를
    # exact revision으로 다시 읽는다. materializer가 현재 head만 fetch하므로 worktree는
    # 바꾸지 않고 canonical bare source에 이 네 object만 보충한다.
    map_source = PINNED_RUNTIME_RELEASE.source_for("map")
    for pair_revision in sorted(revisions):
        _command(
            "/usr/bin/git",
            "-C",
            str(map_root),
            "fetch",
            "--no-tags",
            map_source.canonical_url,
            pair_revision,
        )
    for name, relative_path in _PAIR_SURFACE_PATHS.items():
        entry = mapping[name]
        if not isinstance(entry, dict):
            _fail("pair_contract_invalid", diagnostic="pair entry schema is invalid")
        revision = pinned_map_revision
        try:
            raw = subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(map_root),
                    "show",
                    f"{revision}:{relative_path}",
                ],
                cwd="/",
                env=_SAFE_SUBPROCESS_ENV,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            _fail(
                "pair_contract_invalid",
                diagnostic="pair source blob is unreadable at the contract revision",
            )
        if raw.returncode != 0 or hashlib.sha256(
            raw.stdout
        ).hexdigest() != _sha256_text(entry["openapi_sha256"]):
            # 계약이 **릴리스**와 어긋난다 — 진짜 표면 변경이므로 운영자의
            # 다음 행동은 재벤더링이다. v1에는 "계약이 자기 revision과 어긋난다"는
            # 다른 사실도 있었으나 그 선언이 사라져 이 자리에 한 뜻만 남는다.
            _fail(
                "pair_contract_invalid",
                diagnostic="pair source blob digest differs from the pinned release",
            )
        try:
            source_value = json.loads(raw.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail(
                "pair_contract_invalid",
                diagnostic="pair source blob is not canonical json",
            )
        if hashlib.sha256(_canonical_json(source_value)).hexdigest() != _sha256_text(
            entry["source_canonical_sha256"]
        ):
            _fail(
                "pair_contract_invalid",
                diagnostic="pair source canonical digest differs from the contract",
            )
    service = mapping["service"]
    if not isinstance(service, dict):
        _fail("pair_contract_invalid", diagnostic="pair service entry is invalid")
    service_openapi_sha256 = _sha256_text(service.get("openapi_sha256"))
    # service 표면의 revision을 정하는 것은 pin registry가 **아니다.** 그 값의
    # 정본은 PinVi의 `kor-travel-map-service-provenance-v1.json`이고, v1 pair
    # 계약이 그것을 세 번째로 선언하고 있었을 뿐이다. 여기에 pinned Map revision을
    # 넣으면 PinVi가 부팅 시 거부한다 — `config.py`의
    # `validate_feature_reference_reconciliation`이 이 값을 그 계약과 대조하고,
    # 두 값은 재핀 주기가 달라 실제로 갈라져 있다(적대 리뷰 P0).
    service_source_revision = _service_release_revision(pinvi_root)
    return (
        M05IsolatedPairEvidence(
            map_full_openapi_sha256=map_hash,
            map_source_revision=PINNED_RUNTIME_RELEASE.source_for("map").revision,
            pinvi_full_openapi_sha256=map_hash,
            pinvi_source_revision=PINNED_RUNTIME_RELEASE.source_for("pinvi").revision,
        ),
        service_openapi_sha256,
        service_source_revision,
    )


def _assert_pinvi_manager_admission_contract(pinvi_root: Path) -> None:
    """Pinned PinVi source가 Manager-only isolated admission을 실제로 강제하는지 확인한다."""

    values: dict[str, str] = {}
    for relative in _PINVI_MANAGER_ADMISSION_FILES:
        path = pinvi_root / relative
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 128_000:
                raise OSError
            values[relative] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            _fail("pinvi_manager_admission_contract_invalid")
    if not all(
        token in values["scripts/docker-app.sh"]
        or token in values["scripts/m05_isolated_manager_admission.py"]
        for token in _PINVI_MANAGER_ADMISSION_TOKENS
    ):
        _fail("pinvi_manager_admission_contract_invalid")


def _source_pair_preflight() -> tuple[
    Path,
    Path,
    M05IsolatedPairEvidence,
    str,
    str,
    PinnedRuntimeStatePaths,
    Mapping[str, str],
    str,
]:
    """실행권을 소비하기 전에 pinned source pair의 integration 계약만 검사한다."""

    ambient = dict(os.environ)
    try:
        os.environ.clear()
        values = effective_environment(str(_ROOT / ".env"))
    finally:
        os.environ.clear()
        os.environ.update(ambient)
    state_paths = pinned_runtime_state_paths(
        values, pinset_sha256=PINNED_RUNTIME_RELEASE.pinset_sha256
    )
    sources = materialize_pinned_runtime_sources(
        release=PINNED_RUNTIME_RELEASE, state_paths=state_paths, values=values
    )
    map_root, pinvi_root = (
        sources.source_for("map").root,
        sources.source_for("pinvi").root,
    )
    # 파생 head를 **committed generation manifest**와 exact 대조한다. 종전에는 이
    # 대조가 사람의 선언(배리어 B1 "미반영 변경이 없을 것")이었고, harness는 manifest의
    # `map_application_head`를 한 번도 읽지 않았다 — 유도값 자기무모순 검사뿐이었다.
    # 여기서 기계화하면 낡은 candidate는 실행권 소비 전에 fail-close하고, "미래에
    # 변경이 없을 것"이라는 검증 불가 조건이 필요 없어진다
    # (ktm-m03 docs/reports/map-stall-root-cause-2026-08-31.md §3 I-4).
    #
    # image ID는 대조하지 않는다 — 이 harness는 materialize된 source에서 자체 build
    # 하므로 committed generation의 image ID와 정당하게 다르다. OpenAPI는 아래
    # `_pair`가 이미 pinned release의 digest와 exact 대조한다.
    try:
        committed = read_pinned_runtime_manifest(state_paths.manifest).active_generation
    except (DeploymentContractError, OSError):
        _fail(
            "pair_contract_invalid",
            diagnostic="committed pinned-runtime generation manifest unavailable",
        )
    if committed.pinset_sha256 != PINNED_RUNTIME_RELEASE.pinset_sha256:
        _fail(
            "pair_contract_invalid",
            diagnostic="committed generation pinset differs from the current release",
        )
    if committed.map_application_head != _map_application_head(map_root):
        _fail(
            "pair_contract_invalid",
            diagnostic="derived application head differs from the committed generation",
        )
    pair, service_openapi_sha256, service_source_revision = _pair(pinvi_root, map_root)
    _assert_pinvi_manager_admission_contract(pinvi_root)
    # `state_paths`/`values`도 함께 돌려준다. body가 일회용 실행 체크아웃을 만들려면
    # 이 둘이 필요한데, 거기서 다시 유도하면 같은 사실의 두 번째 선언이 된다.
    #
    # PinVi 핀 tree도 같은 이유로 여기서 낸다. 일회용 체크아웃이 자기 tree를 같은
    # bare에서 다시 유도해 대조하면 git 결정성만 확인하는 자기참조가 된다 —
    # `materialize_pinned_runtime_sources`가 이미 검증한 이 값과 대조해야 핀과의
    # 결박이다(적대 리뷰 2026-09-04 #8).
    return (
        map_root,
        pinvi_root,
        pair,
        service_openapi_sha256,
        service_source_revision,
        state_paths,
        values,
        sources.source_for("pinvi").tree,
    )


def _rotation_pair_digests(mapping: object, *, map_revision: str) -> int:
    """v2 계약의 네 표면 digest가 회전 대상 Map revision의 blob과 같은지 본다.

    `_pair`(격리 e2e)가 pinned 릴리스에 대해 하는 대조와 같은 것을, 아직 pin되지
    않은 회전 대상에 대해 한다. 임시 bare 저장소에 그 revision만 fetch하므로
    기존 상태를 건드리지 않고 실패해도 남기는 것이 없다.
    """

    if not isinstance(mapping, dict) or set(mapping) != set(_PAIR_SURFACE_PATHS):
        print("rotation pair contract inventory is invalid", flush=True)
        return 1
    map_source = PINNED_RUNTIME_RELEASE.source_for("map")
    try:
        with tempfile.TemporaryDirectory() as scratch:
            bare = Path(scratch) / "map.git"
            _command("/usr/bin/git", "init", "--quiet", "--bare", str(bare))
            _command(
                "/usr/bin/git",
                "-C",
                str(bare),
                "fetch",
                "--no-tags",
                "--depth",
                "1",
                map_source.canonical_url,
                map_revision,
            )
            for name, relative_path in _PAIR_SURFACE_PATHS.items():
                entry = mapping[name]
                expected = entry.get("openapi_sha256") if isinstance(entry, dict) else None
                if (
                    not isinstance(expected, str)
                    or len(expected) != 64
                    or any(char not in "0123456789abcdef" for char in expected)
                ):
                    print(f"rotation pair contract {name} digest is not sha256", flush=True)
                    return 1
                blob = subprocess.run(
                    [
                        "/usr/bin/git",
                        "-C",
                        str(bare),
                        "show",
                        f"{map_revision}:{relative_path}",
                    ],
                    cwd="/",
                    env=_SAFE_SUBPROCESS_ENV,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                if blob.returncode != 0:
                    print(
                        f"rotation Map surface is unreadable at the target revision: {name}",
                        flush=True,
                    )
                    return 1
                actual = hashlib.sha256(blob.stdout).hexdigest()
                if actual != expected:
                    # 두 값 모두 공개 digest다 — 비밀이 아니다. 여기서 실제 값을
                    # 보여 주지 않으면 운영자가 다시 traceback으로 역추적한다.
                    print(
                        f"rotation pair contract {name} digest differs from the Map revision: "
                        f"contract={expected} map={actual}",
                        flush=True,
                    )
                    return 1
    except (_PhaseError, OSError, RuntimeError, ValueError):
        print("rotation Map source is unreadable at the target revision", flush=True)
        return 1
    return 0


def rotation_preflight(map_revision: str, pinvi_revision: str) -> int:
    """`pin rotate-pair` **전에** 대상 pair가 서로를 지목하는지 본다.

    `_pair`(:1690)는 계약의 `map.full.source_revision`이 pinned Map revision과
    같기를 요구한다. 그런데 그 검사는 격리 e2e launcher에서만 돌고,
    `run-pinned-rebuild-once`는 이 계약을 읽지 않는다. 그래서 어긋난 pair로
    회전하면 **71분짜리 rebuild를 다 태운 뒤에** 몇 초 만에 거부당한다 —
    2026-09-02에 실제로 그렇게 잃었다.

    여기서 보는 것은 문자열 두 개다. 비용은 fetch 한 번이고, 막아 주는 것은
    rebuild 한 사이클이다. 검사를 **약하게 하지 않고** 앞으로 당긴다.

    회전 대상 PinVi revision은 아직 pinned가 아니므로 materialize된 트리에
    없다. 임시 bare 저장소에 그 하나만 fetch해서 읽는다 — 기존 상태를
    건드리지 않고, 실패해도 남기는 것이 없다.
    """

    for revision in (map_revision, pinvi_revision):
        if len(revision) != _REVISION_LENGTH or any(
            char not in "0123456789abcdef" for char in revision
        ):
            print("rotation revision is not a 40-hex commit", flush=True)
            return 1
    pinvi_source = PINNED_RUNTIME_RELEASE.source_for("pinvi")
    try:
        with tempfile.TemporaryDirectory() as scratch:
            bare = Path(scratch) / "pinvi.git"
            _command("/usr/bin/git", "init", "--quiet", "--bare", str(bare))
            _command(
                "/usr/bin/git",
                "-C",
                str(bare),
                "fetch",
                "--no-tags",
                "--depth",
                "1",
                pinvi_source.canonical_url,
                pinvi_revision,
            )
            raw = _command(
                "/usr/bin/git",
                "-C",
                str(bare),
                "show",
                f"{pinvi_revision}:{_PAIR_CONTRACT_PATH}",
                capture=True,
            )
    except (_PhaseError, OSError, RuntimeError, ValueError):
        print("rotation pair contract is unreadable at the target revision", flush=True)
        return 1
    try:
        contract = json.loads(raw)
        mapping = contract["map"]
        version = contract["version"]
    except (KeyError, TypeError, json.JSONDecodeError):
        print("rotation pair contract schema is invalid", flush=True)
        return 1
    if version != 2:
        print(f"rotation pair contract version is unsupported: {version}", flush=True)
        return 1
    # 계약에는 비교할 revision 문자열이 없다. 그렇다고 볼 것이 없어지는 것은
    # 아니다 — v1에서 revision이 하던 역할("이 계약은 저 Map을 가리킨다")을
    # 이제 **digest가** 한다. 그 대조는 격리 e2e의 `_pair`에도 있지만 그것은
    # 회전·rebuild가 끝난 **뒤**다. 여기서 같은 대조를 회전 대상 revision에 대해
    # 앞으로 당기지 않으면 이 게이트가 막던 71분 소각이 되살아난다(2026-09-02에
    # 실제로 잃은 그 사이클).
    return _rotation_pair_digests(mapping, map_revision=map_revision)



#: leaf가 스스로 밝히는 하네스 이름. 결과 기록과 검증이 같은 상수를 쓴다 —
#: 두 곳에 리터럴로 적으면 한쪽만 바뀌어도 검증이 조용히 통과한다.
_HARNESS_NAME = "m05-isolated-bridge-v1"
_HARNESS_VERSION = 1

#: leaf가 담는 세 증적의 상대 경로. `result.json`의 세 해시가 각각 이것을 가리킨다.
_LEAF_HASHED_ARTIFACTS = {
    "m04_attestation_sha256": "runtime/m04/m04-attestation.json",
    "m05_attestation_sha256": "runtime/m05/attestation.json",
    "runtime_provenance_sha256": "runtime/isolated-runtime-provenance.json",
}


def _leaf_ledger_claim_name(
    *,
    manager_source_revision: str,
    execution_identity_sha256: str,
    pinset_sha256: str,
) -> str:
    """leaf 값에서 ledger claim 파일 이름을 다시 계산한다.

    payload 모양은 `M05IsolatedHarnessPlan.claim_bytes`(services/m05_isolated_harness.py)
    가 정본이고 여기서 그것을 재현한다. 두 곳이 어긋나면 이 축이 조용히 항상
    실패하므로 `test_leaf_ledger_claim_name_matches_the_planner`가 둘을 결박한다.
    """

    payload = {
        "harness": _HARNESS_NAME,
        "manager_source_revision": manager_source_revision,
        "execution_identity_sha256": execution_identity_sha256,
        "pinset_sha256": pinset_sha256,
        "version": _HARNESS_VERSION,
    }
    raw = (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


class _UntrustedLeaf(Exception):
    """leaf가 특권 생산자의 산물이라는 증거가 없다."""


def _trusted_leaf_bytes(path: Path) -> bytes:
    """leaf 파일을 **소유자·권한·symlink를 확인하고** 한 번만 읽는다.

    종전에는 `path.open("rb")`였다 — symlink를 그대로 따라가고 소유자도 mode도
    보지 않았다. 그래서 `--verify-leaf`가 사실상 **아무 디렉터리나** 받았고,
    "root-owned 0600 leaf"라는 근거가 기계로 강제되지 않았다(2026-09-07 적대 리뷰
    P0, 두 리뷰어 모두 독립 지적).

    소유자는 **검증기를 돌리는 euid**와 대조한다. `__main__`이 `os.geteuid() != 0`이면
    `SystemExit(2)`로 막으므로(스크립트 하단) 프로덕션에서 그 euid는 항상 root다.
    리터럴 0으로 박지 않는 이유는 그래야 이 축을 비-root 테스트가 **실제로** 잴 수
    있기 때문이다 — 우회 플래그를 두면 그 플래그가 곧 게이트를 없앤다.

    저장소는 다른 trusted artifact마다 이미 이 규율을 쓴다
    (`_secure_read_root_file`, `runtime_execution_registry._read_trusted_text`,
    `runtime_pin_registry._assert_registry_file_integrity`). 승격을 정의하는 이
    함수만 빠져 있었다.

    **바이트를 한 번만 읽어 돌려준다.** 종전에는 해시용으로 한 번, 파싱용으로 또
    한 번 열어 그 사이에 파일이 바뀔 수 있었다(TOCTOU).
    """

    if not hasattr(os, "O_NOFOLLOW"):
        raise _UntrustedLeaf("O_NOFOLLOW를 쓸 수 없는 플랫폼이다")
    try:
        before = path.lstat()
    except OSError as error:
        raise _UntrustedLeaf(f"{path.name}: 읽을 수 없다") from error
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise _UntrustedLeaf(f"{path.name}: 정규 파일이 아니다")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise _UntrustedLeaf(f"{path.name}: 검사와 읽기 사이에 바뀌었다")
        # 이 uid 검사는 **심층 방어**다. `_assert_trusted_leaf_root`가 디렉터리를
        # 0700 + 특권 신원 소유로 요구하므로 그 안에 다른 uid가 파일을 만들 수
        # 없다 — 그래서 비-root 테스트로 이 축만 따로 뒤집는 변이를 만들 수 없다
        # (실제로 시도했고 초록이었다). 가짜 게이트를 붙이는 대신 사실을 적는다:
        # 이 줄이 지키는 것은 디렉터리 검사가 우회됐을 때뿐이다.
        if opened.st_uid != os.geteuid():
            raise _UntrustedLeaf(
                f"{path.name}: 검증기를 돌리는 신원의 소유가 아니다(uid={opened.st_uid})"
            )
        if stat.S_IMODE(opened.st_mode) & 0o077:
            raise _UntrustedLeaf(
                f"{path.name}: mode {stat.S_IMODE(opened.st_mode):04o} — group/other에 열려 있다"
            )
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
            if sum(len(part) for part in chunks) > 8_000_000:
                raise _UntrustedLeaf(f"{path.name}: 너무 크다")
    finally:
        os.close(fd)
    return b"".join(chunks)


def _assert_trusted_leaf_root(leaf: Path) -> None:
    """leaf 디렉터리가 root 소유이고 group/other에 닫혀 있어야 한다.

    드라이버는 출력 디렉터리에 `_root_directory(output)`를 걸고 시작한다 —
    검증기가 같은 것을 요구하지 않으면 그 규율이 사후에 아무 의미가 없다.
    """

    try:
        metadata = leaf.lstat()
    except OSError as error:
        raise _UntrustedLeaf(f"{leaf}: 없거나 읽을 수 없다") from error
    if leaf.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise _UntrustedLeaf(f"{leaf}: 디렉터리가 아니다")
    if metadata.st_uid != os.geteuid():
        raise _UntrustedLeaf(
            f"{leaf}: 검증기를 돌리는 신원의 소유가 아니다(uid={metadata.st_uid})"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise _UntrustedLeaf(
            f"{leaf}: mode {stat.S_IMODE(metadata.st_mode):04o} — group/other에 열려 있다"
        )


def _leaf_object(value: object, *, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(f"{name} is not an object")
    return value


def verify_leaf(leaf: Path) -> int:
    """격리 M05 leaf를 **현재 pin registry와 다시 계산해** 대조한다.

    승격(`T-VN-M05-ACTIVATION`)의 근거가 무엇인지를 이 함수가 정의한다.

    **서명은 근거가 아니다.** 드라이버는 실행마다 `openssl genpkey`로 Ed25519 키를
    새로 만들어 서명하고 실행 종료와 함께 그 키를 지운다 — 공개키가 어디에도 남지
    않으므로 사후 제3자 검증이 불가능하다. 서명이 봉인하는 것은 생성 시점의 내부
    정합뿐이다(2026-09-07 적대 리뷰 P1).

    실제 근거는 셋이고 전부 지금 다시 계산할 수 있다:

    1. **root-owned 0600 leaf** — 실행이 남긴 파일 자체.
    2. **해시 사슬** — `result.json`의 세 해시가 그 파일들의 sha256과 같다.
    3. **살아 있는 registry와의 일치** — leaf가 주장하는 pinset·Manager revision·
       execution identity·Map/PinVi revision이 지금 pin registry가 말하는 것과 같고,
       그 pinset·execution이 terminal로 차단돼 있지 않다.

    하나라도 어긋나면 거부한다. 통과는 "이 leaf가 **현재** 고정된 pair의 증적이다"를
    뜻하며, pin이 움직이면 같은 leaf가 다시 통과하지 않는다 — 그것이 이 검증이
    문서 문장과 다른 점이다.
    """

    checks: list[tuple[str, bool, str]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))

    try:
        _assert_trusted_leaf_root(leaf)
        result = _leaf_object(
            json.loads(_trusted_leaf_bytes(leaf / "result.json")), name="leaf result"
        )
    except _UntrustedLeaf as error:
        print(f"leaf is not a trusted root-owned artifact: {error}", flush=True)
        return 1
    except (OSError, TypeError, ValueError):
        print("leaf result.json is unreadable", flush=True)
        return 1
    record("L0 leaf 신뢰 경계", True, f"root-owned 비공개 디렉터리 {leaf}")

    record(
        "L1 harness/status/phase",
        result.get("harness") == _HARNESS_NAME
        and result.get("status") == "passed"
        and result.get("phase") == "completed",
        f"harness={result.get('harness')} status={result.get('status')} "
        f"phase={result.get('phase')}",
    )

    # 해시한 **그 바이트**를 뒤에서 그대로 파싱한다 — 두 번 열면 그 사이에 바뀔 수 있다.
    hashed_bytes: dict[str, bytes] = {}
    for field, relative in _LEAF_HASHED_ARTIFACTS.items():
        try:
            raw = _trusted_leaf_bytes(leaf / relative)
        except _UntrustedLeaf as error:
            record(f"L2 {relative}", False, f"신뢰 읽기 실패: {error}")
            continue
        hashed_bytes[field] = raw
        actual = hashlib.sha256(raw).hexdigest()
        record(
            f"L2 {relative}",
            actual == result.get(field),
            f"result.{field}={result.get(field)} recomputed={actual}",
        )

    try:
        attestation = _leaf_object(
            json.loads(hashed_bytes["m05_attestation_sha256"]), name="m05 attestation"
        )
        payload = _leaf_object(attestation.get("payload"), name="m05 attestation payload")
        provenance = _leaf_object(
            json.loads(hashed_bytes["runtime_provenance_sha256"]),
            name="isolated runtime provenance",
        )
        provenance_map = _leaf_object(provenance.get("map"), name="provenance map")
    except (KeyError, OSError, TypeError, ValueError):
        print("leaf attestation/provenance is unreadable", flush=True)
        return 1

    map_source = PINNED_RUNTIME_RELEASE.source_for("map")
    pinvi_source = PINNED_RUNTIME_RELEASE.source_for("pinvi")

    record(
        "L3 pinset",
        payload.get("isolated_pinset_sha256")
        == result.get("pinset_sha256")
        == PINNED_RUNTIME_RELEASE.pinset_sha256,
        f"attestation={payload.get('isolated_pinset_sha256')} "
        f"result={result.get('pinset_sha256')} "
        f"registry={PINNED_RUNTIME_RELEASE.pinset_sha256}",
    )

    # execution identity는 **history**에서 찾는다. `current`만 보면 이 검증기 자신을
    # 배포하는 순간(= rebind로 새 identity가 생기는 순간) 그 이전 leaf가 전부
    # 검증 불가가 된다 — 검증기가 자기가 배포되기 전의 증적을 영원히 못 보는
    # 구조였다. registry history는 append-only이고 각 binding이 pinset·Map·PinVi
    # revision을 함께 들고 있으므로, "그 identity가 **지금 고정된 pair**에 결박된
    # 것이었는가"를 여기서 다시 계산할 수 있다.
    #
    # `current` 여부는 통과 조건이 아니라 **보고 대상**이다. Manager 업그레이드는
    # 정당하게 identity를 바꾸며, 그것이 과거 증적을 무효화하지는 않는다.
    leaf_identity = payload.get("isolated_execution_identity_sha256")
    try:
        trusted_manager: str | None = trusted_manager_source_revision()
    except (DeploymentContractError, OSError, ValueError):
        trusted_manager = None
    try:
        execution = load_runtime_execution_registry()
        bindings = (execution.current, *execution.history)
        # **leaf 자신의** identity가 차단됐는지를 본다. 종전에는 `current`만 봤는데
        # 승격 후보는 둘 다 current가 아닌 identity라, 그 leaf가 소각됐어도 L8이
        # 통과했다(2026-09-07 적대 리뷰 P0).
        execution_blocked = any(
            entry.execution_identity_sha256 == leaf_identity
            for entry in execution.blocked_executions
        ) or execution.is_unconditionally_blocked_current()
        is_current = execution.current.execution_identity_sha256 == leaf_identity
        bound = next(
            (
                binding
                for binding in bindings
                if binding.execution_identity_sha256 == leaf_identity
                and binding.source_pinset_sha256 == PINNED_RUNTIME_RELEASE.pinset_sha256
                and binding.map_revision == map_source.revision
                and binding.pinvi_revision == pinvi_source.revision
            ),
            None,
        )
    except (RuntimeExecutionRegistryError, DeploymentContractError):
        bound = None
        is_current = False
        execution_blocked = True
    record(
        "L5 execution identity",
        bound is not None
        and leaf_identity == result.get("execution_identity_sha256"),
        f"attestation={leaf_identity} result={result.get('execution_identity_sha256')} "
        f"registry_binding={'found' if bound else 'absent'} is_current={is_current}",
    )

    # Manager revision도 **그 binding에서** 파생한다. 설치된 revision과 대조하면
    # L5와 똑같은 이유로 깨진다 — 이 검증기를 배포하는 순간 설치 revision이 바뀌어
    # 자기 배포 이전 leaf를 영원히 못 본다(2026-09-07 n150 실측: L5는 고쳤는데 L4가
    # 같은 결함을 그대로 들고 있어 승격 후보가 거부됐다).
    #
    # 설치된 revision과의 일치 여부는 **보고 대상**이다. Manager 업그레이드는 과거
    # 증적을 무효화하지 않는다.
    record(
        "L4 Manager source revision",
        bound is not None
        and payload.get("isolated_manager_source_revision")
        == result.get("manager_source_revision")
        == bound.manager_source_revision,
        f"attestation={payload.get('isolated_manager_source_revision')} "
        f"result={result.get('manager_source_revision')} "
        f"binding={getattr(bound, 'manager_source_revision', None)} "
        f"installed={trusted_manager} is_installed={trusted_manager == result.get('manager_source_revision')}",
    )

    record(
        "L6 Map/PinVi source revision",
        provenance_map.get("source_revision") == map_source.revision
        and provenance.get("pinvi", {}).get("source_revision") == pinvi_source.revision
        if isinstance(provenance.get("pinvi"), dict)
        else False,
        f"provenance map={provenance_map.get('source_revision')} "
        f"registry map={map_source.revision}",
    )

    record(
        "L7 M04 server-side chain",
        payload.get("m04_server_side_chain_verified") is True,
        f"m04_server_side_chain_verified={payload.get('m04_server_side_chain_verified')}",
    )

    # L7이 자유 불리언 하나였다 — 그것이 주장하는 M04 증적 파일은 L2가 해시만 하고
    # **한 번도 열지 않았다.** m05 attestation payload가 이미 `m04_attestation_sha256`을
    # 들고 있으므로 그것을 L2가 재계산한 값과 대조하면 M04가 사슬에 들어온다
    # (2026-09-07 적대 리뷰 P0-3: "공짜로 쓸 수 있는 결박을 버렸다").
    record(
        "L7b M04 증적이 사슬 안에 있다",
        payload.get("m04_attestation_sha256") == result.get("m04_attestation_sha256"),
        f"attestation={payload.get('m04_attestation_sha256')} "
        f"result={result.get('m04_attestation_sha256')}",
    )

    # **닻.** L3~L6이 대조하는 값은 전부 `-public` 사본에서 world-readable이라
    # (n150 실측 0644) 공개값만으로 조립한 leaf가 L1~L7을 통과할 수 있다. ledger는
    # root-only 0700이고 드라이버가 실행 **전에** O_EXCL로 claim을 남기므로, claim의
    # 실재는 "특권 생산자가 이 (identity, pinset, Manager)로 실제 실행했다"를 뜻한다.
    # 파일 이름은 공개값에서 계산되지만 **만들려면 root여야 한다** — 위조 문턱을
    # "공개값 베끼기"에서 "root"로 올린다. 그 이상을 주장하지 않는다.
    claim = _leaf_ledger_claim_name(
        manager_source_revision=str(result.get("manager_source_revision") or ""),
        execution_identity_sha256=str(leaf_identity or ""),
        pinset_sha256=str(result.get("source_pinset_sha256") or ""),
    )
    try:
        _assert_trusted_leaf_root(_LEDGER)
        claim_metadata = (_LEDGER / claim).lstat()
        claim_present = (
            stat.S_ISREG(claim_metadata.st_mode)
            and claim_metadata.st_uid == os.geteuid()
        )
    except (OSError, _UntrustedLeaf):
        claim_present = False
    record(
        "L9 root-only ledger claim",
        claim_present,
        f"ledger={_LEDGER} claim={claim[:16]}… present={claim_present}",
    )

    try:
        blocked = load_runtime_pin_registry().is_unconditionally_blocked_pinset(
            PINNED_RUNTIME_RELEASE.pinset_sha256
        )
    except (RuntimePinRegistryError, DeploymentContractError):
        blocked = True
    record(
        "L8 terminal 아님",
        not blocked and not execution_blocked,
        f"pinset_blocked={blocked} leaf_execution_blocked={execution_blocked}",
    )

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name} — {detail}", flush=True)
    failed = [name for name, ok, _ in checks if not ok]
    if failed:
        print(f"leaf verification FAILED: {', '.join(failed)}", flush=True)
        return 1
    print("leaf verification PASSED", flush=True)
    return 0

def preflight(expected_revision: str) -> int:
    """launcher용 비소비 source-materialization preflight; terminal/ledger를 쓰지 않는다.

    거부 이유를 **stdout으로 낸다.** 종전에는 phase도 diagnostic도 전부 삼키고
    exit 1만 냈다 — 2026-09-02에 그 때문에 71분짜리 rebuild를 태운 뒤 몇 초 만에
    거부당하고도 이유를 몰라 traceback으로 역추적해야 했다.

    내보내는 값은 **닫힌 어휘로 걸러서** 낸다. 이 경로는 아직 output leaf가 없어
    forensic scrub 채널을 못 쓰고(leaf는 launcher가 preflight **뒤에** 만든다),
    stdout은 launcher가 받는 자리다. allowlist 밖의 문자열은 phase만 낸다 —
    호스트 상태나 경로가 섞여 나가는 경로를 열지 않는다.
    """

    try:
        _validate_trusted_release(expected_revision)
        _assert_current_m05_execution_is_runnable(expected_revision)
        _source_pair_preflight()
    except _PhaseError as error:
        detail = error.diagnostic if error.diagnostic in _PAIR_DIAGNOSTICS else None
        print(error.phase if detail is None else f"{error.phase}: {detail}", flush=True)
        return 1
    except (OSError, RuntimeError, ValueError) as error:
        # 종전에는 여기서 exit 1만 냈다. launcher는 그래서
        # `M05 isolated source pair preflight is not runnable:` 뒤에 **빈칸**을
        # 찍었고, 2026-09-03 e2e23이 그 침묵 때문에 계측 스크립트를 따로 붙여서야
        # 원인(`pinned runtime source worktree is unsafe`)을 알 수 있었다 —
        # 이 함수의 독스트링이 "거부 이유를 stdout으로 낸다"고 약속하는데도.
        #
        # 내용은 여전히 닫아 둔다. 예외 **타입 이름**은 호스트 상태를 담지 않으므로
        # 항상 낼 수 있고, 메시지는 Manager 자신이 쓴 고정 문구일 때만 낸다 —
        # `pinned runtime source `로 시작하는 문자열은 `pinned_runtime_sources`의
        # 리터럴에만 쓰이고 그 뒤도 상수다. 문구를 **열거하지 않으므로** 새 문구가
        # 생겨도 드리프트하지 않는다(AGENTS.md DO NOT 15).
        message = str(error)
        detail = message if message.startswith(_SOURCE_DIAGNOSTIC_PREFIX) else None
        print(
            f"source_materialization: {type(error).__name__}"
            + (f": {detail}" if detail is not None else ""),
            flush=True,
        )
        return 1
    return 0


def _pinvi_manager_admission_environment(
    *,
    env_file: Path,
    bootstrap_credential_file: Path,
    project: str,
    pinvi_source_revision: str,
    execution_identity_sha256: str,
    admission_path: Path,
    compose_extra_file: Path,
) -> dict[str, str]:
    """Manager가 검증한 admission tuple과 one-shot credential 경로만 전달한다."""

    return {
        "PINVI_ENV_FILE": str(env_file),
        # app-api는 첫 기동부터 external Map network에 join해야 한다 — reconciliation
        # worker preflight가 startup에서 Map lease를 실제로 소비하므로, override 없이
        # 뜨면 Map에 닿지 못해 docker-app.sh의 health 대기가 결정적으로 실패한다
        # (2026-09-01 isolated 실측: app-api 내부에서 Map API로 timeout).
        "PINVI_DOCKER_COMPOSE_EXTRA_FILE": str(compose_extra_file),
        # ``docker-app.sh``는 Compose에는 ``PINVI_ENV_FILE``를 넘기지만, migration
        # 전 host-side bootstrap validator는 현재 process 환경에서 이 path를 읽는다.
        # credential 내용은 env에 넣지 않고, owner-only absolute host file path만
        # direct command boundary로 전달한다.
        "PINVI_BOOTSTRAP_ADMIN_CREDENTIAL_FILE": str(bootstrap_credential_file),
        "PINVI_DOCKER_PROJECT": project,
        "PINVI_SOURCE_REVISION": pinvi_source_revision,
        "PINVI_M05_ISOLATED_MANAGER_ADMISSION_PATH": str(admission_path),
        "PINVI_M05_PINSET_SHA256": PINNED_RUNTIME_RELEASE.pinset_sha256,
        "PINVI_M05_EXECUTION_IDENTITY_SHA256": execution_identity_sha256,
    }


def _map_application_head(map_root: Path) -> str:
    """materialize된 Map source에서 application Alembic head를 유도한다.

    종전에는 이 값이 baseline root 리터럴로 박혀 있었다. Map이 migration을
    하나 더하면 `api-entrypoint.sh`가 head 불일치로 기동을 거부해, 이 harness는 **스키마가
    진화한 Map을 영원히 e2e할 수 없게** 된다.

    이미지가 읽는 것과 **같은 파일**을 읽는다 — 이미지는 이 worktree에서 빌드되고,
    `/usr/local/bin/ktm-application-schema`도 설치본의 같은 graph를 읽는다.
    """
    manifest = map_root / "src" / "kortravelmap" / "_application_migration_graph.json"
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail(
            "source_materialization", diagnostic="map application graph unavailable"
        )
    if not isinstance(payload, dict) or not isinstance(payload.get("revisions"), list):
        _fail("source_materialization", diagnostic="map application graph is invalid")
    revisions = payload["revisions"]
    declared = {str(entry["revision"]) for entry in revisions}
    referenced = {
        str(parent)
        for entry in revisions
        for parent in (entry.get("down_revision") or ())
    }
    heads = sorted(declared - referenced)
    if len(heads) != 1 or not referenced.issubset(declared):
        _fail("source_materialization", diagnostic="map application head is ambiguous")
    return heads[0]


def _assert_playwright_runner_matches_pinned_source(pinvi_root: Path) -> None:
    """runner 핀과 pinned PinVi source의 playwright-core 핀을 기계로 결박한다.

    두 핀은 서로 독립적으로 움직일 수 있는 사람-선언이다. 이미지의
    driverVersion == lockfile의 playwright-core 버전이어야 /ms-playwright
    브라우저 캐시가 적중한다 — 불일치는 body 브라우저 기동에서 무조건
    소각으로만 드러난다(적대 리뷰 실측: v1.60.0 digest vs 1.62.1 lockfile).
    """

    try:
        lock_value = json.loads(
            (pinvi_root / "package-lock.json").read_text(encoding="utf-8")
        )
        pinned_playwright = (
            lock_value.get("packages", {})
            .get("node_modules/playwright-core", {})
            .get("version")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("runtime_setup_playwright_runner_image")
    if not isinstance(pinned_playwright, str) or not pinned_playwright:
        _fail("runtime_setup_playwright_runner_image")
    runner_info_raw = _command(
        "/usr/bin/docker",
        "run",
        "--rm",
        "--entrypoint",
        "/bin/cat",
        _PLAYWRIGHT_RUNNER_IMAGE,
        "/ms-playwright/.docker-info",
        capture=True,
    )
    try:
        runner_driver_version = json.loads(runner_info_raw).get("driverVersion")
    except (TypeError, json.JSONDecodeError):
        _fail("runtime_setup_playwright_runner_image")
    if runner_driver_version != pinned_playwright:
        _fail(
            "runtime_setup_playwright_runner_image",
            diagnostic=(
                "runner driverVersion != pinned playwright-core "
                f"({runner_driver_version} != {pinned_playwright})"
            ),
        )


def _compose_model_profiles(
    *,
    root: Path,
    project: str,
    env_file: Path,
    files: tuple[Path, ...],
) -> tuple[str, ...]:
    """cleanup down이 켜야 할 프로파일을 compose 모델 자체에서 파생한다.

    특정 레포의 프로파일 이름("etl", "fresh-init")을 Manager에 리터럴로 박으면
    상대 compose에 프로파일이 추가될 때마다 잔존 컨테이너가 cleanup 검증을
    깨뜨린다(e2e6 실측 클래스). 모델이 선언한 전체 프로파일을 down에 넘기면
    Manager는 상대 구조 변화에 무수정이다(범용성 지시).
    """

    raw = _command(
        "/usr/bin/docker",
        "compose",
        "--project-name",
        project,
        *(item for file in files for item in ("--file", str(file))),
        "--env-file",
        str(env_file),
        "config",
        "--profiles",
        cwd=root,
        capture=True,
        capture_output_limit=_COMPOSE_CONFIG_OUTPUT_LIMIT,
    )
    profiles = tuple(
        sorted({line.strip() for line in raw.splitlines() if line.strip()})
    )
    # 파생값이 argv(--profile <값>)로 되먹혀지므로 whitelist 투영을 거친다 —
    # rendered port 규약과 동일 원칙(적대 리뷰).
    for profile in profiles:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", profile):
            _fail("runtime_inspect_invalid")
    return profiles


def _rendered_service_images(
    *,
    root: Path,
    project: str,
    env_file: Path,
    files: tuple[Path, ...],
    services: tuple[str, ...],
    profiles: tuple[str, ...] = (),
) -> dict[str, str]:
    """rendered Compose 모델에서 서비스별 image 참조를 읽는다.

    이름 **추측**({project}-{service})은 PinVi처럼 명시 ``image:``를 쓰는
    compose에서 성립하지 않는다(e2e8 forensic: "No such image"). 반대로 실행
    컨테이너의 ID를 그대로 쓰면 뒤따르는 image-identity 검증들이 X != X로
    퇴화한다(적대 리뷰). rendered 모델의 참조는 컨테이너와 **독립적인** 소스라
    검증이 실제로 일을 한다. 명시 image가 없으면 Compose 기본 규칙대로
    ``{project}-{service}``다.
    """

    profile_arguments = tuple(
        item for profile in profiles for item in ("--profile", profile)
    )
    raw = _compose(
        root=root,
        project=project,
        env_file=env_file,
        files=files,
        arguments=(*profile_arguments, "config", "--format", "json"),
        capture=True,
    )
    try:
        rendered = json.loads(raw)
        rendered_services = rendered["services"]
    except (TypeError, KeyError, json.JSONDecodeError):
        _fail("runtime_inspect_invalid")
    references: dict[str, str] = {}
    for service in services:
        entry = rendered_services.get(service)
        if not isinstance(entry, dict):
            _fail("runtime_inspect_invalid")
        image = entry.get("image")
        if image is None:
            image = f"{project}-{service}"
        if not isinstance(image, str) or not image:
            _fail("runtime_inspect_invalid")
        references[service] = image
    return references


def _container_id(
    project: str,
    service: str,
    *,
    root: Path,
    env_file: Path,
    files: tuple[Path, ...],
    profiles: tuple[str, ...] = (),
) -> str:
    profile_arguments = tuple(
        item for profile in profiles for item in ("--profile", profile)
    )
    value = _compose(
        root=root,
        project=project,
        env_file=env_file,
        files=files,
        arguments=(*profile_arguments, "ps", "-q", service),
        capture=True,
    ).strip()
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        _fail("runtime_container_identity_invalid")
    return value


def _container_inspect(container_id: str) -> dict[str, Any]:
    """Read one Docker inspect object without allowing its raw payload into a receipt."""

    try:
        value = json.loads(
            _command("/usr/bin/docker", "container", "inspect", container_id, capture=True)
        )[0]
    except (IndexError, TypeError, json.JSONDecodeError):
        _fail("runtime_inspect_invalid")
    if not isinstance(value, dict):
        _fail("runtime_inspect_invalid")
    return value


def _assert_loopback_tcp_publish(
    container: Mapping[str, Any], *, container_port: int, host_port: int
) -> None:
    """Verify the generic host-loopback publish prerequisite before making HTTP readiness calls."""

    network_settings = container.get("NetworkSettings")
    ports = network_settings.get("Ports") if isinstance(network_settings, Mapping) else None
    bindings = ports.get(f"{container_port}/tcp") if isinstance(ports, Mapping) else None
    if (
        not isinstance(bindings, list)
        or len(bindings) != 1
        or not isinstance(bindings[0], Mapping)
        or bindings[0].get("HostIp") != "127.0.0.1"
        or bindings[0].get("HostPort") != str(host_port)
    ):
        _fail("runtime_loopback_publish_invalid")


def _safe_rendered_port_value(value: object, *, kind: str) -> str | int | None:
    """Project one rendered Compose port scalar into a fixed, non-raw evidence type."""

    if kind == "host_ip":
        if not isinstance(value, str) or len(value) > 45:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if kind == "protocol":
        if not isinstance(value, str):
            return None
        normalized = value.lower()
        return normalized if normalized in _SAFE_PORT_PROTOCOLS else None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 5:
        number = int(value)
    else:
        return None
    if not 1 <= number <= 65535:
        return None
    return number if kind == "target" else str(number)


def _safe_rendered_port_evidence(ports: list[Mapping[str, Any]]) -> tuple[dict[str, object], ...]:
    """Return a bounded whitelist projection; never persist a raw Compose mapping."""

    return tuple(
        {
            "host_ip": _safe_rendered_port_value(port.get("host_ip"), kind="host_ip"),
            "protocol": _safe_rendered_port_value(port.get("protocol", "tcp"), kind="protocol"),
            "published": _safe_rendered_port_value(port.get("published"), kind="published"),
            "target": _safe_rendered_port_value(port.get("target"), kind="target"),
        }
        for port in ports[:_RENDERED_PORT_EVIDENCE_LIMIT]
    )


def _assert_rendered_loopback_tcp_publish(
    rendered: str,
    *,
    service: str,
    container_port: int,
    host_port: int,
    evidence_path: Path | None = None,
    parse_failure_evidence_path: Path | None = None,
) -> None:
    """Fail before ledger claim when Compose cannot render the required loopback publish."""

    try:
        value = json.loads(rendered)
        services = value["services"]
        item = services[service]
        ports = item["ports"]
    except (KeyError, TypeError, json.JSONDecodeError):
        if parse_failure_evidence_path is not None:
            _write_compose_output_evidence(parse_failure_evidence_path, output=rendered)
        _fail("runtime_loopback_publish_config_invalid")
    if not isinstance(ports, list) or not all(isinstance(port, Mapping) for port in ports):
        _fail("runtime_loopback_publish_config_invalid")
    safe_ports = _safe_rendered_port_evidence(ports)
    if evidence_path is not None:
        # 검증한 고정 allowlist만 root-only로 남긴다. env·service 전체·raw Compose
        # mapping이나 extension field는 보존하지 않아 다음 preflight 보정에 필요한
        # topology만 남긴다.
        _write_private_json(
            evidence_path,
            {
                "container_port": container_port,
                "host_port": host_port,
                "port_count": len(ports),
                "ports": safe_ports,
                "service": service,
                "version": 1,
            },
        )
    if len(ports) > _RENDERED_PORT_EVIDENCE_LIMIT:
        _fail("runtime_loopback_publish_config_invalid")
    matches = [
        port
        for port in safe_ports
        if port["target"] == container_port
        and port["published"] == str(host_port)
        and port["host_ip"] == "127.0.0.1"
        and port["protocol"] == "tcp"
    ]
    if len(matches) != 1:
        _fail("runtime_loopback_publish_config_invalid")


def _image_id(reference: str) -> str:
    value = _command(
        "/usr/bin/docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        reference,
        capture=True,
    ).strip()
    if not value.startswith("sha256:") or len(value) != 71:
        _fail("runtime_image_identity_invalid")
    return value


def _build_runtime_provenance(
    *,
    plan: M05IsolatedHarnessPlan,
    pair: M05IsolatedPairEvidence,
    map_network: str,
    pinvi_network: str,
    map_api_id: str,
    pinvi_api_id: str,
    map_api_port: int,
    pinvi_api_port: int,
    map_api_container: str,
    pinvi_api_container: str,
    image_references: dict[str, str],
    path: Path,
) -> str:
    def inspect_network(item: str) -> dict[str, Any]:
        try:
            value = json.loads(
                _command("/usr/bin/docker", "network", "inspect", item, capture=True)
            )[0]
        except (IndexError, TypeError, json.JSONDecodeError):
            _fail("runtime_inspect_invalid")
        return value

    def inspect_image(reference: str) -> dict[str, Any]:
        try:
            value = json.loads(
                _command("/usr/bin/docker", "image", "inspect", reference, capture=True)
            )[0]
        except (IndexError, TypeError, json.JSONDecodeError):
            _fail("runtime_inspect_invalid")
        return value

    map_network_value, pinvi_network_value = (
        inspect_network(map_network),
        inspect_network(pinvi_network),
    )
    expectation = M05IsolatedRuntimeExpectation(
        plan=plan,
        networks=(
            M05IsolatedNetworkExpectation(
                "map", map_network, str(map_network_value.get("Id", ""))
            ),
            M05IsolatedNetworkExpectation(
                "pinvi", pinvi_network, str(pinvi_network_value.get("Id", ""))
            ),
        ),
        pair=pair,
        services={
            "map-api": M05IsolatedServiceExpectation(
                "map", 13701, map_api_port, map_api_id
            ),
            "pinvi-api": M05IsolatedServiceExpectation(
                "pinvi", 8000, pinvi_api_port, pinvi_api_id, ("map",)
            ),
        },
    )
    containers = {
        "map-api": _container_inspect(map_api_container),
        "pinvi-api": _container_inspect(pinvi_api_container),
    }
    topology_images = {
        map_api_id: inspect_image(image_references["map-api"]),
        pinvi_api_id: inspect_image(image_references["pinvi-api"]),
    }
    assert_m05_isolated_runtime(
        expectation=expectation,
        containers=containers,
        image_inspects=topology_images,
        network_inspects={
            map_network: map_network_value,
            pinvi_network: pinvi_network_value,
        },
    )
    all_images = {
        name: inspect_image(reference) for name, reference in image_references.items()
    }
    provenance = build_m05_isolated_runtime_provenance(
        expectation=expectation, image_inspects=all_images
    )
    return _write_private_json(path, provenance)


def driver_exit_code(*, completed: bool, receipt_write_failed: bool) -> int:
    """드라이버의 종료 코드 규칙.

    본문이 통과했더라도 **receipt를 남기지 못했으면 성공이 아니다.** launcher는
    `result.json`으로만 결과를 관측하므로, 파일이 없는데 0을 돌려주면 launcher는
    "성공했는데 증적이 사라졌다"와 "애초에 실행되지 않았다"를 구별할 수 없다.

    이 규칙이 함수로 나와 있는 이유는 결박 때문이다. 규칙이 `main`의 `finally`
    뒤 한 줄로만 있으면 그 줄을 지켜 주는 테스트를 쓰려면 본문 전체(docker/npm
    15단계)를 성공시켜야 해서, 실제로는 아무도 지키지 않게 된다.
    """

    return 0 if completed and not receipt_write_failed else 1


def main(expected_revision: str, output: Path) -> int:
    phase = "admission"
    completed = False
    #: 본문(m04_m05_e2e) 진입 여부 — 진입 이후의 모든 실패는 무조건 소각한다
    #: (one-shot: 본문은 정확히 한 번. 적대 리뷰 R1-S4/R2-S4).
    body_entered = False
    # 이 생성기의 **모양**(32자 소문자 hex)은 launcher Tier 1이 receipt에서
    # 직접 검사하고, test_every_preclaim_phase_receipt_is_accepted_as_scoped_by_
    # the_launcher가 실제 출력을 실제 검증기에 먹여 결박한다. 그 결박은 전이적이라
    # **테스트에서 이 호출을 스텁하면 조용히 사라진다** — 결정성이 필요하면 값을
    # 고정하지 말고 receipt를 읽어라.
    transaction = secrets.token_hex(16)
    # receipt의 execution identity는 **plan보다 먼저** 확정돼야 한다. plan은
    # 다섯 개의 실패 가능한 문장 뒤에 만들어지는데, 그 창에서 죽으면 종전 코드는
    # identity를 null로 실었다. launcher는 그걸 Tier 1 불일치로 읽어 receipt를
    # 통째로 버리고 무조건 소각한다 — stale candidate/registry 회전 계열 phase
    # 열 개 전체가 claim 전인데도 exit 4에 도달할 수 없었다(적대 리뷰 BLOCKER-1).
    # 이 값은 pinset + revision에서 결정적으로 파생되므로 여기서 계산할 수 있고,
    # 실제 registry와 어긋나면 launcher가 여전히 fail-close한다(그건 진짜 회전이다).
    execution_identity = ExecutionIdentityV6.build(
        source_pinset_sha256=PINNED_RUNTIME_RELEASE.pinset_sha256,
        manager_source_revision=expected_revision,
    ).execution_identity_sha256
    plan: M05IsolatedHarnessPlan | None = None
    claim_attempted = False
    failure_diagnostic: str | None = None
    map_cleanup: _CleanupProject | None = None
    pinvi_cleanup: _CleanupProject | None = None
    private_files: tuple[Path, ...] = ()
    result_hashes: dict[str, str] = {}
    disposable_run_worktree: _DisposableRunWorktree | None = None
    receipt_write_failed = False
    try:
        os.umask(0o077)
        _validate_trusted_release(expected_revision)
        execution = _assert_current_m05_execution_is_runnable(expected_revision)
        _root_directory(output)
        _LEDGER.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(_LEDGER, 0o700)
        _root_directory(_LEDGER)
        plan = M05IsolatedHarnessPlan(
            PINNED_RUNTIME_RELEASE,
            expected_revision,
            execution.current.execution_identity_sha256,
            transaction,
        )
        phase = "source_materialization"
        (
            map_root,
            pinvi_root,
            pair,
            service_openapi_sha256,
            service_source_revision,
            source_state_paths,
            source_values,
            pinvi_source_tree,
        ) = _source_pair_preflight()
        # head를 여기서 확정한다 — materialize된 source를 읽는 일이므로 이 phase에
        # 속하고, 실패하면 `source_materialization` receipt가 정확히 그 사실을 남긴다.
        # env를 쓰는 자리에서 읽으면 runtime setup 도중에 source 계약 오류가 나온다.
        map_application_head = _map_application_head(map_root)
        # setup 전체를 하나의 `runtime_setup` receipt로 뭉개면 새 immutable source가
        # 어느 안전 경계를 보정해야 하는지 알 수 없다. 아래 단계명은 raw exception,
        # 경로, secret을 싣지 않는 allowlist receipt일 뿐 동일 pinset 재시도 권한은 아니다.
        phase = "runtime_setup_ports"
        ports = _free_ports(transaction)
        phase = "runtime_setup_workspace"
        runtime = output / "runtime"
        runtime.mkdir(mode=0o700)
        _root_directory(runtime)
        # 실행은 봉인된 핀 트리가 아니라 **일회용 체크아웃**에서 한다. 러너는 저장소
        # 루트를 컨테이너에 root RW로 마운트하고 그 안에서 `npm ci`와 Playwright를
        # 돌리므로, 봉인 트리를 그대로 주면 root가 모드를 무시하고 써서 다음
        # preflight가 같은 pinset 재실행을 거부한다(2026-09-03·04 연속 재현).
        #
        # 사본이 아니라 **object store에서 재유도**한다 — 같은 bare 저장소, 같은
        # revision, 같은 tree object다. 그래서 파일 모드도 잔여물도 물려받지 않는다.
        # attestation과 러너가 자기 `__file__`/위치에서 repo root를 유도하므로, 이
        # 루트에서 실행하면 체인 전체가 따라온다(PinVi 쪽 변경이 필요 없다).
        #
        # destination은 **실행마다 유일**해야 한다. 비정상 종료(SIGTERM/SIGHUP)로
        # `finally`가 건너뛰어지면 bare에 admin 엔트리가 남는데, 같은 경로를 재사용하면
        # 다음 `worktree add`가 "missing but already registered"로 죽는다 — 그러면 이
        # 수정 자체가 사이클을 태우는 원인이 된다(적대 리뷰 2026-09-04 #1 실측).
        run_worktree = runtime / f"pinvi-run-{uuid.uuid4().hex}"
        disposable_run_worktree = (
            "pinvi",
            run_worktree,
            source_state_paths,
            source_values,
            output / "disposable-run-worktree.json",
        )
        pinvi_run_root = materialize_disposable_run_worktree(
            release=PINNED_RUNTIME_RELEASE,
            state_paths=source_state_paths,
            values=source_values,
            role="pinvi",
            expected_tree=pinvi_source_tree,
            destination=run_worktree,
        )
        map_env, pinvi_env = runtime / "map.env", runtime / "pinvi.env"
        pinvi_admission = runtime / "pinvi-isolated-manager-admission.json"
        map_override, pinvi_override = (
            runtime / "map.override.yml",
            runtime / "pinvi.override.yml",
        )
        fixture_env = runtime / "map-fixture.env"
        private_key, bootstrap = (
            runtime / "m05-private-key.pem",
            runtime / "pinvi-admin.json",
        )
        # 각 private path를 생성 전부터 cleanup 대상에 넣는다. Map 시작 중간의 실패도
        # credential file을 남기면 안 된다. 없는 파일은 _unlink_private가 무시한다.
        private_files = (
            map_env,
            pinvi_env,
            fixture_env,
            map_override,
            pinvi_override,
            pinvi_admission,
            bootstrap,
            private_key,
        )
        m04_evidence, m05_evidence = runtime / "m04", runtime / "m05"
        m04_evidence.mkdir(mode=0o700)
        m05_evidence.mkdir(mode=0o700)
        _root_directory(m04_evidence)
        _root_directory(m05_evidence)
        phase = "runtime_setup_admission_build"
        admission_payload = build_m05_isolated_manager_admission(plan=plan, pair=pair)
        phase = "runtime_setup_admission_write"
        _write_private_json(
            pinvi_admission,
            admission_payload,
        )
        phase = "runtime_setup_network"
        subnet, map_gateway_ip, map_api_ip, map_frontend_ip = _map_network_addresses(
            transaction
        )
        phase = "runtime_setup_credentials"
        map_secret, feature_request_token, read_token, ack_token = (
            _random_secret(),
            _random_secret(),
            _random_secret(),
            _random_secret(),
        )
        manual_feature_token = _random_secret()
        admin_password = _random_secret()
        # 비밀은 생성 즉시 scrub 레지스트리에 올린다 — 등록이 body 진입 이후로
        # 미뤄지면 admission~pinvi_runtime 구간에서 scrub이 항등함수가 되어,
        # forensic 주석이 주장하는 통제가 그 구간에 존재하지 않는다(적대 리뷰).
        _register_forensic_scrub_secrets(
            {
                "M05_MAP_ADMIN_PROXY_SECRET": map_secret,
                "M05_FEATURE_REQUEST_TOKEN": feature_request_token,
                "M05_RECONCILIATION_READ_TOKEN": read_token,
                "M05_RECONCILIATION_ACK_TOKEN": ack_token,
                "M05_MANUAL_FEATURE_TOKEN": manual_feature_token,
                "M05_PINVI_PASSWORD": admin_password,
            }
        )
        bootstrap_email = f"m05-{transaction[:12]}@example.com"
        _write_private_json(
            bootstrap, {"email": bootstrap_email, "password": admin_password}
        )
        _command(
            "/usr/bin/openssl",
            "genpkey",
            "-algorithm",
            "Ed25519",
            "-out",
            str(private_key),
        )
        _root_file(private_key, mode=0o600)
        phase = "runtime_setup_map_config"
        password = _random_secret()
        token_sha = lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
        migrator_password, api_password, dagster_password, metadata_password = (
            _random_secret(),
            _random_secret(),
            _random_secret(),
            _random_secret(),
        )
        _register_forensic_scrub_secrets(
            {
                "MAP_POSTGRES_PASSWORD": password,
                "MAP_MIGRATOR_PASSWORD": migrator_password,
                "MAP_API_RUNTIME_PASSWORD": api_password,
                "MAP_DAGSTER_RUNTIME_PASSWORD": dagster_password,
                "MAP_DAGSTER_METADATA_PASSWORD": metadata_password,
            }
        )
        map_bootstrap_dsn = (
            f"postgresql://kor_travel_map:{password}@postgres:5432/kor_travel_map"
        )
        ui_hash = _pbkdf2_password_hash(_random_secret()).replace("$", "$$")
        _write_private_text(
            map_env,
            "\n".join(
                (
                    f"KOR_TRAVEL_MAP_GIT_COMMIT={pair.map_source_revision}",
                    "KOR_TRAVEL_MAP_POSTGRES_DB=kor_travel_map",
                    "KOR_TRAVEL_MAP_POSTGRES_USER=kor_travel_map",
                    f"KOR_TRAVEL_MAP_POSTGRES_PASSWORD={password}",
                    "KOR_TRAVEL_MAP_DB_ROLE_BOOTSTRAP_CONFIRM_DATABASE=kor_travel_map",
                    f"KOR_TRAVEL_MAP_BOOTSTRAP_PG_DSN={map_bootstrap_dsn}",
                    f"KOR_TRAVEL_MAP_MIGRATOR_PASSWORD={migrator_password}",
                    f"KOR_TRAVEL_MAP_API_RUNTIME_PASSWORD={api_password}",
                    f"KOR_TRAVEL_MAP_DAGSTER_RUNTIME_PASSWORD={dagster_password}",
                    "KOR_TRAVEL_MAP_DAGSTER_METADATA_USER=kor_travel_map_dagster",
                    f"KOR_TRAVEL_MAP_DAGSTER_METADATA_PASSWORD={metadata_password}",
                    f"KOR_TRAVEL_MAP_MIGRATOR_PG_DSN=postgresql+asyncpg://ktm_feature_migrator:{migrator_password}@postgres:5432/kor_travel_map",
                    f"KOR_TRAVEL_MAP_API_RUNTIME_PG_DSN=postgresql+asyncpg://ktm_feature_api_runtime:{api_password}@postgres:5432/kor_travel_map",
                    f"KOR_TRAVEL_MAP_DAGSTER_RUNTIME_PG_DSN=postgresql+asyncpg://ktm_feature_dagster_runtime:{dagster_password}@postgres:5432/kor_travel_map",
                    f"KOR_TRAVEL_MAP_PG_DSN=postgresql+asyncpg://ktm_feature_dagster_runtime:{dagster_password}@postgres:5432/kor_travel_map",
                    f"KOR_TRAVEL_MAP_DOCKER_DAGSTER_PG_URL=postgresql://kor_travel_map_dagster:{metadata_password}@postgres:5432/kor_travel_map_dagster",
                    f"KOR_TRAVEL_MAP_MIGRATION_EXPECTED_HEAD={map_application_head}",
                    "KOR_TRAVEL_MAP_API_PROFILE=local-dev",
                    "KOR_TRAVEL_MAP_DOCKER_BIND_HOST=127.0.0.1",
                    "KOR_TRAVEL_MAP_API_PORT=13701",
                    f"KOR_TRAVEL_MAP_DAGSTER_PORT={ports['map_dagster']}",
                    f"KOR_TRAVEL_MAP_ADMIN_WEB_PORT={ports['map_api']}",
                    f"KOR_TRAVEL_MAP_POSTGRES_HOST_PORT={ports['map_postgres']}",
                    f"KOR_TRAVEL_MAP_RUSTFS_API_PORT={ports['map_rustfs']}",
                    f"KOR_TRAVEL_MAP_RUSTFS_CONSOLE_PORT={ports['map_rustfs_console']}",
                    f"KOR_TRAVEL_MAP_MOIS_SOURCE_DB_VOLUME={plan.map_project}-mois",
                    f"KOR_TRAVEL_MAP_RUSTFS_VOLUME={plan.map_project}-rustfs",
                    f"KOR_TRAVEL_MAP_APPLICATION_FINAL_PERMIT_VOLUME={plan.map_project}-application-final-permit",
                    f"KOR_TRAVEL_MAP_DAGSTER_STORAGE_PERMIT_VOLUME={plan.map_project}-dagster-storage-permit",
                    f"KOR_TRAVEL_MAP_ADMIN_PROXY_SECRET={map_secret}",
                    f"KOR_TRAVEL_MAP_API_SERVICE_TOKEN={_random_secret()}",
                    f"KOR_TRAVEL_MAP_API_CURSOR_SIGNING_SECRET={_random_secret()}",
                    f"KOR_TRAVEL_MAP_API_METRICS_TOKEN={_random_secret()}",
                    f"KOR_TRAVEL_MAP_API_OPS_READ_TOKEN={_random_secret()}",
                    f"KOR_TRAVEL_MAP_API_OPS_CANCEL_TOKEN={_random_secret()}",
                    f"KOR_TRAVEL_MAP_API_OPS_FIXTURE_TOKEN={_random_secret()}",
                    "KOR_TRAVEL_MAP_API_OPS_PRINCIPAL_REQUIRED=true",
                    f"KOR_TRAVEL_MAP_ADMIN_FEATURE_CREATE_TOKEN={manual_feature_token}",
                    f"KOR_TRAVEL_MAP_API_ADMIN_FEATURE_CREATE_TOKEN_SHA256={token_sha(manual_feature_token)}",
                    "KOR_TRAVEL_MAP_API_ADMIN_MANUAL_FEATURE_CREATE_ENABLED=true",
                    "KOR_TRAVEL_MAP_API_DESTRUCTIVE_ENABLED=true",
                    "KOR_TRAVEL_MAP_API_PUBLIC_API_KEY_REQUIRED=false",
                    f"KOR_TRAVEL_MAP_UI_SESSION_SECRET={_random_secret()}",
                    f"KOR_TRAVEL_MAP_UI_ADMIN_PASSWORD_HASH={ui_hash}",
                    f"KOR_TRAVEL_MAP_OBJECT_STORE_SECRET_ACCESS_KEY={_random_secret()}",
                    "KOR_TRAVEL_MAP_OBJECT_STORE_ACCESS_KEY_ID=m05-isolated-access",
                    f"NEXT_PUBLIC_KOR_TRAVEL_MAP_API=http://127.0.0.1:{ports['map_api']}",
                    "KOR_TRAVEL_MAP_DOCKER_API_INTERNAL_URL=http://api:13701",
                )
            )
            + "\n",
        )
        # generic Map API image에서 실행하는 fixture에는 ordinary Dagster runtime
        # credential만 넣는다. bootstrap/migrator owner DSN은 전달하지 않는다.
        _write_private_text(
            fixture_env,
            "KOR_TRAVEL_MAP_PG_DSN="
            f"postgresql+asyncpg://ktm_feature_dagster_runtime:{dagster_password}"
            "@postgres:5432/kor_travel_map\n",
        )
        # API에는 digest capability만, frontend에는 raw manual-create credential만 전달한다.
        map_override_lines = [
            "services:",
            "  db-application-schema-fresh-300:",
            "    entrypoint:",
            "      - /usr/local/bin/python",
            "      - -I",
            "      - -c",
            "      - >-",
            f"        {_map_fresh_init_diagnostic_entrypoint()}",
            "  api:",
            "    env_file: !reset []",
            "    labels:",
            *[f"      {key}: {value}" for key, value in plan.labels.items()],
            "      io.pinvi.build.environment: isolated",
            "    environment:",
            f"      KOR_TRAVEL_MAP_API_FEATURE_REQUEST_TOKEN_SHA256: {token_sha(feature_request_token)}",
            f"      KOR_TRAVEL_MAP_API_FEATURE_REFERENCE_RECONCILIATION_READ_TOKEN_SHA256: {token_sha(read_token)}",
            f"      KOR_TRAVEL_MAP_API_FEATURE_REFERENCE_RECONCILIATION_ACK_TOKEN_SHA256: {token_sha(ack_token)}",
            # frontend BFF와 root one-shot만 admin endpoint에 닿는다. published
            # loopback 요청은 bridge gateway에서 API로 전달되므로 이를 explicit
            # allowlist에 포함한다. host 밖에서는 이 harness principal을 흉내낼 수 없다.
            f'      KOR_TRAVEL_MAP_API_ADMIN_TRUSTED_PROXY_CIDRS: \'["{map_frontend_ip}/32","{map_gateway_ip}/32","127.0.0.1/32"]\'',
            # !reset은 list를 기본값(빈 값)으로 되돌린다. 기존 publish를 정확한
            # isolated loopback publish 하나로 교체하려면 Compose의 !override여야 한다.
            "    ports: !override",
            f"      - 127.0.0.1:{ports['map_api']}:13701",
            # networks도 ports와 같은 이유로 !override다 — !reset은 중첩 값
            # (ipv4_address)까지 통째로 버려 정적 주소가 적용되지 않는다
            # (적대 리뷰 실측: 렌더 결과 default: null).
            "    networks: !override",
            "      default:",
            f"        ipv4_address: {map_api_ip}",
            "  frontend:",
            "    labels:",
            *[f"      {key}: {value}" for key, value in plan.labels.items()],
            "      io.pinvi.build.environment: isolated",
            "    ports: !reset []",
            "    networks: !override",
            "      default:",
            f"        ipv4_address: {map_frontend_ip}",
            "networks:",
            "  default:",
            f"    name: {plan.map_network}",
            "    ipam:",
            "      config:",
            f"        - subnet: {subnet}",
            # gateway를 명시해 hosts[0] 가정을 행동이 아니라 계약으로 만든다
            # (trusted proxy allowlist가 이 값에 결박된다 — 적대 리뷰).
            f"          gateway: {map_gateway_ip}",
            "    labels:",
            *[f"      {key}: {value}" for key, value in plan.labels.items()],
        ]
        _write_private_text(map_override, "\n".join(map_override_lines) + "\n")
        map_files = (
            map_root / "docker-compose.yml",
            map_root / "docker-compose.local-dev.yml",
            map_override,
        )
        # Compose topology는 Docker mutation 전에 정적으로 판정할 수 있다. 이 단계가
        # 실패하면 private setup만 cleanup하고 execution ledger를 소비하지 않는다.
        phase = "runtime_loopback_publish_config_invalid"
        _assert_rendered_loopback_tcp_publish(
            _compose(
                root=map_root,
                project=plan.map_project,
                env_file=map_env,
                files=map_files,
                arguments=("config", "--format", "json"),
                capture=True,
                failure_phase="runtime_loopback_publish_config_invalid",
                failure_evidence_path=runtime / "rendered-loopback-publish-error.json",
                output_evidence_path=runtime / "rendered-loopback-publish-output.json",
            ),
            service="api",
            container_port=13701,
            host_port=ports["map_api"],
            evidence_path=runtime / "rendered-loopback-publish.json",
            parse_failure_evidence_path=runtime / "rendered-loopback-publish-output.json",
        )
        # source pair와 rendered runtime topology가 정합할 때만 one-shot ledger를
        # 소비한다. O_EXCL create 뒤 write/fsync 실패도 execution을 소비한 것으로 본다.
        # Playwright runner의 핀 digest를 실행권 소비 **전**에 보장한다 — body
        # 단계에서 이미지 부재(예: 호스트 정리로 미사용 이미지 프룬)가 드러나면
        # 무조건 소각이지만(2026-09-01 e2e13 실측), 여기서는 scoped 실패라
        # 보정 후 재시도할 수 있다. digest 참조라 pull은 내용-불변이다.
        phase = "runtime_setup_playwright_runner_image"
        try:
            _command(
                "/usr/bin/docker", "image", "inspect", _PLAYWRIGHT_RUNNER_IMAGE
            )
        except _PhaseError:
            _command("/usr/bin/docker", "pull", _PLAYWRIGHT_RUNNER_IMAGE)
        _assert_playwright_runner_matches_pinned_source(pinvi_root)
        phase = "ledger_claim"
        claim_attempted = True
        claim_m05_isolated_harness_ledger(ledger_root=_LEDGER, plan=plan)
        # launcher가 receipt를 못 읽는 경우(driver 하드 크래시·검증기 도구
        # 사망)에도 "실행권을 소비했는가"를 판정할 수 있어야 한다. 그 사실은
        # registry에도 ledger에도 있지만 둘 다 ktdctl/직렬화 지식이 필요하다 —
        # launcher는 범용 runner이므로 존재 여부만 보면 되는 마커를 남긴다.
        # 없으면 receipt 부재가 'claim 전에 죽었다'와 '본문까지 갔다'를 구분
        # 못 해, 전자는 헛소각되고 후자는 재실행돼 본문이 두 번 돈다(적대 리뷰).
        _write_private_bytes(output / "claimed", b"1\n")
        phase = "runtime_setup_pinvi_config"
        _write_private_text(
            pinvi_env,
            "\n".join(
                (
                    "PINVI_ENVIRONMENT=isolated",
                    f"PINVI_SOURCE_REVISION={pair.pinvi_source_revision}",
                    f"PINVI_M05_ISOLATED_MANAGER_ADMISSION_PATH={pinvi_admission}",
                    f"PINVI_M05_PINSET_SHA256={PINNED_RUNTIME_RELEASE.pinset_sha256}",
                    f"PINVI_M05_EXECUTION_IDENTITY_SHA256={plan.execution_identity_sha256}",
                    # 이미지 태그를 transaction 프로젝트로 스코프한다 — 기본값
                    # pinvi-*:local은 호스트 전역 네임스페이스라 격리 run 사이에
                    # 태그가 움직이면 container↔image identity 검증이 X!=Y로
                    # 오탐하고, 격리 run이 전역 태그를 덮어쓴다(적대 리뷰 정찰).
                    # Manager prod 경로(pinned_runtime_rebuild)와 같은 변수를 쓴다.
                    f"PINVI_API_IMAGE={plan.pinvi_project}-api",
                    f"PINVI_WEB_IMAGE={plan.pinvi_project}-web",
                    f"PINVI_DAGSTER_IMAGE={plan.pinvi_project}-dagster",
                    f"PINVI_API_BUILD_CONTEXT={pinvi_root}",
                    f"PINVI_APP_BUILD_CONTEXT={pinvi_root}",
                    f"PINVI_DOCKER_PROJECT={plan.pinvi_project}",
                    f"PINVI_BOOTSTRAP_ADMIN_CREDENTIAL_FILE={bootstrap}",
                    f"PINVI_POSTGRES_PASSWORD={_random_secret()}",
                    f"PINVI_APP_DB_PASSWORD={_random_secret()}",
                    f"PINVI_MIGRATOR_DB_PASSWORD={_random_secret()}",
                    f"PINVI_JWT_SECRET_KEY={_random_secret()}",
                    f"PINVI_MCP_JWT_SECRET={_random_secret()}",
                    f"PINVI_API_PORT={ports['pinvi_api']}",
                    f"PINVI_WEB_PORT={ports['pinvi_web']}",
                    f"PINVI_RUSTFS_PORT={ports['pinvi_rustfs']}",
                    f"PINVI_RUSTFS_CONSOLE_PORT={ports['pinvi_rustfs_console']}",
                    f"PINVI_DAGSTER_DEV_PORT={ports['pinvi_dagster']}",
                    f"PINVI_CADVISOR_PORT={ports['pinvi_cadvisor']}",
                    f"PINVI_PROMETHEUS_PORT={ports['pinvi_prometheus']}",
                    f"PINVI_GRAFANA_PORT={ports['pinvi_grafana']}",
                    f"PINVI_WEB_BASE_URL=http://127.0.0.1:{ports['pinvi_web']}",
                    f"NEXT_PUBLIC_PINVI_API_URL=http://127.0.0.1:{ports['pinvi_api']}",
                    f'PINVI_CORS_ALLOWED_ORIGINS=["http://127.0.0.1:{ports["pinvi_web"]}"]',
                    "PINVI_RATE_LIMIT_ENABLED=false",
                    # Map API는 host loopback으로만 publish한다. PinVi runtime이
                    # host gateway를 거쳐 그 listener에 붙으면 loopback boundary를
                    # 넘지 못하므로, app-api만 Map isolated bridge에도 join해 API의
                    # fixed private address로 service request를 보낸다.
                    f"PINVI_KOR_TRAVEL_MAP_API_BASE_URL=http://{map_api_ip}:13701",
                    f"PINVI_KOR_TRAVEL_MAP_ADMIN_BASE_URL=http://{map_api_ip}:13701",
                    f"KOR_TRAVEL_MAP_FEATURE_REQUEST_TOKEN={feature_request_token}",
                    "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ENABLED=true",
                    f"PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_READ_TOKEN={read_token}",
                    f"PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACK_TOKEN={ack_token}",
                    (
                        "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION"
                        f"_POLL_SECONDS={_PINVI_RECONCILIATION_POLL_SECONDS}"
                    ),
                    f"PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_EXPECTED_OPENAPI_SHA256={service_openapi_sha256}",
                    f"PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_EXPECTED_SOURCE_REVISION={service_source_revision}",
                )
            )
            + "\n",
        )
        pinvi_override_lines = ["services:"]
        for service in ("app-api", "app-web", "app-dagster"):
            pinvi_override_lines.append(f"  {service}:")
            if service == "app-api":
                # app-api는 PinVi default network를 유지해 own DB/object-store와
                # 통신하고, 별도 external Map network에는 private service call만
                # 할 수 있게 join한다. host publish는 여전히 loopback 하나다.
                pinvi_override_lines.extend(
                    (
                        "    networks:",
                        "      default: {}",
                        "      m05-map: {}",
                    )
                )
            pinvi_override_lines.append("    labels:")
            pinvi_override_lines.extend(
                f"      {key}: {value}" for key, value in plan.labels.items()
            )
            pinvi_override_lines.append("      io.pinvi.build.environment: isolated")
        pinvi_override_lines.extend(
            (
                "networks:",
                "  default:",
                f"    name: {plan.pinvi_network}",
                "    labels:",
            )
        )
        pinvi_override_lines.extend(
            f"      {key}: {value}" for key, value in plan.labels.items()
        )
        pinvi_override_lines.extend(
            (
                "  m05-map:",
                "    external: true",
                f"    name: {plan.map_network}",
            )
        )
        _write_private_text(pinvi_override, "\n".join(pinvi_override_lines) + "\n")
        phase = "map_runtime"
        map_cleanup = (
            map_root,
            plan.map_project,
            map_env,
            map_files,
            _compose_model_profiles(
                root=map_root,
                project=plan.map_project,
                env_file=map_env,
                files=map_files,
            ),
        )
        _compose(
            root=map_root,
            project=plan.map_project,
            env_file=map_env,
            files=map_files,
            arguments=("up", "--detach", "--build", "--wait", "postgres"),
            failure_phase="map_postgres_start_failed",
        )
        _compose(
            root=map_root,
            project=plan.map_project,
            env_file=map_env,
            files=map_files,
            arguments=(
                "--profile",
                "fresh-init",
                "run",
                "--rm",
                "db-application-schema-fresh-300",
            ),
            failure_phase="map_fresh_init_failed",
            failure_exit_diagnostics=_MAP_FRESH_INIT_EXIT_DIAGNOSTICS,
        )
        _compose(
            root=map_root,
            project=plan.map_project,
            env_file=map_env,
            files=map_files,
            arguments=(
                "up",
                "--detach",
                "--build",
                "--wait",
                "rustfs",
                "rustfs-init",
                "api",
                "frontend",
            ),
            failure_phase="map_application_start_failed",
            failure_evidence_path=runtime / "map-application-up-error.json",
        )
        # ``docker compose up --wait``가 container health를 돌려도 host publish
        # binding은 별도 runtime 경계다. HTTP retry보다 먼저 generic binding을
        # 검사해 잘못된 Compose topology를 transport timeout으로 오분류하지 않는다.
        map_api = _container_id(
            plan.map_project, "api", root=map_root, env_file=map_env, files=map_files
        )
        _assert_loopback_tcp_publish(
            _container_inspect(map_api),
            container_port=13701,
            host_port=ports["map_api"],
        )
        # networks !override의 정적 주소가 **실제로** 적용됐는지 단언한다 — 조용히
        # 떨어지면(#280 이전의 silent-drop 클래스) PinVi base URL/BFF allowlist가
        # 허공을 가리켜 훨씬 뒤에서 timeout으로 오분류된다(적대 리뷰).
        map_frontend = _container_id(
            plan.map_project,
            "frontend",
            root=map_root,
            env_file=map_env,
            files=map_files,
        )
        for runtime_container, expected_address in (
            (map_api, map_api_ip),
            (map_frontend, map_frontend_ip),
        ):
            container_networks = _container_inspect(runtime_container).get(
                "NetworkSettings", {}
            )
            if not isinstance(container_networks, dict):
                _fail("runtime_inspect_invalid")
            attached = container_networks.get("Networks")
            if not isinstance(attached, dict):
                _fail("runtime_inspect_invalid")
            entry = attached.get(plan.map_network)
            if (
                not isinstance(entry, dict)
                or entry.get("IPAddress") != expected_address
            ):
                _fail("runtime_container_identity_invalid")
        admin_url = f"http://127.0.0.1:{ports['map_api']}"
        _wait_for_map_health(url=f"{admin_url}/health")
        phase = "map_subscription"
        _data(
            _http_json(
                f"{admin_url}/v1/admin/feature-reference-reconciliation-subscriptions",
                headers={
                    **_map_headers(map_secret),
                    "Idempotency-Key": str(uuid.uuid4()),
                },
                body={"initial_event_sequence": 0},
                failure_phase="map_subscription_http_failed",
            )
        )
        phase = "pinvi_runtime"
        pinvi_files = (pinvi_root / "infra/docker-compose.app.yml", pinvi_override)
        # cleanup down은 모델의 **전체** 프로파일을 켜야 한다 — 프로파일 밖
        # down은 profile-scoped 서비스를 못 보고 --remove-orphans도 남겨,
        # 잔존 컨테이너가 cleanup 검증을 결정적으로 깨뜨린다(e2e6 실측:
        # dagster 잔존 → runtime_cleanup_failed가 실제 실패 phase를 가림).
        # 프로파일 목록은 리터럴이 아니라 모델에서 파생한다(범용성 지시).
        pinvi_cleanup = (
            pinvi_root,
            plan.pinvi_project,
            pinvi_env,
            pinvi_files,
            _compose_model_profiles(
                root=pinvi_root,
                project=plan.pinvi_project,
                env_file=pinvi_env,
                files=pinvi_files,
            ),
        )
        environment = _pinvi_manager_admission_environment(
            env_file=pinvi_env,
            bootstrap_credential_file=bootstrap,
            project=plan.pinvi_project,
            pinvi_source_revision=pair.pinvi_source_revision,
            execution_identity_sha256=plan.execution_identity_sha256,
            admission_path=pinvi_admission,
            compose_extra_file=pinvi_override,
        )
        for action in ("build", "up"):
            try:
                _command(
                    str(pinvi_root / "scripts/docker-app.sh"),
                    action,
                    cwd=pinvi_root,
                    env=environment,
                    capture_failure_stderr=os.environ.get(_FORENSIC_CAPTURE_ENV) == "1",
                )
            except _PhaseError as error:
                if error.phase == "runtime_command_failed":
                    _write_command_failure_evidence(
                        runtime / f"pinvi-runtime-{action}-error.json",
                        returncode=error.returncode,
                        stderr=error.stderr,
                        stdout=error.stdout,
                    )
                raise
        # 종전의 `up --force-recreate app-api app-web` 재기동은 제거했다:
        # docker-app.sh up이 이미 같은 override 세트로 기동·health까지 확인하고,
        # 재기동은 startup preflight의 Map lease를 두 번째로 소비해 첫 lease와의
        # 경합(409)을 스스로 만들 수 있다(적대 리뷰).
        _compose(
            root=pinvi_root,
            project=plan.pinvi_project,
            env_file=pinvi_env,
            files=pinvi_files,
            arguments=(
                "--profile",
                "etl",
                "up",
                "--detach",
                "--build",
                "--wait",
                "app-dagster",
            ),
        )
        pinvi_api = _container_id(
            plan.pinvi_project,
            "app-api",
            root=pinvi_root,
            env_file=pinvi_env,
            files=pinvi_files,
        )
        map_rendered_images = _rendered_service_images(
            root=map_root,
            project=plan.map_project,
            env_file=map_env,
            files=map_files,
            services=("api", "frontend"),
        )
        pinvi_rendered_images = _rendered_service_images(
            root=pinvi_root,
            project=plan.pinvi_project,
            env_file=pinvi_env,
            files=pinvi_files,
            services=("app-api", "app-web", "app-dagster"),
            profiles=("etl",),
        )
        image_references = {
            "map-admin": map_rendered_images["api"],
            "map-api": map_rendered_images["api"],
            "map-frontend": map_rendered_images["frontend"],
            "pinvi-api": pinvi_rendered_images["app-api"],
            "pinvi-dagster": pinvi_rendered_images["app-dagster"],
            "pinvi-web": pinvi_rendered_images["app-web"],
        }
        _build_runtime_provenance(
            plan=plan,
            pair=pair,
            map_network=plan.map_network,
            pinvi_network=plan.pinvi_network,
            map_api_id=_image_id(image_references["map-api"]),
            pinvi_api_id=_image_id(image_references["pinvi-api"]),
            map_api_port=ports["map_api"],
            pinvi_api_port=ports["pinvi_api"],
            map_api_container=map_api,
            pinvi_api_container=pinvi_api,
            image_references=image_references,
            path=runtime / "isolated-runtime-provenance.json",
        )
        phase = "m04_m05_e2e"
        body_entered = True
        pinvi_web = _container_id(
            plan.pinvi_project,
            "app-web",
            root=pinvi_root,
            env_file=pinvi_env,
            files=pinvi_files,
        )
        # app-dagster는 etl 프로파일 소속이라 프로파일 없는 ps는 빈 결과를
        # 돌려 body 진입 후 무조건 소각을 만든다(적대 리뷰 — 프로파일 비가시성은
        # e2e6 cleanup에서 실측된 것과 동일 클래스).
        pinvi_dagster = _container_id(
            plan.pinvi_project,
            "app-dagster",
            root=pinvi_root,
            env_file=pinvi_env,
            files=pinvi_files,
            profiles=("etl",),
        )
        map_frontend = _container_id(
            plan.map_project,
            "frontend",
            root=map_root,
            env_file=map_env,
            files=map_files,
        )
        pinvi_api_url = f"http://127.0.0.1:{ports['pinvi_api']}"
        pinvi_web_url = f"http://127.0.0.1:{ports['pinvi_web']}"
        admin_opener = _pinvi_admin_opener(
            pinvi_api_url, email=bootstrap_email, password=admin_password
        )
        feature_request_id = _pinvi_submit_m04_fixture(
            api_url=pinvi_api_url, opener=admin_opener, transaction=transaction
        )
        m04_environment = {
            "PINVI_M04_LIVE_EMAIL": bootstrap_email,
            "PINVI_M04_LIVE_PASSWORD": admin_password,
        }
        _register_forensic_scrub_environment(m04_environment)
        _command(
            sys.executable,
            "-I",
            str(pinvi_run_root / "scripts/m05_activation_attestation.py"),
            "m04",
            "--evidence-dir",
            str(m04_evidence),
            "--private-key",
            str(private_key),
            "--pinvi-api-url",
            pinvi_api_url,
            "--pinvi-api-container",
            pinvi_api,
            "--pinvi-web-url",
            pinvi_web_url,
            "--pinvi-web-container",
            pinvi_web,
            "--feature-request-id",
            feature_request_id,
            "--pinvi-source-revision",
            pair.pinvi_source_revision,
            "--scope",
            "isolated",
            "--playwright-runner-image",
            _PLAYWRIGHT_RUNNER_IMAGE,
            "--require-root-owned",
            "--",
            str(pinvi_run_root / "scripts/n150-playwright-runner.sh"),
            "--",
            "npm",
            "-w",
            "@pinvi/web",
            "run",
            "test:e2e:live-mutating",
            "--",
            "apps/web/e2e/admin-feature-request-queue-live-mutating.live.ts",
            "--workers=1",
            cwd=pinvi_run_root,
            env=m04_environment,
        )
        manual_feature_uuid = _approve_map_request(
            admin_url=admin_url,
            request_id=feature_request_id,
            proxy_secret=map_secret,
            manual_create_token=manual_feature_token,
        )
        manual_feature_id = _resolve_manual_feature_text_id(
            admin_url=admin_url,
            proxy_secret=map_secret,
            feature_uuid=manual_feature_uuid,
        )
        fixture = _seed_m05_provider_fixture(
            map_network=plan.map_network,
            map_env=fixture_env,
            image=image_references["map-api"],
            manual_feature_id=manual_feature_id,
        )
        # Map decision을 커밋하기 **전에** 참조를 심어야 PinVi worker가 그것을
        # 보고 리바인드한다. 심지 않으면 impact_count가 0이 되고 live spec의
        # 중심 단언이 공허하게 참이 된다.
        seeded_references = _seed_pinvi_feature_reference(
            api_url=pinvi_api_url,
            opener=_pinvi_admin_opener(
                pinvi_api_url, email=bootstrap_email, password=admin_password
            ),
            feature_id=manual_feature_id,
        )
        event_id = _resolve_m05_case(
            admin_url=admin_url,
            proxy_secret=map_secret,
            case_id=fixture["case_id"],
            provider_feature_id=fixture["provider_feature_id"],
        )
        impact_count = _wait_for_pinvi_receipt(
            api_url=pinvi_api_url,
            opener=_pinvi_admin_opener(
                pinvi_api_url, email=bootstrap_email, password=admin_password
            ),
            event_id=event_id,
        )
        # 심은 참조가 실제로 리바인드됐는지 여기서 못 박는다. 이 대조가 없으면
        # receipt가 impact 0을 보고해도 게이트가 그대로 통과한다.
        if impact_count < seeded_references:
            _fail("m05_pinvi_impact_missing")
        m05_environment = {
            "M05_MAP_ADMIN_PROXY_SECRET": map_secret,
            "M05_PINVI_EMAIL": bootstrap_email,
            "M05_PINVI_PASSWORD": admin_password,
            "PINVI_M05_LIVE_OLD_FEATURE_ID": manual_feature_id,
            "PINVI_M05_LIVE_REPLACEMENT_FEATURE_ID": fixture["provider_feature_id"],
            "PINVI_M05_LIVE_IMPACT_COUNT": str(impact_count),
        }
        _register_forensic_scrub_environment(m05_environment)
        _command(
            sys.executable,
            "-I",
            str(pinvi_run_root / "scripts/m05_activation_attestation.py"),
            "live",
            "--evidence-dir",
            str(m05_evidence),
            "--private-key",
            str(private_key),
            "--map-admin-url",
            admin_url,
            "--map-case-id",
            fixture["case_id"],
            "--map-docker-project",
            plan.map_project,
            "--map-admin-container",
            map_api,
            "--map-admin-service",
            "api",
            "--map-api-container",
            map_api,
            "--map-api-service",
            "api",
            "--map-frontend-container",
            map_frontend,
            "--map-frontend-service",
            "frontend",
            "--map-source-root",
            str(map_root),
            "--m04-evidence-dir",
            str(m04_evidence),
            "--pinvi-api-url",
            pinvi_api_url,
            "--pinvi-docker-project",
            plan.pinvi_project,
            "--pinvi-api-container",
            pinvi_api,
            "--pinvi-web-url",
            pinvi_web_url,
            "--pinvi-web-container",
            pinvi_web,
            "--pinvi-dagster-container",
            pinvi_dagster,
            "--event-id",
            event_id,
            "--pinvi-source-revision",
            pair.pinvi_source_revision,
            "--scope",
            "isolated",
            "--isolated-runtime-provenance",
            str(runtime / "isolated-runtime-provenance.json"),
            "--isolated-manager-source-revision",
            expected_revision,
            "--isolated-pinset-sha256",
            PINNED_RUNTIME_RELEASE.pinset_sha256,
            "--isolated-execution-identity-sha256",
            plan.execution_identity_sha256,
            "--playwright-runner-image",
            _PLAYWRIGHT_RUNNER_IMAGE,
            "--require-root-owned",
            "--",
            str(pinvi_run_root / "scripts/n150-playwright-runner.sh"),
            "--",
            "npm",
            "-w",
            "@pinvi/web",
            "run",
            "test:e2e:live-mutating",
            "--",
            "apps/web/e2e/admin-feature-reference-reconciliations-live-mutating.live.ts",
            "--workers=1",
            cwd=pinvi_run_root,
            env=m05_environment,
        )
        result_hashes = {
            "m04_attestation_sha256": hashlib.sha256(
                _secure_read_root_file(
                    m04_evidence / "m04-attestation.json",
                    mode=0o600,
                    encoding="utf-8",
                    limit=2_000_000,
                ).encode("utf-8")
            ).hexdigest(),
            "m05_attestation_sha256": hashlib.sha256(
                _secure_read_root_file(
                    m05_evidence / "attestation.json",
                    mode=0o600,
                    encoding="utf-8",
                    limit=2_000_000,
                ).encode("utf-8")
            ).hexdigest(),
            "runtime_provenance_sha256": hashlib.sha256(
                _secure_read_root_file(
                    runtime / "isolated-runtime-provenance.json",
                    mode=0o600,
                    encoding="utf-8",
                    limit=2_000_000,
                ).encode("utf-8")
            ).hexdigest(),
        }
        completed = True
    except _PhaseError as error:
        # 파일명은 실패 순간의 **진행 phase**(pinvi_runtime 등)에서 딴다 —
        # error.phase는 대부분 runtime_command_failed 상수라 무정보다(적대 리뷰).
        progress_phase = phase
        phase = error.phase
        failure_diagnostic = error.diagnostic
        if os.environ.get(_FORENSIC_CAPTURE_ENV) == "1" and (
            error.stderr or error.returncode is not None
        ):
            # 증거 기록 실패가 결과/phase를 바꾸면 안 된다. output leaf는
            # launcher가 root 0700으로 만들었으므로 초기 실패에도 존재한다.
            # returncode만 있는 실패도 고정 영수증은 남긴다(.stderr는
            # _write_command_failure_evidence가 forensic 게이트로 분리).
            try:
                _write_command_failure_evidence(
                    output
                    / f"failed-{_public_terminal_phase(progress_phase)}-command.json",
                    returncode=error.returncode,
                    # scrub은 evidence writer 내부에서 수행된다.
                    stderr=error.stderr,
                    # 러너의 진짜 진단은 대개 stdout에 있다(Playwright 등).
                    stdout=error.stdout,
                )
            except Exception:  # noqa: BLE001, S110 - evidence-only boundary
                pass
        if (
            os.environ.get(_FORENSIC_CAPTURE_ENV) == "1"
            and failure_diagnostic is not None
            and failure_diagnostic not in _MAP_FRESH_INIT_REASONS
        ):
            # receipt에는 어휘 내 값만 실리므로 어휘 밖 원문은 여기서만 남긴다.
            try:
                _write_private_bytes(
                    output
                    / f"failed-{_public_terminal_phase(progress_phase)}-diagnostic.txt",
                    _scrub_forensic_bytes(failure_diagnostic.encode("utf-8"))[
                        :_FORENSIC_CAPTURE_LIMIT
                    ]
                    or b"\n",
                )
            except Exception:  # noqa: BLE001, S110 - evidence-only boundary
                pass
    # 이 boundary 밖으로 예외가 새면 launcher는 raw driver output 없이 결과 부재만
    # 관측한다. 예상하지 못한 ordinary exception도 현재 allowlist 실행 경계로만
    # 수렴하므로, raw detail 없이 다음 immutable candidate의 보정 범위를 좁힐 수 있다.
    # BaseException은 잡지 않아 root 운영자가 중단 신호를 보낼 수 있게 둔다.
    except Exception:  # noqa: BLE001 - fixed terminal receipt boundary
        # ordinary exception은 traceback이 통째로 사라져 phase 이름 하나로
        # 원인을 재구성해야 했다(e2e9 실측: pinvi_runtime 구간 어딘가의
        # 익명 예외에 격리 run 1회 소모). forensic 모드에서는 root 0600
        # leaf에 traceback을 남긴다 — receipt/공개 표면에는 여전히 phase만
        # 실린다. 통제의 실체(적대 리뷰가 교정): (1) leaf 자체가 root 0600,
        # (2) format_exc는 frame locals를 싣지 않는다, (3) scrub은 생성
        # 즉시 등록된 비밀(_register_forensic_scrub_secrets)에만 기여한다.
        if os.environ.get(_FORENSIC_CAPTURE_ENV) == "1":
            try:
                _write_private_bytes(
                    output
                    / f"failed-{_public_terminal_phase(phase)}-exception.txt",
                    _scrub_forensic_bytes(
                        traceback.format_exc().encode("utf-8")
                    )[:_FORENSIC_CAPTURE_LIMIT]
                    or b"\n",
                )
            except Exception:  # noqa: BLE001, S110 - evidence-only boundary
                pass
        phase = _public_terminal_phase(phase)
    finally:
        (
            cleanup_failed,
            unexpected_finalization_failure,
            run_worktree_retained,
        ) = _cleanup_temporary_resources(
            map_cleanup=map_cleanup,
            pinvi_cleanup=pinvi_cleanup,
            private_files=private_files,
            disposable_run_worktree=disposable_run_worktree,
        )
        # driver_phase는 cleanup 전 실행 표면의 정본이다(2026-08-28 journal 계약).
        # 종전 코드는 강등/블록 표기 **뒤에** 대입해 두 결함을 만들었다:
        # (1) cleanup 실패가 실제 실패 phase를 통째로 가림 — e2e6에서 원인 재현에
        #     격리 run 1회를 태웠다. (2) passed 경로에서 마지막 body phase가 실려
        #     launcher의 passed 검증(driver_phase == "completed")이 첫 PASS를
        #     무효 receipt로 만들고 무조건 block으로 승격시킨다.
        driver_phase = "completed" if completed else phase
        if unexpected_finalization_failure or cleanup_failed:
            completed = False
            # claim 이전이면 phase를 바꾸지 않는다. 바꾸면 preflight_rejected
            # receipt가 driver_phase != phase가 되어 launcher가 거부하고, 아무것도
            # claim하지 않은 실행이 소각된다(적대 리뷰 BLOCKER-2). claim 이후에는
            # phase가 block scope를 고르므로 재작성이 유효하다.
            if (
                claim_attempted
                and not body_entered
                and _terminal_block_phase(phase) is not None
            ):
                # 본문 진입 이후(또는 ledger claim 실패)는 무조건 소각을 유지해야
                # 하므로 cleanup phase가 실패 표면을 강등하지 못한다(R1-S4).
                # cleanup 신호는 result의 `cleanup_failed` 필드가 이미 나른다.
                # 실제 실패 phase는 위 driver_phase가 이미 보존한다.
                phase = "runtime_cleanup_failed"
        if not completed and claim_attempted:
            try:
                pinset_blocked = _block_terminal_m05_execution(
                    phase,
                    expected_manager_revision=expected_revision,
                    force_unconditional=body_entered,
                )
            except Exception:  # noqa: BLE001 - fixed terminal receipt boundary
                pinset_blocked = False
            if not pinset_blocked:
                phase = "runtime_execution_block_failed"
        for name in _RAW_ENV_NAMES:
            os.environ.pop(name, None)
        result: dict[str, object] = {
            "harness": _HARNESS_NAME,
            "manager_source_revision": expected_revision,
            "phase": "completed" if completed else phase,
            "driver_phase": driver_phase,
            "cleanup_failed": cleanup_failed,
            # 일회용 체크아웃 제거 실패는 실행을 태우지 않는다. 그래도 조용히 넘기면
            # output leaf에 PinVi 체크아웃 전체가 남은 것을 아무도 모른다.
            "disposable_run_worktree_retained": run_worktree_retained,
            "pinset_sha256": PINNED_RUNTIME_RELEASE.pinset_sha256,
            "execution_identity_sha256": execution_identity,
            "status": (
                "passed"
                if completed
                else "blocked"
                if claim_attempted
                else "preflight_rejected"
            ),
            "transaction_id": transaction,
            # launcher는 이 세 key를 status=="passed"에서만 허용한다. body가
            # 통과한 뒤 cleanup이 실패하면 completed는 False가 되는데 hash는 남아
            # key 집합이 어긋났고, 그러면 "본문이 통과했다"는 가장 값진 사실이
            # launcher_safe_result_unavailable로 지워졌다(적대 리뷰 MAJOR-1).
            **(result_hashes if completed else {}),
        }
        # 어휘뿐 아니라 **phase**로도 잠근다. diagnostic은 _command/_compose의
        # 범용 채널이라, 다른 호출부가 겹치는 단어를 쓰는 exit map을 넘기는 순간
        # 무관한 실패에 fresh-init 사유가 붙는다(적대 리뷰 MAJOR-2).
        if (
            driver_phase == "map_fresh_init_failed"
            and failure_diagnostic in _MAP_FRESH_INIT_REASONS
        ):
            result["map_fresh_init_reason"] = failure_diagnostic
        try:
            _write_private_json(output / "result.json", result)
        except (OSError, _PhaseError):
            receipt_write_failed = True
    # `finally` 안에서 return하면 **전파 중인 BaseException을 삼킨다.** 위
    # `except Exception`이 ordinary exception을 이미 잡으므로 여기까지 살아
    # 오는 것은 KeyboardInterrupt/SystemExit뿐인데, 그것은 "root 운영자가
    # 중단 신호를 보낼 수 있게" 일부러 안 잡은 바로 그 신호다. return을
    # finally 밖으로 빼서 중단이 계속 전파되게 둔다. (Python 3.14가
    # SyntaxWarning으로 이 결함을 매 실행마다 알리고 있었다.)
    return driver_exit_code(
        completed=completed, receipt_write_failed=receipt_write_failed
    )


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit(2)
    if len(sys.argv) == 3 and sys.argv[1] == "--preflight":
        raise SystemExit(preflight(sys.argv[2]))
    if len(sys.argv) == 4 and sys.argv[1] == "--rotation-preflight":
        raise SystemExit(rotation_preflight(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-leaf":
        raise SystemExit(verify_leaf(Path(sys.argv[2])))
    if len(sys.argv) != 3:
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1], Path(sys.argv[2])))
