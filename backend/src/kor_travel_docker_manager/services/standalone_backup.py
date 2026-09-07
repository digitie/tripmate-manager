"""전용 PostgreSQL 인스턴스별 독립 백업 (issue #177).

ADR-37 4-instance 분리(geo/concierge/map/pinvi) 뒤에도 백업 주체는 map 하나뿐이었다.
이 모듈은 v5 rebuild의 cache-target/compatible-pair 기계와 완전히 무관하게, 네
인스턴스 각각을 `docker exec` + `pg_dump`로 독립 백업한다.

산출물은 `docs/docker-management.md`의 "3종 세트" 관례를 따른다 —
`<role>-<ts>.dump` · `<role>-<ts>.dump.sha256`(`sha256sum -c` 그대로 먹는 형태) ·
`<role>-<ts>.manifest`.

포트·admin role 이름은 하드코딩하지 않고 살아있는 컨테이너에서 읽는다
(`_discover_port`/`_discover_admin_role`) — `.env`가 기본 포트를 덮어썼거나
role 이름이 프로젝트마다 달라도(예: map은 `KOR_TRAVEL_MAP_POSTGRES_USER`에
기본값이 없다) 항상 실제 기동값과 일치한다. host network + 프로젝트별 포트라
`--port`를 빠뜨리면 컨테이너 기본값 5432를 찾아 조용히 실패한다.

connection은 TCP가 아니라 `docker exec --user postgres` + unix socket을 쓴다 —
로컬 소켓 인증은 `trust`로 남아 있어(호스트 TCP만 scram으로 잠갔다) 비밀번호
없이 붙을 수 있고, 그래서 이 모듈은 어떤 postgres 비밀번호도 읽거나 다루지
않는다.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import logging
import os
import re
import stat
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from kor_travel_docker_manager.services.secure_state_file import (
    atomic_write_bytes,
    atomic_write_json,
)

BackupRole = Literal[
    "geo",
    "geo_dagster",
    "concierge",
    "map_application",
    "map_dagster",
    "pinvi",
]

BACKUP_ROLES: tuple[BackupRole, ...] = (
    "geo",
    "geo_dagster",
    "concierge",
    "map_application",
    "map_dagster",
    "pinvi",
)

_CONTAINER_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
_ROLE_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
_DATABASE_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_SCHEMA_REVISION = re.compile(r"^[0-9a-z][0-9a-z_.-]{0,127}$")
_FILENAME = re.compile(r"^[a-z][a-z0-9_]{0,32}-[0-9]{1,20}\.dump$")
_ALEMBIC_SCHEMA_CANDIDATES = ("public", "app")
_logger = logging.getLogger(__name__)
BACKUP_SHARED_GROUP_ENV = "KTDM_BACKUP_SHARED_GROUP"

# (container_env, container_default, database_name). container_default는
# config/docker-targets.yml의 4-instance 계약과 같은 이름이다. docker-compose.yml이
# concierge/map/pinvi 컨테이너 이름을 env override로 허용하므로(geo만 리터럴 고정)
# 같은 override를 여기서도 존중한다 — 안 그러면 override된 스택에서 엉뚱한(또는
# 존재하지 않는) 컨테이너를 겨냥해 fail-close로 조용히 실패한다. 포트는 여기 두지
# 않는다 — 실제 기동 인자에서 읽는다.
_ROLE_CONFIG: dict[BackupRole, tuple[str | None, str, str]] = {
    "geo": (None, "kor-travel-geo-postgres", "kor_travel_geo"),
    "geo_dagster": (None, "kor-travel-geo-postgres", "kor_travel_geo_dagster"),
    "concierge": (
        "KOR_TRAVEL_CONCIERGE_POSTGRES_CONTAINER",
        "kor-travel-concierge-postgres",
        "kor_travel_concierge",
    ),
    "map_application": (
        "KOR_TRAVEL_MAP_POSTGRES_CONTAINER",
        "kor-travel-map-postgres",
        "kor_travel_map",
    ),
    "map_dagster": (
        "KOR_TRAVEL_MAP_POSTGRES_CONTAINER",
        "kor-travel-map-postgres",
        "kor_travel_map_dagster",
    ),
    "pinvi": ("PINVI_POSTGRES_CONTAINER", "pinvi-postgres", "pinvi"),
}


class StandaloneBackupError(RuntimeError):
    """백업 생성/조회/정리 중 발생한 fail-close 오류."""


class StandaloneBackupNotFoundError(StandaloneBackupError):
    """복원 대상 백업이 없다 — 도구 오류가 아니라 판정 결과다.

    호출자가 exit code를 이 사실과 그 밖의 오류(잘못된 파일명 등)로 구분해야 할 때
    ``isinstance``로 판별한다. 문구를 바꾸면 판정이 조용히 어긋나는 문자열 매칭
    (예: ``"no backup" in str(exc)``)을 대체한다."""


class StandaloneBackupInProgressError(StandaloneBackupError):
    """GM-13: 같은 role의 DB에 이미 pg_dump가 돌고 있어 새 백업을 시작할 수 없다.

    role lock(파일 기반 fcntl)만으로는 막지 못하는 경우를 잡는다 — 그 lock을
    쥔 프로세스가 재기동으로 죽으면 커널이 lock을 즉시 풀어주지만, 컨테이너 안의
    pg_dump 자체는 `docker exec`가 timeout을 전파하지 않아 서버 쪽에서 계속 돈다
    (진행 상황은 create_standalone_backup의 docstring 참고)."""


@dataclass(frozen=True)
class BackupManifest:
    role: BackupRole
    created_at_unix: int
    duration_sec: float
    byte_size: int
    sha256: str
    backup_filename: str
    instance: str
    db_size_bytes: int
    toc_entry_count: int
    alembic_head: str | None

    def to_json(self) -> dict[str, object]:
        return {
            "role": self.role,
            "created_at_unix": self.created_at_unix,
            "duration_sec": self.duration_sec,
            "byte_size": self.byte_size,
            "sha256": self.sha256,
            "backup_filename": self.backup_filename,
            "instance": self.instance,
            "db_size_bytes": self.db_size_bytes,
            "toc_entry_count": self.toc_entry_count,
            "alembic_head": self.alembic_head,
        }


@dataclass(frozen=True)
class GcOutcome:
    """gc가 실제로 지운 것. 회전과 잔해 수거는 성격이 달라 분리해 알린다.

    ``deleted``는 "최신 keep개만 남긴다"는 정책의 결과이고, ``orphans_removed``는
    중단된 create가 남긴 복원 불가능한 dump다. 둘을 한 목록으로 합치면 운영자가
    "왜 예상보다 많이 지워졌나"를 알 수 없다.
    """

    deleted: tuple[str, ...]
    orphans_removed: tuple[str, ...]

    @property
    def total(self) -> int:
        return len(self.deleted) + len(self.orphans_removed)

    def to_json(self) -> dict[str, object]:
        return {
            "deleted": list(self.deleted),
            "orphans_removed": list(self.orphans_removed),
        }


@dataclass(frozen=True)
class _ArtifactModePolicy:
    """backup 디렉터리·파일의 소유 모드 정책.

    UI(backend 프로세스)와 cron(별도 계정)이 같은 디렉터리를 공유하면 한쪽이 만든
    dump를 다른 쪽이 읽지도 지우지도 못한다. 특히 unlink는 파일이 아니라 **디렉터리**
    쓰기 권한이라, 공유하려면 setgid 그룹 디렉터리가 필요하다. 공유 그룹을 선언하지
    않은 설치본은 기존 `0700`/`0600` 그대로다 — 아무도 요구하지 않은 권한 완화를
    기본값으로 만들지 않는다.
    """

    shared_gid: int | None
    directory_mode: int
    file_mode: int
    # lock은 양쪽이 `O_RDWR`로 열어야 하므로 **그룹 쓰기**가 필요하다. 산출물(0640)과
    # 같은 mode를 쓰면 읽기만 되어 두 번째 프로세스가 lock을 잡지 못한다.
    lock_mode: int


def _resolve_shared_gid(raw: str) -> int:
    if raw.isdigit():
        return int(raw)
    try:
        import grp

        return grp.getgrnam(raw).gr_gid
    except (ImportError, KeyError) as exc:
        raise StandaloneBackupError(
            f"{BACKUP_SHARED_GROUP_ENV}={raw!r} is not a group on this host — create it and "
            f"add both the backend service user and the cron user to it "
            f"(groupadd {raw}; usermod -aG {raw} <backend-user>; usermod -aG {raw} "
            f"<cron-user>), then restart the backend so the new supplementary group takes "
            f"effect"
        ) from exc


def _artifact_mode_policy() -> _ArtifactModePolicy:
    raw = os.environ.get(BACKUP_SHARED_GROUP_ENV, "").strip()
    if not raw:
        return _ArtifactModePolicy(
            shared_gid=None, directory_mode=0o700, file_mode=0o600, lock_mode=0o600
        )
    return _ArtifactModePolicy(
        shared_gid=_resolve_shared_gid(raw),
        directory_mode=0o2770,
        file_mode=0o640,
        lock_mode=0o660,
    )


def _prepare_backup_root(root: Path, policy: _ArtifactModePolicy) -> None:
    """공유 그룹 모드에서는 디렉터리 mode를 **덮어쓰지 않는다.**

    운영자가 건 setgid나 ACL을 코드가 추측해 재설정하면 조용히 되돌아간다. 대신 전제가
    깨졌으면 정확한 복구 명령과 함께 fail-close한다. 새 role 하위 디렉터리는 setgid
    부모에서 mkdir하면 그룹과 setgid를 상속하므로 전제는 루트 한 곳에만 걸면 된다.
    """

    created = not root.exists()
    root.mkdir(parents=True, exist_ok=True)
    if policy.shared_gid is None:
        os.chmod(root, policy.directory_mode)
        return
    # setgid 부모 아래에서 mkdir하면 **그룹과 setgid 비트는** 상속하지만 permission
    # 비트는 umask가 정한다(2770 부모 아래 자식이 2755가 된다). 그래서 role 하위
    # 디렉터리를 우리가 방금 만들었다면 mode를 명시적으로 맞춘다 — 이걸 빼면 그 role의
    # **첫 백업**이 항상 실패한다.
    if created:
        try:
            os.chmod(root, policy.directory_mode)
        except OSError:
            pass
    metadata = root.lstat()
    if (
        metadata.st_gid != policy.shared_gid
        or not (metadata.st_mode & stat.S_ISGID)
        or (stat.S_IMODE(metadata.st_mode) & 0o070) != 0o070
    ):
        # 붙여넣어서 그대로 도는 명령을 준다. 파일까지 2770으로 만들면 dump가
        # group-writable·실행 가능해져 0640 정책과 어긋나므로 디렉터리만 손댄다.
        raise StandaloneBackupError(
            f"backup directory {root} is not a shared setgid directory "
            f"(gid={metadata.st_gid}, mode={stat.S_IMODE(metadata.st_mode):04o}); run: "
            f"sudo chgrp -R {policy.shared_gid} {root.parent} && "
            f"sudo find {root.parent} -type d -exec chmod 2770 {{}} + && "
            f"sudo find {root.parent} -type f -exec chmod 0640 {{}} +"
        )


def _assert_shared_group_effective(
    path: Path, policy: _ArtifactModePolicy, *, role: BackupRole
) -> None:
    """읽을 수 없는 dump를 남기느니 지운다.

    목록에는 보이는데 cron이 열지 못하는 백업은 "백업이 있다"는 거짓 안전감만 만든다.
    """

    if policy.shared_gid is None:
        return
    actual_gid = path.stat().st_gid
    if actual_gid == policy.shared_gid:
        return
    path.unlink(missing_ok=True)
    raise StandaloneBackupError(
        f"{role} backup landed in group {actual_gid} instead of shared group "
        f"{policy.shared_gid} — the setgid bit on {path.parent} is not effective; "
        f"the unreadable dump was removed rather than left behind"
    )


def create_standalone_backup(
    role: BackupRole,
    *,
    backup_root: Path | None = None,
    timeout: int = 14_400,
) -> BackupManifest:
    """`role`의 앱 DB를 `pg_dump -Fc`로 컨테이너 안에 뜬 뒤 host로 복사한다.

    geo(33GB급)처럼 큰 인스턴스는 기본 timeout(4시간)으로도 부족할 수 있다 —
    호출자가 `timeout`을 넉넉히 늘려야 한다. **timeout에 걸리면 로컬 `docker exec`
    client만 중단되고 컨테이너 안의 `pg_dump`는 서버 쪽에서 계속 실행된다**(docker
    exec는 timeout을 안쪽 프로세스로 전파하지 않는다) — 같은 role을 바로 재시도하면
    두 pg_dump가 동시에 돌아 DB에 이중 부하가 걸릴 수 있으므로, 같은 role의 동시
    실행은 아래 파일 락으로 막는다. 이 락은 **프로세스 재기동에서는 살아남지
    못한다** — backend가 pg_dump 도중 재기동되면 락은 즉시 풀리지만 컨테이너
    안의 pg_dump는 계속 돈다. 그래서 락을 잡은 뒤에도 `pg_stat_activity`로
    실제 실행 중인 pg_dump가 있는지 한 번 더 확인한다(`GM-13`).
    """

    container_name, database_name = _role_config(role)
    port = _discover_port(container_name)
    admin_name = _discover_admin_role(container_name)

    policy = _artifact_mode_policy()
    root = _resolve_backup_root(role, backup_root)
    _prepare_backup_root(root, policy)

    with _role_lock(root):
        if _pg_dump_already_running(container_name, port, admin_name, database_name):
            raise StandaloneBackupInProgressError(
                f"a pg_dump for {role} ({database_name}) is already running on the "
                "server — this usually means the backend restarted mid-backup and "
                "lost track of the job; wait for the existing pg_dump to finish "
                "instead of starting a second one against the same database"
            )
        created_at_unix = int(time.time())
        filename = f"{role}-{created_at_unix}.dump"
        dest_path = root / filename
        copy_path = root / f".{filename}.copying"
        container_tmp = f"/tmp/{filename}"

        try:
            started = time.monotonic()
            _run_checked(
                [
                    "docker",
                    "exec",
                    "--user",
                    "postgres",
                    container_name,
                    "pg_dump",
                    "--username",
                    admin_name,
                    "--port",
                    str(port),
                    "--dbname",
                    database_name,
                    "--format=custom",
                    "--compress=6",
                    "--file",
                    container_tmp,
                ],
                label=f"{role} pg_dump",
                timeout=timeout,
            )
            duration_sec = round(time.monotonic() - started, 3)
            toc_entry_count = _count_toc_entries(container_name, container_tmp, timeout=timeout)
            copy_path.unlink(missing_ok=True)
            _run_checked(
                ["docker", "cp", f"{container_name}:{container_tmp}", str(copy_path)],
                label=f"{role} backup copy-out",
                timeout=timeout,
            )
            if not copy_path.is_file():
                raise StandaloneBackupError(f"{role} backup copy-out produced no file")
            os.chmod(copy_path, policy.file_mode)
            os.replace(copy_path, dest_path)
        finally:
            # pg_dump 실패/timeout이어도 시도한 만큼은 지운다 — 시도가 계속 서버
            # 쪽에서 돌고 있더라도 rm은 디렉터리 항목을 즉시 없애 다음 목록/GC가
            # 반쪽 파일을 보지 않게 한다(inode는 그 프로세스가 끝나야 실제 회수된다).
            copy_path.unlink(missing_ok=True)
            subprocess.run(
                ["docker", "exec", container_name, "rm", "-f", container_tmp],
                capture_output=True,
                check=False,
                timeout=30,
            )

        return _finish_standalone_backup(
            policy=policy,
            role=role,
            container_name=container_name,
            database_name=database_name,
            port=port,
            admin_name=admin_name,
            dest_path=dest_path,
            filename=filename,
            root=root,
            created_at_unix=created_at_unix,
            duration_sec=duration_sec,
            toc_entry_count=toc_entry_count,
        )


def _finish_standalone_backup(
    *,
    policy: _ArtifactModePolicy,
    role: BackupRole,
    container_name: str,
    database_name: str,
    port: int,
    admin_name: str,
    dest_path: Path,
    filename: str,
    root: Path,
    created_at_unix: int,
    duration_sec: float,
    toc_entry_count: int,
) -> BackupManifest:
    if not dest_path.is_file():
        raise StandaloneBackupError(f"{role} backup copy-out produced no file")
    os.chmod(dest_path, policy.file_mode)
    _assert_shared_group_effective(dest_path, policy, role=role)
    byte_size = dest_path.stat().st_size
    if byte_size == 0:
        dest_path.unlink(missing_ok=True)
        raise StandaloneBackupError(f"{role} backup produced an empty file")

    sha256 = _sha256_file(dest_path)
    # `sha256sum -c`가 그대로 먹는 형태: "<hash>  <filename>"
    sha256_path = root / f"{filename}.sha256"
    _atomic_write_bytes(sha256_path, f"{sha256}  {filename}\n".encode("ascii"))
    os.chmod(sha256_path, policy.file_mode)

    manifest = BackupManifest(
        role=role,
        created_at_unix=created_at_unix,
        duration_sec=duration_sec,
        byte_size=byte_size,
        sha256=sha256,
        backup_filename=filename,
        instance=f"{container_name}:127.0.0.1:{port}/{database_name}",
        db_size_bytes=_query_db_size(container_name, port, admin_name, database_name),
        toc_entry_count=toc_entry_count,
        alembic_head=_discover_alembic_head(container_name, port, admin_name, database_name),
    )
    manifest_path = _manifest_path(root, filename)
    _atomic_write_json(manifest_path, manifest.to_json())
    os.chmod(manifest_path, policy.file_mode)
    return manifest


def list_standalone_backups(
    role: BackupRole,
    *,
    backup_root: Path | None = None,
) -> list[BackupManifest]:
    """fail-close 목록 — manifest 하나라도 읽기 실패·형식 위반·role 불일치면
    예외를 던진다. `gc_standalone_backups`/`plan_standalone_restore`처럼 이
    목록을 기준으로 "무엇을 지울지/복원할지" 판단하는 mutation-adjacent
    코드 전용이다: 손상된 manifest를 조용히 건너뛰면 그 백업이 `manifests`에도
    없고(gc의 kept 집합에서 빠짐) `_FILENAME` 패턴에 맞는 `.dump`가 그대로
    남아 orphan으로 오인돼 지워질 수 있다. 순수 조회(`GET /api/v1/backups`)는
    `list_standalone_backups_for_display`를 쓴다."""

    _role_config(role)
    root = _resolve_backup_root(role, backup_root)
    if not root.is_dir():
        return []
    manifests = [
        _read_manifest(path, expected_role=role) for path in sorted(root.glob("*.manifest"))
    ]
    return sorted(manifests, key=lambda item: item.created_at_unix)


def list_standalone_backups_for_display(
    role: BackupRole,
    *,
    backup_root: Path | None = None,
) -> list[dict[str, object]]:
    """GM-13: `GET /api/v1/backups` 전용 — manifest 하나가 손상돼도 나머지
    목록은 그대로 보여준다. geo 백업 세트를 map 디렉터리에 잘못 복사하는 것
    같은 흔한 실수 하나로, 장애 중 가장 필요한 순간에 멀쩡한 백업 전체 목록이
    사라지는 것을 막는다. 디렉터리 자체를 못 읽는 경우(예: 권한 문제)만
    `StandaloneBackupError`를 던진다 — 이건 라우트가 503로 옮긴다."""

    _role_config(role)
    root = _resolve_backup_root(role, backup_root)
    if not root.is_dir():
        return []
    try:
        manifest_paths = sorted(root.glob("*.manifest"))
    except OSError as exc:
        raise StandaloneBackupError(f"{role} backup directory is unreadable: {exc}") from exc

    readable: list[tuple[int, dict[str, object]]] = []
    unreadable: list[dict[str, object]] = []
    for path in manifest_paths:
        try:
            manifest = _read_manifest(path, expected_role=role)
        except StandaloneBackupError as exc:
            unreadable.append({"state": "unreadable", "filename": path.name, "reason": str(exc)})
            continue
        readable.append((manifest.created_at_unix, manifest.to_json()))
    readable.sort(key=lambda item: item[0])
    return [row for _, row in readable] + unreadable


def gc_standalone_backups(
    role: BackupRole,
    *,
    keep: int,
    backup_root: Path | None = None,
) -> GcOutcome:
    """가장 최신 `keep`개만 남기고 나머지 dump/sha256/manifest 세트를 지운다.

    **create와 같은 role lock 아래에서 실행한다.** 락이 없으면 진행 중인 백업
    (geo는 실측 20분 이상)의 산출물을 지울 수 있다 — dump는 manifest보다 먼저
    쓰이므로 그 창에서는 orphan과 구분되지 않는다.
    """

    if keep < 1:
        raise StandaloneBackupError("keep must be at least 1")
    root = _resolve_backup_root(role, backup_root)
    if not root.is_dir():
        return GcOutcome(deleted=(), orphans_removed=())
    with _role_lock(root):
        manifests = list_standalone_backups(role, backup_root=backup_root)
        deleted: list[str] = []
        for manifest in manifests[: max(len(manifests) - keep, 0)]:
            _unlink_backup_set(root, manifest.backup_filename)
            deleted.append(manifest.backup_filename)
        # manifest가 없는 dump는 목록에도 안 잡히고 복원 경로도 없다(무결성 메타가
        # 없어 검증할 수 없다). 중단된 create의 잔해이므로 락 아래에서만 수거한다.
        kept_names = {manifest.backup_filename for manifest in manifests} - set(deleted)
        orphans: list[str] = []
        for dump in sorted(root.glob("*.dump")):
            if dump.name in kept_names or not _FILENAME.fullmatch(dump.name):
                continue
            _unlink_backup_set(root, dump.name)
            orphans.append(dump.name)
    return GcOutcome(deleted=tuple(deleted), orphans_removed=tuple(orphans))


def _unlink_backup_set(root: Path, backup_filename: str) -> None:
    """dump·sha256·manifest 3종 세트를 함께 지운다."""

    if not _FILENAME.fullmatch(backup_filename):
        raise StandaloneBackupError(f"backup filename is invalid: {backup_filename}")
    (root / backup_filename).unlink(missing_ok=True)
    (root / f"{backup_filename}.sha256").unlink(missing_ok=True)
    _manifest_path(root, backup_filename).unlink(missing_ok=True)


@dataclass(frozen=True)
class RestorePlanFinding:
    """복원 계획에서 발견한 사실 하나. 차단인지 아닌지를 스스로 안다."""

    code: str
    text: str
    blocking: bool

    def to_json(self) -> dict[str, object]:
        return {"code": self.code, "text": self.text, "blocking": self.blocking}


@dataclass(frozen=True)
class RestorePlan:
    """"이 백업으로 복원하면 무슨 일이 일어나는가"를 **아무것도 바꾸지 않고** 답한다.

    복원 자체는 아직 구현하지 않는다. 먼저 이것을 만드는 이유는, 목록에 백업이 보이는
    것과 그 백업으로 실제 복원할 수 있는 것이 다르기 때문이다 — dump가 잘려 있거나
    manifest와 digest가 어긋나거나 live schema revision이 백업 시점과 달라도 목록은
    똑같이 초록색이다. 그 거짓 안전감을 복원을 만들기 전에 걷어낸다.
    """

    role: BackupRole
    backup_filename: str
    dump_path: str
    manifest: BackupManifest
    observed_sha256: str | None
    observed_byte_size: int | None
    live_alembic_head: str | None
    containers: tuple[str, ...]
    findings: tuple[RestorePlanFinding, ...]

    @property
    def restorable(self) -> bool:
        return not any(finding.blocking for finding in self.findings)

    def to_json(self) -> dict[str, object]:
        return {
            "role": self.role,
            "backup_filename": self.backup_filename,
            "dump_path": self.dump_path,
            "manifest": self.manifest.to_json(),
            "observed_sha256": self.observed_sha256,
            "observed_byte_size": self.observed_byte_size,
            "live_alembic_head": self.live_alembic_head,
            "containers": list(self.containers),
            "findings": [finding.to_json() for finding in self.findings],
            "restorable": self.restorable,
        }


def plan_standalone_restore(
    role: BackupRole,
    *,
    backup_filename: str | None = None,
    backup_root: Path | None = None,
) -> RestorePlan:
    """복원 **계획**만 만든다. 파일도 DB도 컨테이너도 건드리지 않는다.

    `backup_filename`을 주지 않으면 가장 최근 백업을 고른다. digest는 실제로 다시
    계산한다 — manifest에 적힌 값을 그대로 믿으면 이 점검이 아무것도 검증하지 않는다.
    """

    container_name, database_name = _role_config(role)
    root = _resolve_backup_root(role, backup_root)
    manifests = list_standalone_backups(role, backup_root=backup_root)
    if not manifests:
        raise StandaloneBackupNotFoundError(f"{role} has no backup to restore from")
    if backup_filename is None:
        manifest = max(manifests, key=lambda item: item.created_at_unix)
    else:
        if not _FILENAME.fullmatch(backup_filename):
            raise StandaloneBackupError(f"backup filename is invalid: {backup_filename}")
        selected = [item for item in manifests if item.backup_filename == backup_filename]
        if not selected:
            raise StandaloneBackupNotFoundError(f"{role} has no backup named {backup_filename}")
        manifest = selected[0]

    dump_path = root / manifest.backup_filename
    findings: list[RestorePlanFinding] = []
    observed_sha256: str | None = None
    observed_byte_size: int | None = None

    if not dump_path.is_file():
        findings.append(
            RestorePlanFinding(
                "DUMP_MISSING",
                f"manifest는 있지만 dump 파일이 없습니다: {dump_path.name}",
                True,
            )
        )
    else:
        try:
            observed_byte_size = dump_path.stat().st_size
            observed_sha256 = _sha256_file(dump_path)
        except OSError as exc:
            # gc가 lock을 잡고 지우는 사이일 수 있다. 여기서 raw OSError가 새어 나가면
            # CLI가 traceback으로 죽고, 이 함수가 만들어야 할 "판정"이 사라진다.
            findings.append(
                RestorePlanFinding(
                    "DUMP_UNREADABLE",
                    f"dump를 읽는 중 사라졌거나 읽을 수 없습니다: {exc.strerror}",
                    True,
                )
            )
            observed_byte_size = None
            observed_sha256 = None
        if observed_byte_size is not None and observed_byte_size != manifest.byte_size:
            findings.append(
                RestorePlanFinding(
                    "SIZE_MISMATCH",
                    f"dump 크기가 manifest와 다릅니다"
                    f"({observed_byte_size} vs {manifest.byte_size}).",
                    True,
                )
            )
        if observed_sha256 is not None and observed_sha256 != manifest.sha256:
            findings.append(
                RestorePlanFinding(
                    "SHA256_MISMATCH",
                    "dump의 sha256이 manifest와 다릅니다. 이 파일로 복원하면 안 됩니다.",
                    True,
                )
            )

    # live schema revision은 best-effort다. 읽지 못하는 것을 "맞다"로 말하지 않는다.
    live_alembic_head: str | None = None
    containers: tuple[str, ...] = ()
    try:
        port = _discover_port(container_name)
        admin_name = _discover_admin_role(container_name)
    except StandaloneBackupError as exc:
        findings.append(
            RestorePlanFinding(
                "INSTANCE_UNREACHABLE",
                f"대상 인스턴스를 확인할 수 없습니다: {exc}",
                True,
            )
        )
    else:
        containers = (container_name,)
        live_alembic_head = _discover_alembic_head(
            container_name, port, admin_name, database_name
        )
        if live_alembic_head is None:
            findings.append(
                RestorePlanFinding(
                    "LIVE_HEAD_UNKNOWN",
                    "현재 DB의 schema revision을 읽지 못했습니다. 백업 시점과 같은지 "
                    "확인할 수 없습니다.",
                    False,
                )
            )
        elif manifest.alembic_head is None:
            findings.append(
                RestorePlanFinding(
                    "MANIFEST_HEAD_UNKNOWN",
                    "백업 manifest에 schema revision이 없습니다. 현재 DB와 같은 "
                    "시점인지 확인할 수 없습니다.",
                    False,
                )
            )
        elif live_alembic_head != manifest.alembic_head:
            findings.append(
                RestorePlanFinding(
                    "HEAD_MISMATCH",
                    f"현재 DB의 schema revision({live_alembic_head})이 백업 시점"
                    f"({manifest.alembic_head})과 다릅니다. 복원하면 코드가 기대하는 "
                    "schema보다 과거로 되돌아갑니다.",
                    False,
                )
            )

    if not findings:
        findings.append(
            RestorePlanFinding(
                "OK", "이 백업은 무결성과 schema revision이 모두 일치합니다.", False
            )
        )

    return RestorePlan(
        role=role,
        backup_filename=manifest.backup_filename,
        dump_path=str(dump_path),
        manifest=manifest,
        observed_sha256=observed_sha256,
        observed_byte_size=observed_byte_size,
        live_alembic_head=live_alembic_head,
        containers=containers,
        findings=tuple(findings),
    )


_REHEARSAL_DB_PREFIX = "ktdm_rehearsal_"
_REHEARSAL_CONTAINER_DIR = "/tmp"

#: 리허설의 createdb/pg_restore를 실행하는 컨테이너 안 유저.
#:
#: dump를 컨테이너로 넣은 뒤 **이 유저에게 소유권을 넘긴다.** 둘이 갈라지면
#: `docker cp`가 host 소유권(root:root 0600)을 그대로 보존하므로 pg_restore가
#: 자기가 복원할 파일을 읽지 못한다 — 2026-09-07 n150 실측:
#:
#:     pg_restore: error: could not open input file
#:     "/tmp/rehearsal-....dump": Permission denied
#:
#: 모든 백업이 root 0600이므로 이 명령은 그전까지 한 번도 성공한 적이 없다.
_REHEARSAL_EXEC_USER = "postgres"
# 기본 timeout(4시간)보다 넉넉히 커야 "아직 진행 중인" 리허설을 실수로 지우지 않는다.
_REHEARSAL_STALE_AFTER_SECONDS = 6 * 60 * 60
# 복원된 크기가 백업 시점 크기의 이 비율에도 못 미치면 "일부만 복원됐을 수 있다"로 본다.
_REHEARSAL_SIZE_SHORTFALL_RATIO = 0.5


@dataclass(frozen=True)
class RehearsalOutcome:
    """백업을 scratch DB에 실제로 복원해 검증한 결과. 운영 DB는 전혀 건드리지 않는다.

    scratch DB는 대상과 같은 인스턴스 안에 이름이 겹치지 않게 새로 만들었다가,
    검증이 끝나면 성공이든 실패든 항상 지운다. 실제 role DB로 덮어쓰는 파괴적
    복원은 이 함수의 범위 밖이다 — 그 결정은 오너가 이미 로드맵 뒤로 미뤄 두었다
    (docs/general-mgmt-audit.md GM-07 검증 노트, journal 2026-08-28).
    """

    role: BackupRole
    backup_filename: str
    plan: RestorePlan
    attempted: bool
    restore_succeeded: bool | None
    scratch_database: str | None
    restored_alembic_head: str | None
    restored_db_size_bytes: int | None
    duration_sec: float | None
    findings: tuple[RestorePlanFinding, ...]
    #: 복원된 scratch DB와 **현재 운영 DB**의 카탈로그 지문. 같으면 소유권·ACL·
    #: routine 보안 속성이 살아남았다는 뜻이다. `None`은 "읽지 못했다"이지
    #: "같다"가 아니다.
    restored_catalog_digest: str | None = None
    live_catalog_digest: str | None = None

    @property
    def verified(self) -> bool:
        return (
            self.attempted
            and self.restore_succeeded is True
            and not any(finding.blocking for finding in self.findings)
        )

    def to_json(self) -> dict[str, object]:
        return {
            "role": self.role,
            "backup_filename": self.backup_filename,
            "plan": self.plan.to_json(),
            "attempted": self.attempted,
            "restore_succeeded": self.restore_succeeded,
            "scratch_database": self.scratch_database,
            "restored_alembic_head": self.restored_alembic_head,
            "restored_db_size_bytes": self.restored_db_size_bytes,
            "duration_sec": self.duration_sec,
            "findings": [finding.to_json() for finding in self.findings],
            "verified": self.verified,
        }


def _rehearsal_database_age_seconds(database_name: str, *, now: float) -> float | None:
    """scratch DB 이름에 박힌 epoch를 읽어 나이를 계산한다. 형식이 아니면 None."""

    if not database_name.startswith(_REHEARSAL_DB_PREFIX):
        return None
    epoch_part = database_name[len(_REHEARSAL_DB_PREFIX) :].split("_", 1)[0]
    if not epoch_part.isdigit():
        return None
    return now - int(epoch_part)


def _drop_stale_rehearsal_databases(
    container_name: str, port: int, admin_name: str
) -> tuple[str, ...]:
    """이전 리허설이 kill -9 등으로 죽으면서 남긴 scratch DB를 다음 실행이 스스로 치운다.

    아직 진행 중일 수 있는 DB를 건드리지 않으려 이름의 epoch가
    `_REHEARSAL_STALE_AFTER_SECONDS`보다 오래된 것만 지운다. 조회·삭제가 실패해도
    조용히 넘어간다 — 이 스윕은 최선의 노력이지 이번 리허설의 성패를 좌우해서는
    안 된다. `dropdb --if-exists`라 이미 지워졌거나 다른 스윕과 동시에 지워도 안전하다.
    """

    try:
        output = _run_checked(
            [
                "docker",
                "exec",
                "--user",
                "postgres",
                container_name,
                "psql",
                "--username",
                admin_name,
                "--port",
                str(port),
                "--dbname",
                "postgres",
                "--no-psqlrc",
                "--tuples-only",
                "--no-align",
                "--command",
                f"SELECT datname FROM pg_database WHERE datname LIKE '{_REHEARSAL_DB_PREFIX}%'",
            ],
            label=f"{container_name} stale rehearsal database listing",
            timeout=30,
        ).decode("utf-8", "replace")
    except StandaloneBackupError:
        return ()

    now = time.time()
    dropped: list[str] = []
    for candidate in output.splitlines():
        candidate = candidate.strip()
        if not candidate or not _DATABASE_IDENTIFIER.fullmatch(candidate):
            continue
        age = _rehearsal_database_age_seconds(candidate, now=now)
        if age is None or age < _REHEARSAL_STALE_AFTER_SECONDS:
            continue
        subprocess.run(
            [
                "docker",
                "exec",
                "--user",
                "postgres",
                container_name,
                "dropdb",
                "--username",
                admin_name,
                "--port",
                str(port),
                "--if-exists",
                candidate,
            ],
            capture_output=True,
            check=False,
            timeout=60,
        )
        dropped.append(candidate)
    return tuple(dropped)


def rehearse_standalone_restore(
    role: BackupRole,
    *,
    backup_filename: str | None = None,
    backup_root: Path | None = None,
    timeout: int = 14_400,
) -> RehearsalOutcome:
    """백업이 실제로 복원 가능한지 scratch DB에서 증명한다. 운영 DB는 건드리지 않는다.

    `plan_standalone_restore`가 차단(blocking) 사유를 찾으면 시도조차 하지 않는다 —
    무결성이 깨진 파일을 scratch DB에라도 복원 시도하는 것은 낭비다. 통과하면 같은
    인스턴스 안에 이름이 겹치지 않는 scratch DB를 만들어 그 안에만 `pg_restore`하고,
    TOC 적용이 실제로 끝까지 갔는지(exit code)와 schema revision·DB 크기가 말이 되는지
    확인한 뒤, 결과와 무관하게 scratch DB와 그 안의 dump 사본을 지운다.

    `create_standalone_backup`과 같은 한계를 공유한다 — **timeout에 걸리면 로컬
    `docker exec` client만 중단되고 컨테이너 안의 `pg_restore`는 서버 쪽에서 계속
    실행될 수 있다**(docker exec는 timeout을 안쪽 프로세스로 전파하지 않는다). 이
    호출이 잡고 있는 `_role_lock`이 같은 role의 재시도를 막고, 다음 호출의
    `_drop_stale_rehearsal_databases`가 결국 그 scratch DB를 회수한다 — 하지만 그
    사이 대상 인스턴스에 걸리는 부하는 이 함수가 취소할 수 없다. `geo`처럼 큰 role은
    트래픽이 적은 시간대에 실행하는 것을 권장한다.
    """

    plan = plan_standalone_restore(role, backup_filename=backup_filename, backup_root=backup_root)
    if not plan.restorable:
        return RehearsalOutcome(
            role=role,
            backup_filename=plan.backup_filename,
            plan=plan,
            attempted=False,
            restore_succeeded=None,
            scratch_database=None,
            restored_alembic_head=None,
            restored_db_size_bytes=None,
            duration_sec=None,
            findings=(
                RestorePlanFinding(
                    "PLAN_BLOCKED",
                    "복원 계획에 차단 사유가 있어 리허설을 시도하지 않았습니다. "
                    "'db-backup restore-plan'으로 원인을 먼저 확인하세요.",
                    True,
                ),
            ),
        )

    container_name, _database_name = _role_config(role)
    root = _resolve_backup_root(role, backup_root)
    port = _discover_port(container_name)
    admin_name = _discover_admin_role(container_name)
    # epoch만으로는 부족하다 — geo/geo_dagster, map_application/map_dagster처럼 같은
    # 컨테이너를 공유하는 role 쌍이 같은 초에 각자 리허설을 시작하면 이름이 겹쳐 한쪽의
    # dropdb가 다른 쪽이 한창 복원 중인 scratch DB를 지울 수 있다. 무작위 접미사를 더해
    # role/컨테이너와 무관하게 항상 유일하게 만든다.
    scratch_database = f"{_REHEARSAL_DB_PREFIX}{int(time.time())}_{os.urandom(4).hex()}"
    if not _DATABASE_IDENTIFIER.fullmatch(scratch_database):
        raise StandaloneBackupError(
            f"generated scratch database name is invalid: {scratch_database}"
        )
    container_dump_path = f"{_REHEARSAL_CONTAINER_DIR}/rehearsal-{scratch_database}.dump"

    # kill -9 등으로 죽은 이전 리허설이 남긴 scratch DB를 이번 실행이 스스로 치운다 —
    # `db-backup list`/`gc`는 파일 manifest만 보므로 DB 잔해는 이 스윕 말고는 발견되지
    # 않는다. lock 밖에서 해도 안전하다: `dropdb --if-exists`는 멱등이고, 이 스윕이
    # 건드리는 대상은 이름의 epoch가 오래된(진행 중일 수 없는) DB로 한정된다.
    stale_databases = _drop_stale_rehearsal_databases(container_name, port, admin_name)

    findings: list[RestorePlanFinding] = []
    restore_succeeded: bool | None = None
    restored_catalog_digest: str | None = None
    live_catalog_digest: str | None = None
    restored_alembic_head: str | None = None
    restored_db_size_bytes: int | None = None
    started = time.monotonic()

    with _role_lock(root, label="rehearsal"):
        try:
            _run_checked(
                ["docker", "cp", plan.dump_path, f"{container_name}:{container_dump_path}"],
                label=f"{role} rehearsal dump copy-in",
                timeout=timeout,
            )
            # `docker cp`는 host 파일의 소유권·권한을 그대로 보존한다. 백업은
            # root:root 0600이고 pg_restore는 `_REHEARSAL_EXEC_USER`로 도므로,
            # 소유권을 넘기지 않으면 자기가 복원할 파일을 읽지 못한다. 모드는
            # 0600 그대로 두고 **소유자만** 바꾼다 — 읽을 수 있는 주체를 늘리지
            # 않는다.
            _run_checked(
                [
                    "docker",
                    "exec",
                    "--user",
                    "root",
                    container_name,
                    "chown",
                    f"{_REHEARSAL_EXEC_USER}:{_REHEARSAL_EXEC_USER}",
                    container_dump_path,
                ],
                label=f"{role} rehearsal dump ownership handover",
                timeout=60,
            )
            _run_checked(
                [
                    "docker",
                    "exec",
                    "--user",
                    _REHEARSAL_EXEC_USER,
                    container_name,
                    "createdb",
                    "--username",
                    admin_name,
                    "--port",
                    str(port),
                    "--owner",
                    admin_name,
                    scratch_database,
                ],
                label=f"{role} rehearsal scratch database create",
                timeout=60,
            )
            returncode, stderr = _run_pg_restore(
                [
                    "docker",
                    "exec",
                    "--user",
                    _REHEARSAL_EXEC_USER,
                    container_name,
                    "pg_restore",
                    "--username",
                    admin_name,
                    "--port",
                    str(port),
                    "--dbname",
                    scratch_database,
                    # **`--no-owner --no-privileges`를 쓰지 않는다.** 그 둘은 소유권과
                    # ACL을 벗겨내므로, 붙인 채로는 "복원본이 원본과 같은 소유권을
                    # 갖는가"를 **구조적으로 물을 수 없다** — 리허설이 증명하는 것이
                    # "행이 들어갔다"에 그치게 된다. scratch DB는 원본과 **같은
                    # 인스턴스** 안에 만들므로 dump가 참조하는 role은 전부 실재한다.
                    # `--exit-on-error`가 남아 있어 GRANT 하나만 실패해도 시끄럽게
                    # 죽는다 — 조용히 반쯤 복원된 DB를 통과시키지 않는다.
                    "--exit-on-error",
                    container_dump_path,
                ],
                label=f"{role} rehearsal pg_restore",
                timeout=timeout,
            )
            restore_succeeded = returncode == 0
            if not restore_succeeded:
                findings.append(
                    RestorePlanFinding(
                        "REHEARSAL_RESTORE_FAILED",
                        f"scratch DB로의 pg_restore가 실패했습니다(exit {returncode}): "
                        f"{stderr.decode('utf-8', 'replace')[:2000]}",
                        True,
                    )
                )
            else:
                restored_db_size_bytes = _query_db_size(
                    container_name, port, admin_name, scratch_database
                )
                # **소유권·ACL이 살아남았는가.** 지금까지 리허설은 "pg_restore가
                # exit 0이고 head·크기가 말이 된다"까지만 봤다 — 그것은 행이
                # 들어갔다를 뜻하지, SECURITY DEFINER 소유자와 relation ACL이
                # 그대로라를 뜻하지 않는다. 복원이 "됐다"고 말하려면 그것까지 같아야
                # 한다(T-VN-M05-2 C단계).
                restored_catalog_digest = catalog_digest(
                    container_name, port, admin_name, scratch_database
                )
                live_catalog_digest = catalog_digest(
                    container_name, port, admin_name, _role_config(role)[1]
                )
                if restored_catalog_digest is None or live_catalog_digest is None:
                    findings.append(
                        RestorePlanFinding(
                            "REHEARSAL_CATALOG_UNKNOWN",
                            "카탈로그 지문을 읽지 못해 소유권·ACL이 복원됐는지 "
                            "확인할 수 없습니다. 읽지 못한 것은 통과가 아닙니다.",
                            False,
                        )
                    )
                elif restored_catalog_digest != live_catalog_digest:
                    findings.append(
                        RestorePlanFinding(
                            "REHEARSAL_CATALOG_DRIFT",
                            "복원된 DB의 소유권·ACL·routine 보안 속성이 현재 DB와 "
                            "다릅니다. 행은 들어갔더라도 그 상태로는 런타임이 "
                            "자기 표를 읽지 못할 수 있습니다.",
                            False,
                        )
                    )
                restored_alembic_head = _discover_alembic_head(
                    container_name, port, admin_name, scratch_database
                )
                if restored_alembic_head is None:
                    findings.append(
                        RestorePlanFinding(
                            "REHEARSAL_HEAD_UNKNOWN",
                            "복원된 scratch DB의 schema revision을 읽지 못했습니다.",
                            False,
                        )
                    )
                elif (
                    plan.manifest.alembic_head is not None
                    and restored_alembic_head != plan.manifest.alembic_head
                ):
                    findings.append(
                        RestorePlanFinding(
                            "REHEARSAL_HEAD_MISMATCH",
                            f"복원된 schema revision({restored_alembic_head})이 manifest"
                            f"({plan.manifest.alembic_head})과 다릅니다 — pg_restore는 "
                            "끝났지만 내용이 기대와 다를 수 있습니다.",
                            True,
                        )
                    )
                if restored_db_size_bytes == 0:
                    findings.append(
                        RestorePlanFinding(
                            "REHEARSAL_EMPTY_DATABASE",
                            "복원된 scratch DB의 크기가 0바이트입니다 — 실제로 데이터가 "
                            "들어가지 않았을 수 있습니다.",
                            True,
                        )
                    )
                elif (
                    plan.manifest.db_size_bytes > 0
                    and restored_db_size_bytes
                    < plan.manifest.db_size_bytes * _REHEARSAL_SIZE_SHORTFALL_RATIO
                ):
                    # 갓 만든 빈 DB도 카탈로그만으로 몇 MB이므로 위 "0바이트" 판정은
                    # 실제로는 거의 걸리지 않는다 — 백업 시점 크기 대비 비율로 봐야
                    # TOC가 일부만 적용된 부분 복원을 실제로 잡는다.
                    findings.append(
                        RestorePlanFinding(
                            "REHEARSAL_SIZE_SHORTFALL",
                            f"복원된 크기({restored_db_size_bytes} bytes)가 백업 시점 크기"
                            f"({plan.manifest.db_size_bytes} bytes)의 "
                            f"{_REHEARSAL_SIZE_SHORTFALL_RATIO:.0%}에도 못 미칩니다 — "
                            "일부만 복원됐을 수 있습니다.",
                            True,
                        )
                    )
        finally:
            # 성공/실패와 무관하게 항상 지운다 — scratch 잔해가 다음 리허설과 이름이
            # 겹치거나 디스크를 잠식하면 안 된다. 정리 실패까지 예외로 새어 나가면
            # 원래 실패 사유가 가려지므로 여기서는 절대 raise하지 않지만, 조용히
            # 넘어가지는 않는다 — 못 지웠으면 findings에 남겨 다음 스윕(또는 운영자
            # 수동 개입)이 필요함을 알린다.
            subprocess.run(
                ["docker", "exec", container_name, "rm", "-f", container_dump_path],
                capture_output=True,
                check=False,
                timeout=30,
            )
            dropdb_result = subprocess.run(
                [
                    "docker",
                    "exec",
                    "--user",
                    "postgres",
                    container_name,
                    "dropdb",
                    "--username",
                    admin_name,
                    "--port",
                    str(port),
                    "--if-exists",
                    scratch_database,
                ],
                capture_output=True,
                check=False,
                timeout=60,
            )
            if dropdb_result.returncode != 0:
                findings.append(
                    RestorePlanFinding(
                        "REHEARSAL_CLEANUP_INCOMPLETE",
                        f"scratch DB({scratch_database}) 삭제가 실패했을 수 있습니다"
                        f"(dropdb exit {dropdb_result.returncode}). 다음 리허설이 "
                        f"{_REHEARSAL_STALE_AFTER_SECONDS // 3600}시간 뒤부터 자동으로 "
                        "정리를 시도하지만, 급하면 "
                        f"'DROP DATABASE \"{scratch_database}\"'를 직접 실행하세요.",
                        False,
                    )
                )

    duration_sec = round(time.monotonic() - started, 3)
    if stale_databases:
        findings.append(
            RestorePlanFinding(
                "STALE_REHEARSAL_DATABASES_CLEANED",
                f"이전 리허설이 남긴 오래된 scratch DB {len(stale_databases)}개를 "
                f"이번 실행 전에 정리했습니다: {', '.join(stale_databases)}.",
                False,
            )
        )
    if not findings:
        findings.append(
            RestorePlanFinding(
                "OK",
                "scratch DB 복원 리허설이 성공했고 schema revision·크기도 말이 됩니다.",
                False,
            )
        )

    return RehearsalOutcome(
        role=role,
        backup_filename=plan.backup_filename,
        plan=plan,
        attempted=True,
        restore_succeeded=restore_succeeded,
        scratch_database=scratch_database,
        restored_alembic_head=restored_alembic_head,
        restored_db_size_bytes=restored_db_size_bytes,
        duration_sec=duration_sec,
        findings=tuple(findings),
        restored_catalog_digest=restored_catalog_digest,
        live_catalog_digest=live_catalog_digest,
    )


def _role_config(role: BackupRole) -> tuple[str, str]:
    if role not in _ROLE_CONFIG:
        raise StandaloneBackupError(f"unknown backup role: {role}")
    container_env, container_default, database_name = _ROLE_CONFIG[role]
    container_name = container_default
    if container_env is not None:
        override = os.environ.get(container_env, "").strip()
        if override:
            container_name = override
    return container_name, database_name


@contextlib.contextmanager
def _role_lock(root: Path, *, label: str = "backup") -> Iterator[None]:
    """같은 role의 동시 백업 생성을 막는다 — 겹치면 두 pg_dump가 같은
    `container_tmp`/`dest_path`에 동시에 쓰면서 서로의 산출물을 덮어쓸 수 있다.

    lock 파일도 **산출물과 같은 mode 정책**을 따라야 한다. `0600`으로 고정하면 공유 그룹
    모드에서 처음 만든 쪽만 열 수 있고, 다른 쪽(UI가 먼저 만들었다면 cron)은 이후 영원히
    `EACCES`를 받는다 — 공유 디렉터리 기능 전체가 조용히 죽는다.

    `label`은 오류 문구에만 쓴다 — 리허설이 이 lock을 잡고 있을 때 cron backup이
    "another backup is already running"을 보면 실제로는 리허설과 부딪힌 것인데
    사람이 엉뚱한 백업 프로세스를 찾아 헤맨다.
    """

    policy = _artifact_mode_policy()
    lock_path = root / ".backup.lock"
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, policy.lock_mode)
    except OSError as exc:  # noqa: TRY302 - 아래에서 typed error로 바꾼다
        # 여기서 raw OSError가 새어 나가면 CLI가 traceback으로 죽는다 —
        # `_cmd_db_backup_create`는 StandaloneBackupError만 잡는다.
        raise StandaloneBackupError(
            f"backup lock cannot be opened: {lock_path} ({exc.strerror}). 공유 그룹 "
            f"모드라면 'sudo chgrp <group> {lock_path} && sudo chmod 0660 {lock_path}'로 "
            "기존 lock의 소유·권한을 맞추세요."
        ) from exc
    try:
        # `os.open`의 mode는 umask에 깎인다(0660 → 0640). 그러면 두 번째 프로세스가
        # `O_RDWR`로 열지 못해 공유가 깨지므로 명시적으로 다시 건다. 우리 소유가 아니면
        # 이미 상대가 정한 것이므로 조용히 넘어간다.
        try:
            os.fchmod(fd, policy.lock_mode)
        except OSError:
            pass
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise StandaloneBackupError(
                f"another {label} is already running for this role"
            ) from exc
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _resolve_backup_root(role: BackupRole, backup_root: Path | None) -> Path:
    if backup_root is not None:
        return backup_root
    base = os.environ.get("KTDM_BACKUP_ROOT", "").strip()
    root = Path(base) if base else Path.home() / "backups"
    return root / role


def backup_root_for_role(role: BackupRole, *, backup_root: Path | None = None) -> Path:
    """`role`의 백업 산출물 디렉터리 경로. off-box 동기화 등 이 모듈 밖에서
    같은 경로 해석 규칙(``KTDM_BACKUP_ROOT`` → ``~/backups`` fallback)이 필요할 때
    쓴다 — private 함수를 다른 모듈이 직접 가져오지 않게 한다."""

    return _resolve_backup_root(role, backup_root)


def _manifest_path(root: Path, backup_filename: str) -> Path:
    if not backup_filename.endswith(".dump"):
        raise StandaloneBackupError(f"backup filename is invalid: {backup_filename}")
    return root / f"{backup_filename[: -len('.dump')]}.manifest"


def _discover_port(container_name: str) -> int:
    """실행 인자의 `-p <port>`를 읽는다 — host network + 프로젝트별 포트라
    `.env` override 여부와 무관하게 항상 실제 listen 포트와 일치해야 한다."""

    if not _CONTAINER_NAME.fullmatch(container_name):
        raise StandaloneBackupError("container name is invalid")
    output = _run_checked(
        ["docker", "inspect", "--format", "{{json .Config.Cmd}}", container_name],
        label=f"{container_name} command introspection",
        timeout=30,
    )
    try:
        cmd = json.loads(output)
    except json.JSONDecodeError as exc:
        raise StandaloneBackupError(f"{container_name} command introspection is invalid") from exc
    if not isinstance(cmd, list):
        raise StandaloneBackupError(f"{container_name} command introspection is invalid")
    for index, token in enumerate(cmd):
        if token == "-p" and index + 1 < len(cmd):
            candidate = cmd[index + 1]
            if isinstance(candidate, str) and candidate.isdigit():
                return int(candidate)
    raise StandaloneBackupError(f"{container_name} does not declare an explicit -p port")


def _discover_admin_role(container_name: str) -> str:
    """superuser role 이름을 `.env` 변수명 추측 대신 살아있는 `Config.Env`에서 읽는다.

    `POSTGRES_USER`는 role 식별자일 뿐 비밀이 아니다 — `POSTGRES_PASSWORD`는
    절대 읽지 않는다(issue #178 이후 secret file로만 존재해 여기서 볼 수도 없다).
    """

    if not _CONTAINER_NAME.fullmatch(container_name):
        raise StandaloneBackupError("container name is invalid")
    output = _run_checked(
        [
            "docker",
            "inspect",
            "--format",
            "{{range .Config.Env}}{{println .}}{{end}}",
            container_name,
        ],
        label=f"{container_name} environment introspection",
        timeout=30,
    ).decode("utf-8", "replace")
    values = [
        line[len("POSTGRES_USER=") :]
        for line in output.splitlines()
        if line.startswith("POSTGRES_USER=")
    ]
    if len(values) != 1 or not _ROLE_NAME.fullmatch(values[0]):
        raise StandaloneBackupError(f"{container_name} POSTGRES_USER is missing or invalid")
    return values[0]


def _count_toc_entries(container_name: str, container_dump_path: str, *, timeout: int) -> int:
    """`pg_restore --list`의 TOC 항목 수 — 문서의 수동 baseline 검증과 같은 방식이다.

    dump가 실제로 복원 가능한 형태인지의 값싼 sanity check이기도 하다. 스키마·시퀀스·
    트리거를 포함한 전체 TOC 항목 수이지 테이블 수만이 아니다.
    """

    output = _run_checked(
        ["docker", "exec", container_name, "pg_restore", "--list", container_dump_path],
        label="backup TOC listing",
        timeout=timeout,
    ).decode("utf-8", "replace")
    return sum(
        1 for line in output.splitlines() if line.strip() and not line.lstrip().startswith(";")
    )


def _query_db_size(container_name: str, port: int, admin_name: str, database_name: str) -> int:
    if not _DATABASE_IDENTIFIER.fullmatch(database_name):
        raise StandaloneBackupError("database name is invalid")
    output = _run_checked(
        [
            "docker",
            "exec",
            "--user",
            "postgres",
            container_name,
            "psql",
            "--username",
            admin_name,
            "--port",
            str(port),
            "--dbname",
            "postgres",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command",
            f"SELECT pg_database_size('{database_name}')",
        ],
        label=f"{database_name} size query",
        timeout=30,
    ).decode("ascii", "replace").strip()
    if not output.isdigit():
        raise StandaloneBackupError(f"{database_name} size query returned an unexpected value")
    return int(output)


def _pg_dump_already_running(
    container_name: str, port: int, admin_name: str, database_name: str
) -> bool:
    """GM-13: role lock은 프로세스 재기동에서 살아남지 못한다 — fcntl lock은 그
    lock을 쥔 프로세스가 죽으면 커널이 즉시 풀어준다. 재기동 직후 같은 role을
    다시 시작하면 파일 lock은 비어 있어도 컨테이너 안 이전 pg_dump가 여전히
    돌고 있을 수 있다(`docker exec`는 timeout을 안쪽 프로세스로 전파하지 않는다).
    pg_dump는 기본적으로 `application_name`을 `pg_dump`로 설정하므로, 새 pg_dump를
    시작하기 전에 서버 쪽 `pg_stat_activity`를 직접 물어 이미 실행 중인지 확인한다."""

    if not _DATABASE_IDENTIFIER.fullmatch(database_name):
        raise StandaloneBackupError("database name is invalid")
    output = _run_checked(
        [
            "docker",
            "exec",
            "--user",
            "postgres",
            container_name,
            "psql",
            "--username",
            admin_name,
            "--port",
            str(port),
            "--dbname",
            "postgres",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command",
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'pg_dump' "
            f"AND datname = '{database_name}'",
        ],
        label=f"{database_name} pg_dump activity check",
        timeout=30,
    ).decode("ascii", "replace").strip()
    if not output.isdigit():
        raise StandaloneBackupError(
            f"{database_name} pg_dump activity check returned an unexpected value"
        )
    return int(output) > 0


#: 복원된 DB가 **원본과 같은 소유권·권한·routine 보안 속성**을 갖는지 재는 지문.
#:
#: 리허설은 지금까지 "pg_restore가 exit 0이고 alembic head와 크기가 말이 된다"까지만
#: 봤다. 그것은 **행이 들어갔다**를 뜻하지 소유권·ACL이 살아남았다를 뜻하지 않는다 —
#: SECURITY DEFINER 프로시저의 소유자가 바뀌면 그 프로시저는 다른 권한으로 돌고,
#: relation ACL이 비면 런타임이 자기 표를 못 읽는다. 복원이 "됐다"고 말하려면
#: 그것까지 같아야 한다.
#:
#: **role에 무관하다** — 특정 프로젝트의 relation 이름을 알지 않고 카탈로그를 그대로
#: 훑는다(Manager 범용성 유지).
#: `search_path`를 **고정한다.** `pg_get_function_identity_arguments()`는 세션의
#: `search_path`에 따라 타입을 `geometry`로도 `x_extension.geometry`로도 렌더링한다.
#: 운영 DB의 세션은 `x_extension`을 path에 갖고 scratch DB는 안 갖는 것이 기본이라,
#: 고정하지 않으면 **소유권·ACL이 완전히 같은데도** 지문이 달라진다 — n150 실측에서
#: PostGIS 함수 495건이 그 이유만으로 어긋났다(2026-09-08). 거짓 양성은 진짜 drift를
#: 덮으므로 없는 것보다 나쁘다.
_CATALOG_DIGEST_SQL = """
SET LOCAL search_path = pg_catalog;
SELECT string_agg(line, E'
' ORDER BY line) FROM (
    SELECT format('r|%s|%s|%s|%s|%s',
        n.nspname, c.relname, c.relkind,
        pg_get_userbyid(c.relowner),
        array_to_string(
            coalesce(
                c.relacl,
                acldefault(
                    (CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END)::"char",
                    c.relowner
                )
            )::text[],
            ','
        )
    ) AS line
    FROM pg_catalog.pg_class AS c
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
      AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
    UNION ALL
    SELECT format('f|%s|%s|%s|%s|%s|%s',
        n.nspname, p.proname,
        pg_catalog.pg_get_function_identity_arguments(p.oid),
        pg_get_userbyid(p.proowner), p.prosecdef,
        array_to_string(
            coalesce(p.proacl, acldefault('f'::"char", p.proowner))::text[], ','
        )
    )
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
    UNION ALL
    SELECT format('n|%s|%s|%s',
        n.nspname, pg_get_userbyid(n.nspowner),
        array_to_string(
            coalesce(n.nspacl, acldefault('n'::"char", n.nspowner))::text[], ','
        )
    )
    FROM pg_catalog.pg_namespace AS n
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
    UNION ALL
    SELECT format('e|%s|%s', extname, extversion)
    FROM pg_catalog.pg_extension
) AS catalog_line
"""


def catalog_digest(
    container_name: str, port: int, admin_name: str, database_name: str
) -> str | None:
    """카탈로그 지문을 읽는다. 읽지 못하면 `None`이고 **통과로 읽지 않는다.**"""

    completed = subprocess.run(  # noqa: S603
        [
            "docker",
            "exec",
            "--user",
            "postgres",
            container_name,
            "psql",
            "--username",
            admin_name,
            "--port",
            str(port),
            "--dbname",
            database_name,
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command",
            _CATALOG_DIGEST_SQL,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    if completed.returncode != 0:
        return None
    payload = completed.stdout.strip()
    if not payload:
        return None
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _discover_alembic_head(
    container_name: str, port: int, admin_name: str, database_name: str
) -> str | None:
    """alembic head를 best-effort로 읽는다 — 프로젝트마다 schema 위치가 달라
    (map/geo/concierge는 `public`, pinvi는 `app`) 실패해도 백업 자체는 막지 않는다."""

    for schema in _ALEMBIC_SCHEMA_CANDIDATES:
        completed = subprocess.run(
            [
                "docker",
                "exec",
                "--user",
                "postgres",
                container_name,
                "psql",
                "--username",
                admin_name,
                "--port",
                str(port),
                "--dbname",
                database_name,
                "--no-psqlrc",
                "--tuples-only",
                "--no-align",
                "--command",
                f'SELECT version_num FROM "{schema}"."alembic_version"',
            ],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0 or completed.stderr:
            continue
        lines = completed.stdout.decode("utf-8", "replace").strip().splitlines()
        if len(lines) == 1 and _SCHEMA_REVISION.fullmatch(lines[0]):
            return lines[0]
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """GM-10 후속: mkstemp+write+fsync+os.replace 인라인 반복을 정본
    ``atomic_write_bytes``로 옮겼다. hardlink나 교체 전 identity 재검사가 없는
    평범한 발행이라 그대로 옮겨진다. 옮기기 전에는 디렉터리 fsync가 아예 없었으므로
    (``dir_fsync`` 기본값 적용) durability만 더해질 뿐 기존 동작을 약화하지 않는다.
    발행 직후 호출자가 정책 mode로 다시 chmod하므로 여기서는 임시 파일 단계의
    보수적 기본값(``0o600``)만 준다.
    """

    atomic_write_bytes(path, data, mode=0o600)


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    atomic_write_json(path, payload, mode=0o600)


def _read_manifest(
    manifest_path: Path,
    *,
    expected_role: BackupRole | None = None,
) -> BackupManifest:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StandaloneBackupError(f"manifest is unreadable: {manifest_path.name}") from exc
    try:
        role = data["role"]
        created_at_unix = int(data["created_at_unix"])
        duration_sec = float(data["duration_sec"])
        byte_size = int(data["byte_size"])
        sha256 = str(data["sha256"])
        backup_filename = str(data["backup_filename"])
        instance = str(data["instance"])
        db_size_bytes = int(data["db_size_bytes"])
        toc_entry_count = int(data["toc_entry_count"])
        alembic_head = data["alembic_head"]
        if alembic_head is not None:
            alembic_head = str(alembic_head)
    except (KeyError, TypeError, ValueError) as exc:
        raise StandaloneBackupError(f"manifest is malformed: {manifest_path.name}") from exc
    if role not in _ROLE_CONFIG:
        raise StandaloneBackupError(f"manifest role is invalid: {manifest_path.name}")
    if not _FILENAME.fullmatch(backup_filename):
        raise StandaloneBackupError(f"manifest backup_filename is invalid: {manifest_path.name}")
    # manifest 내용이 **자기 파일 이름과 결박**되지 않으면, 손상되거나 손으로 편집된
    # manifest 하나가 gc로 하여금 전혀 다른(살아 있는) 백업을 지우게 만든다.
    # 정본은 파일 이름이므로 내용이 그와 다르면 그 manifest를 신뢰하지 않는다.
    if _manifest_path(manifest_path.parent, backup_filename).name != manifest_path.name:
        raise StandaloneBackupError(
            f"manifest backup_filename does not match its own file: {manifest_path.name}"
        )
    if expected_role is not None and role != expected_role:
        raise StandaloneBackupError(
            f"manifest role does not match the requested role: {manifest_path.name}"
        )
    return BackupManifest(
        role=role,
        created_at_unix=created_at_unix,
        duration_sec=duration_sec,
        byte_size=byte_size,
        sha256=sha256,
        backup_filename=backup_filename,
        instance=instance,
        db_size_bytes=db_size_bytes,
        toc_entry_count=toc_entry_count,
        alembic_head=alembic_head,
    )


def _run_checked(arguments: list[str], *, label: str, timeout: int) -> bytes:
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise StandaloneBackupError(f"{label} could not run") from exc
    if completed.returncode != 0 or completed.stderr:
        raise StandaloneBackupError(
            f"{label} failed (exit {completed.returncode}): "
            f"{completed.stderr.decode('utf-8', 'replace')[:2000]}"
        )
    if not isinstance(completed.stdout, bytes):
        raise StandaloneBackupError(f"{label} produced invalid output")
    return completed.stdout


def _run_pg_restore(arguments: list[str], *, label: str, timeout: int) -> tuple[int, bytes]:
    """`pg_restore`는 성공해도 stderr에 경고를 낼 수 있어 `_run_checked`의 엄격한
    "stderr가 있으면 실패" 판정을 쓰면 안 된다 — 실제 성패는 exit code로만 가른다.
    실행 자체가 안 됐거나 timeout이면(OSError/SubprocessError) 여전히 fail-close다.
    """

    try:
        completed = subprocess.run(arguments, capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise StandaloneBackupError(f"{label} could not run") from exc
    return completed.returncode, completed.stderr
