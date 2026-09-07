from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import Mock

import pytest

import kor_travel_docker_manager.services.standalone_backup as standalone_backup
from kor_travel_docker_manager.services.standalone_backup import (
    BACKUP_ROLES,
    StandaloneBackupError,
    StandaloneBackupInProgressError,
    create_standalone_backup,
    gc_standalone_backups,
    list_standalone_backups,
    list_standalone_backups_for_display,
    plan_standalone_restore,
    rehearse_standalone_restore,
)

_CMD_JSON = json.dumps(["postgres", "-p", "12500", "-c", "listen_addresses=127.0.0.1"]).encode(
    "utf-8"
)
_ENV_OUTPUT = b"POSTGRES_USER=addr\nPOSTGRES_DB=kor_travel_geo\n"
_TOC_OUTPUT = b";\n; Archive created ...\n;\n1; 2615 SCHEMA public\n2; 1259 TABLE t\n"


def _fake_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        standalone_backup,
        "time",
        Mock(time=Mock(return_value=1000.0), monotonic=Mock(side_effect=[500.0, 500.879])),
    )


def _happy_run_checked():
    def run_checked(arguments: list[str], *, label: str, timeout: int) -> bytes:
        if arguments[:2] == ["docker", "inspect"] and "Cmd" in arguments[3]:
            return _CMD_JSON
        if arguments[:2] == ["docker", "inspect"] and "Env" in arguments[3]:
            return _ENV_OUTPUT
        if "pg_stat_activity" in " ".join(arguments):
            return b"0\n"
        if arguments[:3] == ["docker", "exec", "--user"] and "pg_dump" in arguments:
            return b""
        if arguments[:2] == ["docker", "exec"] and "pg_restore" in arguments:
            return _TOC_OUTPUT
        if arguments[:2] == ["docker", "cp"]:
            Path(arguments[-1]).write_bytes(b"fake dump contents")
            return b""
        if "pg_database_size" in " ".join(arguments):
            return b"12345\n"
        raise AssertionError(f"unexpected _run_checked command: {arguments}")

    return run_checked


def _happy_subprocess_run():
    def run(arguments: list[str], **kwargs: object) -> Mock:
        if "alembic_version" in " ".join(arguments):
            return Mock(returncode=0, stderr=b"", stdout=b"0099_abcdef\n")
        if arguments[:2] == ["docker", "exec"] and "rm" in arguments:
            return Mock(returncode=0, stderr=b"", stdout=b"")
        raise AssertionError(f"unexpected subprocess.run command: {arguments}")

    return Mock(side_effect=run)


def test_create_standalone_backup_happy_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "geo"
    _fake_time(monkeypatch)
    run_checked = Mock(side_effect=_happy_run_checked())
    monkeypatch.setattr(standalone_backup, "_run_checked", run_checked)
    subprocess_run = _happy_subprocess_run()
    monkeypatch.setattr(standalone_backup.subprocess, "run", subprocess_run)

    manifest = create_standalone_backup("geo", backup_root=root)

    # exact argument lists, not just prefix/substring matches — a flag-order or
    # value-swap bug (wrong port/db/container) must fail this test.
    pg_dump_call = next(
        call for call in run_checked.call_args_list if "pg_dump" in call.args[0]
    )
    assert pg_dump_call.args[0] == [
        "docker",
        "exec",
        "--user",
        "postgres",
        "kor-travel-geo-postgres",
        "pg_dump",
        "--username",
        "addr",
        "--port",
        "12500",
        "--dbname",
        "kor_travel_geo",
        "--format=custom",
        "--compress=6",
        "--file",
        "/tmp/geo-1000.dump",
    ]
    toc_call = next(call for call in run_checked.call_args_list if "pg_restore" in call.args[0])
    assert toc_call.args[0] == [
        "docker",
        "exec",
        "kor-travel-geo-postgres",
        "pg_restore",
        "--list",
        "/tmp/geo-1000.dump",
    ]
    cp_call = next(call for call in run_checked.call_args_list if call.args[0][:2] == ["docker", "cp"])
    assert cp_call.args[0] == [
        "docker",
        "cp",
        "kor-travel-geo-postgres:/tmp/geo-1000.dump",
        str(root / ".geo-1000.dump.copying"),
    ]

    assert manifest.role == "geo"
    assert manifest.created_at_unix == 1000
    assert manifest.duration_sec == pytest.approx(0.879)
    assert manifest.backup_filename == "geo-1000.dump"
    assert manifest.byte_size == len(b"fake dump contents")
    assert manifest.instance == "kor-travel-geo-postgres:127.0.0.1:12500/kor_travel_geo"
    assert manifest.db_size_bytes == 12345
    assert manifest.toc_entry_count == 2
    assert manifest.alembic_head == "0099_abcdef"

    dump_path = root / manifest.backup_filename
    sha256_path = root / f"{manifest.backup_filename}.sha256"
    manifest_path = root / "geo-1000.manifest"
    assert dump_path.is_file()
    assert sha256_path.is_file()
    assert manifest_path.is_file()
    assert stat.S_IMODE(dump_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(sha256_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(root.stat().st_mode) == 0o700

    assert sha256_path.read_text(encoding="ascii") == f"{manifest.sha256}  geo-1000.dump\n"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert saved == manifest.to_json()

    cleanup_calls = [call for call in subprocess_run.call_args_list if "rm" in call.args[0]]
    assert len(cleanup_calls) == 1
    assert cleanup_calls[0].args[0][:2] == ["docker", "exec"]


def test_create_standalone_backup_rejects_unknown_role(tmp_path: Path) -> None:
    with pytest.raises(StandaloneBackupError, match="unknown backup role"):
        create_standalone_backup("unknown", backup_root=tmp_path)  # type: ignore[arg-type]


def test_create_standalone_backup_rejects_empty_dump_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "pinvi"

    def run_checked(arguments: list[str], *, label: str, timeout: int) -> bytes:
        if arguments[:2] == ["docker", "inspect"] and "Cmd" in arguments[3]:
            return json.dumps(["postgres", "-p", "12800"]).encode("utf-8")
        if arguments[:2] == ["docker", "inspect"] and "Env" in arguments[3]:
            return b"POSTGRES_USER=pinvi\n"
        if "pg_stat_activity" in " ".join(arguments):
            return b"0\n"
        if "pg_dump" in arguments:
            return b""
        if "pg_restore" in arguments:
            return _TOC_OUTPUT
        if arguments[:2] == ["docker", "cp"]:
            Path(arguments[-1]).write_bytes(b"")
            return b""
        raise AssertionError(f"unexpected command: {arguments}")

    monkeypatch.setattr(standalone_backup, "_run_checked", Mock(side_effect=run_checked))
    _fake_time(monkeypatch)
    monkeypatch.setattr(
        standalone_backup.subprocess, "run", Mock(return_value=Mock(returncode=0, stderr=b""))
    )

    with pytest.raises(StandaloneBackupError, match="empty file"):
        create_standalone_backup("pinvi", backup_root=root)
    assert not (root / "pinvi-1000.dump").exists()


def test_create_standalone_backup_attempts_container_cleanup_even_on_copy_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "map_application"

    def run_checked(arguments: list[str], *, label: str, timeout: int) -> bytes:
        if arguments[:2] == ["docker", "inspect"] and "Cmd" in arguments[3]:
            return json.dumps(["postgres", "-p", "12700"]).encode("utf-8")
        if arguments[:2] == ["docker", "inspect"] and "Env" in arguments[3]:
            return b"POSTGRES_USER=kor_travel_map\n"
        if "pg_stat_activity" in " ".join(arguments):
            return b"0\n"
        if "pg_dump" in arguments:
            return b""
        if "pg_restore" in arguments:
            return _TOC_OUTPUT
        if arguments[:2] == ["docker", "cp"]:
            Path(arguments[-1]).write_bytes(b"partial dump")
            raise StandaloneBackupError("copy-out failed")
        raise AssertionError(f"unexpected command: {arguments}")

    monkeypatch.setattr(standalone_backup, "_run_checked", Mock(side_effect=run_checked))
    _fake_time(monkeypatch)
    cleanup = Mock(return_value=Mock(returncode=0, stderr=b""))
    monkeypatch.setattr(standalone_backup.subprocess, "run", cleanup)

    with pytest.raises(StandaloneBackupError, match="copy-out failed"):
        create_standalone_backup("map_application", backup_root=root)
    cleanup.assert_called_once()
    assert not (root / ".map_application-1000.dump.copying").exists()
    assert not (root / "map_application-1000.dump").exists()


def test_create_standalone_backup_refuses_when_a_pg_dump_is_already_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """GM-13: role lock은 프로세스 재기동에서 살아남지 못한다 — 재기동 직후 같은
    role을 다시 시작했을 때 컨테이너 안에 이전 pg_dump가 여전히 돌고 있으면
    (pg_stat_activity로 확인) 새 pg_dump를 시작하지 않고 즉시 거부해야 한다."""

    root = tmp_path / "geo"

    def run_checked(arguments: list[str], *, label: str, timeout: int) -> bytes:
        if arguments[:2] == ["docker", "inspect"] and "Cmd" in arguments[3]:
            return _CMD_JSON
        if arguments[:2] == ["docker", "inspect"] and "Env" in arguments[3]:
            return _ENV_OUTPUT
        if "pg_stat_activity" in " ".join(arguments):
            return b"1\n"
        raise AssertionError(f"unexpected command after in-progress guard: {arguments}")

    monkeypatch.setattr(standalone_backup, "_run_checked", Mock(side_effect=run_checked))
    _fake_time(monkeypatch)
    subprocess_run = Mock(side_effect=AssertionError("pg_dump must not start"))
    monkeypatch.setattr(standalone_backup.subprocess, "run", subprocess_run)

    with pytest.raises(StandaloneBackupInProgressError, match="already running"):
        create_standalone_backup("geo", backup_root=root)
    subprocess_run.assert_not_called()
    assert not (root / "geo-1000.dump").exists()
    assert not (root / "geo-1000.manifest").exists()


def test_discover_port_parses_dash_p_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        standalone_backup,
        "_run_checked",
        Mock(return_value=json.dumps(["postgres", "-p", "12600", "-c", "x=1"]).encode()),
    )
    assert standalone_backup._discover_port("kor-travel-concierge-postgres") == 12600


def test_discover_port_rejects_missing_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        standalone_backup, "_run_checked", Mock(return_value=json.dumps(["postgres"]).encode())
    )
    with pytest.raises(StandaloneBackupError, match="does not declare an explicit -p port"):
        standalone_backup._discover_port("kor-travel-concierge-postgres")


def test_discover_admin_role_reads_postgres_user_only(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = Mock(return_value=b"POSTGRES_PASSWORD_FILE=/run/secrets/x\nPOSTGRES_USER=addr\n")
    monkeypatch.setattr(standalone_backup, "_run_checked", runner)

    assert standalone_backup._discover_admin_role("kor-travel-geo-postgres") == "addr"
    command = runner.call_args.args[0]
    assert "POSTGRES_PASSWORD" not in " ".join(command)


@pytest.mark.parametrize(
    "output", [b"", b"POSTGRES_USER=addr\nPOSTGRES_USER=other\n", b"POSTGRES_USER=bad-name\n"]
)
def test_discover_admin_role_rejects_missing_or_ambiguous_user(
    monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    monkeypatch.setattr(standalone_backup, "_run_checked", Mock(return_value=output))
    with pytest.raises(StandaloneBackupError, match="POSTGRES_USER"):
        standalone_backup._discover_admin_role("kor-travel-geo-postgres")


def test_discover_alembic_head_falls_back_to_second_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(arguments: list[str], **kwargs: object) -> Mock:
        if '"public"."alembic_version"' in " ".join(arguments):
            return Mock(returncode=1, stderr=b"relation does not exist", stdout=b"")
        if '"app"."alembic_version"' in " ".join(arguments):
            return Mock(returncode=0, stderr=b"", stdout=b"0007_pinvi_head\n")
        raise AssertionError(arguments)

    monkeypatch.setattr(standalone_backup.subprocess, "run", Mock(side_effect=run))

    head = standalone_backup._discover_alembic_head("pinvi-postgres", 12800, "pinvi", "pinvi")

    assert head == "0007_pinvi_head"


def test_discover_alembic_head_returns_none_when_no_schema_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        standalone_backup.subprocess,
        "run",
        Mock(return_value=Mock(returncode=1, stderr=b"nope", stdout=b"")),
    )

    head = standalone_backup._discover_alembic_head(
        "kor-travel-concierge-postgres", 12600, "addr", "kor_travel_concierge"
    )

    assert head is None


def test_list_standalone_backups_sorted_by_created_at(tmp_path: Path) -> None:
    root = tmp_path / "pinvi"
    root.mkdir()
    for created_at, name in [(2000, "pinvi-2000.dump"), (1000, "pinvi-1000.dump")]:
        (root / name.replace(".dump", ".manifest")).write_text(
            json.dumps(_manifest_payload("pinvi", created_at, name)),
            encoding="utf-8",
        )

    manifests = list_standalone_backups("pinvi", backup_root=root)

    assert [m.created_at_unix for m in manifests] == [1000, 2000]


def test_list_standalone_backups_empty_when_root_missing(tmp_path: Path) -> None:
    assert list_standalone_backups("geo", backup_root=tmp_path / "does-not-exist") == []


def test_list_standalone_backups_for_display_degrades_a_single_corrupt_manifest(
    tmp_path: Path,
) -> None:
    """GM-13: manifest 하나가 손상돼도(여기서는 role 불일치) 나머지 정상 manifest는
    여전히 보이고, 손상된 것은 예외 대신 {"state": "unreadable", ...} 행이 된다."""

    root = tmp_path / "geo"
    root.mkdir()
    (root / "geo-1000.manifest").write_text(
        json.dumps(_manifest_payload("geo", 1000, "geo-1000.dump")), encoding="utf-8"
    )
    # role 불일치 — map 세트가 geo 디렉터리에 잘못 복사된 것과 같은 실제 사고를 재현.
    (root / "geo-999.manifest").write_text(
        json.dumps(_manifest_payload("map_application", 999, "geo-999.dump")),
        encoding="utf-8",
    )

    rows = list_standalone_backups_for_display("geo", backup_root=root)

    assert len(rows) == 2
    assert rows[0]["backup_filename"] == "geo-1000.dump"
    assert rows[1]["state"] == "unreadable"
    assert rows[1]["filename"] == "geo-999.manifest"
    assert "role does not match" in rows[1]["reason"]


def test_list_standalone_backups_for_display_empty_when_root_missing(tmp_path: Path) -> None:
    assert (
        list_standalone_backups_for_display("geo", backup_root=tmp_path / "does-not-exist")
        == []
    )


def test_list_standalone_backups_for_display_all_corrupt_returns_no_readable_rows(
    tmp_path: Path,
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    (root / "geo-1.manifest").write_text("not json", encoding="utf-8")

    rows = list_standalone_backups_for_display("geo", backup_root=root)

    assert rows == [
        {
            "state": "unreadable",
            "filename": "geo-1.manifest",
            "reason": "manifest is unreadable: geo-1.manifest",
        }
    ]


def test_list_standalone_backups_for_display_raises_when_the_directory_itself_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """디렉터리 자체를 못 읽는 것(권한 문제 등)은 개별 manifest 손상과 성격이 다르다
    — 이건 여전히 fail-close다(라우트가 503로 옮긴다). drvfs 마운트에서는 실제
    chmod 권한 거부가 재현되지 않을 수 있어(conftest.py 참고) glob 자체를
    OSError로 monkeypatch해 결정적으로 재현한다."""

    root = tmp_path / "geo"
    root.mkdir()

    def raising_glob(self: Path, pattern: str):
        if self == root:
            raise OSError("Permission denied")
        return []

    monkeypatch.setattr(standalone_backup.Path, "glob", raising_glob)

    with pytest.raises(StandaloneBackupError, match="unreadable"):
        list_standalone_backups_for_display("geo", backup_root=root)


def test_list_standalone_backups_rejects_malformed_manifest(tmp_path: Path) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    (root / "geo-1.manifest").write_text("{}", encoding="utf-8")
    with pytest.raises(StandaloneBackupError, match="malformed"):
        list_standalone_backups("geo", backup_root=root)


def test_gc_standalone_backups_keeps_newest_and_deletes_rest(tmp_path: Path) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    for created_at in (1000, 2000, 3000):
        name = f"geo-{created_at}.dump"
        (root / name).write_bytes(b"x")
        (root / f"{name}.sha256").write_text("deadbeef  " + name, encoding="ascii")
        (root / name.replace(".dump", ".manifest")).write_text(
            json.dumps(_manifest_payload("geo", created_at, name)), encoding="utf-8"
        )

    outcome = gc_standalone_backups("geo", keep=1, backup_root=root)

    assert outcome.deleted == ("geo-1000.dump", "geo-2000.dump")
    assert outcome.orphans_removed == ()
    remaining = {p.name for p in root.iterdir()}
    assert remaining == {
        "geo-3000.dump",
        "geo-3000.dump.sha256",
        "geo-3000.manifest",
        # gc가 create와 같은 role lock을 잡으므로 lock 파일이 남는다.
        ".backup.lock",
    }


def test_gc_standalone_backups_noop_when_within_keep(tmp_path: Path) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    name = "geo-1000.dump"
    (root / name).write_bytes(b"x")
    (root / name.replace(".dump", ".manifest")).write_text(
        json.dumps(_manifest_payload("geo", 1000, name)), encoding="utf-8"
    )

    assert gc_standalone_backups("geo", keep=5, backup_root=root).total == 0


def test_gc_standalone_backups_keeps_all_when_keep_equals_count(tmp_path: Path) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    for created_at in (1000, 2000, 3000):
        name = f"geo-{created_at}.dump"
        (root / name).write_bytes(b"x")
        (root / name.replace(".dump", ".manifest")).write_text(
            json.dumps(_manifest_payload("geo", created_at, name)), encoding="utf-8"
        )

    assert gc_standalone_backups("geo", keep=3, backup_root=root).total == 0
    assert {p.stem for p in root.glob("*.manifest")} == {"geo-1000", "geo-2000", "geo-3000"}


def test_gc_standalone_backups_rejects_keep_below_one(tmp_path: Path) -> None:
    with pytest.raises(StandaloneBackupError, match="keep must be at least 1"):
        gc_standalone_backups("geo", keep=0, backup_root=tmp_path)


def test_discover_port_rejects_invalid_container_name(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = Mock()
    monkeypatch.setattr(standalone_backup, "_run_checked", runner)
    with pytest.raises(StandaloneBackupError, match="container name is invalid"):
        standalone_backup._discover_port("../etc/passwd")
    runner.assert_not_called()


def test_discover_admin_role_rejects_invalid_container_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = Mock()
    monkeypatch.setattr(standalone_backup, "_run_checked", runner)
    with pytest.raises(StandaloneBackupError, match="container name is invalid"):
        standalone_backup._discover_admin_role("$(rm -rf /)")
    runner.assert_not_called()


def test_query_db_size_rejects_invalid_database_name() -> None:
    with pytest.raises(StandaloneBackupError, match="database name is invalid"):
        standalone_backup._query_db_size("kor-travel-geo-postgres", 12500, "addr", "'; DROP")


def test_query_db_size_parses_digit_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(standalone_backup, "_run_checked", Mock(return_value=b"98765\n"))
    assert (
        standalone_backup._query_db_size("kor-travel-geo-postgres", 12500, "addr", "kor_travel_geo")
        == 98765
    )


def test_role_lock_rejects_concurrent_acquisition(tmp_path: Path) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    with standalone_backup._role_lock(root):
        with pytest.raises(StandaloneBackupError, match="already running"):
            with standalone_backup._role_lock(root):
                pass  # pragma: no cover - must not be reached


def test_role_lock_releases_after_context_exits(tmp_path: Path) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    with standalone_backup._role_lock(root):
        pass
    with standalone_backup._role_lock(root):
        pass  # second acquisition succeeds once the first has released


@pytest.mark.parametrize(
    ("role", "env_var", "expected"),
    [
        ("concierge", "KOR_TRAVEL_CONCIERGE_POSTGRES_CONTAINER", "concierge-override"),
        ("map_application", "KOR_TRAVEL_MAP_POSTGRES_CONTAINER", "map-override"),
        ("pinvi", "PINVI_POSTGRES_CONTAINER", "pinvi-override"),
    ],
)
def test_role_config_respects_container_name_override(
    monkeypatch: pytest.MonkeyPatch, role: str, env_var: str, expected: str
) -> None:
    monkeypatch.setenv(env_var, expected)
    container_name, _ = standalone_backup._role_config(role)
    assert container_name == expected


def test_role_config_geo_ignores_env_since_compose_hardcodes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KOR_TRAVEL_GEO_POSTGRES_CONTAINER", "should-be-ignored")
    container_name, _ = standalone_backup._role_config("geo")
    assert container_name == "kor-travel-geo-postgres"


def test_backup_roles_cover_four_instances() -> None:
    assert set(BACKUP_ROLES) == {
        "geo",
        "geo_dagster",
        "concierge",
        "map_application",
        "map_dagster",
        "pinvi",
    }


# --- 복원 계획(KUM-M13, 읽기 전용) --------------------------------------------
#
# 이 블록의 요점: 목록에 백업이 보이는 것과 그 백업으로 복원할 수 있는 것은 다르다.
# dump가 잘려 있어도, digest가 어긋나도, live schema가 백업 시점과 달라도 목록은
# 똑같이 초록색이다. 계획은 그 거짓 안전감을 걷어내야 하고, **아무것도 바꾸지 않아야**
# 한다.


def _seed_backup(root: Path, role: str, created_at: int, body: bytes) -> str:
    import hashlib

    name = f"{role}-{created_at}.dump"
    (root / name).write_bytes(body)
    payload = _manifest_payload(role, created_at, name)
    payload["byte_size"] = len(body)
    payload["sha256"] = hashlib.sha256(body).hexdigest()
    (root / f"{role}-{created_at}.manifest").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    return name


def _plan_probes(monkeypatch: pytest.MonkeyPatch, *, live_head: str | None) -> None:
    monkeypatch.setattr(standalone_backup, "_discover_port", lambda name: 12500)
    monkeypatch.setattr(standalone_backup, "_discover_admin_role", lambda name: "addr")
    monkeypatch.setattr(
        standalone_backup,
        "_discover_alembic_head",
        lambda *args, **kwargs: live_head,
    )


def test_restore_plan_confirms_a_healthy_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _plan_probes(monkeypatch, live_head="0001_head")
    before = {path.name: path.read_bytes() for path in root.iterdir()}

    plan = plan_standalone_restore("geo", backup_root=root)

    assert plan.restorable is True
    assert plan.backup_filename == "geo-1000.dump"
    assert plan.live_alembic_head == "0001_head"
    assert plan.containers == ("kor-travel-geo-postgres",)
    # 계획은 아무것도 바꾸지 않는다.
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before


def test_restore_plan_picks_the_newest_backup_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"old")
    _seed_backup(root, "geo", 3000, b"new")
    _plan_probes(monkeypatch, live_head="0001_head")

    assert plan_standalone_restore("geo", backup_root=root).backup_filename == (
        "geo-3000.dump"
    )
    assert plan_standalone_restore(
        "geo", backup_filename="geo-1000.dump", backup_root=root
    ).backup_filename == "geo-1000.dump"


def test_restore_plan_recomputes_the_digest_rather_than_trusting_the_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """manifest에 적힌 값을 그대로 믿으면 이 점검은 아무것도 검증하지 않는다."""

    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    # dump만 조용히 바뀐 상태 — 크기는 같고 내용이 다르다.
    (root / "geo-1000.dump").write_bytes(b"dump-BYTES")
    _plan_probes(monkeypatch, live_head="0001_head")

    plan = plan_standalone_restore("geo", backup_root=root)

    assert plan.restorable is False
    assert [f.code for f in plan.findings if f.blocking] == ["SHA256_MISMATCH"]


def test_restore_plan_blocks_a_truncated_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    (root / "geo-1000.dump").write_bytes(b"dump")
    _plan_probes(monkeypatch, live_head="0001_head")

    plan = plan_standalone_restore("geo", backup_root=root)

    assert plan.restorable is False
    assert "SIZE_MISMATCH" in [f.code for f in plan.findings]


def test_restore_plan_blocks_when_the_dump_is_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    (root / "geo-1000.dump").unlink()
    _plan_probes(monkeypatch, live_head="0001_head")

    plan = plan_standalone_restore("geo", backup_root=root)

    assert plan.restorable is False
    assert [f.code for f in plan.findings if f.blocking] == ["DUMP_MISSING"]


def test_a_schema_revision_drift_is_reported_but_does_not_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """복원 자체는 가능하다 — 다만 코드가 기대하는 schema보다 과거로 간다는 사실을
    모르고 실행하면 안 된다. 판단은 사람이 한다."""

    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _plan_probes(monkeypatch, live_head="0007_much_later")

    plan = plan_standalone_restore("geo", backup_root=root)

    assert plan.restorable is True
    drift = [f for f in plan.findings if f.code == "HEAD_MISMATCH"]
    assert drift and drift[0].blocking is False
    assert "0007_much_later" in drift[0].text


def test_an_unreadable_live_head_is_reported_not_assumed_equal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _plan_probes(monkeypatch, live_head=None)

    plan = plan_standalone_restore("geo", backup_root=root)

    assert "LIVE_HEAD_UNKNOWN" in [f.code for f in plan.findings]


def test_restore_plan_blocks_when_the_instance_cannot_be_inspected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")

    def explode(name: str) -> int:
        raise StandaloneBackupError("container is not running")

    monkeypatch.setattr(standalone_backup, "_discover_port", explode)

    plan = plan_standalone_restore("geo", backup_root=root)

    assert plan.restorable is False
    assert [f.code for f in plan.findings if f.blocking] == ["INSTANCE_UNREACHABLE"]
    assert plan.containers == ()


def test_restore_plan_refuses_an_unknown_backup_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _plan_probes(monkeypatch, live_head="0001_head")

    with pytest.raises(StandaloneBackupError, match="no backup named"):
        plan_standalone_restore("geo", backup_filename="geo-9999.dump", backup_root=root)
    with pytest.raises(StandaloneBackupError, match="invalid"):
        plan_standalone_restore("geo", backup_filename="../etc/passwd", backup_root=root)


def test_restore_plan_refuses_when_there_is_nothing_to_restore(tmp_path: Path) -> None:
    root = tmp_path / "geo"
    root.mkdir()

    with pytest.raises(StandaloneBackupError, match="no backup"):
        plan_standalone_restore("geo", backup_root=root)


def _manifest_payload(role: str, created_at: int, backup_filename: str) -> dict[str, object]:
    return {
        "role": role,
        "created_at_unix": created_at,
        "duration_sec": 1.0,
        "byte_size": 10,
        "sha256": "a" * 64,
        "backup_filename": backup_filename,
        "instance": "container:127.0.0.1:12345/db",
        "db_size_bytes": 100,
        "toc_entry_count": 2,
        "alembic_head": "0001_head",
    }


def test_gc_binds_manifest_content_to_its_own_filename(tmp_path: Path) -> None:
    """손상된 manifest 하나가 살아 있는 다른 백업을 지우게 하면 안 된다.

    이전에는 gc가 삭제 대상을 manifest **내용**의 `backup_filename`에서 가져왔고
    그 값이 자기 파일 이름과 같은지 확인하지 않았다. 그래서 `geo-1000.manifest`의
    내용을 `geo-3000.dump`로 바꿔 두면 최신 백업이 지워졌다.
    """

    root = tmp_path / "geo"
    root.mkdir()
    for created_at in (1000, 3000):
        name = f"geo-{created_at}.dump"
        (root / name).write_bytes(b"x")
        (root / name.replace(".dump", ".manifest")).write_text(
            json.dumps(_manifest_payload("geo", created_at, name)), encoding="utf-8"
        )
    # 내용만 최신 백업을 가리키게 바꾼다.
    (root / "geo-1000.manifest").write_text(
        json.dumps(_manifest_payload("geo", 1000, "geo-3000.dump")), encoding="utf-8"
    )

    with pytest.raises(StandaloneBackupError, match="does not match its own file"):
        gc_standalone_backups("geo", keep=1, backup_root=root)

    assert (root / "geo-3000.dump").exists()


def test_gc_rejects_a_manifest_belonging_to_another_role(tmp_path: Path) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    name = "geo-1000.dump"
    (root / name).write_bytes(b"x")
    (root / "geo-1000.manifest").write_text(
        json.dumps(_manifest_payload("pinvi", 1000, name)), encoding="utf-8"
    )

    with pytest.raises(StandaloneBackupError, match="does not match the requested role"):
        list_standalone_backups("geo", backup_root=root)


def test_gc_collects_orphan_dumps_left_by_an_interrupted_backup(tmp_path: Path) -> None:
    """manifest 없는 dump는 목록에도 안 잡히고 복원할 수도 없어 영원히 쌓였다."""

    root = tmp_path / "geo"
    root.mkdir()
    name = "geo-3000.dump"
    (root / name).write_bytes(b"x")
    (root / name.replace(".dump", ".manifest")).write_text(
        json.dumps(_manifest_payload("geo", 3000, name)), encoding="utf-8"
    )
    # 중단된 create가 남긴 잔해: dump와 sha256만 있고 manifest가 없다.
    (root / "geo-1000.dump").write_bytes(b"orphan")
    (root / "geo-1000.dump.sha256").write_text("deadbeef  geo-1000.dump", encoding="ascii")

    outcome = gc_standalone_backups("geo", keep=5, backup_root=root)

    assert outcome.deleted == ()
    assert outcome.orphans_removed == ("geo-1000.dump",)
    assert not (root / "geo-1000.dump").exists()
    assert not (root / "geo-1000.dump.sha256").exists()
    # 정상 백업은 keep 안에 있으므로 그대로다.
    assert (root / "geo-3000.dump").exists()


def test_gc_refuses_while_a_backup_holds_the_role_lock(tmp_path: Path) -> None:
    """gc가 락을 잡지 않으면 진행 중인 백업(geo는 20분 이상)의 산출물을 지운다."""

    import fcntl as _fcntl

    root = tmp_path / "geo"
    root.mkdir()
    lock_path = root / ".backup.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        with pytest.raises(StandaloneBackupError, match="already running"):
            gc_standalone_backups("geo", keep=1, backup_root=root)
    finally:
        _fcntl.flock(fd, _fcntl.LOCK_UN)
        os.close(fd)


# --- 공유 그룹(setgid) 모드 — 적대 리뷰 2건이 각각 다른 각도로 찾은 결함 -------


def _shared_group_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """`2770` setgid 루트를 만들고 정책을 그 그룹으로 고정한다."""

    root = tmp_path / "backups"
    root.mkdir()
    gid = os.stat(root).st_gid
    monkeypatch.setenv(standalone_backup.BACKUP_SHARED_GROUP_ENV, str(gid))
    os.chmod(root, 0o2770)
    return root


def test_a_new_role_directory_gets_the_shared_mode_not_the_umask_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """setgid 부모 아래 mkdir은 그룹과 setgid만 상속하고 permission 비트는 umask가 정한다.

    그 사실을 놓치면 `2770` 부모 아래 자식이 `2755`가 되어 그 role의 **첫 백업**이
    항상 거부된다 — 하필 cron이 건드리지 않아 UI로만 만드는 role들이다.
    """

    root = _shared_group_root(tmp_path, monkeypatch)
    policy = standalone_backup._artifact_mode_policy()
    assert policy.shared_gid is not None

    role_root = root / "geo"
    standalone_backup._prepare_backup_root(role_root, policy)

    mode = stat.S_IMODE(role_root.lstat().st_mode)
    assert mode & 0o070 == 0o070, f"group bits missing: {mode:04o}"
    assert role_root.lstat().st_mode & stat.S_ISGID


def test_the_role_lock_follows_the_shared_mode_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """lock을 `0600`으로 고정하면 처음 만든 쪽만 열 수 있어 공유가 조용히 끝난다."""

    root = _shared_group_root(tmp_path, monkeypatch)
    role_root = root / "geo"
    standalone_backup._prepare_backup_root(
        role_root, standalone_backup._artifact_mode_policy()
    )

    with standalone_backup._role_lock(role_root):
        pass

    mode = stat.S_IMODE((role_root / ".backup.lock").lstat().st_mode)
    assert mode & 0o060 == 0o060, f"lock is not group-accessible: {mode:04o}"


def test_an_unopenable_role_lock_is_a_typed_error_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI는 StandaloneBackupError만 잡는다 — raw OSError는 traceback으로 죽는다."""

    root = tmp_path / "geo"
    root.mkdir()

    def refuse(*args: object, **kwargs: object) -> int:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(standalone_backup.os, "open", refuse)

    with pytest.raises(StandaloneBackupError, match="backup lock cannot be opened"):
        with standalone_backup._role_lock(root):
            pass


def test_the_shared_group_recovery_message_has_no_placeholder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """붙여넣어서 그대로 도는 명령이어야 한다 — `<group>`은 실행되지 않는다."""

    root = _shared_group_root(tmp_path, monkeypatch)
    role_root = root / "geo"
    role_root.mkdir(mode=0o755)
    os.chmod(role_root, 0o755)

    with pytest.raises(StandaloneBackupError) as caught:
        standalone_backup._prepare_backup_root(
            role_root, standalone_backup._artifact_mode_policy()
        )

    message = str(caught.value)
    assert "<group>" not in message
    # 파일까지 2770으로 만들라고 하지 않는다 — 0640 정책과 어긋난다.
    assert "chmod -R 2770" not in message


def test_restore_plan_turns_a_vanishing_dump_into_a_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """gc가 lock을 잡고 지우는 사이일 수 있다 — traceback 대신 판정을 내야 한다."""

    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _plan_probes(monkeypatch, live_head="0001_head")

    def vanish(path: Path) -> str:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(standalone_backup, "_sha256_file", vanish)

    plan = plan_standalone_restore("geo", backup_root=root)

    assert plan.restorable is False
    assert "DUMP_UNREADABLE" in [f.code for f in plan.findings]


# --- 복원 리허설(GM-07, scratch DB만 건드림) -----------------------------------
#
# 이 블록의 요점: 운영 DB로 덮어쓰는 파괴적 복원은 여전히 없다(오너가 로드맵 뒤로
# 미룸). 여기서 증명하는 것은 "이 백업이 scratch DB에 실제로 복원된다"는 사실뿐이고,
# scratch DB는 성공/실패와 무관하게 항상 지워야 한다.


#: 마지막 리허설이 실제로 낸 명령 순서. 순서 게이트가 읽는다 — 소유권 이양이
#: copy-in 뒤·pg_restore 앞에 있어야 하고, 그 위치는 값이 아니라 **순서**다.
REHEARSAL_COMMANDS: list[list[str]] = []


def _rehearsal_probes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pg_restore_returncode: int = 0,
    pg_restore_stderr: bytes = b"",
    restored_head: str | None = "0001_head",
    restored_size: int = 12345,
) -> list[list[str]]:
    """createdb/pg_restore/cleanup을 가짜로 응답하고, cleanup 호출을 기록한다."""

    monkeypatch.setattr(standalone_backup, "_discover_port", lambda name: 12500)
    monkeypatch.setattr(standalone_backup, "_discover_admin_role", lambda name: "addr")
    monkeypatch.setattr(standalone_backup, "_query_db_size", lambda *a, **k: restored_size)
    monkeypatch.setattr(
        standalone_backup, "_discover_alembic_head", lambda *a, **k: restored_head
    )
    # 오래된 scratch DB 스윕은 별도 테스트에서 다룬다 — 여기서는 항상 없다고 답한다.
    monkeypatch.setattr(
        standalone_backup, "_drop_stale_rehearsal_databases", lambda *a, **k: ()
    )

    REHEARSAL_COMMANDS.clear()

    def run_checked(arguments: list[str], *, label: str, timeout: int) -> bytes:
        REHEARSAL_COMMANDS.append(list(arguments))
        if arguments[:2] == ["docker", "cp"]:
            return b""
        if "chown" in arguments:
            return b""
        if "createdb" in arguments:
            return b""
        raise AssertionError(f"unexpected _run_checked command in rehearsal: {arguments}")

    monkeypatch.setattr(standalone_backup, "_run_checked", run_checked)

    def run_pg_restore(arguments: list[str], *, label: str, timeout: int) -> tuple[int, bytes]:
        assert "pg_restore" in arguments
        REHEARSAL_COMMANDS.append(list(arguments))
        return pg_restore_returncode, pg_restore_stderr

    monkeypatch.setattr(standalone_backup, "_run_pg_restore", run_pg_restore)

    cleanup_calls: list[list[str]] = []

    def fake_subprocess_run(arguments: list[str], **kwargs: object) -> Mock:
        cleanup_calls.append(arguments)
        return Mock(returncode=0, stderr=b"", stdout=b"")

    monkeypatch.setattr(standalone_backup.subprocess, "run", fake_subprocess_run)
    return cleanup_calls


def test_rehearse_standalone_restore_confirms_a_healthy_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    cleanup_calls = _rehearsal_probes(monkeypatch, restored_head="0001_head")

    outcome = rehearse_standalone_restore("geo", backup_root=root)

    assert outcome.attempted is True
    assert outcome.restore_succeeded is True
    assert outcome.verified is True
    assert outcome.restored_alembic_head == "0001_head"
    assert outcome.restored_db_size_bytes == 12345
    assert outcome.scratch_database is not None
    # scratch DB는 항상 지운다 — dropdb가 실제로 호출됐는지 확인한다.
    assert any("dropdb" in call for call in cleanup_calls)
    assert any("rm" in call for call in cleanup_calls)


def test_rehearse_restore_hands_the_dump_over_before_restoring_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """복원 전에 dump의 소유권을 복원 유저에게 넘긴다.

    `docker cp`는 host 파일의 소유권·권한을 **그대로 보존한다.** 백업은 root:root
    0600이고 pg_restore는 컨테이너 안 postgres(uid 999)로 도므로, 넘겨주지 않으면
    자기가 복원할 파일을 읽지 못한다. 2026-09-07 n150 실측:

        pg_restore: error: could not open input file
        "/tmp/rehearsal-....dump": Permission denied

    모든 백업이 root 0600이라 이 명령은 그전까지 한 번도 성공한 적이 없다 — 그래서
    `T-VN-H49-{GEO-DAGSTER,CONCIERGE,PINVI}`의 마지막 조건이 닫히지 못하고 있었다.

    결박하는 것은 **순서**다. chown이 copy-in 뒤·pg_restore 앞에 있지 않으면 아무
    의미가 없다.
    """
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _rehearsal_probes(monkeypatch, restored_head="0001_head")

    rehearse_standalone_restore("geo", backup_root=root)

    kinds = [
        "cp"
        if command[:2] == ["docker", "cp"]
        else next((token for token in ("chown", "createdb", "pg_restore") if token in command), "?")
        for command in REHEARSAL_COMMANDS
    ]
    assert "cp" in kinds and "chown" in kinds and "pg_restore" in kinds, kinds
    assert kinds.index("cp") < kinds.index("chown") < kinds.index("pg_restore"), kinds

    chown = REHEARSAL_COMMANDS[kinds.index("chown")]
    restore = REHEARSAL_COMMANDS[kinds.index("pg_restore")]
    # chown 대상 경로 == pg_restore가 읽는 경로.
    assert chown[-1] == restore[-1]
    # 소유자는 복원을 실행하는 그 유저다 — 둘이 갈라지면 결박이 없는 것과 같다.
    exec_user = standalone_backup._REHEARSAL_EXEC_USER
    assert chown[-2] == f"{exec_user}:{exec_user}"
    assert restore[restore.index("--user") + 1] == exec_user
    # chown 자체는 root로 돈다 — 컨테이너 기본 유저로는 소유권을 넘길 수 없다.
    assert chown[chown.index("--user") + 1] == "root"


def test_rehearse_standalone_restore_skips_the_attempt_when_the_plan_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """무결성이 깨진 dump를 scratch DB에라도 복원 시도하는 것은 낭비다."""

    root = tmp_path / "geo"
    root.mkdir()
    # dump 파일 자체가 없다 — plan이 DUMP_MISSING으로 차단한다. 이 probe는
    # plan_standalone_restore 자신의 정당한 live-schema 조회만 허용한다.
    payload = _manifest_payload("geo", 1000, "geo-1000.dump")
    (root / "geo-1000.manifest").write_text(json.dumps(payload), encoding="utf-8")
    _plan_probes(monkeypatch, live_head="0001_head")

    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("복원 계획이 차단됐으면 pg_restore를 시도하면 안 된다")

    monkeypatch.setattr(standalone_backup, "_run_pg_restore", fail_if_called)

    outcome = rehearse_standalone_restore("geo", backup_root=root)

    assert outcome.attempted is False
    assert outcome.verified is False
    assert outcome.plan.restorable is False


def test_rehearse_standalone_restore_reports_a_failed_pg_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    cleanup_calls = _rehearsal_probes(
        monkeypatch, pg_restore_returncode=1, pg_restore_stderr=b"boom"
    )

    outcome = rehearse_standalone_restore("geo", backup_root=root)

    assert outcome.attempted is True
    assert outcome.restore_succeeded is False
    assert outcome.verified is False
    assert "REHEARSAL_RESTORE_FAILED" in [f.code for f in outcome.findings]
    assert any(f.blocking for f in outcome.findings)
    # 실패해도 scratch DB 정리는 여전히 시도한다.
    assert any("dropdb" in call for call in cleanup_calls)


def test_rehearse_standalone_restore_flags_a_schema_mismatch_after_a_successful_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pg_restore가 exit 0으로 끝나도 복원된 내용이 manifest와 다르면 검증 실패다."""

    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _rehearsal_probes(monkeypatch, restored_head="9999_other_head")

    outcome = rehearse_standalone_restore("geo", backup_root=root)

    assert outcome.restore_succeeded is True
    assert outcome.verified is False
    assert "REHEARSAL_HEAD_MISMATCH" in [f.code for f in outcome.findings]


def test_rehearse_standalone_restore_always_drops_the_scratch_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cleanup은 try 블록의 예외 여부와 무관하게 실행돼야 한다(finally)."""

    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    monkeypatch.setattr(standalone_backup, "_discover_port", lambda name: 12500)
    monkeypatch.setattr(standalone_backup, "_discover_admin_role", lambda name: "addr")

    def run_checked(arguments: list[str], *, label: str, timeout: int) -> bytes:
        if arguments[:2] == ["docker", "cp"]:
            return b""
        raise StandaloneBackupError("createdb exploded")

    monkeypatch.setattr(standalone_backup, "_run_checked", run_checked)

    cleanup_calls: list[list[str]] = []

    def fake_subprocess_run(arguments: list[str], **kwargs: object) -> Mock:
        cleanup_calls.append(arguments)
        return Mock(returncode=0, stderr=b"", stdout=b"")

    monkeypatch.setattr(standalone_backup.subprocess, "run", fake_subprocess_run)

    with pytest.raises(StandaloneBackupError):
        rehearse_standalone_restore("geo", backup_root=root)

    assert any("dropdb" in call for call in cleanup_calls)


def test_rehearse_standalone_restore_generates_a_unique_scratch_database_name_per_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """같은 초에 두 번 불러도 이름이 겹치면 안 된다 — geo/geo_dagster처럼 컨테이너를
    공유하는 role 쌍이 동시에 리허설하면 한쪽 dropdb가 다른 쪽의 진행 중인 scratch
    DB를 지울 수 있었다."""

    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _rehearsal_probes(monkeypatch)
    monkeypatch.setattr(standalone_backup.time, "time", lambda: 1000.0)

    first = rehearse_standalone_restore("geo", backup_root=root)
    second = rehearse_standalone_restore("geo", backup_root=root)

    assert first.scratch_database != second.scratch_database
    assert first.scratch_database.startswith("ktdm_rehearsal_1000_")


def test_rehearse_standalone_restore_flags_a_size_shortfall_short_of_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """복원된 크기가 0은 아니어도 백업 시점 크기의 절반에 못 미치면 부분 복원을 의심한다.

    갓 만든 빈 DB도 카탈로그만으로 몇 MB라 순수 0바이트 판정은 현실에서 거의 걸리지
    않는다 — manifest 크기 대비 비율로 봐야 실제로 잡는다.
    """

    root = tmp_path / "geo"
    root.mkdir()
    # _manifest_payload의 db_size_bytes == 100.
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _rehearsal_probes(monkeypatch, restored_size=10)

    outcome = rehearse_standalone_restore("geo", backup_root=root)

    assert outcome.restore_succeeded is True
    assert outcome.verified is False
    assert "REHEARSAL_SIZE_SHORTFALL" in [f.code for f in outcome.findings]
    assert "REHEARSAL_EMPTY_DATABASE" not in [f.code for f in outcome.findings]


def test_rehearse_standalone_restore_surfaces_a_cleanup_failure_without_hiding_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """dropdb 정리가 실패해도 예외로 삼키지 않고 findings에 남긴다 — 그래야 잔해가
    생겼다는 사실이 조용히 사라지지 않는다. 복원 자체는 성공했으므로 verified는 유지한다.
    """

    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    monkeypatch.setattr(standalone_backup, "_discover_port", lambda name: 12500)
    monkeypatch.setattr(standalone_backup, "_discover_admin_role", lambda name: "addr")
    monkeypatch.setattr(standalone_backup, "_query_db_size", lambda *a, **k: 12345)
    monkeypatch.setattr(standalone_backup, "_discover_alembic_head", lambda *a, **k: "0001_head")
    monkeypatch.setattr(
        standalone_backup, "_drop_stale_rehearsal_databases", lambda *a, **k: ()
    )

    def run_checked(arguments: list[str], *, label: str, timeout: int) -> bytes:
        return b""

    monkeypatch.setattr(standalone_backup, "_run_checked", run_checked)
    monkeypatch.setattr(
        standalone_backup, "_run_pg_restore", lambda *a, **k: (0, b"")
    )

    def fake_subprocess_run(arguments: list[str], **kwargs: object) -> Mock:
        if "dropdb" in arguments:
            return Mock(returncode=1, stderr=b"still has active connections", stdout=b"")
        return Mock(returncode=0, stderr=b"", stdout=b"")

    monkeypatch.setattr(standalone_backup.subprocess, "run", fake_subprocess_run)

    outcome = rehearse_standalone_restore("geo", backup_root=root)

    assert outcome.restore_succeeded is True
    assert outcome.verified is True
    assert "REHEARSAL_CLEANUP_INCOMPLETE" in [f.code for f in outcome.findings]


def test_drop_stale_rehearsal_databases_removes_only_databases_older_than_the_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 1_000_000.0
    stale_epoch = int(now) - standalone_backup._REHEARSAL_STALE_AFTER_SECONDS - 1
    fresh_epoch = int(now) - 10
    listing = (
        f"ktdm_rehearsal_{stale_epoch}_aaaa\n"
        f"ktdm_rehearsal_{fresh_epoch}_bbbb\n"
        "\n"
    ).encode()

    monkeypatch.setattr(standalone_backup.time, "time", lambda: now)

    def run_checked(arguments: list[str], *, label: str, timeout: int) -> bytes:
        assert "pg_database" in " ".join(arguments)
        return listing

    monkeypatch.setattr(standalone_backup, "_run_checked", run_checked)

    dropped_names: list[str] = []

    def fake_subprocess_run(arguments: list[str], **kwargs: object) -> Mock:
        if "dropdb" in arguments:
            dropped_names.append(arguments[-1])
        return Mock(returncode=0, stderr=b"", stdout=b"")

    monkeypatch.setattr(standalone_backup.subprocess, "run", fake_subprocess_run)

    dropped = standalone_backup._drop_stale_rehearsal_databases(
        "kor-travel-geo-postgres", 12500, "addr"
    )

    assert dropped == (f"ktdm_rehearsal_{stale_epoch}_aaaa",)
    assert dropped_names == [f"ktdm_rehearsal_{stale_epoch}_aaaa"]


def test_rehearse_standalone_restore_reports_swept_stale_databases_as_a_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "geo"
    root.mkdir()
    _seed_backup(root, "geo", 1000, b"dump-bytes")
    _rehearsal_probes(monkeypatch)
    monkeypatch.setattr(
        standalone_backup,
        "_drop_stale_rehearsal_databases",
        lambda *a, **k: ("ktdm_rehearsal_1_aaaa",),
    )

    outcome = rehearse_standalone_restore("geo", backup_root=root)

    assert "STALE_REHEARSAL_DATABASES_CLEANED" in [f.code for f in outcome.findings]
    assert outcome.verified is True
