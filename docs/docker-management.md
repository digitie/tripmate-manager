# Docker 관리 설계

이 문서는 `kor-travel-docker-manager`가 Portainer와 유사한 Docker 관리 경험을 제공하되, Kor Travel/PinVi 개발 및 로컬 운영에 필요한 범위로 제한하는 기준을 정리한다.

---

## 1. 목표

`kor-travel-docker-manager`는 불특정 다수에게 노출되는 범용 Docker 콘솔이 아니다. 목적은 `pinvi`, `kor-travel-concierge`, `kor-travel-map`, `kor-travel-geo`가 의존하는 공용 Docker 인프라와 앱 컨테이너를 한 곳에서 확인하고 실행하는 것이다.

- 의존 Docker가 꺼져 있으면 UI, API, CLI에서 즉시 실행한다.
- 개발환경에서는 필요한 경우 `docker compose up -d --build`로 빌드 후 실행한다.
- UI에서 상태, 포트, 리소스, 로그, compose 설정, Docker inspect 핵심 정보를 확인한다.
- 컨테이너 파라미터는 `docker-compose.yml`을 source of truth로 저장하되, credential 값은 `.env` override로 둔다.
- `DESIGN.md`와 `frontend/tokens.css`의 Hallmark Cobalt 토큰, 밝은 Workbench 표면, 얕은 그림자와 절제된 상태색을 관리 대시보드에 적용한다.
- dev 기본 네트워크는 Docker host 모드(`KTDM_DOCKER_NETWORK_MODE=host`)이며, 각 컨테이너는 호스트 정규 포트에 직접 바인딩한다.
- 운영(prod) 공개 주소는 저장소에 커밋하지 않고 gitignore된 `.env`(`KTDM_PROD_URL_*`)에만 두며, registry/대시보드가 이를 읽어 컨테이너별 공개 URL을 표시한다.

---

## 2. 현재 코드 수준

| 영역 | 현재 상태 | 보완 기준 |
|---|---|---|
| 상태 조회 | `GET /api/v1/containers`, WebSocket `/api/v1/ws/status` 구현 | target 단위 상태와 container inspect를 UI에 연결 |
| 제어 | `start`, `stop`, `restart` 구현 | target 단위 `ensure`와 개발환경 `--build` 지원 |
| 로그 | REST 최근 로그, WebSocket 실시간 로그 구현 | CLI `logs`와 UI 상세 패널에서 동일한 대상 기준 사용 |
| 메트릭 | CPU, 메모리, I/O 10초 수집 및 30일 보관 | 컨테이너 상세 화면에서 최근 추세와 현재값 동시 표시 |
| 설정 변경 | compose의 ports, env, volumes, networks 저장 및 재생성 구현 | 입력 검증, secret redaction, 변경 전 diff 표시 |
| CLI | `ktdctl` Python CLI 추가 | 다른 Kor Travel/PinVi 프로젝트에서 의존 Docker 실행용으로 사용 |
| 문서 | DB 모델과 CLI/API target 기준 정리 | 대시보드 상세 패널 구현 시 화면 문서 추가 |

### WebSocket 종료 코드 계약 (C7)

거절은 반드시 handshake(101)를 먼저 완료한 뒤 application close frame으로 전달한다. accept
이전에 close하면 ASGI 규약상 handshake 거절이 되어 uvicorn이 HTTP 403으로 바꿔 보내고,
브라우저 WebSocket API는 4401 대신 1006(빈 reason, `wasClean=false`)만 본다.

| 상황 | 서버 동작 | 브라우저 관측 |
|---|---|---|
| 미인증 · 세션 만료/폐기 · 허용되지 않은 Origin | accept(101) → data frame 0건 → `close(4401, "AUTH_REQUIRED")` | `code=4401`, `wasClean=true` |
| 알 수 없는 `container_id` (`/ws/logs`) | accept(101) → data frame 0건 → `close(4000, "INVALID_CONTAINER_ID")` | `code=4000` |
| 인가 동시성 상한 초과 | accept(101) → data frame 0건 → `close(1013, "TRY_AGAIN_LATER")` | `code=1013` |
| 연결 유지 중 세션 만료/폐기 (`/ws/status`·`/ws/logs` 모두 60초 주기 재검증) | `close(4401)` | `code=4401` |
| docker 접근/스트림 실패 | `{"error": ...}` 1건 → `close(1011)` | `code=1011` |
| 로그 스트림 EOF | `{"error": "로그 스트림이 종료되었습니다."}` → `close(1000)` | `code=1000` |
| 정상 종료 | `close(1000)` | `code=1000` |

- accept가 실패하면 close를 보내지 않는다(다시 pre-handshake 거절로 퇴화한다).
- accept(101)과 close frame 사이 settle 대기는 `KTDM_WS_ACCEPT_CLOSE_SETTLE_SECONDS`로
  조절한다(clamp 범위 `[0, 5]`). ASGI에는 transport drain acknowledgement가 없어 두 write가
  한 TCP 세그먼트로 합쳐지면 프록시 엣지가 close frame을 잘라 브라우저가 1006으로 뭉갤 수
  있다. **기본값 `0.0`은 실측으로 정했다** — 운영 HAProxy TLS 엣지를 경유한 실제 Chromium에서
  `0.25` 10/10, `0.0` 12/12 모두 `code=4401, wasClean=true, data frame 0건`이었고 1006은 한 번도
  나오지 않았다(거절 왕복 264~791ms → 79~373ms). uvicorn 0.28.1의 legacy `websockets_impl`이
  `websocket.close`를 `handshake_completed_event` 뒤에 처리해 서버 단에서 이미 직렬화되기
  때문이다. Map(`T-VN-H11`)이 `0.25`를 쓴 것은 `websockets-sansio` 구현이라 수치가 그대로
  이식되지 않는다. **uvicorn ws 구현이나 프록시 토폴로지를 바꾸면 반드시 재측정한다.**
- 클라이언트는 4401을 종단 상태로 취급하고 재연결하지 않는다. 4401을 소비하지 않으면
  서버 수정은 관측되지 않는다.
- 클라이언트는 서버의 첫 프레임 이전에 소켓에 쓰지 않는다. `onopen`에서 optimistic하게
  보내면 거절 close와 동시 close가 되어 프록시가 RST로 close frame을 자른다.
  `ws_status`의 `receive()`는 keepalive를 허용하지만, 추가한다면 첫 서버 프레임 이후에만 보낸다.
- 재검증 시점은 monotonic deadline에 고정한다. `asyncio.wait`의 timeout을 그대로 쓰면
  프레임이 올 때마다 창이 리셋돼, keepalive를 주기보다 자주 보내는 client가 logout·TTL
  만료를 무한히 우회한다.
- 미인증 peer도 handshake를 완료하게 되므로 거절 경로의 close는 peer의 close echo를
  오래 기다리지 않는다(`_REJECT_CLOSE_TIMEOUT_SECONDS`).
- **인가 동시성 상한**: 동시에 인가(Origin+세션 쿠키 검증) 처리 중인 handshake를
  `KTDM_WS_MAX_PENDING_AUTHORIZATIONS`(기본 `64`, clamp `[1, 10000]`, **프로세스당**)로
  묶고, 초과분은 `1013`으로 흘려보낸다.
  - **이 상한이 묶는 것**: `to_thread` dispatch와 동시 인가 handshake 수, 그리고 유효
    서명 쿠키를 가진 peer에 한해 executor queue 깊이.
  - **묶지 않는 것**: fd, uvicorn protocol 객체, ASGI task, accept/close 소켓 수명.
    flood에서 실제로 고갈되는 자원은 이쪽이므로 이 상한을 DoS 완화로 과신하면 안 된다.
  - 미인증 peer는 **SQLite에 도달하지 못한다**. `validate_session_cookie`는 쿠키가 없으면
    session을 열기 전에 `None`을 돌려주고, DB SELECT는 HMAC 서명 검증 뒤에 있다
    (측정: 미인증 경로 DB session 0건, 호출당 0.2~2.6us). "거절마다 DB 조회가 잡힌다"는
    근거로 이 값을 튜닝하지 말 것.
  - shed 로그는 **상태 진입/해제에서만** 남긴다. 거절 1건마다 기록하면 attacker가 제어하는
    동기 디스크 write가 되어 shed 경로가 완화하려던 경로보다 비싸진다(측정: 거절당
    1039~1207us → 로그 제거 시 57~62us, 4401 경로 285~313us).
  - **per-IP 제한은 쓰지 않는다.** 이 배포의 공개 트래픽은 전부 리버스 프록시 IP 하나로
    도착하고(신뢰 프록시 CIDR이 loopback 전용이라 `X-Forwarded-For`를 신뢰하지 않는다),
    per-IP 버킷은 인터넷 전체를 한 키에 묶어 정상 관리자까지 함께 막는다. per-IP로
    가려면 **먼저** `KTDM_TRUSTED_PROXY_CIDRS`에 프록시 IP를 추가해야 한다(필수 조건).
    `KTDM_TRUSTED_PROXY_SECRET`는 loopback 위조를 막는 추가 방어이지 활성화 스위치가 아니다.
  - **전체 동시 연결 수는 uvicorn `--limit-concurrency`로 막을 수 없다.** h11 구현이
    WebSocket upgrade를 503 검사 **이전에** return하기 때문이다(0.28.1
    `h11_impl.py:221-230`). 연결 수 제한은 프록시에서 건다(HAProxy `maxconn`,
    stick-table 연결률 제한).
- TestClient는 pre-accept close와 accept-then-close를 모두 같은 `WebSocketDisconnect(4401)`로
  보고하므로 계약 회귀는 `backend/tests/test_ws_contract.py`의 ASGI 메시지 시퀀스로 고정한다.

현재 registry가 관리하는 런타임 컨테이너는 다음 21개다. dev 기본 네트워크는 host 모드(`KTDM_DOCKER_NETWORK_MODE=host`)이며, 포트 NAT가 없으므로 각 컨테이너는 호스트 정규 포트에 직접 바인딩한다(컨테이너 내부 포트 = 호스트 포트). 서비스 간 참조는 `127.0.0.1:<포트>`를 사용한다.

| 컨테이너 ID | Docker 컨테이너 | 역할 | 포트(host=container) |
|---|---|---|---|
| `kor-travel-geo-postgresql` | `kor-travel-geo-postgres` | Kor Travel Geo 전용 PostgreSQL / PostGIS (`kor_travel_geo`, `kor_travel_geo_dagster`) | `12500` |
| `kor-travel-concierge-postgresql` | `kor-travel-concierge-postgres` | Kor Travel Concierge 전용 (`kor_travel_concierge`) | `12600` |
| `pinvi-postgresql` | `pinvi-postgres` | PinVi 전용 (`pinvi`) | `12800` |
| `rustfs` | `kor-travel-rustfs` | Kor Travel/PinVi 계열 미디어 및 원천 데이터용 S3 호환 오브젝트 스토리지 | `12101`, `12105` |
| `grafana` | `kor-travel-grafana` | 다른 앱과도 공통 연계하는 Grafana 시각화 도구 | `12205` |
| `cadvisor` | `kor-travel-cadvisor` | Docker 컨테이너 리소스 메트릭을 노출하는 cAdvisor Exporter | `12301` |
| `prometheus` | `kor-travel-prometheus` | cAdvisor Exporter와 앱 메트릭을 수집하고 저장하는 Prometheus | `12401` |
| `kor-travel-geo-api` | `kor-travel-geo-api-latest` | `kor-travel-geo` REST API | `12501` |
| `kor-travel-geo-ui` | `kor-travel-geo-ui-latest` | `kor-travel-geo` admin Web UI | `12505` |
| `kor-travel-concierge-api` | `kor-travel-concierge-api-latest` | `kor-travel-concierge` API | `12601` |
| `kor-travel-concierge-mcp` | `kor-travel-concierge-mcp-latest` | `kor-travel-concierge` MCP HTTP | `12602` |
| `kor-travel-concierge-scheduler` | `kor-travel-concierge-scheduler-latest` | `kor-travel-concierge` scheduler | 내부 실행 |
| `kor-travel-concierge-ui` | `kor-travel-concierge-ui-latest` | `kor-travel-concierge` Web UI | `12605` |
| `kor-travel-map-postgresql` | `kor-travel-map-postgres` | Map application·Dagster metadata 전용 PostgreSQL / PostGIS | `12700` |
| `kor-travel-map-api` | `kor-travel-map-api-latest` | `kor-travel-map` admin API | `12701` |
| `kor-travel-map-dagster` | `kor-travel-map-dagster-latest` | `kor-travel-map` Dagster Webserver | `12702` |
| `kor-travel-map-dagster-daemon` | `kor-travel-map-dagster-daemon-latest` | `kor-travel-map` Dagster daemon | 내부 실행 |
| `kor-travel-map-ui` | `kor-travel-map-ui-latest` | `kor-travel-map` admin Web UI | `12705` |
| `pinvi-api` | `pinvi-api-latest` | PinVi API | `12801` |
| `pinvi-dagster` | `pinvi-dagster-latest` | PinVi Dagster Webserver (`apps/etl/Dockerfile`, code location `pinvi.etl.definitions`, `DAGSTER_HOME=/opt/pinvi/.dagster`) | `12802` |
| `pinvi-web` | `pinvi-web-latest` | PinVi Web UI | `12805` |

---

## 3. 설정 파일 기반 target 모델

UI/API/CLI는 Docker service 이름을 직접 외우지 않고 앱 관점 target을 사용한다. 공식 target 정의와 의존 관계는 `config/docker-targets.yml`에서 읽는다. 의존 관계는 각 target의 `depends_on`으로 표현되는 **DAG**이며, `ktdctl <target>`은 해당 target의 transitive 의존 폐포를 위상정렬 순서로 실행한다(`dependency_order`는 표시/결정적 정렬용 linearization).

```text
db -> storage -> gra -> cadv -> prom ─┬─ geo ──┐
                                      └─ conc ──┴─> map -> pinvi
```

핵심 의존: `geo`와 `conc`는 모두 `prom`에만 의존하며 서로 독립이다(**concierge는 geo에 의존하지 않는다**). `map`은 `geo`와 `conc` 모두에 의존하고, `pinvi`는 `map`에 의존한다. 예를 들어 `ktdctl conc`는 `db, storage, gra, cadv, prom, conc`만 실행하고(geo 제외), `ktdctl map`은 `db, storage, gra, cadv, prom, geo, conc, map`을 실행한다. 새 의존성은 `targets.<id>.depends_on`으로 선언한다.

**`docker-targets.yml` 편집 후 재기동 전 검증(GM-11, docker-targets.yml 스키마 검증
잔여로 갱신)**: `registry.load_targets_config()`는 컨테이너 필수 필드·`depends_on`/
`include`/`containers`/`dependency_order`의 참조 무결성·alias 충돌을 fail-close로
검증한다. `MANAGED_CONTAINERS`/`MANAGED_TARGETS`/`TARGET_ALIASES`(registry.py:187-191)는
이제 최초 실제 접근(구독·순회·`in`·`.items()`) 시점에만 이 검증을 실행하는 지연
`Mapping`이다 — 예전에는 이 계산이 모듈 import 시점의 top-level 코드였어서, `ktdctl`은
`--help`조차 argparse가 뜨기도 전에 raw traceback으로 죽었고 **backend(FastAPI)
프로세스 자체의 기동**도 막았다. 지금은 두 프로세스 다 config가 깨져 있어도 뜨는 것
자체는 막지 않는다 — backend는 대신 매 metrics 수집 tick(10초 간격)과 실제 target/
container 조회가 필요한 요청에서 같은 오류를 계속 관측 가능하게 다시 낸다(조용히
사라지지 않는다).

그래도 오타 하나가 서비스 재기동 직후 일부 기능 저하로 이어질 수 있으므로, 편집 후
재기동하기 **전에** 미리 검증하는 습관은 그대로 유지한다. 정식 인터페이스는 CLI
서브커맨드다:

```bash
KOR_TRAVEL_DOCKER_MANAGER_TARGETS_FILE=/path/to/edited/docker-targets.yml ktdctl targets validate
```

exit 0 + `OK`면 안전하게 배포본에 반영하고 재기동한다. exit 1이면 출력된
`{파일} targets.<id>.<필드>: ...` 메시지가 고칠 위치를 정확히 짚는다. `ktdctl`이 아직
설치되지 않은 환경에서는 예전과 같은 python 한 줄로도 동일하게 검증할 수 있다(무거운
`cli.py`/`compose_service.py` import 체인을 타지 않는 `registry.py` 단독 import라
안전하다):

```bash
KOR_TRAVEL_DOCKER_MANAGER_TARGETS_FILE=/path/to/edited/docker-targets.yml \
  <venv>/bin/python -c \
  'from kor_travel_docker_manager.services.registry import load_targets_config; load_targets_config(); print("OK")'
```

| 공식 별칭 | 의미 | 누적 실행 범위 | 대표 별칭 |
|---|---|---|---|
| `db` | Kor Travel Geo DB | geo 전용 PostgreSQL/PostGIS(:12500) 실행 및 DB/extension/schema grant 복구. 다른 프로젝트 DB는 각 target이 소유한다(ADR-37) | `postgresql`, `postgres`, `database` |
| `storage` | 통합 RustFS | `db` + RustFS 실행 및 bucket 복구 | `rustfs`, `s3`, `object-storage` |
| `gra` | 공용 Grafana | `storage` + Grafana Web UI 실행 | `grafana`, `dashboard`, `visualization` |
| `cadv` | cAdvisor Exporter | `gra` + cAdvisor Exporter 실행 | `cadvisor`, `exporter`, `metrics-exporter` |
| `prom` | Prometheus | `cadv` + Prometheus 실행 | `prometheus`, `metrics`, `monitoring` |
| `geo` | 지오코더/리버스지오코더 | `prom` + `kor-travel-geo` API/Web UI 실행 + 원천 데이터 적재 검증 | `kor-travel-geo`, `geocoder`, `reverse-geocoder` |
| `conc` | Kor Travel Concierge | `prom` + `kor-travel-concierge` API/MCP/Scheduler/Web UI 실행 (geo 비의존) | `kor-travel-concierge`, `concierge`, `agent` |
| `map` | Kor Travel Map | `geo`+`conc` + `kor-travel-map` API/Dagster/Web UI 실행 | `kor-travel-map`, `krtour-map`, `python-krtour-map` |
| `pinvi` | PinVi | `map` + PinVi API/Dagster/Web UI 실행 | `srv`, `main`, `pinvi` |
| `all` | 전체 | `db`부터 `pinvi`까지 전체 순서 | `default` |

`geo` 이후 앱 target은 모두 실제 앱 컨테이너를 이 저장소 compose에서 빌드하고 실행한다. `main`은 독립 target이 아니라 `pinvi`의 호환 별칭이며, 새 자동화에서는 짧은 별칭 `srv`를 사용한다.

로컬 host 포트는 `docs/ports.md`의 정책을 따른다. `db` 대역 `12000-12099`는 폐지된 통합 instance의 자리라 비어 있다 — PostgreSQL은 프로젝트마다 전용 instance이고 포트는 각 대역의 `x00`(`12500`/`12600`/`12700`/`12800`, ADR-37)이다. `storage` 대역의 RustFS는 S3 API `12101`, console `12105`를 사용한다. `gra`는 Grafana `12205`, `cadv`는 cAdvisor `12301`, `prom`은 Prometheus `12401`을 사용한다. `geo` 대역의 `kor-travel-geo`는 API `12501`, Web UI `12505`를 사용한다. `conc` 대역은 `12601`/`12602`/`12605`, `map` 대역은 `12701`/`12702`/`12705`, `pinvi` 대역은 `12801`(API)/`12802`(Dagster)/`12805`(Web)를 사용한다. `kor-travel-docker-manager` 자체 Backend API와 Dashboard Web은 dependency 변화에 흔들리지 않도록 `12901`, `12905`를 사용한다.

### 3.1 `.env` 완전성 — 한 target만 써도 전체 필수 변수가 다 있어야 한다

`docker compose`는 요청한 서비스와 무관하게 파일 전체를 interpolate한 뒤에야 대상을
고른다 — 즉 `up gra`(Grafana, 자체 필수 변수 0개) 한 줄도 Map/PinVi처럼 전혀 무관한
target의 `${VAR:?...}` 하나가 `.env`에 없으면 그 자리에서 그대로 실패한다. Compose
profile로도 피할 수 없다(비활성 profile의 서비스도 interpolate 대상이다 — 실측
확인). 새 worktree/새 개발 환경에서 `.env`를 `.env.example`에서 막 복사했다면, 실제로
쓸 target만 값이 있어도 다른 target들의 `:?` 변수가 전부 비어 있어 **아무 target도**
못 띄운다. `docker compose config --quiet`로 먼저 전체 파일이 interpolate되는지
확인하고, 안 쓸 target들은 값의 정합성이 필요 없으니 placeholder로만 채워도 된다.

---

## 4. 초기화 및 복구 흐름

`ensure`는 `docker compose up -d` 후 target 순서에 맞춰 idempotent 초기화 단계를 실행한다.

| 단계 | 실행 조건 | 스크립트 | 역할 |
|---|---|---|---|
| DB 복구 | `db` 이상 | `scripts/ensure-kor-travel-geo-db.sh` | Geo 전용 PostgreSQL readiness 대기, `kor_travel_geo` database와 PostGIS/pg_stat_statements/schema grant만 보정. 다른 프로젝트의 role·database는 건드리지 않음 |
| RustFS 복구 | `storage` 이상 | `scripts/ensure-rustfs-buckets.sh` | RustFS health 대기 후 `pinvi-media`, `kor-travel-geo`, `kor-travel-concierge`, `krtour-map`, `krtour-uploads` bucket 생성 |
| Geo 원천 검증 | `geo` 이상 | `scripts/verify-kor-travel-geo-source.sh` | `/data/juso` 마운트와 `load_manifest`, `tl_juso_text`, `mv_geocode_target` 적재 상태 확인 |

`geo` target은 compose에서 `kor-travel-geo-api`, `kor-travel-geo-ui`를 실행하고, dev 기본 host 네트워크에서 API 컨테이너는 `127.0.0.1:12500`(geo 전용 PostgreSQL)과 `127.0.0.1:12101`(RustFS)을 사용한다. 대시보드와 CLI는 registry에 등록된 컨테이너 이름(`kor-travel-geo-api-latest`, `kor-travel-geo-ui-latest`)을 같은 Docker 대상으로 사용한다.

`geo` 검증은 원천 DB가 비어 있거나 핵심 테이블이 없으면 기본적으로 실패한다. 전체 적재는 무겁고 `kor-travel-geo`의 도메인 로더가 책임지는 작업이므로, manager는 자동 전체 적재 대신 명확한 실패 메시지와 복구 지침을 출력한다. 비어 있는 DB를 의도적으로 허용해야 하는 경우에만 `.env`에서 `KOR_TRAVEL_GEO_STRICT_SOURCE_CHECK=0`으로 낮춘다.

---

## 5. 공개 인터페이스

### 5.1 CLI

정식 CLI는 백엔드 패키지의 console script인 `ktdctl`이다. 짧은 별칭은 곧바로 `ensure`로 해석된다.

```bash
ktdctl targets list
ktdctl targets validate
ktdctl db --build
ktdctl storage
ktdctl geo --recreate
ktdctl conc --build
ktdctl map --build
ktdctl srv --build
ktdctl gra
ktdctl cadv
ktdctl prom
```

명시형 명령도 유지한다.

```bash
ktdctl status srv
ktdctl ensure geo --build
ktdctl logs storage --follow
ktdctl action kor-travel-geo-postgresql restart
ktdctl inspect kor-travel-geo-postgresql --json
```

다른 Kor Travel/PinVi 저장소에서는 개발 서버 시작 전에 필요한 target만 호출한다.

```bash
ktdctl srv --build
```

#### `ktdctl pin` — Map·PinVi pinned revision registry

pinned revision은 더 이상 소스코드 상수가 아니라 **root 소유 JSON registry 파일**에
있다. 값은 파일에 있어도 검증은 코드가 소유한다 — canonical URL 집합, 40-hex 형식,
role 순서(map→pinvi), pinset digest 재계산 대조가 로드마다 실행되고 하나라도 어긋나면
fail-close한다. 따라서 파일을 편집해 임의 저장소를 가리키게 만드는 것은 코드 수정
없이는 불가능하다. 부재·파싱 실패·digest 불일치도 **상수 폴백 없이** fail-close다.

```bash
ktdctl pin show [--json]     # 현재 pin·digest·회전 메타·차단 목록 (읽기 전용)
ktdctl pin verify [--json]   # registry와 v6/v8 generation 공개 사본 strict 정합 (읽기 전용)
ktdctl pin publish-generation --manifest <absolute-v6-path> --journal <absolute-v8-path> --confirm
ktdctl pin init --confirm    # 호스트 최초 1회 (기본 seed: config/runtime-pins.seed.json)
ktdctl pin rotate --role map|pinvi --revision <40-hex> --reason "..." --confirm
ktdctl pin rotate-pair --map-revision <40-hex> --pinvi-revision <40-hex> --reason "..." --confirm
ktdctl pin block <pinset-sha256> --reason "..." --confirm
ktdctl pin rollback --to <pinset-sha256> --reason "..." --confirm
ktdctl pin show-pending [--json]        # 대시보드가 남긴 회전 요청 (읽기 전용)
ktdctl pin apply-pending --expect-revision <40-hex> --confirm   # 요청 적용 (root 전용)
ktdctl pin clear-pending --request-id <id> --confirm
```

- **경로**: 설치 root(`/opt/kor-travel-docker-manager`)에서 실행하면 기본값이 자동으로
  배포 트리 밖(`/var/lib/kor-travel-docker-manager/`)을 가리킨다. trusted installer는
  트리를 staging→commit으로 통째 교체하므로 registry가 트리 안에 있으면 다음 release
  설치가 회전 결과를 조용히 덮어쓰기 때문이며, **트리 안 경로로의 회전은 거부된다**.
  저장소의 `config/runtime-pins.seed.json`은 추적되는 **읽기 전용 seed**이고 회전 대상이
  아니다. 운영 registry와 `runtime-pins.<digest>.json` 보존본은 백업 대상에 등재한다.
- **파일 무결성**: 읽을 때마다 `lstat`으로 일반 파일·소유자(root 또는 자기 자신)·
  group/other 쓰기 금지를 확인하고, 위반하면 값을 쓰지 않고 fail-close한다.
- **공개 사본**: registry는 root `0600`이라 비-root backend가 읽지 못한다. root가
  실행하는 `pin init`/`pin rotate`/`pin rotate-pair`가 secret 없는 `0644` 공개 사본을 함께 쓰고
  (`KTDM_RUNTIME_PINS_PUBLIC_FILE`), 조회 API는 그 사본을 읽는다. 설치 root에서의
  기본 경로는 registry와 **다른 트리**(`/var/lib/kor-travel-docker-manager-public/`)다 —
  registry 트리는 installer가 매 설치마다 `0700`으로 되돌려 비-root가 traverse할 수 없다.
  사본이 registry보다 오래되면 `stale`, 사본 없이 registry를 직접 읽었으면 `degraded`,
  둘 다 읽을 수 없으면 `unknown`으로 표시하고 값을 추측하지 않는다.
- **generation 공개 계약**: v6 manifest·v8 journal은 root private state에 계속 두고,
  writer와 root `pin publish-generation`만 같은 public 트리에 `0644` 원본 사본을 원자
  기록한다. backend·Map·PinVi의 관측 정본은
  `GET /api/v1/pinned-runtime/generation`이며, 사람이 읽는 summary·terminal은 API
  envelope에만 둔다. raw 문서 키를 바꾸지 않는다.
- **재기동 불요**: 로드는 mtime·size·inode 스탬프로 캐시를 무효화하므로 pin 회전은
  실행 중 Manager에 즉시 반영된다.
- **회전 이력과 롤백**: rotate는 digest를 자동 계산하고 이전 registry를
  `runtime-pins.<old-digest>.json`으로 보존하며 `history`에 사유·주체·직전 pinset을
  남긴다. `pin rollback`은 그 보존본으로 원복하되 **차단된 pinset으로는 원복하지
  않는다**.
- **대시보드 회전 요청(2-step)**: 대시보드는 registry를 쓸 수 없으므로 회전 **요청**만
  별도 파일(`/var/lib/kor-travel-docker-manager-requests/`, `0600`)에 남기고, 적용은
  root의 `pin apply-pending --expect-revision <40-hex> --confirm`이 한다. 적용 시
  요청에서 취하는 것은 role과
  40-hex revision, 표시용 문자열뿐이며 URL·digest·차단 목록은 코드와 registry에서 다시
  만든다. 요청 이후 pin이 바뀌었으면 거부하고 요청을 남겨 둔다. 상세 계약은
  [`runtime-pin-registry.md`](runtime-pin-registry.md) §7-1.

#### pinset lifecycle — terminal candidate 차단

registry는 현재 pin뿐 아니라 **재시도가 금지된 pinset 목록**(`blocked_pinsets`)도
소유한다. 이전에는 이 규율이 Manager 코드의 d9 상수 3종과 kor-travel-map·pinvi 저장소
문서의 수기 목록에만 있어서, 어긴 실행을 막는 기계 게이트가 없었다.

- **조건 없는 차단**(`phase` 없음) — 그 pinset의 모든 실행을 금지한다.
  `rebuild-pinned`가 **어떤 mutation보다 먼저** 거부한다. 해소 경로는
  `ktdctl pin rotate-pair`로 새 Map·PinVi pinset을 만드는 것뿐이다(의도적으로 `pin unblock`은 없다).
- M05처럼 Map·PinVi compatibility pair를 바꿀 때는 `ktdctl pin rotate-pair`만 사용한다.
  terminal current pinset의 role별 `pin rotate`는 intermediate tuple을 만들지 않도록 거부된다.
- **phase 한정 차단** — 그 phase의 journal 재개만 금지한다. 기존 d9 admission과
  동일한 의미이며 rebuild 시작 게이트는 관여하지 않는다.
- `pin rotate`/`pin rotate-pair --block-previous`는 직전 pinset을 terminal로 등재한다. 회전 사유가
  "직전 candidate가 실패로 끝났다"인 경우의 표준 사용법이다.
- **차단 하한선은 코드가 소유한다.** registry가 손상되거나 오래된 사본으로 시딩돼도
  d9 계열 historical 차단은 유지된다 — 목록은 데이터, 하한선은 코드다.
- `pin verify`는 현재 pinset이 재시도 금지 상태이거나 registry/generation 공개 사본이
  incomplete·malformed·drift이면 비정상 종료한다. pair 회전 직후의 완전한 이전 generation은
  `pending_rebuild`로 알리되 current라고 부르지 않는다. digest가 맞다는 이유만으로 0을 반환하면
  운영자가 rebuild 직전에 잘못 안심하게 되기 때문이다.
- 의도적으로 `pin unblock`은 제공하지 않는다. 해소 경로는 새 revision으로의 회전이다.

### 5.2 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/api/v1/targets` | 앱 관점 target 목록과 의존 순서 |
| `POST` | `/api/v1/targets/{target}/ensure` | target 서비스를 `docker compose up -d`로 실행하고 초기화 단계 수행 |
| `GET` | `/api/v1/containers` | 관리 컨테이너 상태 목록 |
| `GET` | `/api/v1/containers/{container_id}/inspect` | Docker inspect 핵심 정보의 redacted 요약 |
| `POST` | `/api/v1/containers/{container_id}/action` | `start`, `stop`, `restart` |
| `POST` | `/api/v1/containers/{container_id}/config` | compose 파라미터 저장 및 재생성 |
| `POST` | `/api/v1/containers/{container_id}/reset` | 허용된 개발 lifecycle에서 기본 설정으로 복구 및 재생성 |
| `GET` | `/api/v1/containers/{container_id}/logs` | 최근 로그 |
| `GET` | `/api/v1/containers/{container_id}/metrics` | 최근 메트릭 이력 |
| `POST` | `/api/v1/auth/login`, `/api/v1/auth/logout` | 관리자 세션 로그인·로그아웃 |
| `GET` | `/api/v1/auth/me` | 현재 관리자 세션 확인 |
| `GET` | `/api/v1/backups` | 전용 PostgreSQL 백업 산출물 목록(디스크 manifest — 무엇이 실제로 남았는지의 권위) |
| `POST` | `/api/v1/backups/{role}` | 백업 생성을 시작하고 `202` + job id를 돌려준다. 동시 실행은 `409` |
| `GET` | `/api/v1/backups/{role}/jobs[/{job_id}]` | job 상태 폴링. `/jobs`는 새로고침 뒤 재접속용 최신 job |
| `GET` | `/api/v1/runtime-pins` | pinned revision·pinset digest·회전 이력·차단 목록·대기 중인 회전 요청. registry 회전은 root `ktdctl pin rotate`/`pin rotate-pair`/`pin apply-pending` 전용이라 이 route는 registry를 쓰지 않는다 |
| `GET` | `/api/v1/pinned-runtime/generation` | root가 발행한 v6 manifest·v8 rebuild journal 원본과 terminal·진행 요약. backend는 private state를 읽지 않으며, raw 문서 키를 바꾸지 않는다 |
| `POST/DELETE` | `/api/v1/runtime-pins/requests[/{id}]` | 회전 **요청** 기록·취소. 적용은 root `ktdctl pin apply-pending --expect-revision <40-hex> --confirm` 전용이다 |
| `GET` | `/api/v1/deployment-readiness` | 재구축 사전 점검(관측 전용). 무엇도 pull하지 않으며 호스트를 읽지 못하면 `unknown` 행으로 떨어진다. 검사하지 않기로 **결정한** 항목은 `unavailable_checks`로 이유와 함께 노출한다. 검사 4종: Compose 단일 파일, 사이드카 필수 스크립트, 고정 PinVi revision의 역할 부트스트랩 계약, Map 후보 빌드의 고정 Python base image |
| `GET` | `/api/v1/pinned-rebuild/preflight` | 재구축을 지금 시작할 수 있는지의 판정(관측 전용). registry뿐 아니라 공개 generation이 `match` 또는 회전 직후의 유효한 `pending_rebuild`인지 함께 요구한다. **실행 route가 아니다** — 재구축은 root를 요구하므로 payload는 차단 사유와 실행할 명령만 준다 |
| `GET` | `/api/v1/source-status` | 설치 기록·작업 사본·실행 중 이미지·계약 일치·환경 완결성(관측 전용) |
| `GET` | `/api/v1/system/disk-usage` | `docker system df`를 사람 말로 번역. 정리(prune)는 파괴적이라 CLI에만 있다 |
| `GET` | `/api/v1/admin/login-audit-events` | 관리자 로그인·로그아웃 감사 이벤트 |
| `GET/POST/DELETE` | `/api/v1/admin/public-api-keys...` | public API key 관리 |
| `GET` | `/api/v1/admin/password/preflight` | 미종결 rebuild journal 가드 판정(읽기 전용). 폼을 그리기 전에 읽는다 |
| `POST` | `/api/v1/admin/password` | 관리자 비밀번호 회전. `.env` 단일 키만 다시 쓰고 재기동 없이 즉시 적용된다. 증명된 미종결 journal은 **우회 불가** 거부 |
| `WS` | `/api/v1/ws/status`, `/api/v1/ws/logs/{container_id}` | 상태·로그 실시간 스트림 |

`ensure`는 Docker SDK가 아니라 `docker compose`를 인자 배열로 실행한다. 반면 stats, logs, inspect, 개별 action은 Docker SDK를 유지한다.

---

## 6. UI 방향

대시보드는 관리 작업에 집중한다. 마케팅 hero나 장식 이미지를 넣지 않고, `DESIGN.md`와 `frontend/tokens.css`의 룩앤필을 아래 방식으로만 반영한다.

- 밝은 Cobalt page/card surface, `--color-line` 구분선, `--radius-card`/`--radius-panel`을 기본 표면으로 사용한다.
- `--color-brand`는 선택·주요 조치·작은 상태 강조에만 사용하고, 의미 없는 gradient·glass 효과를 추가하지 않는다.
- 상태 테이블은 dense dashboard 형태를 유지하고, 반복 카드 남용을 피한다.
- 상세 패널은 컨테이너 선택 시 오른쪽 drawer 또는 modal로 열어 inspect, mounts, networks, env redaction, 최근 로그, 최근 메트릭을 함께 보여 준다.
- 파라미터 편집은 변경 전 diff와 재생성 경고를 표시하고, credential literal 입력은 `.env` 사용을 안내한다.

---

## 7. 안전 규칙

- Docker 관리 대상은 registry에 등록된 target과 container로 제한한다.
- target registry의 공식 source of truth는 `config/docker-targets.yml`이며, 임시 하드코딩 target을 API/CLI에 추가하지 않는다.
- 외부 공개 인증, 사용자 계정, 멀티테넌시 기능은 v1 범위가 아니다.
- `docker compose` 실행은 반드시 문자열 shell이 아니라 인자 배열로 수행한다.
- inspect와 로그 출력에서 secret 성격의 environment 값은 redaction한다.
- compose 파일은 구조 설정을 저장하고, 비밀번호와 API key는 `.env` 또는 `.env.local`에 둔다.
- 포트 `12500`, `12600`, `12700`, `12800`, `12101`, `12105`, `12205`, `12301`, `12401`, `12501`, `12505`, `12601`, `12602`, `12605`, `12701`, `12702`, `12705`, `12801`, `12802`, `12805`, `12901`, `12905`는 Kor Travel/PinVi 계열 프로젝트가 공용으로 사용하므로 임의 변경하지 않는다.

### 7.1 작업이 만든 컨테이너는 그 작업이 끝날 때 정리한다

**한 작업이 띄운 컨테이너는 그 작업이 끝나면 내린다.** 디버깅·검증·일회성
재현으로 올린 것이 대상이다. 상시 운영 스택은 여기 해당하지 않는다 —
무엇이 상시인지는 소유자가 정하고, 판단이 서지 않으면 내리지 말고 묻는다.

근거는 정돈이 아니라 **실패 모드**다. n150은 메모리 14GB 단일 호스트이고,
M05 격리 one-shot은 그 위에 Map 스택 + PinVi 스택 + Playwright runner를
한꺼번에 올린다. 남은 여유가 모자라 나는 ENOMEM은 단순 실패가 아니라 이
저장소가 반복해서 마주친 **소각 경로들의 방아쇠**다 — driver가 본문 진입 후
OOM-kill되면 `finally`의 terminal block이 돌지 않고, 같은 압박으로 registry
관측(fork 2개)도 함께 실패한다. 그 조합이 pinset candidate 1개 + 1~2시간을
태운다(`docs/journal.md` 2026-09-02, `scripts/run-m05-isolated-e2e-once` 헤더).

즉 정리해야 할 것은 **떠도는 잔여물**이지 서비스가 아니다. 잔여물이 쌓이면
긴 one-shot이 쓸 여유가 그만큼 줄고, 그 대가가 후보 소각이다.

규칙:

- 작업 중 띄운 컨테이너·네트워크·볼륨은 그 작업이 끝나는 즉시 내리고 지운다.
  재부팅에도 안 뜨게 하려면 `docker update --restart=no <name>` 후 `docker stop`.
- 실패로 중단된 실행이 남긴 잔해도 같다. M05 격리는 `m05i-map-<txn>` /
  `m05i-pinvi-<txn>` 이름을 쓰므로 `docker ps -a --filter name=m05i`로 확인한다.
- **남이 띄운 것을 임의로 내리지 않는다.** 여러 에이전트와 사람이 같은 호스트를
  쓴다. 자기가 띄운 것만 정리하고, 남의 것이 걸리면 소유자에게 확인한다.
  상시 스택(weather·concierge·geo·parking-radar·prometheus 등)은 기본이 유지다.
- 긴 one-shot 전에는 **현재 여유를 측정하고 기록**한다(`free -g`, `docker ps -q | wc -l`).
  부족하면 스택을 내리는 대신 소유자와 일정을 조율한다.
- 무엇을 왜 내렸는지와 되돌리는 명령을 작업 기록에 남긴다
  (`docker update --restart=unless-stopped <name> && docker start <name>`).

### 7.2 Concierge 소비자 read 키 배포

`kor-travel-map`의 Concierge feature pull은 루트 `.env`의
`KOR_TRAVEL_MAP_KOR_TRAVEL_CONCIERGE_API_KEY` 한 값을 유일한 secret source로 사용한다.
base compose가 이 값을 실제 fetcher를 실행하는 Dagster·Dagster daemon에 같은 이름으로 주입한다.
map API에는 사용하지 않는 read secret을 주입하지 않는다.
Concierge BFF/operator용 static `API_KEYS`를 소비자에 공유하거나, gitignore된
`docker-compose.override.yml`에 key literal을 반복하지 않는다.

prod 전환 순서는 다음과 같다.

1. 최신 Concierge API/UI를 배포하고 실제 Alembic runner로 `upgrade head`를 실행한다. DB head
   `20260713_0017`과 scope migration `20260713_0016`의 `scope` `NOT NULL`·`read|admin` CHECK를
   각각 확인한 뒤 API/MCP/scheduler/UI를
   서비스별로 재생성한다. UI의 admin hash/session secret이 비어 있지 않고 실제 로그인 POST가
   200+`Set-Cookie`, 잘못된 비밀번호가 401인지 확인한다.
2. Concierge 관리 UI/API에서 소비자·owner·발급일을 식별할 수 있는 label로 DB `read` scope 키를
   발급하고, DB에는 hash만 남았으며 발급 audit가 기록됐는지 확인한다.
3. manager의 gitignore된 prod `.env`는 mode `0600`으로 유지한다. legacy
   `docker-compose.override.yml`가 남아 있으면 수동 편집·삭제·`docker compose` 실행을 하지 않는다.
   trusted `/opt` release는 canonical Compose execution root이고 home checkout은 runtime source가 아니다.
   먼저 root-owned `0600` final legacy override와 고정 sibling Concierge `.env`를
   `ktdctl compose-boundary stage-legacy-override --source <absolute-path> --confirm`으로 protected C6c
   state에 snapshot한 뒤, `ktdctl compose-boundary retire-legacy-override --confirm`으로 그 staged 입력의
   알려진 Geo backup과 Concierge UI source만 이관한다. stage는 Docker/Compose를 호출하거나 home source를
   삭제하지 않으며 이후 retire/retry도 home 경로를 다시 읽지 않는다. retire는 candidate `.env`를 원자
   갱신하기 전에 stage 명령은 legacy `env_file`이 exact sibling source의 구형 상대 문자열 또는 exact sibling `path`와 boolean
   `required: true`만 든 Compose 장형 mapping 한 항목인지 확인한다. 장형의 `format`은 `raw`일 때만 허용하며 다른
   path·key·format·optional source는 fail-close한다.
   staged Concierge source가 `API_KEYS`, `APP_ENV`, `API_AUTH_ENABLED`를 전혀 선언하지 않을 때만 각각 이미 있는
   canonical root `KOR_TRAVEL_CONCIERGE_*` 값을 사용한다. source에서 이 값을 선언했다면 빈 값도 포함해 source 값이
   필수이며, `KTC_*` UI 인증·session·proxy·origin 값에는 root fallback이 없다. 최종 API key-set/backend key
   membership·`production`·authentication-enabled 검증은 동일하게 수행한다.
   candidate의 raw/resolved C6c 검증과 정확한 네 Concierge service recreate는 trusted canonical Compose에서
   Concierge API/MCP/scheduler/UI와 전이 `depends_on`, 실제 참조한 top-level entity만 추린 root-owned 일시 projection을
   함께 쓴다. 따라서 아직 materialize하지 않은 Map/PinVi candidate의 explicit guard를 억지로 해석하지 않으며,
   그 candidate의 값·Compose source·runtime을 Concierge retirement에 유입시키지 않는다.
   retire는 candidate `.env`를 원자
   갱신하고 canonical `/opt` Compose를 출력 없이 검증한 뒤에만 같은 protected state 안의 pending snapshot을
   owner-only archive로 옮긴다. n150의 rebuild 정본은 `rehearsal/rebuildable` mode이므로 stage/retire는 이를
   PinVi production·Map principal-required contract와 함께 재검증하고 `rebuild-pinned`와 같은 root-owned host
   lease로 직렬화한다. mode를 수동으로 production으로 바꾸거나 caller가 project root/state root/lock path를
   지정할 수 없다. read 키는 `.env`의 단일 변수에만 저장하며 override에 Map API·Dagster·daemon key/base URL
   literal을 새로 만들지 않는다.
4. Dagster·Dagster daemon을 재생성한다. 과거 배포에서 map API에 같은 환경변수가 들어갔다면
   map API도 한 번 재생성해 과거 secret을 제거한다. map API에는 해당 key env가 없음을 확인한다.
   `.env`와 두 수집기 컨테이너의 값을 한 프로세스 안에서 constant-time 비교해
   `nonempty && all_equal`의 성공 여부와 exit code만 확인한다. 값·길이·digest는 출력하지 않는다.
5. n150에서 Concierge backend를 직접 호출한다. 먼저 `limit=1`로 snapshot과 changes를 각각
   2페이지까지 요청해 cursor가 실제 다음 페이지를 가리키는지 검증한다. 이어 `page_size=200`으로
   두 모드를 끝까지 순회해 전체 건수와 export ID 무중복을 확인한다. cursor는 opaque라 크기를
   비교하지 않는다. `has_more=true`면 unseen `next_cursor`가 필수이고 그 값을 다음 요청에 그대로
   쓰며, `has_more=false`면 non-null cursor여도 종료한다. 빈 최종 page의 입력 cursor echo도
   허용한다. 실제 Dagster 컨테이너 fetcher는 `endpoint=snapshot|changes`, `cursor=None`,
   `page_size=200`을 각각 명시해 두 모드의 전체 결과를 소비한다. read 키의
   `DELETE /api/v1/destinations/0`과 `GET /api/v1/settings`가 403이고 응답이 admin scope 부족을
   가리키는지 확인한다. 데이터가 2페이지보다 적다면 cursor 검증을 합격으로 처리하지 않는다.
6. 기존 static 키가 BFF와 공유돼 있으면 먼저 BFF/operator key를 회전한다. 새 static admin 키를
   `KOR_TRAVEL_CONCIERGE_API_KEYS=old,new`와 `KOR_TRAVEL_CONCIERGE_BACKEND_API_KEY=new`에 함께
   반영한다. C6c와 이관 명령은 backend key가 allowlist의 exact member인지 값 비노출으로 검증한다.
   Concierge API는 `KOR_TRAVEL_CONCIERGE_APP_ENV=production` 및
   `KOR_TRAVEL_CONCIERGE_API_AUTH_ENABLED=true`를 root authority로 명시해야 하며, 이 둘이 local/false이면
   이관 명령이 실패한다.
   이관 명령이 deployment lock 안에서 API/MCP/scheduler/UI를 canonical single-file source로 재생성한 뒤 실제 로그인
   POST와 BFF 호출을 다시 확인한다. canonical rehearsal/rebuildable에서는 `rebuild-pinned`와 같은
   pinned-runtime host lease를, production에서는 fixed C6c global mutation lock을 사용한다. 재생성만 재시도해야 하면
   `ktdctl compose-boundary activate-concierge --confirm`을 사용한다. production의 일반 `ensure`는 이 경로에 사용할 수 없다.
7. 모든 smoke가 통과한 뒤에만 `KOR_TRAVEL_CONCIERGE_API_KEYS=new`으로 구 static 키를 제거하고
   API/MCP/scheduler를 재생성한다. 구 키 401, 새 admin 키의 내부 API 200, read 키의 공급 GET 200·
   내부/write 403, UI 로그인 200+`Set-Cookie`를 다시 확인한다.
8. 성공 시 key/cookie 임시 파일을 즉시 삭제한다. 이관 뒤 override는 owner-only archive로 남아 있으므로
   수동 restore 대상으로 쓰지 않는다. 실패 시 root `.env`에서 구 static 키를 allowlist에 임시 재등록하고
   `ktdctl compose-boundary activate-concierge --confirm`으로 API/MCP/scheduler/UI를 재생성하며 incident와 조치
   시점만 기록한다.

2026-07-13 n150 전환에서는 위 절차를 다음 결과로 완료했다.

- snapshot·changes의 `limit=1` 2페이지 cursor 검증이 모두 통과했다.
- `page_size=200` 전체 순회는 두 모드 모두 8페이지, 1,416건이었고 export ID 중복이 없었다. 실제
  Dagster 컨테이너 수집기도 두 모드에서 각각 1,416건을 반환했다.
- map API를 재생성해 사용하지 않는 read secret을 제거했고, Dagster·Dagster daemon만 `.env`의
  동일한 read key를 가진다는 값 비노출 동등성 검증을 통과했다.
- static admin 교체 후 구 키 401, 신규 admin GET 200, read 공급 GET 200, read 내부/write 403을
  확인했다. UI 로그인 POST 200+`Set-Cookie`, BFF settings 200, 잘못된 비밀번호 401도 재확인했다.
- 성공 뒤 key/cookie 임시 파일과 secret 포함 제한권한 백업을 모두 삭제했다.

### 7.3 Map OpiNet·KREX provider 키 주입

`kor-travel-map`의 OpiNet·KREX credential은 gitignore된 루트 `.env`의 현재 이름을 source로
사용한다.

- `KOR_TRAVEL_MAP_OPINET_API_KEY`: OpiNet station·price 수집용이다. base compose가 실제 수집기를
  실행하는 Dagster·Dagster daemon에만 같은 이름으로 명시 보간한다.
- `KOR_TRAVEL_MAP_KREX_EX_API_KEY`: 교통 돌발·notice를 포함한 EX endpoint용이다. base compose가
  Dagster·Dagster daemon에만 같은 이름으로 명시 보간한다.
- `KOR_TRAVEL_MAP_KREX_GO_API_KEY`: data.go.kr 계열 KREX 수집용이다. 같은 두 수집 서비스에만 명시
  보간한다.

Map API에는 provider credential을 하나도 주입하지 않는다. provider 조회·수집은 Dagster 경계에서
수행하며, 제거된 `KOR_TRAVEL_MAP_API_*_SERVICE_KEY`와 legacy
`KOR_TRAVEL_MAP_DATA_GO_KR_SERVICE_KEY`가 빈 값으로라도 API container environment에 존재하면 Map
entrypoint 또는 Manager C6c preflight가 기동 전에 거부한다. Map API compose의 `command`와
`entrypoint` override도 금지해 immutable image의 migration·fail-close entrypoint를 우회하지 못하게 한다.
기동 뒤 runtime inspect에서도 Map image가 봉인한 `Entrypoint=["/app/docker/api-entrypoint.sh"]`,
`Cmd=null`과 provider environment 부재를 다시 확인한다. Compose의 `command`·`entrypoint`
override는 계속 금지한다.

과거 `KRTOUR_MAP_*` 이름을 source로 쓰면 `.env`에 현재 이름의 key가 있어도 빈 문자열이
컨테이너로 전달된다. 따라서 override에 bare key나 secret literal을 반복하지 않는다. 변경 뒤에는
resolved config 전체를 출력하지 말고 `docker compose config --quiet`를 실행한 뒤, 한 프로세스
안에서 `.env`와 두 수집 컨테이너 값을 constant-time 비교하고 API 컨테이너에는 provider runtime
변수가 없는지 확인한다. 검증 결과는 `nonempty && all_equal` 같은 불리언만 남기며
실제 값·길이·digest는 로그에 남기지 않는다. API 컨테이너에는 제거된 provider runtime 이름이
하나도 없어야 한다.

### 7.4 Map↔PinVi canonical ops read/cancel principal

PinVi API는 Map의 canonical `/v1/ops/datasets*`와 `/v1/ops/pipeline*` 조회, 그리고
`POST /v1/ops/pipeline/executions/import_job/{job_id}/cancel`만 사용한다. 브라우저 BFF secret,
public service token, trusted CIDR을 재사용하지 않는다.

Map dataset grid의 행 identity는 provider/dataset display pair가 아니라
`provider_dataset_id × sync_scope × operation_key`다. Manager와 PinVi는
`/v1/ops/datasets/{provider_dataset_id}?sync_scope=...&operation_key=...`를 exact membership
detail URL로 검증하며, refresh operation이 없는 catalog-only 행의 null `operation_key`만 query에서
생략한다. 따라서 같은 dataset의 형제 operation을 한 행으로 접거나 legacy
`/v1/ops/datasets/detail?provider=...&dataset_key=...` URL을 허용하지 않는다.

Map API의 production fail-closed 설정은 ops pair만으로 완결되지 않는다. ADR-23에 따라 manager
`.env`는 admin proxy secret, API-only service token, API-only cursor signing secret도 서로 다른
값으로 보관한다. admin proxy secret은 Map API와 Map UI BFF에만 전달하고 service/cursor 값은 Map
API 외 service에 전달하지 않는다. profile은 `production`, public API key gate는 `true`, debug route는
`false`, feature 관리 REST는 `true`로 candidate에 고정한다. Map metrics는 인증된 Prometheus scrape 경로가 없는 동안 endpoint를
`false`로 명시해 무인증 fallback과 startup drift를 함께 차단한다. host network admin proxy의
trusted CIDR는 `127.0.0.1/32`·`::1/128` exact JSON으로 명시한다. 실제 값·길이·digest는 로그에
남기지 않고 shape, 상호 불일치, 허용 service별 존재 여부만 증거로 남긴다.

- manager `.env`가 `KOR_TRAVEL_MAP_API_OPS_READ_TOKEN`,
  `KOR_TRAVEL_MAP_API_OPS_CANCEL_TOKEN`, `KOR_TRAVEL_MAP_API_OPS_FIXTURE_TOKEN`의 단일 source다.
  세 값은 각각 32자 이상이고 공백 문자가 하나도 없으며 서로 달라야 한다.
- Map API에는 세 값을 같은 이름으로 전달한다. PinVi API에는 read/cancel만 각각
  `PINVI_KOR_TRAVEL_MAP_OPS_READ_TOKEN`과 `PINVI_KOR_TRAVEL_MAP_OPS_CANCEL_TOKEN`으로 전달한다.
  fixture token은 Map의 exact fixture lifecycle route와 `service:docker-manager` actor에만 결박되어
  PinVi나 Map UI/Dagster에는 전달하지 않는다.
- mode는 추론하지 않는다. 개발 PC는 `KTDM_DEPLOYMENT_ENVIRONMENT=local`,
  `PINVI_ENVIRONMENT=development`, `KOR_TRAVEL_MAP_API_OPS_PRINCIPAL_REQUIRED=false`, n150은 각각
  `production`, `production`, `true`를 명시한다. 세 값이 없거나 서로 맞지 않으면 manager는 어떤
  container도 변경하기 전에 중단한다.
- PinVi API의 Map 주소는 `PINVI_KOR_TRAVEL_MAP_ADMIN_BASE_URL`이며, manager host-network
  기본값은 `http://127.0.0.1:${KOR_TRAVEL_MAP_API_CONTAINER_PORT}`이다. publish port가 아니라 Map
  process의 실제 bind port를 사용한다. production은 host network·loopback·bind port 일치를
  preflight에서 강제한다.
- Map Dagster·daemon·UI와 PinVi Web·Dagster에는 위 token을 전달하지 않는다. `docker inspect`로
  검증할 때도 값을 출력하지 말고 서비스별 존재 여부와 constant-time 동등성 boolean만 남긴다.
- read token은 GET에만 사용한다. cancel token은 exact import-job cancel endpoint에만
  사용하며 schedule command, refresh policy, update request mutation은 같은 token으로도 403이어야
  한다.

### 7.5 T-VN-40 PinVi canonical snapshot principal

canonical collection snapshot은 기존 ops read/cancel principal과 별도의 두 ServiceToken을 쓴다.
manager `.env`의 `PINVI_KOR_TRAVEL_MAP_CURATION_SNAPSHOT_TOKEN`과
`PINVI_KOR_TRAVEL_MAP_CURATION_CUTOVER_MAPPING_TOKEN`은 함께 설정하거나 함께 비워야 한다. 각각
32자 이상·공백 없음이어야 하며 서로와 기존 C6c 보호 credential을 재사용할 수 없다.

- ordinary PinVi API에만 두 원시 token을 각각 같은 이름으로 전달한다. PinVi Web·Dagster·admin
  bootstrap과 Map의 모든 원시 token surface에는 전달하지 않는다.
- Manager가 frozen environment에서 각 SHA-256을 파생해 Map API에만
  `KOR_TRAVEL_MAP_API_PINVI_CURATION_SNAPSHOT_TOKEN_SHA256` 및
  `KOR_TRAVEL_MAP_API_PINVI_CURATION_CUTOVER_MAPPING_TOKEN_SHA256`로 전달한다. Map은 digest만
  소비하며 원시 token을 받지 않는다.
- 원시 pair 없이 digest만 주입하거나, 선언한 digest가 파생값과 다르거나, 한 token만 설정하면 raw·resolved
  Compose preflight가 container mutation 전에 중단한다. T-VN-40 rollout receipt가 pending인 동안
  빈 pair는 legacy compatible-pair를 위해 허용한다.

### 7.6 T-VN-M01 manual Feature 생성 credential

manual Feature 생성은 특정 provider나 PinVi 전용 기능이 아니다. Manager `.env`의
`KOR_TRAVEL_MAP_ADMIN_FEATURE_CREATE_TOKEN` 원문과 그 SHA-256인
`KOR_TRAVEL_MAP_API_ADMIN_FEATURE_CREATE_TOKEN_SHA256`을 함께 provision한다. 두 값은
32자 이상 원문·소문자 64자리 digest여야 하고, Manager가 원문에서 digest를 다시 계산해
불일치·부분 설정을 모두 fail-close한다.

- Map API에는 digest만 `KOR_TRAVEL_MAP_API_ADMIN_FEATURE_CREATE_TOKEN_SHA256`로 전달한다.
  API image나 API environment에는 원문을 넣지 않는다.
- Map UI에는 server-only BFF가 사용하는 원문만 `KOR_TRAVEL_MAP_ADMIN_FEATURE_CREATE_TOKEN`으로
  전달한다. `NEXT_PUBLIC_*`, build argument, PinVi·Dagster·Geo 컨테이너에는 전달하지 않는다.
- 두 값은 기존 C6c ops/service/cursor credential과 분리한다. 실제 값은 gitignore된 `.env` 또는
  승인된 secret env에만 저장하고, 로그·receipt·문서에는 값이나 digest를 남기지 않는다.
- Manager는 API service·ops·cursor·metrics·Geo·UI 인증·curation·cache-target digest와의
  재사용도 DB reset 전에 거부한다. API가 kill-switch를 `false`로 둔 사전 provision 단계라도
  production profile에서는 digest를 요구한다. 기본 flag는
  `KOR_TRAVEL_MAP_API_ADMIN_MANUAL_FEATURE_CREATE_ENABLED=false`이며, paired live gate와
  승인된 cutover에서만 `true`로 바꾼다. 따라서 새 Map image가 M01 route를 아직 열지 않은
  동안에도 배선·credential 재사용 drift를 먼저 발견한다.

Map UI runtime 인증의 `KOR_TRAVEL_MAP_UI_ADMIN_USERNAME`,
`KOR_TRAVEL_MAP_UI_ADMIN_PASSWORD_HASH`, `KOR_TRAVEL_MAP_UI_SESSION_SECRET`은 기본값 없는 `:?`
보간으로 Map UI의 정확한 Env path에만 전달한다. PBKDF2 반복 수는 100,000 이상, session secret은 32자
이상이며 Python `str.isspace()`가 인식하는 모든 Unicode 공백 문자를 포함할 수 없다. Map UI는
`env_file`을 사용할 수 없다. username은 confidential 값이 아닌 identity라 다른 서비스의 일반 scalar와
같거나 그 일부여도 허용하지만, Map UI의 exact wiring/runtime equality와 Map UI 밖 username 환경변수 이름
금지는 유지한다.

### 7.7 F1D application `300` 비운영 runtime 재구축

새 Map·PinVi generation과 새 schema를 만드는 mutation은 격리된
`rehearsal/rebuildable` 환경의 다음 명령 하나다.

```bash
sudo -n /opt/kor-travel-docker-manager/backend/.venv/bin/ktdctl \
  pinvi-pair rebuild-pinned --confirm
```

이 명령은 tracked Map·PinVi exact source pin과 Map application-300 paired candidate로 일곱 runtime
image와 세 schema head를 먼저 attest한다. Map API·Dagster는 Map sealed builder가 같은 commit/tree에서
만든 exact image ID를 쓰고, Manager는 Map UI와 PinVi API·Web·Dagster 네 image만 build한다. 그 뒤 Map
application·Map Dagster·PinVi database를 drop/create한다.

Map application은 과거 Alembic chain이나 restore를 replay하지 않는다. fresh DB identity를 고정하고
root/finalize operation plan·fence·durable intent·result를 순서대로 검증한 뒤 application final permit을
발행해 head `300`을 만든다. Dagster metadata는 별도 DB identity와 metadata permit을 사용하고 storage
migration은 journal transaction ID를 operation ID로 쓰는 DB intent+receipt로 수렴한다. root/finalize의
결과 없는 intent 재개는 append-only DB receipt를 먼저 복구하고, receipt 부재와 exact pre-state를 함께
증명할 때만 같은 operation을 안전하게 재실행한다. Dagster 재개도 같은 operation ID로 receipt를
복구·완결하며, web·daemon은 `--no-deps`로 기동해 migration을 암묵적으로 다시 실행하지 않는다. 이후
PinVi bootstrap·서비스 readiness·F1J smoke를 순서대로 검증한다.

기본 후보는 현재 pinset state root에서 root/finalize fence와 application/Dagster permit의 고정
mount directory를 먼저 계산한다. 이 directory의 준비와 candidate volume graph 검증 외에는 source
materialize·image build·journal·DB reset보다 먼저 발생하는 작업이 없다. 운영 `.env`에 pinset별
artifact 경로를 따로 유지하거나 수동으로 주입해서는 안 된다.

PinVi M05의 database role topology는 `pinvi-db-runtime-role` bootstrap one-shot이 한 번만
만든다. PostgreSQL initial-superuser secret file은 PostgreSQL·DB 생성 one-shot·이 role one-shot만
읽으며, normal PinVi API·Dagster에는 runtime application role DSN만, `pinvi-admin-bootstrap`에는
migrator role DSN만 전달한다. initial superuser·runtime application·migrator credential 값도 서로 달라야
한다. rebuild는 role one-shot을 명시적으로 open한 뒤 admin/schema bootstrap을 수행하고, 성공·실패 어느
경우에도 같은 one-shot으로 migrator login을 seal한다. endpoint는 host network의
`127.0.0.1:12800`으로 고정한다. source bootstrap script는 읽기 전용 bind에 실행 비트를 요구하지 않도록
`sh`로 호출한다. 이 lifecycle 밖의 수동 Compose·SQL 실행은 허용하지 않는다.

새 pinset candidate의 Map paired candidate·frozen Compose source contract·external readiness는 기존 DB를
폐기하기 전에 확인한다. 반면 sealed topology verifier는 폐기 대상인 기존 catalog를 target-state로
해석하지 않는다. PinVi DB drop/create만으로는 PostgreSQL cluster-global role catalog가 비워지지 않으므로,
Manager는 reset intent를 journal에 fsync하고 새 DB identity를 결박한 root-owned `0600` permit을 발행한 뒤
fresh-only exact four-role catalog reset one-shot을 실행한다. permit·empty target·foreign dependency·catalog lock
검증 하나라도 실패하면 generic terminal receipt만 남기고 runtime을 정지한다. 이후 PinVi role open → admin/migration bootstrap → migrator seal과 exact
PinVi schema head 확인을 마친 fresh DB에만 같은 one-shot을
`PINVI_ROLE_TOPOLOGY_VERIFY_ONLY=1`·sealed migrator로 실행한다. verifier는 고정 schema의 canonical
결과만 통과시키며, ordered fixed reason의 noncanonical·입력/endpoint/검증 불가·형식 불일치는 원문 출력
없이 fail-close한다. 이 실패는 `pinvi_role_verify`의 비밀 비포함 terminal receipt로 v8 journal에 먼저
기록하고 seven runtime을 정지하므로 같은 pinset은 재시도할 수 없다. verify-only를 지원하는 PinVi immutable
revision과 함께만 이 gate를 배포하며, 기존 pinset이나 historical journal을 재시도·수정하지 않는다.

`rebuild-pinned --confirm`은 fresh root `.env`에 위 topology의 여섯 role 값이 모두 **미선언**인 경우에만,
trusted `/opt/kor-travel-docker-manager`의 Compose·`.env` pair를 caller path override 없이 고정하고, root-owned
pinned-runtime host lease 안에서 exact rebuildable admission과 C6c token을 먼저 확인한 뒤 정해진 서로 다른 role명과
무작위 runtime/migrator password를 `0600` root `.env`에 원자적으로 초기화한다. 한 값이라도 선언·공백·중복·
불일치하거나 file identity가 바뀌면 기존 값을 채우거나 회전하지 않고 candidate/journal/runtime/DB mutation 전에
fail-close한다. pinned root `.env`의 값은 dotenv/caller 환경 보간을 적용하지 않는 literal authority이며, 완전한
기존 role 값은 같은 원문 여섯 값을 frozen Compose snapshot에 명시적으로 결박해 재사용만 한다. 원문 credential은
Compose output, journal, CLI result, log에 넣지 않는다.

current pinset의 `map_runtime_ready` v8 journal만 예외적으로 fresh role source를 재결박할 수 있다. 같은 root
write에는 이전 environment SHA만 남긴 marker를 넣고, candidate raw/resolved Compose 검증 뒤 journal에 이전/현재
environment SHA와 resolved Compose SHA를 포함한 단 한 번의 receipt를 추가한다. 다른 phase/digest 또는 이미
재결박된 journal은 새 role credential을 쓰기 전에 거부하므로 기존 resume의 immutable candidate authority를
약화하지 않는다.

manifest는 v6, pinset별 resume journal/tombstone은 v8이다. final/committed resume은 일곱 실행 중
container의 실제 image ID와 세 DB head를 generation에 다시 exact 대조한다. 실패와 재실행 모두 기존 DB,
image, manifest를 복원하지 않는다. backup·scratch restore·이전 revision rollback은 release gate가 아니다.
source/ETL 재적재는 committed 뒤의 별도 workflow다.

rebuildable 환경에서는 cache-target integration이 완전히 inert여야 한다. Map principal registry는 `[]`,
PinVi sync는 `false`, 관련 token·contract scalar는 비어 있고 consumer ID는 Compose 기본값이어야 한다.
설정된 integration은 candidate build나 DB 변경 전에 거부한다.

`deploy`, `rollback`, `cache-target`, `map-ui-auth` 공개 명령은 없다. 최종 schema
backup/restore가 필요해지면 과거 pair/cache state와 독립된 새 primitive로 설계한다.
(`db-backup`은 #177에서 pair/cache와 독립된 primitive로 다시 도입됐다.)

### 7.8 퇴역한 C7 v4 `pinvi-pair capture`

> **실행 금지 · 역사 기록** — application `300`의 current authority는 seven-service v6
> `pinned-runtime-generation`과 v8 rebuild journal뿐이다. `compatible-pair-v4.json`은
> F1D legacy tombstone 대상이며, 이를 생성·갱신·attestation 입력으로 쓰는 절차는 현재
> candidate를 증명하지 못한다.

현재 Manager CLI에는 `pinvi-pair capture`가 없다. 설치본에 같은 이름의 하위 명령이
보이면 과거 v4 설치본으로 간주한다. 그 명령은 `--help`를 포함해 실행하거나 검사 대상으로
삼지 말고, 정확한 merged trusted Manager release를 먼저 설치한다.

설치 전에는 source revision과 배포 증적만 읽기 전용으로 대조한다. 설치 후에는 top-level
`pinvi-pair` 도움말에서 `rebuild-pinned`만 노출되는지와 `capture`가 parser 단계에서
거부되는지만 확인한다. 이 확인 전에는 rebuild, C7 attestation, consumer acceptance를
재개하지 않는다.

v4 artifact는 current input으로 재사용하지 않는다. rebuild가 남기는 v6 manifest, v8
journal 및 legacy tombstone receipt만 현재 generation의 provenance로 사용한다.

### 7.9 퇴역한 v4 compatible-pair 설계 (역사 기록 · 실행 금지)

아래는 이전 v4 구현의 근거를 보존한 역사 기록이다. 여기 나오는 command와 state file은 현행
Manager에 존재하지 않으며 실행하면 안 된다. 현재 운영 절차로 해석하지 않는다.

현재 pair의 exact `map_source_revision`에서 Map source `docker-compose.yml`을 읽었을 때
admin/service/profile/public/debug hard-require가 있고 cursor가 아직 없는 source env v3가 manifest
active/rollback 양쪽에만 있고 marker가 없으면, manager는 manifest logical hash를 sibling
`map-production-env-migration-v1.json`의 pending baseline으로 mutation 전에 원자 기록한다. pending은
동일 manifest 재시도만 허용하며 현재 UI admin proxy는 없음 또는 frozen exact다. activation·runtime
격리·전체 smoke가 성공하면 manifest commit 전에 marker를 complete로 바꾸며 manager는 이를 삭제하거나
pending으로 낮추지 않는다. complete 뒤에는 pair rotation으로 slot이 다시 v3/v3가 되어도 admin proxy는
필수 exact다. marker는 fixed-shape 0600 owner regular file이며 corrupt/symlink/wrong owner/mode와 baseline
drift는 fail-close한다. compatible-pair manifest v4와 pair의 exact 9개 필드는 바꾸지 않는다.

source classifier는 profile/public/debug/service를 API-only, admin을 API+frontend, cursor를 v3 전체
scalar tree 0회/v4 API-only exact 1회로 제한한다. API·Dagster·daemon의 `env_file`은 실제 Map
source의 service별 path/options만 허용하고, 허용 파일이 exact commit에 추적돼 있으면 그 내용에도
보호 이름이 없어야 한다. 추적 파일은 exact path의 단일 `100644 blob`, 64 KiB 이하, UTF-8이어야 하며
허용 목록 밖 service는 값이 `null`이어도 `env_file` key 자체를 가질 수 없다.
보호 이름·placeholder가 다른 service나 build/label/command/config/secret
등 다른 source path에 있으면 거부한다. manager candidate와 runtime의 metrics-off·trusted
loopback 검사는 이 source 세대 판정과 섞지 않고 기존 raw/resolved/runtime validator가 담당한다.
`KTDM_C6C_CONTRACT_GENERATION`, Map UI smoke 평문 비밀번호, PinVi admin smoke 계정은 manager `.env`에만 둔다.
이 값들은 compose service env나 다른
`env_file`에 주입하지 않는다. 특히 contract generation은 secret이 아니더라도 배포 판단용 manager-only
값이므로 resolved compose의 command·label·build arg를 포함한 scalar와 runtime Env 어디에도 전달하지
않는다. frozen snapshot과 rollback도 최초 environment snapshot의 Map UI 인증값만 해석하고 hash·session
secret·ops token의 다른 서비스 노출이나 평문 비밀번호 주입을 전역 scalar에서 거부한다. 최초 설치의
manifest가 없는 환경에서는 base dependency부터 전체 토폴로지를 순서대로 bootstrap하고
candidate runtime set 전체 계약을 검증해 최초 v4를 만든다. Map dependent provenance가 없는 v1/v2/v3는
자동 전환하지 않고 거부한다. canonical v4 경로 옆에 저장소 역사상 실제 기본 파일명이었던
`compatible-pair-v2.json` 또는 `compatible-pair-v3.json`이 남아 있어도 빈 state로 간주하지 않는다.
payload를 읽어 자동 변환하지 않으며 symlink·비정규 파일·다른 owner·group/world writable mode를
포함한 어느 legacy artifact든 mutation 전에 operator migration/removal을 요구한다.

이하 v4 설명의 명령과 동작은 **역사 기록이며 실행하지 않는다**. 옛 parser에는
`--verified-compatible`, `--build`, `--wait-timeout` 조합이 있었고 capture가 runtime을 중지·재생성했다.
current CLI에는 capture parser나 v4 attestation 절차가 없으며, current authority는 §7.5가 가리키는
v6 generation·v8 journal뿐이다.

> **실행 금지** — 역사적 `deploy`의 정확한 명령 문자열은 복사·실행 위험 때문에 의도적으로
> 기록하지 않는다. current authority는 §7.5의 `rebuild-pinned`뿐이며, 이 문단은 현재 운영
> 절차가 아니다.

kor-travel-map API는 uvicorn 기동 전에 `alembic upgrade head`를 실행한다. 대상 마이그레이션이
`CREATE INDEX CONCURRENTLY` 등 `autocommit_block()`을 쓰면 수십 분이 걸릴 수 있는데, `--wait-timeout`
기본값(`docker compose up --wait`의 초 단위 상한, 120)을 넘기면 deploy가 실패로 판정되어
`_recover_previous_pair` rollback이 발동하고 **진행 중이던 마이그레이션 컨테이너가 뜯긴다** —
대상 마이그레이션이 durable한 부분 적용 상태로 남을 수 있다. `--wait-timeout <seconds>`로
1~3600초 사이 값을 지정하면 이 상한을 늘릴 수 있다(범위 밖 값과 int가 아닌 값은 lock 진입 전에
거부한다). 값을 지정하지 않으면 기존과 동일하게 120초를 쓴다.

전용 deploy는 다음 순서를 코드로 강제한다.

1. deployment-wide host lock을 잡고 mode/token/base URL/generation, 단일 canonical base compose의
   host network·PinVi production mode·Map bind port·정확한 loopback base·container identity·다섯 immutable
   image override·`env_file`/secret 격리를 runtime 변경 전에 검사한다. 별도 compose override/include/extends는
   mutation source로 허용하지 않는다. `--build`는 두 저장소 build context가 exact Git root이고
   worktree가 clean인지 검사한 뒤 각 lowercase 40자 `HEAD`를
   `KOR_TRAVEL_MAP_GIT_COMMIT`/`PINVI_SOURCE_REVISION`으로 파생하고 PinVi build mode를
   `production`으로 고정한다. 다섯 candidate image는 runtime `up`과 분리해 먼저 build하고 immutable
   image ID·revision label과 PinVi production label을 검증한다. 사용자가 지정한 값이 파생값과
   다르거나 image label이 유효하지 않으면 첫 container stop/recreate 전에 거부한다. Docker에는
   live checkout 대신 각 `HEAD`의 일회성 Git archive context만 전달해 build 중 변경·원복과 ignored
   파일 혼입을 막는다. raw/resolved build mapping도 이 context, 저장소 내부 지정 Dockerfile,
   provenance arg만 exact 허용하고 external Dockerfile·additional context·secret·target을 거부한다.
   build 유무와 무관하게 manifest active/rollback 합집합을 service별 manager 전용 content-addressed
   retention tag로 additive 보존하고 exact ID를 재검증한다. stale manager tag 정리가 성공해야 다음
   단계로 진행하며, build된 candidate도 첫 container stop 전에 보존한다. 일부 tag 실패는 기존
   reference를 덮어쓰지 않은 채 mutation 전에 중단한다. manifest commit 뒤 새 rollback 밖 tag의
   cleanup 실패는 commit된 runtime을 복구하지 않고 다음 pair mutation 전에 해소한다. explicit
   rollback과 최초 capture도 같은 retention 경계를 사용한다.
2. 현재 active set과 공용 dependency·Map/PinVi UI·Dagster가 canonical resolved Compose의
   service별 readiness 계약을 만족하는지 확인한다. 활성 healthcheck가 있으면 `running + healthy`,
   healthcheck가 없거나 명시적으로 비활성화됐으면 `running`을 요구한다. service 누락·종료,
   선언된 healthcheck의 빈/`starting`/`unhealthy` 상태, malformed/모호한 healthcheck는 모두
   mutation 전에 거부한다. 조회는 `ps --all`을 사용하고 canonical scale/`deploy.replicas`와
   service별 runtime record를 정확히 singleton으로 고정한다. stopped/stale duplicate, 예상 밖
   service, canonical `container_name` drift, payload의 malformed record는 정상 record가 함께
   있어도 거부한다. 현재 Map UI
   container를 inspect해 username·hash·session secret이 frozen environment와 정확히 같은지 검증한 다음,
   login→`/ops/datasets`→logout→재차단 lifecycle을 통과해야 한다. 어느 단계든 실패하면 Docker mutation은
   0이며 기존 runtime도 중지하지 않는다. 통과하면 다섯 runtime을 함께 중지해 mixed set 노출을 막은 뒤
   `--no-deps`로 새 Map API image를 먼저 재생성한다.
   image의 `org.opencontainers.image.revision`을 clean Map `HEAD`와 비교한 뒤에만 직접 read 200,
   무토큰 401,
   cancel token으로 허용된 cancel 계약과 대표 non-cancel schedule command mutation 403을 확인한다.
   실제 running job이 없으면
   존재하지 않는 import-job ID의 404까지 인증 통과 증거로 사용하고, 파괴적 취소는 최종 C7 gate의
   owned job에서 수행한다.
3. `--no-deps`로 Map UI·Dagster web·daemon의 exact candidate image를 재생성하고 공통 Map revision을
   검증한 다음 새 PinVi API image를 재생성한다. PinVi image의
   `org.opencontainers.image.revision`과 `io.pinvi.build.environment=production`을 먼저 검증한 뒤
   PinVi admin ETL/provider-sync에서 canonical 조회가
   200인지 확인한다. owned fixture 취소는 409 `PIPELINE_CANCELLATION_IN_PROGRESS`,
   502 `DAGSTER_TERMINATE_FAILED`, 503 `DAGSTER_UNAVAILABLE` 중 status/code/details/retryability가 정확히
   일치하고 양의 `Retry-After`를 보존해야 한다. 429나 generic code는 실패다.
4. 변경하지 않은 모든 필수 service가 같은 canonical readiness를 계속 만족하는지 확인한 뒤 managed container를 `docker inspect`로
   검사한다. Map API에는 Map 이름 세 개(read/cancel/required), PinVi API에는 대응 token 두 개만,
   Map UI에는 username·PBKDF2 hash·session secret 세 개만 존재해야 한다. runtime `.Config`의
   Env/Cmd/Entrypoint/Labels와 안전하게 순회할 수 있는 모든 scalar에서 confidential 이름·값을 찾고 각
   서비스의 정확한 허용 Env path 외 노출과 UI 평문 비밀번호 주입을 거부한다. username은 Map UI exact
   Env 이름·값만 고정하며 일반 scalar의 동일 문자열은 secret leak으로 처리하지 않는다.
5. Map UI 로그인·`/ops/datasets` 보호 화면·로그아웃·재차단과 PinVi Web login shell을 확인한다.
   PinVi shell은 200·`text/html`·비어 있지 않은 body·일반 `/_next/static/` marker와
   `/_next/static/chunks/app/(admin)/admin/login/page-<hex>.js`를 모두 요구하며, route chunk 없는 generic
   fallback은 거부한다. `Suspense fallback={null}` client page의 hydrated `admin-login-form`과 실제
   로그인 동작은 최종 n150 Playwright가 검증한다. 새
   generation의 Map/PinVi canonical smoke와 runtime 격리를 한 번 더 확인한 뒤에만 active manifest를
   갱신한다.

모든 중간 실패는 배포 시작 시점 active set의 다섯 immutable image를 함께 복원하고 같은 merged
contract·Map/PinVi canonical smoke·UI auth·runtime 검사를 다시 수행한다. 복구 검증도 실패하면 다섯
runtime을 중지하고 명시적인 operator-required 상태로 끝낸다. legacy/과거 generation으로의 부분 fallback은 없다.

> **실행 금지** — 역사적 `rollback`의 정확한 명령 문자열은 복사·실행 위험 때문에 의도적으로
> 기록하지 않는다. current authority는 §7.5의 `rebuild-pinned`뿐이며, 이 문단은 현재 운영
> 절차가 아니다.

rollback 명령은 manifest의 다섯 image ID가 모두 로컬에 있는지 먼저 확인하고 단일 canonical
compose가 전체 계약을 만족하는지 **stop 전에** 확인한다. 다섯 service를 함께 중지한 뒤 Map API
복원·signed smoke, Map dependent 복원·revision 검증, PinVi 복원과 전체 smoke·UI auth·runtime 격리가
모두 일치해야 manifest의 active set을 갱신한다. 실패하면 시작 시점 set을 복구하거나 모두 중지한다.

manifest와 mode 0600 lock은 checkout이 아니라
`~/.local/state/kor-travel-docker-manager/<COMPOSE_PROJECT_NAME>/`에 함께 저장한다. production에서는
root와 `compatible-pair-v4.json`/`deployment.lock`/`map-production-env-migration-v1.json` 파일명을
고정하고 모든 path override를 거부해 같은
Compose project가 서로 다른 lock으로 갈라지지 않게 한다. manifest version은 bool/string/float 변환 없이
정확한 integer만 허용하고 두 pair의 `recorded_at`은 offset ISO 8601 datetime이어야 한다. 기록은 파일
fsync, 원자 replace, 부모 디렉터리 fsync 순서이며 마지막 fsync 실패 시 이전 byte/mode를 다시 원자
복원·fsync한다. 복원을 완료할 수 없지만 새 byte가 정확히 남아 있으면 rename commit으로 일관되게 취급해
runtime과 manifest가 서로 다른 pair로 갈라지지 않게 한다.

대시보드의 일반 container config 변경·reset·미생성 start fallback도 같은 host lock과 공통 mode 계약을
사용한다. compose 파일을 바꾼 뒤 service recreate 또는 RustFS init이 실패하면 원본 byte와 file mode를
원자 복원하고 기존 설정으로 service를 다시 recreate한다. 복원 결과의 config/runtime 성공 여부는 API
500 응답의 `detail.restoration.config_restored`와 `runtime_restored`에 분리해 남기며, 실패한 candidate
설정을 파일에 방치하지 않는다. 첫 Docker mutation이 성공한 뒤 다음 command의 preflight에서 snapshot이나
raw/resolved graph drift를 발견하면 단순 409로 축소하지 않는다. 원래 candidate 오류, `mutation_applied=true`,
복구 시도·성공 여부와 진단을 `COMPOSE_POST_MUTATION_CONTRACT_FAILURE` typed 500으로 반환한다. 이때 config
경로와 `ensure` 모두 mutation 시작 시점의 원본 byte/mode를 먼저 원자 복원하고, 같은 raw/resolved hash와
system snapshot을 재검증한 뒤에만 baseline target runtime을 force-recreate한다. 복원·재검증 실패 시 Docker
recovery는 실행하지 않으며 복구 실패가 원래 계약 오류를 덮지 않는다. preflight drift 뒤 원본 원자 복원마저
실패해 candidate compose가 durable하게 남으면 409/no-mutation으로 축소하지 않고 같은 typed 500에
`config_restored=false`, `mutation_applied=true`를 기록한다.
Compose `wait`는 기본적으로 read-only지만 `--down-project`와
`--down-project=<bool>` 형식은 뒤에 특정 service가 있어도 project 전체 mutation으로 분류해 runtime-set guard와
같은 host lock을 적용한다. runtime `.Config.Env`
목록은 dict로 축약하지 않고 raw 순서로 검사하며 중복 이름을 거부한다. PinVi datetime은 날짜-only나
offset 없는 문자열을 거부하고 timezone offset이 있는 ISO 8601 값만 허용한다.

clean bootstrap result는 `init_results`를 항상 초기화하고 실제 init command가 예외를 내도 실패 결과로
흡수한다. 각 단계 전에 touched service를 기록하므로 이 경로를 포함한 모든 실패에서 transaction이 새로
만든 dependency/API만 제거하고 기존 container는 보존한다. signed Map smoke는 dataset-grid의 canonical
`execution_coverage`, typed `meta`, 각 dataset row의 identity/freshness/schedule/execution/catalog/policy/issue
shape를 검사하고 배열의 `null` 또는 잘못된 원소를 거부한다. PinVi smoke도 repository/asset/job/schedule/
sensor 배열 원소와 nullable datetime을 실제 admin DTO에 맞춰 깊게 검사한다. owned cancel 409/502/503은
fixture root member가 정확히 한 번 존재하고 UUID가 중복되지 않으며 unresolved count가 실제
`pending|cancel_failed` member 수와 같아야 한다. CAS 전이 중에는 0도 허용한다.
created service 제거 또는 기존 stopped service 복원 명령 자체가 예외를 내면 bootstrap 호출 밖으로
전파하지 않고 다섯 runtime halt 결과를 보존한 operator-required 상태로 끝낸다.

production compatible-pair preflight는 Map host bind port와 PinVi Map base URL을 각각 정확히 `12701`과
`http://127.0.0.1:12701`로 고정한다. 둘이 서로 일치하더라도 다른 포트면 첫 container mutation 전에
실패한다. local/development에서는 두 값을 동일하게 맞춘 비표준 포트를 허용한다.

Map capability smoke는 tokenless read의 typed 401뿐 아니라 cancel token의 GET/read, read token의 exact
import-job cancel, cancel token의 schedule mutation을 모두 typed 403 `OPS_SCOPE_FORBIDDEN`으로 확인한다.
올바른 cancel token의 exact path만 typed 404 domain boundary에 도달해야 한다. HTTP status와 RFC7807
`code`가 서로 다르면 실패한다.

PinVi owned cancel은 compatible-pair transaction마다 정확히 한 번만 POST한다. deploy/bootstrap의 첫
검증 결과를 final verification과 recovery에 재사용하며, 이미 요청했지만 결과를 검증하지 못한 경우에는
retryable/uncertain 상태를 바꿀 수 있는 두 번째 요청을 금지하고 fail-close한다. rollback과 그 recovery도
같은 transaction state를 공유한다. full cancel detail은 attempt datetime/error, member lifecycle,
`dagster_runs`, `committed_data_rolled_back=false`, warning을 실제 canonical DTO대로 검사한다. durable attempt가
아직 없는 409 `PIPELINE_CANCELLATION_IN_PROGRESS`만 exact `{root, cancellation: null}` shape를 허용한다.

full 409 attempt의 `unresolved_member_count`는 0을 허용하고 모든 member의 `pending|cancel_failed` 개수와
정확히 같아야 한다. owned root가 이미 resolved이고 child만 unresolved인 경우와 CAS/reconcile 중 잠시 모든
member가 resolved인 경우도 root identity와 member/run topology가 보존되면 canonical이다. retryable attempt의
`cancel_failed` member는 반드시 termination 대상 Dagster run에 결박되고, member와 matching run 모두
retryable structured error를 가진 exact `cancel_failed`여야 한다. 반면 in-progress/definitive CAS drift에서는
`cancel_failed` member와 이미 `cancelled`인 run 조합을 canonical transition으로 허용한다. definitive
attempt는 `409 PIPELINE_CANCELLATION_UNSAFE`+`failed`, timeout은
`503 DAGSTER_TERMINATION_TIMEOUT`+`retryable` pair로만 허용하고, root-only shape는
`409 PIPELINE_CANCELLATION_IN_PROGRESS`에만 한정한다.

in-progress runless `cancel_failed`는 definitive error code만 허용한다. run-backed `cancel_failed`의 run도
실패 snapshot이면 member와 retryable/definitive policy group이 같아야 한다. resolved run-backed member는
`cancelled↔CANCELED`, `done↔SUCCESS`, `failed↔FAILURE`를 정확히 맞춘다. 단,
`provider_feature_load_run`의 failed member와 SUCCESS run 조합은 동일 run에 초기 `done`이 아니었던
`provider_feature_load` child가 함께 있어 tracking failure를 입증할 때만 허용한다.

failed attempt의 top error는 definitive여야 하지만 member/run 증거는 frozen-base mismatch의 definitive
error와 exact run-backed retryable error가 함께 존재할 수 있다. attempt `status`는 `finished_at`/`error`의
DB lifecycle과 정확히 맞고, retry lineage는 self-reference를 금지하며 run-backed unresolved subset만 가진다.
member의 `requires_run_termination`은 frozen `initial_status`·`operation_kind`·Dagster run ID로 다시 계산해
일치해야 하고, run engine timestamp는 terminal result에서만 종료시각과 정렬되어야 한다.

`Retry-After`는 헤더 존재와 양의 정수 파싱 성공을 별도로 검사한다. retryable 502/503은 존재하는 양의
정수만 허용하고 non-retryable 409는 헤더 자체가 없어야 한다. 값은 공백·부호 없는 ASCII `[0-9]+` 중
1..300만 허용하며 Unicode digit, 0, 301 이상도 status와 무관하게 fail-close한다. low-level Compose
mutation parser는 `kill -s/--signal VALUE SERVICE`의 값을 service로
오인하지 않으며, service-less/project-wide·unknown command/option·option value 누락은 다섯 runtime 대상으로
default-deny한다.

Compose option은 command별 의미를 사용한다. `build --pull`, `run --rm`, `rm -s/--stop`은 값을 소비하지
않는 flag이고 `kill -s/--signal`만 다음 signal 값을 소비한다. `docker compose config -o/--output`은
resolved 설정을 파일에 쓰므로 분리·inline·값 누락 여부와 무관하게 mutation capability와 host lock을
요구한다. `config --format json`처럼 명시한 read-only option만 lock 없이 허용하며 unknown/incomplete
option은 runtime-set scope로 default-deny한다.

config/runtime 복원 실패 응답은 `returncode`, `stdout`, `stderr`, `error`를 `detail.restoration` 안에 그대로
보존한다. 미생성 container의 start fallback도 이 nested 복원 진단과 candidate command 결과를 REST 500까지
전달한다.

일반 non-API container config update/reset과 미생성 start-create뿐 아니라 generic ensure/up/create/recreate도
수정하거나 실행할 service만 검사하지 않는다. mutation 전에 raw와 Docker Compose resolved 문서의 전체 graph를
검사한다. 범위에는 모든 service 필드와 top-level `secrets`, `configs`, `x-*` extension, service의
secret/config mount·reference가 포함된다. 실제 존재하는 non-root `env_file`과 top-level secret/config 외부
파일 내용도 보호 이름·현재 값이 없는지 확인한다.

mutation source는 단일 canonical compose 파일이다. top-level `include`, service `extends`, process의
`COMPOSE_FILE`, `KOR_TRAVEL_DOCKER_MANAGER_OVERRIDE_FILE`, 실제 존재하는 `docker-compose.override.yml` 중
하나라도 있으면 resolution이나 Docker mutation 전에 fail-close한다. 운영에 필요한 prod 차이는 canonical
base compose의 명시적 environment 보간으로 합쳐야 한다. mutation command 자체도 original compose
directory를 `--project-directory`로 고정하고
`docker compose --env-file /dev/null --project-directory <canonical-directory> -f -`로 완전 해석된
compose JSON을 stdin에서 소비하며 override를 탐색하지 않는다.
transaction 시작 시 `.env`의 존재 여부·byte·device/inode/mode/uid/gid와 process env를 합친 effective
environment를 한 번만 snapshot한다. raw/resolved 검증과 Docker subprocess는 이 frozen mapping만 사용하며,
subprocess 직전에 `.env` 생성·삭제·내용·identity drift를 다시 확인한다. recovery도 최초 snapshot을 재사용하고
새 baseline을 만들지 않는다. snapshot의 값·원문 byte는 repr·오류·로그·hash에 노출하지 않는다. 같은 mutex
안에서 source byte와 include/extends/env/override 부재도 다시 확인하며, raw/resolved 계약을 별도 파일 합성
순서에 맡기지 않는다.

production mutation mutex는 compose project나 checkout별 state가 아니라 사용자별 단일 전역 경로를 사용한다.
local test process만 명시 override할 수 있고 production 값은 고정된다. lock 안에서 manifest 경로, root `.env`,
canonical compose byte/mode와 external `env_file` 입력을 한 번만 capture한다. `env_file`은 list의 exact
`{path, required, format}` mapping만 허용하며 각 regular file의 존재 여부·byte·device/inode/mode/uid/gid를
동결한다. Docker resolution에는 동결한 byte를 익명 fd로만 제공하고 외부 secret/config file source는 지원하지
않는다. deploy/capture/rollback의 stage, verification, recovery/halt는 모두 같은 transaction snapshot을 사용한다.
첫 mutation 이후 source나 외부 입력 계약이 바뀌면 원래 계약 오류와 recovery 결과를 typed post-mutation 오류로
보존하고, 검증되지 않은 pair를 계속 진행하지 않는다.
복구/halt만 frozen resolved transaction을 사용해 live env/source 재검증을 생략하며, config forward는 exact
candidate transaction, 원본 파일·runtime 복원은 persisted baseline transaction만 사용한다.
pair deploy/rollback과 bootstrap capture는 첫 mutation 전에 manifest active immutable image SHA를 root frozen
입력으로 해석한 별도 recovery transaction을 만들며, forward는 계속 root/candidate transaction을 사용한다.

Map API read/cancel/required 및 PinVi API 대응 read/cancel key는 source 이름뿐 아니라 default/required suffix와
메시지까지 고정된 canonical raw 표현만 허용한다. `env_file`과 외부 파일 경로의 `$VAR`, `${VAR}`, `:-`, `-`,
`:?`, `?`, `:+`, `+`, `$$`를 Compose 의미로 해석하고, 중첩·미완성·지원하지 않는 표현은 fail-close한다.
그 밖의 environment key/value, label, command, build arg, 외부 reference가 ops 또는 manager-only 이름이나 현재
보호값을 참조하면 `COMPOSE_CANDIDATE_PROTECTED_REFERENCE`로 거부한다. raw와 resolved 검증이 모두 끝나기 전에는
compose 파일 또는 container를 변경하는 Docker mutation subprocess를 실행하지 않으며 REST 409 detail에
`stage=candidate_validation`, `mutation_applied=false`를 남긴다.

service `volumes`는 short syntax(`source:target[:mode]`)와 long syntax(`type: bind`)를 모두 source 보간 뒤
compose 파일 디렉터리 기준 canonical path로 해석한다. symlink와 `..`도 최종 실제 경로로 비교하므로 manager
루트 `.env`, compatible-pair manifest/lock, 보호 이름·현재 값이 든 regular file은 read-only mount여도
거부한다. Windows drive/UNC처럼 Linux에서 안전하게 canonicalize할 수 없는 source는 fail-close한다. 반면
Compose 규칙상 named volume인 source는 host file로 읽지 않으며 기존 전체 graph의 보호 이름/reference 검사는
계속 적용한다. top-level secret/config가 `external: true`이거나 내용 없는 external `name`만 제공하면 manager가
내용을 검증할 수 없으므로 service reference를 허용하지 않는다. 현재 canonical API wiring에도 external
secret/config mount 허용 항목은 없다.

기존 DB/RustFS/Geo/Prometheus/Grafana data와 init script처럼 운영자가 관리하는 canonical bind는 현재 persisted
compose의 source/target/access mode가 그대로인 경우에만 유지한다. config API는 top-level `volumes` 정의와 모든
service `volumes` reference를 raw 문서와 Docker-resolved 문서에서 각각 정규화하고, mutex 안에서 persisted
compose의 두 hash와 모두 exact 비교한다. add/remove/source/target/type/mode
변경은 기능상 지원하지 않으며 `COMPOSE_CANDIDATE_PROTECTED_REFERENCE` 409,
`mutation_applied=false`로 끝난다. UI/API 사용자는 `volumes`에 현재 값을 그대로 보내야 하며 env/port/network만
변경할 수 있다. 이 불변 경계 덕분에 운영 데이터 이전 없이 request가 임의 mutable host path를 새로 주입하거나
Docker의 missing-source directory 자동 생성을 유도할 수 없다.

새 named volume은 top-level internal/default 정의와 일치하는 service reference만 허용한다. `local` driver의
non-empty `driver_opts`(`type`, `o=bind|rbind`, `device` 포함), 알 수 없는 driver/option, raw의 명시적 `name` 또는
`external` key, 미선언 service reference는 fail-close한다. resolved volume `name`은 exact
`<canonical-project>_<top-level-alias>`여야 하고 project name을 확정할 수 없으면 named volume 전체를 거부한다.
기존 operator bind도 manager
`.env`·state file의 ancestor 또는 host root를 노출할 수 없고, regular file은 1 MiB 이하 UTF-8 내용 검사를
통과해야 한다.

cAdvisor system bind는 raw literal과 resolved identity 모두 정확히 두 개의 set, 즉 RO `/sys -> /sys`와
RO `/var/run/docker.sock -> /var/run/docker.sock`만 허용한다. Compose는 이 두 bind 외에 cAdvisor 호환성을 위해
`privileged: true`와 `/dev/kmsg` device를 선언한다. named/anonymous/추가 bind, writable mode,
source/target interpolation alias는 모두 거부한다. `/sys`는 root-owned mountpoint/directory이고 source와 parent chain이 group/other-writable이 아니어야
한다. Docker socket은 실제 socket, uid 0, `docker` group, mode `0660`, other-write 금지 계약을 강제한다.
source와 parent chain의 canonical path·inode·device·mode·uid/gid snapshot은 같은 manager mutex 안에서 capture해
compose write 직전과 각 Docker subprocess 직전에 재검증한다. 변경되면 write 전에 중단하거나 이미 쓴 compose
byte를 원자 복원한다. `docker` group 구성원은 Docker daemon을 통해 root-equivalent 권한을 가진다는 기존 Linux
위협 모델에 포함하며, root 또는 동일 권한의 privileged host actor가 mutex 밖에서 filesystem을 교체하는 공격은
이 경계의 보호 대상이 아니다. Docker socket을 `0600`으로 바꾸는 별도 운영 전제는 두지 않는다.

cAdvisor는 더 이상 `/:/rootfs`, `/var/run`, `/var/lib/docker`, `/dev/disk`를 mount하지 않는다.
`--docker_only=true`와 read-only `/var/run/docker.sock`, `/sys`, `/dev/kmsg` device를 사용해 container CPU·memory·I/O 지표를
노출한다. host root filesystem/disk inventory는 제공하지 않지만 manager 대시보드의 Docker SDK 기반 container
상태·stats와 Prometheus의 container metric 수집은 유지한다.
## PostgreSQL 백업 (ADR-37 이후 4개 인스턴스)

2026-08-17 전용 instance 분리(ADR-37)로 백업 주체가 **넷**이 됐다. 그전까지 절차가 있던
것은 map 하나뿐이었고 geo는 **33GB인데 백업이 0건**이었다(#177).

### 실측 (2026-08-17, n150)

| 인스턴스 | 포트 | 원본 | `pg_dump -Fc --compress=6` | 소요 | `pg_restore -l` |
|---|---|---|---|---|---|
| geo | `12500` | 33 GB | **4.4 GB** | **879초** | 300항목 ✅ |
| concierge | `12600` | 65 MB | 4.6 MB | 2초 | 238항목 ✅ |
| map | `12700` | 6.3 GB | 587 MB | — | 1182항목 ✅ |
| pinvi | `12800` | 11 MB | 236 KB | 1초 | 426항목 ✅ |

**재보기 전에는 "geo를 매일 뜨는 게 현실적인가"에 답할 수 없었다.** 15분/4.4GB면
일 1회가 현실적이고, 7세대를 남겨도 31GB라 현재 여유(118GB) 안이다.

### 뜨는 법

host network라 **`-p`가 필수**다. 빠뜨리면 컨테이너 기본값 `5432`를 찾는데 그 포트를
듣는 것이 없어 실패한다(유닉스 소켓도 그 포트에 없다).

수동 `docker exec -e PGPASSWORD=...` 예시는 사용하지 않는다. 비밀번호를 명령행·환경변수로
전달하면 shell history나 process/audit 기록에 남을 수 있다. 현재 정식 경로는 password를
다루지 않는 Unix socket 기반 CLI다.

```bash
ktdctl db-backup create geo --timeout 14400
ktdctl db-backup create concierge --timeout 14400
ktdctl db-backup create map_application --timeout 14400
ktdctl db-backup create map_dagster --timeout 14400
ktdctl db-backup create pinvi --timeout 14400
```

| 인스턴스 | 컨테이너 | 포트 | user | database |
|---|---|---|---|---|
| geo | `kor-travel-geo-postgres` | 12500 | `addr` | `kor_travel_geo` |
| concierge | `kor-travel-concierge-postgres` | 12600 | `addr` | `kor_travel_concierge` |
| map | `kor-travel-map-postgres` | 12700 | `kor_travel_map` | `kor_travel_map` |
| pinvi | `pinvi-postgres` | 12800 | `pinvi` | `pinvi` |

### 산출물 3종 세트

dump 하나만 두지 않는다. **`.sha256`과 `.manifest`가 없으면 "복원 가능한 백업"이 아니라
"복원해 봐야 아는 파일"이다.**

```
~/backups/<인스턴스>/<날짜>-<태그>.dump
~/backups/<인스턴스>/<날짜>-<태그>.dump.sha256    # 파일명은 반드시 <dump 이름>.sha256
~/backups/<인스턴스>/<날짜>-<태그>.manifest       # 복구 때 대조할 값
```

> ⚠️ sha256 파일명을 `<태그>.sha256`(dump 확장자 없이)으로 두지 마라. 2026-08-17에
> 두 형식이 섞여 있어서, 한쪽을 가정한 검사가 다른 쪽을 **조용히 건너뛰었다** —
> 파일은 멀쩡한데 "sha256 없음"으로 넘어갔다. `sha256sum -c`가 그대로 먹는 형태로 통일한다.

manifest에 넣을 것: `created_at_unix` · `instance`(컨테이너 + `127.0.0.1:포트`) · `database` ·
`duration_sec` · `toc_entry_count` · `db_size_bytes` · `alembic_head`. **포트를 적었으면 포트가 바뀔 때
같이 고쳐야 한다** — 2026-08-17에 map manifest가 죽은 `12703`을 가리키고 있었고, 복구할
사람이 그 값을 보고 죽은 포트로 간다. 고칠 때는 `port_corrected=` 같은 이력 줄을 남긴다.
조용히 고치면 다음 사람이 그 값을 못 믿는다.

권한은 **600**이다. 각 저장소의 비밀 보관 규정(kor-travel-map `docs/external-apis.md` §1.1)이
dump를 포함한다 — dump는 DB 전체를 담는다.

### 복원

**map은** kor-travel-map `docs/backup-restore.md` **§8.1 prod 복구**가 정본이다
(옆에 복원 → 대조 → rename 교체 → **ACL 재조정** → ETL 검증). `pg_dump -d <db>`가
role·ACL을 담지 않으므로 `--no-owner --no-privileges` 복원 뒤 ACL 재조정이 필수다 —
빼먹으면 기동은 되고 쿼리에서 permission denied가 난다.

**geo·concierge·pinvi는** 각 프로젝트 alembic이 스키마를 소유하므로 복원 후 그쪽
migration을 태운다. 빈 PGDATA에서 시작할 때 superuser 확장이 먼저 있어야 하는 함정은
이슈 #109에 있다.

### `ktdctl db-backup` (issue #177 결선 — 위 수동 절차의 CLI화)

> **geo는 앱 레벨 백업이 정본이다(2026-08-18).** kor-travel-geo에는 T-228~244·T-290g의 완결된 백업 체계
> (`db_backup` Dagster job → pg_dump 디렉터리 + zstd `.tar.zst`, manifest·sha256·verify·restore drill·hot-swap·
> retention janitor, admin UI 카탈로그)가 있고, prod에서는 `.env`의 `KOR_TRAVEL_GEO_BACKUP_SCHEDULE_ENABLED=true`
> (+`_INTERVAL_HOURS=24`, `_ARTIFACT_TTL_DAYS=7`, `_RETENTION_KEEP_MIN=3`)를 준다. 첫 자동 백업은
> 2026-08-18T00:15Z에 4.71 GB로 성공했다(`KOR_TRAVEL_GEO_BACKUP_DIR`). 단, 매일 실행과 bounded
> retention은 Dagster `scheduled_backup`(*/15 run-due)과 `backup_retention_janitor_daily`(06:00)가
> 모두 RUNNING이고 최근 run이 성공해야 성립한다. `ktdctl db-backup`을 geo에도 주기 실행하면
> **중복(2×4.7 GB/일)**이므로 application DB role인 `geo`에서는 수동 비상 백업으로만 사용한다.
> `geo_dagster`는 별도 metadata DB라 standalone 주기 백업 대상으로 남긴다.

위 "뜨는 법" 수작업을 대체하는 CLI다. 여섯 role(`geo`/`geo_dagster`/`concierge`/
`map_application`/`map_dagster`/`pinvi`)을 지원하고, 포트·admin role 이름을
하드코딩하지 않고 살아있는 컨테이너(`docker inspect`)에서 읽는다 — `.env`가
기본 포트를 덮어썼거나 role 이름이 프로젝트마다 달라도 항상 실제 기동값과
일치한다. 연결은 TCP가 아니라 `docker exec --user postgres` + unix socket이라
어떤 postgres 비밀번호도 읽거나 다루지 않는다.

```bash
ktdctl db-backup create concierge
ktdctl db-backup list concierge
ktdctl db-backup gc concierge --keep 7
ktdctl db-backup restore-plan concierge [--file <name>] [--json]      # 읽기 전용
ktdctl db-backup rehearse-restore concierge [--file <name>] [--timeout <초>] [--json]
```

#### `restore-plan` — 복원하기 전에 "복원할 수 있는가"를 먼저 묻는다

**실제 role DB로 덮어쓰는 파괴적 복원 명령은 아직 없다** — 그 결정은 오너가 이미
로드맵 뒤로 미뤄 두었다(`docs/general-mgmt-audit.md` GM-07 검증 노트, 2026-08-28
journal). `restore-plan`을 먼저 만든 이유는, 목록에 백업이 보이는 것과 그 백업으로
실제 복원할 수 있는 것이 다르기 때문이다 — dump가 잘려 있어도, digest가 manifest와
어긋나도, live schema revision이 백업 시점과 달라도 목록은 똑같이 보인다.

계획은 아무것도 바꾸지 않고 다음을 답한다:

- 어느 dump를 쓸 것인가(생략 시 가장 최근).
- **digest를 다시 계산해** manifest와 대조한다. manifest에 적힌 값을 그대로 믿으면 이
  점검은 아무것도 검증하지 않는다.
- 크기가 manifest와 같은가(잘린 dump 탐지).
- live schema revision과 백업 시점 revision이 같은가.
- 어느 컨테이너가 영향을 받는가.

차단(`DUMP_MISSING`·`SIZE_MISMATCH`·`SHA256_MISMATCH`·`INSTANCE_UNREACHABLE`)과 참고
(`HEAD_MISMATCH`·`LIVE_HEAD_UNKNOWN`·`MANIFEST_HEAD_UNKNOWN`)를 구분한다. schema revision
불일치는 **차단이 아니다** — 복원 자체는 가능하고, 코드가 기대하는 schema보다 과거로
간다는 사실을 알고 결정하는 것이 사람의 몫이다. 차단 요인이 있으면 exit 1이라 스크립트
게이트로 쓸 수 있다.

#### `rehearse-restore` — 이 백업이 실제로 복원되는지 scratch DB에서 증명한다

`restore-plan`이 통과(차단 없음)한 백업만 시도한다. **대상과 같은, 실행 중인 postgres
인스턴스** 안에 이름이 겹치지 않는 scratch 데이터베이스
(`ktdm_rehearsal_<epoch>_<random>`)를 만들어 그 안에만 `pg_restore`하고, 검증이
끝나면 **성공이든 실패든 항상** scratch DB와 컨테이너 안의 dump 사본을 지운다 — 운영
DB(`concierge`/`geo` 등 실제 role 데이터베이스)는 어떤 경로로도 건드리지 않는다.
이름에 role을 넣지 않고 epoch+무작위 접미사만 쓰는 이유는 `geo`/`geo_dagster`,
`map_application`/`map_dagster`처럼 컨테이너를 공유하는 role 쌍이 같은 초에 각자
리허설을 시작해도 이름이 절대 겹치지 않게 하기 위함이다 — role별 `_role_lock`은
같은 role의 중복 실행만 막고 컨테이너 공유까지는 막지 않는다.

**운영 비용 — 실제 서비스 중인 인스턴스에 부하를 준다.** scratch DB로의 `pg_restore`는
같은 postgres 프로세스 안에서 실행되므로 CPU·IO·커넥션을 실제 서비스와 공유한다.
`map_application`처럼 큰 role은 복원 자체가 90분 이상 걸릴 수 있고(대시보드 "백업
이력" 실측 참고), 그동안 scratch DB가 원본과 비슷한 만큼의 디스크를 추가로 쓴다.
**트래픽이 적은 시간대에 실행**하고, 여러 role을 한 번에 리허설하지 말 것. 03:15/
03:30/03:55 cron(`geo_dagster`/`concierge`/`pinvi` 백업 생성)과 겹치면 `_role_lock`이
그 role의 backup 생성을 "another rehearsal is already running for this role"로
거부하고 wrapper는 `set -eu`로 그대로 중단한다 — 자동화 없이 수동으로만 돌리는 지금
단계에서는 저 cron 시각을 피해서 실행할 것.

검증 항목:

- `pg_restore` exit code(경고성 stderr는 실패로 치지 않는다 — 성공한 복원도 notice를
  낼 수 있다).
- 복원된 scratch DB의 schema revision이 manifest의 `alembic_head`와 같은가
  (`REHEARSAL_HEAD_MISMATCH`, 차단).
- 복원된 scratch DB 크기가 0바이트가 아닌가(`REHEARSAL_EMPTY_DATABASE`, 차단) —
  드물게만 걸린다(갓 만든 빈 DB도 카탈로그만으로 몇 MB다). 실제로 부분 복원을 잡는
  것은 다음 항목이다.
- 복원된 크기가 백업 시점 크기(manifest의 `db_size_bytes`)의 50% 미만인가
  (`REHEARSAL_SIZE_SHORTFALL`, 차단) — TOC가 일부만 적용된 부분 복원 탐지.

모두 통과해야 `verified: true`이고 exit 0이다.

**잔해 처리.** 프로세스가 `kill -9`나 OOM으로 죽으면 `finally` cleanup이 못 돌아
scratch DB와 컨테이너 안 dump 사본이 남을 수 있다 — `db-backup list`/`gc`는 파일
manifest만 보므로 이 DB 잔해를 발견하지 못한다. 다음 `rehearse-restore` 실행(같은
role이 아니어도 된다, 인스턴스가 같으면 된다)이 시작할 때마다 이름이
`ktdm_rehearsal_`로 시작하고 6시간보다 오래된 DB를 스스로 찾아 지운다
(`STALE_REHEARSAL_DATABASES_CLEANED` 참고 finding으로 결과에 남는다). 급하게 수동
확인이 필요하면 `docker exec <container> psql -U <admin> -c "SELECT datname FROM
pg_database WHERE datname LIKE 'ktdm_rehearsal_%'"`로 잔해를 조회하고 `dropdb`로
직접 지울 수 있다. dropdb 자체가 실패(예: 아직 연결이 남아 있음)해도 예외로 삼키지
않고 `REHEARSAL_CLEANUP_INCOMPLETE` finding으로 남긴다.

실제 role DB로 덮어쓰는 경로(운영자가 직접 압박받는 장애 대응 시나리오)는 writer
정지/재기동 절차 설계가 별도로 필요해 의도적으로 범위 밖에 남아 있다 — 장애 시에는
여전히 각 프로젝트의 수동 `pg_restore` 절차를 따른다. 주기 자동화(cron/systemd
timer)도 아직 없다 — 지금은 운영자가 수동으로 트리거하는 1차 primitive다.

geo application DB는 위 앱 레벨 백업이 정본이다. 운영자가 장애 대응을 위해 한 번만 수동 dump가 필요할 때는
`ktdctl db-backup create geo --timeout <초>`처럼 명시적으로 실행하고, cron/systemd timer에는 넣지 않는다.
`geo_dagster`는 앱 백업이 대신하지 않으므로 아래 wrapper 예시에 남긴다.

산출물은 위 "산출물 3종 세트" 관례를 그대로 따른다(`<role>-<ts>.dump` ·
`<role>-<ts>.dump.sha256`(`sha256sum -c` 그대로 먹는 형태) · `<role>-<ts>.manifest`
— `created_at_unix`·`duration_sec`·`instance`·`db_size_bytes`·`toc_entry_count`(pg_restore
-l TOC 항목 수 — 위 수동 검증과 같은 sanity check)·`alembic_head`(best-effort,
`public`/`app` schema 순서로 시도) 포함). 주기 실행은
`scripts/run-standalone-backup.sh <role> <keep>`을 cron/systemd timer에 건다.
`geo` role은 앱 레벨 백업과 중복되므로 이 wrapper의 주기 실행 예시에서 제외한다. 같은 role의 동시 실행은 `~/backups/<role>/
.backup.lock`(`flock`)으로 막는다.

Manager backend가 root service로 실행되고 operator가 별도 계정으로 CLI를 실행하는
환경에서는 두 프로세스가 `Path.home()`을 서로 다르게 해석한다. 따라서 백업 root는
`KTDM_BACKUP_ROOT=<operator-owned-absolute-backup-root>`처럼 명시하고 API와 CLI가
같은 절대 경로를 사용하게 한다. 이 값을 생략하면 backend가 `/root/backups`에 새
목록을 만들 수 있어 UI가 CLI 백업을 보지 못한다.

#### 공유 그룹(setgid) — UI와 cron이 같은 디렉터리를 쓸 때

`POST /api/v1/backups/{role}`이 생기면서 백업을 만드는 주체가 둘이 된다. 두 주체가 서로의
산출물을 읽고 지우려면 **디렉터리** 쓰기 권한이 필요하다(unlink는 파일 권한이 아니라
디렉터리 권한이다). 그래서 `KTDM_BACKUP_SHARED_GROUP`(그룹 이름 또는 gid)을 선언하면
산출물이 `0640`, 디렉터리는 setgid `2770` 계약으로 다뤄진다. 선언하지 않으면 기존
`0700`/`0600` 그대로다 — 아무도 요구하지 않은 권한 완화를 기본값으로 만들지 않는다.

전제(코드가 만들지 않고 **확인만** 한다. 운영자가 건 setgid/ACL을 코드가 추측해 되돌리면
조용히 원상복구되기 때문이다):

```bash
sudo groupadd ktdm-backup
sudo usermod -aG ktdm-backup <backend-user>
sudo usermod -aG ktdm-backup <cron-user>
sudo chgrp -R ktdm-backup "$KTDM_BACKUP_ROOT"
# 디렉터리만 setgid 2770으로 만든다. `chmod -R 2770`은 **dump 파일까지** group-writable·
# 실행 가능으로 만들어 코드가 강제하는 0640 정책과 어긋난다.
sudo find "$KTDM_BACKUP_ROOT" -type d -exec chmod 2770 {} +
sudo find "$KTDM_BACKUP_ROOT" -type f -exec chmod 0640 {} +
# 보조 그룹은 프로세스 재기동 후에야 반영된다.
```

전제가 깨져 있으면 백업이 **시작되지 않고** 위 복구 명령과 함께 거부한다. setgid가 실제로
먹지 않아 산출물이 다른 그룹에 떨어지면 그 dump를 **지우고** 실패한다 — 목록에는 보이는데
아무도 못 읽는 백업은 "백업이 있다"는 거짓 안전감만 만든다.

#### job 폴링의 단일 프로세스 전제

`POST`가 돌려주는 job id는 **프로세스 메모리**에 있다. uvicorn을 `--workers 2` 이상으로
띄우면 폴링이 다른 worker에 닿아 404가 난다. 운영 기동은 worker 1개이므로 성립하지만,
worker를 늘리려면 `services/job_runner.py`부터 durable store로 바꿔야 한다. job 기록의
소실은 데이터 손실이 아니다 — 무엇이 남았는지의 권위는 언제나 디스크의 manifest다.

**재기동 위험**: role lock은 이 프로세스가 쥔 `flock`이다. 종료하면 락은 풀리지만 컨테이너
안의 `pg_dump`는 계속 돈다. UI가 시작한 백업이 도는 동안 backend를 재기동하면 같은 DB에
두 번째 `pg_dump`가 붙을 수 있다.

#### gc의 동작 변화

`gc`는 이제 role lock을 잡고, **manifest 없는 고아 dump를 함께 수거**한다(중단된 create가
copy-out과 manifest 쓰기 사이에서 죽으면 그 dump는 어떤 목록에도 뜨지 않고 어떤 gc도
지우지 않아 영구히 디스크를 먹는다). manifest 내용의 `backup_filename`이 자기 파일 이름과
다르거나 role이 디렉터리와 어긋나면 **그 role의 gc 전체를 거부한다** — 그대로 두면 남겨야
할 최신 dump를 지우고 손상된 manifest는 남아 매 실행마다 같은 오삭제를 반복한다.

기존 plain-text manifest를 새 standalone JSON manifest와 같은 role directory에 두지
않는다. 새 parser가 schema 오류로 fail-close하므로 dump·sha256·manifest triplet을
`${KTDM_BACKUP_ROOT}/legacy/<role>/`에 보존 이동하고, active directory에는 새 형식
3종 세트만 둔다. 삭제 대신 격리하므로 수동 복구 자료는 남는다.

legacy triplet 격리는 role lock을 잡은 뒤 다음 순서로 한다.

1. `KTDM_BACKUP_ROOT`가 절대 경로인지 확인하고 `<root>/<role>`의 dump·`.sha256`·
   `.manifest` 세 파일이 모두 있는지 확인한다. 이동 전 `sha256sum -c`가 실패하면
   이동하지 않는다.
2. `<root>/legacy/<role>`을 0700으로 만들고 세 파일을 같은 filesystem 안에서
   각각 이동한다. 중단되면 파일이 있는 쪽을 기준으로 부족한 파일만 재개하며 삭제하지
   않는다. 대상은 새 active directory가 아니라 항상 같은 `KTDM_BACKUP_ROOT` 아래다.
3. 이동 후 legacy 파일 수·소유자·0600 권한·sha256을 다시 확인하고 active directory에
   plain-text manifest가 남지 않았는지 확인한다. 되돌릴 때도 role lock 안에서 같은
   세 파일을 active directory로 함께 이동한 뒤 `list`와 sha256 검증을 다시 실행한다.

2026-08-20 n150 실증에서는 `CRON_TZ=UTC`를 포함해
`geo_dagster`·`concierge`·`pinvi`에 wrapper cron을 설치했다(03:15/03:30/03:55,
keep 4/7/7). geo application은 앱 레벨
백업이 정본이고 Map application/Dagster 주기화는 kor-travel-map #148 정책이므로
이 wrapper에 넣지 않았다.

읽기 전용 `GET /api/v1/backups?role=<role>`도 있다 — Dashboard "백업 이력" 패널이
쓴다. 생성·GC는 CLI 전용이며 API에 노출하지 않는다(이 저장소의 표준 mutation
경계). **실제 role DB로 덮어쓰는 복원 CLI는 아직 없다** — scratch DB 리허설
(`rehearse-restore`)은 있다. 아래 "아직 안 된 것" 참고.

**GM-13**: manifest 하나가 손상·형식 위반·role 불일치여도 이 목록 전체를 지우지
않는다 — 그 항목만 `{"state": "unreadable", "filename", "reason"}` 행으로 격하되고
나머지 정상 manifest는 그대로 보인다(디렉터리 자체를 못 읽는 경우만 `503`).
같은 작업에서, `POST /api/v1/backups/{role}`가 시작하는 `pg_dump`는 role lock
아래에서도 `pg_stat_activity`를 먼저 물어 같은 role의 DB에 이미 pg_dump가
돌고 있으면 새 pg_dump를 시작하지 않고 거부한다 — role lock(파일 기반)은
backend 재기동에서 살아남지 못하지만 컨테이너 안 pg_dump는 계속 돌 수 있어서다.

#### `offbox-sync` — 백업과 pin registry 보존본을 원격 호스트로 옮기고 재검증한다 (GM-08)

로컬 백업만으로는 호스트 디스크 유실에서 살아남지 못한다. `runtime-pins.json`과
그 옆의 `runtime-pins.<digest>.json` 보존본(= `pin rollback`의 유일한 소스, git
밖)도 같은 문제를 안고 있다(ADR-40 트레이드오프가 이미 자인한 공백). `offbox-sync`는
설정된 원격 호스트에 `rsync`로 옮기고, 원격에서 `sha256sum -c`로 다시 확인한다.

```bash
export KTDM_OFFBOX_HOST=backup-vault.example         # 미설정이면 동기화는 비활성
export KTDM_OFFBOX_USER=ktdm-sync
export KTDM_OFFBOX_REMOTE_ROOT=/srv/ktdm-offbox
export KTDM_OFFBOX_SSH_KEY=/etc/ktdm/offbox-sync-key  # 생략하면 기본 SSH 설정을 쓴다
export KTDM_OFFBOX_PORT=22                            # 생략하면 22

sudo -n backend/.venv/bin/ktdctl offbox-sync run --json
sudo -n backend/.venv/bin/ktdctl offbox-sync status --json   # root 불필요, 마지막 결과만 읽음
```

- pin registry 파일은 root `0600`이라 `run`은 root 실행을 요구한다. `status`는 상태
  파일이 `0644`라 root가 필요 없다.
- role마다 독립적으로 진행한다 — 한 role의 rsync/검증 실패가 나머지를 막지 않는다.
  `--skip-pin-registry`로 백업만 돌릴 수도 있다.
- `.dump` 파일은 백업 생성 시점에 이미 만든 `.dump.sha256` sidecar를 그대로 신뢰해
  원격 검증에 쓴다 — 매 동기화마다 수십 GB 백업을 다시 로컬에서 해시하는 비용을
  피한다. sidecar가 없는 작은 파일(manifest, pin registry JSON)만 즉석에서
  스트리밍 해시한다.
- 결과는 `KTDM_BACKUP_ROOT/.offbox-sync-status.json`(`0644`)에 남고, 읽기 전용
  `GET /api/v1/backups/offbox-sync-status`로 Dashboard "백업 이력" 패널에도 보인다.
  트리거는 위 CLI 전용이다 — API에 mutation 라우트를 두지 않는다(표준 mutation 경계).
- `scripts/run-offbox-sync.sh`가 `scripts/run-standalone-backup.sh`와 같은
  wrapper 관례로 이미 있다. **root** crontab에 걸어야 한다(pin registry가 0600).
  03:15/03:30/03:55 role 백업 생성 cron과 겹치면 `_role_lock`이 거부하므로 그
  창을 피한다(예: 04:45). 어느 host에 어떤 주기로 걸지는 운영자가 결정한다 —
  목적지·자격증명이 환경마다 달라 이 저장소가 기본값을 강제하지 않는다.
- `--delete`를 쓰지 않는다 — 로컬 `gc`가 지운 오래된 백업도 원격에는 남는다.
  off-box 사본의 존재 이유가 재해 복구 보험이므로, 로컬에서 이미 지워진 자료를
  원격에서까지 따라 지우면 그 보험 가치가 줄어든다.

### 아직 안 된 것

- **실제 role DB로 덮어쓰는 파괴적 복원 CLI가 없다.** `rehearse-restore`가 백업이
  scratch DB에 실제로 복원됨을 증명하지만, 운영 DB 자체를 되돌리는 경로는 writer
  정지/재기동 절차 설계가 필요해 오너가 의도적으로 로드맵 뒤로 미뤘다
  (`docs/general-mgmt-audit.md` GM-07 검증 노트). map은 여전히 kor-travel-map
  `docs/backup-restore.md` §8.1 수동 절차가 정본이고, geo·concierge·pinvi는 각
  프로젝트 alembic migration을 타야 한다(§ "복원" 참고).
- **off-box 동기화를 실제로 cron/systemd timer에 거는 것은 운영자 몫이다.**
  `scripts/run-offbox-sync.sh` wrapper와 목적지 env 관례는 있지만, 이 저장소는
  어떤 host에도 자동으로 걸지 않는다 — 설정 없이는 아무 일도 일어나지 않으므로,
  env만 선언하고 wrapper를 crontab에 걸지 않으면 이 기능은 방치된 상태로 남는다.
  Dashboard의 "설정됐지만 아직 실행한 적이 없습니다" 배지가 이 상태를 알린다.
- 위 실측 표의 수치는 **일 1회가 가능하다**는 것만 보여준다. Map 쪽 최종 주기화
  여부는 kor-travel-map #148이 소유하며, 이 wrapper는 Map role을 주기 실행하지 않는다.

### 복원 리허설 실측 기록 (2026-09-07)

Map 원장 `T-VN-H49-{GEO-DAGSTER,CONCIERGE,PINVI}`의 마지막 해제 조건이 "복원 리허설
1회와 그 기록"이었다. 기록 위치는 소유자 판정으로 **이 runbook**이다 — Map
`docs/backup-restore.md`가 "n150 운영 backup은 Docker Manager runbook이 정본"이라고
스스로 위임하고 있어 그 위임을 따른다.

**리허설이 그동안 한 번도 성공한 적이 없었다.** `docker cp`가 host 파일의 소유권을
보존하는데(백업은 `root:root 0600`) `pg_restore`는 컨테이너 안 `postgres`(uid 999)로
돈다 — 넘겨받지 못한 파일을 읽으려 했다. 모든 백업이 root 0600이라 role을 바꿔도
결과가 같았다. copy-in 직후 소유권을 복원 유저에게 넘기도록 고친 뒤 아래를 얻었다
(모드 `0600`은 그대로 두고 소유자만 바꾼다).

| role | backup | 리허설 | alembic head | 복원 크기 |
|---|---|---|---|---|
| `pinvi` | 기존(2026-08-25) | `verified: true` | `20260821_0061` | 12,104,163 B |
| `geo_dagster` | 이번에 생성 | `verified: true` | `29b539ebc72a` | 59,847,139 B |
| `concierge` | 이번에 생성 | `verified: true` | `20260901_0029` | 78,918,115 B |

셋 다 scratch DB로 복원해 schema revision·크기를 확인하고 정리했다. **운영 DB는
건드리지 않았다.** `pinvi`는 `HEAD_MISMATCH`(백업 시점 `20260821_0061` vs 현재
`20260824_0101`)를 비차단 finding으로 냈다 — 복원하면 코드가 기대하는 schema보다
과거로 돌아간다는 뜻이고, 리허설 자체의 성립을 막지는 않는다.

**함께 드러난 것 — 이 host에 예약 백업이 없다.**

`geo_dagster`와 `concierge`는 백업이 **0건**이어서 `create`가 선행해야 했다. 확인해
보니 원인이 있다:

- `crontab -l`(root) → `no crontab for root`
- backup systemd timer 없음(`dpkg-db-backup.timer`는 Debian 자체 기능이다)
- `/etc/logrotate.d/`에 kor-travel 항목 없음 — `/opt/kor-travel-docker-manager/.env`에
  `KTDM_BACKUP_ROOT`가 없어 trusted installer의 `install_backup_logrotate()`가 skip됐다
- 백업이 있는 role은 `map_application` 1건, `map_dagster` 1건, `pinvi` 2건뿐이고
  전부 수동 생성분이다

즉 "주기 백업이 최근 성공과 bounded retention으로 수렴한다"는 전제는 **수렴할 대상이
돌지 않는 상태**다. 이 축은 Map `T-VN-H49-OFFBOX`가 소유한다(목적지 호스트·계정·ssh
키가 운영자 몫이고, 그 뒤 env 4개와 root crontab 한 줄이다).
