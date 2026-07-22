# KAR SOT 1.9.0 적합성 리뷰 후속 작업 목록

2026-07-22 SOT 1.9.0 전수 적합성 리뷰(9-에이전트 감사, 전 발견 오케스트레이터 재검증)에서 도출된 수정 항목이다.
리뷰 결과: 정량 오라클(17 커맨드 / 4 canonical argv / 85 카탈로그 / 84 체크섬 / 25 스키마-예제 쌍) 전건 일치, `make test` 전체 그린, **P0 위반 0건**. 아래는 확인된 P1 2건 + P2 다수의 수정 목록이며, 우선순위 순으로 정렬되어 있다.

## 0. 공통 작업 규칙 (모든 항목 착수 전 필독)

- **SOT 무결성 계약**: `sot/` 아래 어떤 파일이라도 수정하면 `sot/CHECKSUMS.sha256`(84 페이로드, 자기 제외)과 임베디드 아카이브 다이제스트가 어긋난다. 수정 후 반드시 `go generate ./internal/app/init && go generate ./internal/builtin`을 실행해 재생성할 것. `make test`의 `test-prepare`가 이를 검증한다.
- **파일 수 불변**: `sot/` 카탈로그는 85경로/84페이로드로 고정된 오라클이다(`internal/builtin/generate.go:122-124`가 84를 하드코딩). **sot/에 파일을 추가·삭제하지 말 것.** 기존 파일의 내용 수정만 허용된다.
- **검증 명령**: 각 항목 완료 후 `make test` 전체 통과(darwin/arm64 필수) + `git status --porcelain` 클린(생성물 드리프트 없음)을 확인할 것.
- **SPEC_VERSION**: SOT 문서를 수정하는 항목을 완료하면 `sot/SPEC_VERSION`(현재 1.9.0) 증가와 `sot/VALIDATION_REPORT.md` 상태일자 갱신 여부는 운영자 결정 사항이다. 임의로 판단하지 말고 작업 완료 보고에 결정 필요 사항으로 명시할 것.
- **작업 대상 아님**: `sot/IMPLEMENTATION_CHECKLIST.md:89`의 미체크 항목(macOS AGY native-auth 프로덕션 경계)은 **라이브 provider P2 영수증 3건(가족별 non-SKIP)이 필요한 운영 게이트**다. 코드 경계는 이미 구현 완료로 검증되었다. 이 항목을 체크하거나, 영수증을 위조·모의 생성하거나, `REOPENED_PRODUCTION_REVIEW_INCOMPLETE` 상태를 변경하려 시도하지 말 것.
- 완료 판정·증거 문구는 정직하게: 테스트가 실패하면 실패로 보고하고, 역사적 증거(`.gjc/`)는 append-only이므로 절대 수정·삭제하지 말 것.

## 1. [P1] followup 의미검증 결손 보강

**문제**: followup 경로의 의미검증(`internal/app/validation/followup.go:303-347` `validateFollowupSemantics`)이 resolution enum과 evidence 라인범위만 검사한다. review 경로에 구현된 두 검사가 followup에는 없다:
1. 의미값(placeholder) 거부 — review는 `internal/app/validation/review.go:906-917`의 `meaningfulText`가 `""`, `"n/a"`, `"tbd"`, `"todo"`, `"unknown"`, `"none"`, `"-"`를 거부한다. followup은 스키마 `minLength:1`뿐이라 `"rationale": "TBD"`가 통과한다.
2. SOT가 명명한 의미검사 규칙 미구현 — `sot/docs/07-output-validation-and-repair.md:153`: "Followup says `resolved` but rationale states the issue remains → Invalid semantic output".

`sot/IMPLEMENTATION_CHECKLIST.md:61` "Apply meaningful-value checks in addition to key presence"는 `[x]`이지만 실제로는 review 경로만 참이다.

**수정 방향** (권장: 구현으로 해소):
- followup의 AI-owned 필수 텍스트 필드(`summary`, `rationale`, 신규 finding의 `title`/`description`/`recommendation` 등 — `docs/07 §3.2`의 소유권 목록 기준)에 `meaningfulText` 동급 검사를 적용. 기존 함수를 followup에서 재사용할 수 있게 배치할 것.
- `resolved` + rationale 모순 검사는 결정론적으로 구현 가능한 범위로: 최소한 `resolution=="resolved"`인데 rationale이 placeholder이거나 명백한 잔존 진술 패턴일 때 semantic invalid 처리. 구현 범위는 `docs/07:153`의 규칙 의도를 기준으로 판단하되, 비결정적(모델 기반) 판정을 넣지 말 것.

**완료 기준**: placeholder rationale / resolved-모순 케이스가 semantic invalid로 거부되는 단위 테스트 추가, 기존 followup 검증 테스트 그린, `make test` 통과. 구현하지 않고 SOT 문구를 고치는 대안을 택할 경우 checklist 61행을 PARTIAL 사유와 함께 정정해야 하며, 이는 SOT 상태 변경이므로 운영자 승인 필요로 보고할 것.

## 2. [P1] reviewrun→providercli 직수입 레이어링 예외 해소

**문제**: `internal/architecture/architecture_test.go:17-21`이 `internal/app/reviewrun/{current_qualifier,production_candidates,qualifier}.go` 3개 파일의 `internal/adapters/providercli` 직수입을 명시적 허용목록으로 예외 처리한다(실수입: `internal/app/reviewrun/qualifier.go:12`). `sot/docs/11-go-architecture.md §1`의 의존 방향 규범(app은 adapters를 수입하지 않음)과 상충하고, `internal/app/reviewrun` 패키지 자체가 `docs/11 §2` 레이아웃에 등재되어 있지 않다.

**수정 방향** (둘 중 하나, 전자 권장):
- (a) reviewrun이 사용하는 providercli 타입(`RuntimeDefinition`, `QualificationNamespace` 등)을 `internal/ports/`의 포트 인터페이스/타입으로 추출하고 providercli가 이를 구현하도록 역전 → 허용목록 3건 제거.
- (b) 구조 변경이 과대하다고 판단되면 `docs/11`에 reviewrun 패키지와 이 의도적 예외(범위·사유)를 명문화하고 허용목록과 문서가 1:1이 되게 유지.

**완료 기준**: (a)라면 `architecture_test.go`의 `allowedAdapterImports` 제거 후 전체 그린. (b)라면 docs/11 갱신 + SOT 재생성(§0 규칙) + 아키텍처 테스트 주석에 문서 참조 추가.

## 3. [P2] 소스변조 감지 실패를 exit 8(보안)로 분류

**문제**: `sot/docs/10-reporting-ci-and-exit-codes.md:147`은 exit `8`을 "Security policy violation, including secret exposure or **source mutation**"으로 정의한다. 그러나 자식 워크플로 핸들러(`internal/entrypoint/kar/handlers.go:229,278,319`)는 서비스 오류를 일괄 `domain.FailureArtifact` 폴백으로 넘기고, followup의 오류 타입(`internal/app/followup/model.go:218-232`)과 delta의 소스변조 오류(`internal/app/delta/service.go:181` "source changed during child execution")는 `*domain.Failure`가 아닌 일반 `fmt.Errorf`라서 `reducedFailureClass`(`internal/entrypoint/kar/application.go:1252-1310`)가 인식하지 못한다. 결과: 감지된 소스변조가 exit **7**(artifact)로 투영된다. fail-closed는 유지되나 문서화된 보안 신호가 강등된다.

**수정 방향**: followup/delta/rerun의 소스변조 감지 경로에서 `domain.FailureSecurityPolicy` 클래스의 typed failure를 반환하도록 수정(서비스 계층에서 typed로 만들거나, 핸들러에서 변조 오류를 식별해 매핑). 취소 경로(`ctx.Err()` 래핑)는 현재 정상이므로 건드리지 말 것.

**완료 기준**: 소스변조 감지 시 exit 8을 단언하는 테스트(세 워크플로 각각), 기존 exit 우선순위 테스트 그린. 참고: 이 경로는 현재 프로덕션 미배선(오프라인 G008 하네스 전용)이므로 동작 회귀 위험은 낮다.

## 4. [P2] 커맨드 레지스트리 typed-exits에 cancellation(9) 반영

**문제**: `sot/docs/03-cli-workflows.md`의 커맨드 표는 init `2,4,7,8,9,10`(41행), doctor `2,4,7,8,9`(42행), config `2,4,7,8,9,10`(52행)을 명시한다. 그러나 `internal/adapters/cli/registry.go`의 `canonicalCommandSpecs()`는 init(96행)·config(107행)에서 `{2,4,7,8,10}`, doctor(97행)에서 `{2,4,7,8}`로 **9(cancellation)가 누락**되어 있고, 골든 테스트(`internal/adapters/cli/registry_test.go:22,23,33`)가 이 오값을 고정하고 있다. 라이브 exit 테이블(`internal/entrypoint/kar/application.go:1350,1351,1363`)은 정상적으로 9를 포함하므로 관측 동작은 맞다 — 문제는 SOT가 명명한 canonical registry 오라클의 메타데이터 드리프트다(checklist 111행의 native-home 관측 취소 exit 9 계약과도 어긋남).

**수정 방향**: 세 커맨드 spec에 `app.ExitCodeCancellation` 추가, `registry_test.go` 골든 동기화. `internal/adapters/cli/dispatch.go:53-55`의 invariant 검사도 이로써 문서와 일치하게 된다.

**완료 기준**: registry 골든 테스트가 docs/03 표와 1:1 일치, 전체 그린.

## 5. [P2] reportFailurePrecedence 보안/아티팩트 순위 역전 수정

**문제**: `internal/app/report/render.go:1009-1032`의 `reportFailurePrecedence`가 `FailureArtifact=6 > FailureSecurityPolicy=5`로 순위를 매겨 `docs/10 §8`의 우선순위(security 8 > artifact 7)와 반대다. 추적 결과 현재는 관측 영향이 없는(비활성) 코드 경로지만, 라이브 우선순위 테이블(`application.go:1312-1329`, 정상)과 상충하는 잠복 불일치다.

**수정 방향**: security를 artifact보다 상위로 정정하고, 두 우선순위 정의가 향후 갈라지지 않도록 라이브 테이블과의 일치를 단언하는 테스트를 추가.

**완료 기준**: 순위 정정 + 일치 단언 테스트, 전체 그린.

## 6. [P2] childrun 직접 단위 테스트 및 epoch 발행 경로 보강

**문제**: `internal/app/childrun/`은 소스 563 LOC 대비 직접 테스트가 13 LOC(생성자 nil 가드)뿐이며, 계보 검증 분기(`executor.go:104-111,170-195`)는 `internal/entrypoint/kar/g008_*` E2E의 happy path로만 간접 커버된다. 또한 childrun은 프로세스-로컬 epoch 소스로 `publisher.Publish(epoch)`를 직접 호출한다(`executor.go:137,141`, `followup.go:174,178`) — 프로덕션 발행 진입점 `PublishNext`(`internal/app/publication/service.go:167`, durable 단조성 강제)와 다른 경로다. 두 프로세스가 한 스토어를 공유하면 fail-closed로 충돌하는 안전한 실패지만, 온라인 자식 워크플로를 프로덕션 배선하기 전에 정리가 필요하다.

**수정 방향**: (1) 계보 검증 실패 분기들에 대한 직접 단위 테스트 추가(잘못된 소스 run, 세션 불일치, 부분 권한 등). (2) childrun 발행을 `PublishNext` 계열의 스토어 승인 epoch 경로로 이관하거나, 현행 제약(단일 프로세스 오프라인 하네스 전용)을 코드 주석과 docs/08 관련 절에 명문화.

**완료 기준**: childrun 실패 분기 커버 테스트 추가, epoch 경로 결정 반영, 전체 그린.

## 7. [P2] 아키텍처 테스트 금지 의존성 검사 확대

**문제**: `docs/11 §1`은 "Core domain and application packages do not depend on Cobra, YAML, JSON Schema libraries, Git commands, os/exec, or filesystem implementations"라고 규정하지만, `internal/architecture/architecture_test.go`는 domain에 대해 내부 패키지·`unsafe`·`C`만(43행), app에 대해 `os/exec`·`yaml`·`jsonschema`만(52-54행) 검사한다. Cobra와 맨 `"os"`(파일시스템) 수입은 어느 계층에서도 검사되지 않는다. 현재 라이브 위반은 0건으로 확인되었다(app의 `"os"` 수입은 `//go:build ignore` 생성기 `internal/app/init/generate_contract.go`뿐) — 집행 공백만 존재한다.

**수정 방향**: architecture 테스트에 domain/app 대상 `"os"`(bare import) 및 cobra 계열 수입 금지 검사를 추가. build-ignore 태그 파일은 제외 처리(현행 walk가 파싱하는 방식에 맞춰).

**완료 기준**: 확대된 검사로 전체 그린(위반 0건 유지 확인).

## 8. [P2] docs/02 §5 상태 다이어그램에 blocked 간선 추가

**문제**: `sot/docs/02-domain-and-state-model.md` §4.2(136행)는 role task 상태로 `blocked`를 선언하지만 §5 mermaid 다이어그램(246-264행)에는 `blocked` 간선이 없다(SOT 자체 불일치). 구현(`internal/domain/states.go:83-98`)은 `pending→blocked`, `primary_queued→blocked`를 허용하고 blocked를 종결 상태로 처리한다.

**수정 방향**: 다이어그램에 `pending --> blocked`, `primary_queued --> blocked`, `blocked --> [*]` 간선을 추가해 코드와 일치시킨다. 코드 변경 없음.

**완료 기준**: 다이어그램 갱신 + SOT 재생성(§0 규칙), 전체 그린.

## 9. [P2] docs/02 §7 fingerprint 공식 표기를 구현과 일치

**문제**: `docs/02:347-353`의 fingerprint 공식은 `SHA-256(normalized rule/category + normalized path + normalized evidence region)`(문자열 연결)인데, 구현(`internal/domain/finding.go:245-255`)은 필드별 8바이트 big-endian 길이 접두 프레이밍을 사용한다(충돌 안전성이 더 강한 canonical 방식). SOT 스스로 "지문은 보조 수단(aid, not proof)"이라 하므로 기능 영향은 없으나 자구가 다르다.

**수정 방향**: docs/02 §7의 공식 기술을 길이-접두 프레이밍 방식으로 정정(구현을 문서에 맞춰 약화시키지 말 것).

**완료 기준**: 문서 갱신 + SOT 재생성, 전체 그린.

## 10. [P2] workspace access 모드 기술 정정 (docs/15 용어집 + docs/05 표)

**문제**: `sot/docs/15-glossary.md:40`이 "Workspace access | Provider filesystem exposure mode: none, read-only snapshot, or **live project**"로 3모드를 기술한다. 그러나 `docs/05:145` "Workspace access is closed to `none|readonly_snapshot`"이고, 코드에는 `project` 모드가 존재하지 않으며 config가 그 외 값을 전부 거부한다(`internal/app/config/reducer.go:13-19`, `internal/adapters/config/yaml.go:371`). `docs/05:143`의 모드 표에도 `project` 행이 "Dangerous explicit opt-in"으로 남아 있어 산문("closed to two")과 긴장이 있다. 런타임 위험은 0(하드 거부)이나 보안 인접 용어의 과대 기술이다.

**수정 방향**: 용어집을 2모드로 정정하고 `project`는 "정의되었으나 선택 불가·거부되는 개념"으로 명시. docs/05 표의 `project` 행도 선택 불가임이 표 안에서 자명하도록 표기 정정.

**완료 기준**: 두 문서 갱신 + SOT 재생성, 전체 그린.

## 11. [P2] docs/04 workspace_access "기본값 none" 문구 정정

**문제**: `sot/docs/04-configuration.md:34` "Workspace access is `none` by default", 48행 "omitted optional fields continue to receive their code-fixed defaults"는 생략 시 기본값 부여를 시사한다. 실제 구현은 생략을 **거부**한다(`internal/adapters/config/yaml.go:371-373` — `none`/`readonly_snapshot` 외 전부 오류, 더 강한 fail-closed). 기본값 `none`의 의도는 init이 명시 기록(`internal/app/init/service.go:556`)으로 실현한다.

**수정 방향**: docs/04를 "필수 필드이며 init이 `none`을 기록한다(생략은 거부)"로 정정.

**주의**: `internal/builtin/catalog_test.go:316-349`의 임베디드 help 센서스가 "Workspace access is \`none\` by default" 정확 부분문자열을 단언한다. docs/04 문구를 바꾸면 이 센서스 단언도 함께 갱신해야 한다.

**완료 기준**: 문서+센서스 테스트 동기 갱신 + SOT 재생성, 전체 그린.

## 12. [P2] docs/06 §3 공통계약 must-include 목록을 /2 레이어 구성과 일치

**문제**: `sot/docs/06-prompt-contract.md §3`은 공통계약이 9개 지정 문장을 "must include"라고 규정하지만, 실제 자산 `sot/prompts/root-review/common.v2.txt`(/2 재작성)에는 "Return exactly one JSON object matching the supplied schema."와 "Do not wrap JSON in Markdown fences."가 없고(출력 레이어 `output-provider-review-wire.v2.txt`에 강화된 표현으로 존재), "Return review evidence and findings only."는 "Return review findings and honest coverage information only."로 재표현되었다. 의도는 상위집합으로 보존되나 문서의 자구 계약과 자산이 불일치한다.

**수정 방향**: docs/06 §3을 /2 레이어 구성(공통+출력 레이어로 분산, 강화 표현) 기준으로 재기술한다. 프롬프트 자산을 문서에 맞춰 되돌리는 방향은 /2 강화 표현을 약화시키므로 택하지 말 것.

**완료 기준**: docs/06 갱신 + SOT 재생성, 전체 그린.

## 13. [P2] docs/01 §4 "Required help statement" 노출 경로 결정

**문제**: `sot/docs/01-product-contract.md:76-80`의 "Required help statement"(역할은 기능적 렌즈이며 사람·조직 권한이 아님) 리터럴 블록이 `kar help`의 12개 토픽 어디에서도 노출되지 않는다(help 토픽 소스 별칭에 docs/01이 없음 — `internal/builtin/generate.go:412-425`; `help:roles`는 docs/02 매핑). 승인권한을 시사하는 제품 문구는 0건으로 확인되어 실질 위반은 없으나, "required"로 명명된 문구의 노출 경로가 없다.

**수정 방향** (둘 중 하나): (a) 해당 문구를 노출하는 help 소스에 docs/01을 별칭 추가하거나 기존 토픽(예: roles) 소스 문서에 동일 문구를 반영. (b) docs/01의 "Required help statement" 명명을 실제 노출 계약에 맞게 완화. 어느 쪽이든 12토픽 수와 골든 테스트 정합을 유지할 것.

**완료 기준**: 결정 반영 + 임베디드 재생성 + help 골든/센서스 테스트 그린.

## 14. [P2] docs/11 아키텍처 문서 현행화 (§2 레이아웃, §10 asset ID)

**문제**: `docs/11 §2`의 패키지 레이아웃 스케치가 현행과 다수 불일치: report가 `internal/app/report/`(문서는 adapters), validation/evidence/prompt는 포트 없이 구체 app 패키지, provider 어댑터는 평면 `internal/adapters/{fakeprovider,providercli}/`(문서는 가족별 하위 디렉토리), 컴포지션 루트 `internal/entrypoint/kar` 및 어댑터 `environment/reviewinput/runtime/workspace`와 `internal/app/reviewrun`이 문서에 부재. `docs/11 §10`의 asset ID 예시 `builtin:help/security@1`도 실제 `help:security`(버전은 아카이브 SHA로 일괄 고정)와 다르다. 의존 방향 원칙 자체는 코드에서 유지 확인됨(2번 항목 예외 제외).

**수정 방향**: docs/11 §2를 실제 레이아웃으로 갱신(2번 항목의 결정을 반영), §10 asset ID 형식 기술 정정.

**완료 기준**: 문서 갱신 + SOT 재생성, 전체 그린.

## 15. [P2] docs/14 결정로그 표 셀 파손 수정

**문제**: `sot/docs/14-decision-log.md:75` — §2 표는 2열(`| Draft concept | Final decision |`, 63행)인데 마지막 행이 3셀이라 마크다운 표 파싱이 깨진다. 내용은 D-030 항목(36행)과 중복.

**수정 방향**: 해당 행을 2셀로 병합 정리(정보 손실 없이).

**완료 기준**: 표 렌더 정상 + SOT 재생성, 전체 그린.

## 16. [P2] SOT 3문서 상태일자·문구 정합화

**문제**: `IMPLEMENTATION_CHECKLIST.md`·`README.md`는 상태일자 2026-07-19, `VALIDATION_REPORT.md`는 2026-07-21로 스큐가 있다. G005 delivered-scope 문구도 3문서에서 "outcome axes" / "independent axes" / "completion axes"로 각기 다르다(상태·마커는 동일).

**수정 방향**: 다음 SOT 리비전 시 상태일자를 단일 값으로 동기화하고 G005 문구를 하나로 통일. 이 항목은 다른 SOT 수정 항목(8-15)과 같은 리비전에서 일괄 처리하는 것이 효율적이다.

**완료 기준**: 3문서 정합 + SOT 재생성, 전체 그린.

## 17. [P2·선택] Kimi 역사 영수증 내구 보존

**문제**: 체크리스트 123행의 controlled Kimi 영수증 실파일이 저장소 밖 `/tmp/g009-live-kimi-receipt.json`(휘발성)에만 존재한다. 해시 핀(`1227711091fc94aff32dfed18d34f009da7404862b1eb63d99a2313a30c2be27`)은 `.gjc` 원장에 내구 기록되어 있고 현재 파일 해시와 일치함을 확인했다. 재부팅 등으로 파일이 소실되면 해시 핀만 남는다.

**수정 방향**: 원본을 수정하지 않는 **추가적** 보존만 허용된다 — 예: `artifacts/` 아래에 사본 보관(보관 시 사본의 SHA-256이 핀과 일치함을 검증·기록). `.gjc/` 증거 트리는 append-only이므로 기존 항목을 절대 수정하지 말 것. 보존 위치는 운영자 결정이 필요하므로, 실행 전 결정 요청으로 보고하는 것도 유효한 완료다.

**완료 기준**: 사본+해시 검증 기록 또는 운영자 결정 요청 보고.

## 18. [P2·선택] 테스트 전략 보강: property·보안 스위트 열거

**문제**: `docs/12 §1`이 명명한 property 검증 범주(IDs/paths/ordering/merge/validation) 중 무작위 생성 기반은 1파일(`internal/app/prompt/compiler_test.go:647`, seeded rand 80회)뿐이고 paths 범주는 생성적 커버가 없다(순열 전수 방식은 finding/planner 테스트에 존재). `docs/12 §8`의 보안 테스트 14개 사례는 전건 분산 커버가 확인되나 "보안 스위트"를 한눈에 열거할 단일 산출물이 없다.

**수정 방향**: (1) paths·IDs에 seeded 생성 기반 property 테스트 추가(외부 라이브러리 도입 여부는 go.mod 정책 판단 — 표준 `testing/quick` 또는 현행 seeded-rand 패턴 권장). (2) docs/12 §8의 14개 사례 각각에 대응 테스트 위치를 명시한 매핑(문서 내 표 또는 테스트 파일 주석 인덱스)을 추가.

**완료 기준**: 신규 property 테스트 그린, 보안 사례↔테스트 매핑 존재, 전체 그린.

## Epic G010 — Config-driven Multi-provider Production Release Gate

- [x] G010-T01: SOT 1.10.0 계약, 역할별 primary/fallback matrix, workflow 범위, `make test` gate를 구현 전에 동결한다.
- [x] G010-T02: Config v2와 canonical init/config 출력을 구현한다.
- [ ] G010-T03: configured planner/fallback과 reporting을 구현한다.
- [ ] G010-T04: 실제 followup/delta/rerun production composition을 구현한다.
- [ ] G010-T05: 실제 Kimi/ZCode/AGY E2E와 Makefile gate를 구현한다.
- [ ] G010-T06: 최종 tree에서 `make test`를 통과시키고 SOT를 `RELEASE_READY`로 closeout한다.
