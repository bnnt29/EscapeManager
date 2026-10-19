# Graph Report - EscapeManager  (2026-10-18)

## Corpus Check
- 121 files · ~205,093 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 3, .ini 2, .csv 1)

## Summary
- 3287 nodes · 6545 edges · 166 communities (130 shown, 36 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 513 edges (avg confidence: 0.86)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `b66116ba`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- escape_component.py
- SkeletonStore
- EscapeComponent
- _Connection
- Device
- SkeletonStore
- HardwareEsp32
- test_protocol.py
- SerialLink
- test_http.py
- ProtocolAdapter
- FakeHost
- Manager
- test_interop.py
- test_crypto.py
- test_persistence.py
- Json.cpp
- Protocol.cpp
- test_store.py
- bare_status
- SetupChange
- entry.js
- SerialHost
- escape_component_serial_host.cpp
- device_storage.py
- em_client.mjs
- HardwareEsp32.cpp
- EscapeComponent
- ComponentSnapshot
- wait_for
- SecureTransport
- _Host
- test_crypto.cpp
- LocalComponent
- test_net.cpp
- Net.cpp
- Peers.cpp
- HttpServer::Connection
- SecureTransport
- edit.test.mjs
- Host
- SimSetupSink
- PeerEntry
- Override
- test_sim.py
- HttpClient
- .find
- FakeSink
- HttpServer
- DeviceInfo
- ._sync_job
- Any
- __init__.py
- test_device.cpp
- client.cpp
- DevicePlatform
- MemoryStorage
- SimHost
- test_base64.cpp
- test_fuzz.cpp
- test_json.cpp
- escape_component_sim.cpp
- SecureTransport.cpp
- selfupgrade.test.mjs
- hw_smoke.mjs
- u32
- Vec
- escape_component_sim.py
- Value
- Node
- helpers.mjs
- pytest
- string
- test_store.cpp
- cstring
- CryptoBackend
- hw_wrap_test.mjs
- Host
- base64UrlEncode
- Announcement
- manager/setup.test.mjs
- test_serial_host.py
- HttpRequest
- validate_setup_change
- Options
- Enum
- Http.cpp
- test_http.cpp
- ProtocolAdapter
- Setup.cpp
- Options
- DummyComponent
- HostNetwork.hpp
- gen_vectors.mjs
- build_manager_crypto.mjs
- setup/setup.test.mjs
- parse_announcement
- EscapeManager wire protocol, level 2 ("proto 2")
- SimComponent
- Sink
- crypto.test.mjs
- manager/package.json
- DeviceOptions
- test_setup.cpp
- http_get
- FakeArduino
- TestHandler
- HttpResponse
- RateLimiter
- _Http
- Host
- OpenSslCryptoBackend.cpp
- build_ui.py
- test_device_storage.py
- e2e.test.mjs
- .service
- handleSetupPortal
- LineFramer
- HttpServer
- Mdns.hpp
- Device.cpp
- SyncRequest
- .start
- EscapeManager
- Result
- SkeletonSigner
- FileStorage
- CommandLineTests
- Client
- Warn
- Cleanup
- ReconnectTests
- setup/package.json
- .begin
- find_fields
- diagnostics/main.cpp
- NvsBlobs
- Platform
- Type
- Known
- host_wifi/main.cpp
- SkeletonInfo
- SkeletonSigner
- DerivedKeys
- OpenResult
- Compat.hpp
- Result
- Scan
- ReplayEntry
- SetupResult
- Throttle
- EscapeComponent::Host::customConfigDefs
- RouteInfo
- PlanAction
- run_serial_host.sh
- run_sim.sh
- Resource behaviour (the library lives inside another program)
- .post
- AGENTS.md
- arduino/README.md
- runDeviceTests

## God Nodes (most connected - your core abstractions)
1. `HardwareEsp32` - 92 edges
2. `Device` - 86 edges
3. `EscapeComponent` - 71 edges
4. `Manager` - 64 edges
5. `SerialHost` - 62 edges
6. `SecureTransport` - 49 edges
7. `EscapeComponent` - 43 edges
8. `SerialLink` - 43 edges
9. `get()` - 39 edges
10. `FakeHost` - 37 edges

## Surprising Connections (you probably didn't know these)
- `test_setup_json()` --calls--> `parseSetupJson()`  [INFERRED]
  test/test_core/test_setup.cpp → src/protocol/Setup.cpp
- `6. Limits (`EscapeConfig`, mirrored in `/security.json` `limits`)` --references--> `EscapeConfig`  [INFERRED]
  PROTOCOL.md → src/python/escape_component.py
- `test_client_get()` --calls--> `nowMillis()`  [INFERRED]
  test/test_net/test_net.cpp → src/net/Clock.hpp
- `hexOf()` --calls--> `hexEncode()`  [INFERRED]
  test/test_core/test_crypto.cpp → src/protocol/Base64Url.cpp
- `test_query_and_percent_decoding()` --calls--> `queryParam()`  [INFERRED]
  test/test_core/test_http.cpp → src/protocol/Http.cpp

## Import Cycles
- None detected.

## Communities (166 total, 36 thin omitted)

### Community 0 - "escape_component.py"
Cohesion: 0.06
Nodes (46): _lower_ascii(), MdnsQuery, parse_mdns_query(), _read_name(), setup_network_name(), fields(), test_depth_limit(), test_dom_basics() (+38 more)

### Community 1 - "SkeletonStore"
Cohesion: 0.18
Nodes (6): hex8(), parseHex8(), SkeletonStore, index_, signer_, validRoomName()

### Community 3 - "_Connection"
Cohesion: 0.18
Nodes (7): _Abort, _Connection, error_body(), _error_code_for(), format_response_head(), origin_allowed(), status_text()

### Community 4 - "Device"
Cohesion: 0.04
Nodes (39): Device, begun_, client_, ctr_, didBytes_, dirty_, dns_, dnsTried_ (+31 more)

### Community 5 - "SkeletonStore"
Cohesion: 0.08
Nodes (15): build_peers_doc(), build_skeleton_index_doc(), fnv1a32(), hex8(), json_validate(), jstr(), parse_hex8(), room_key() (+7 more)

### Community 6 - "HardwareEsp32"
Cohesion: 0.04
Nodes (39): HardwareEsp32, _apAuto, _apClients, _apName, _apUp, _attemptArmed, _attemptStartMs, _buttonArmed (+31 more)

### Community 7 - "test_protocol.py"
Cohesion: 0.06
Nodes (23): FakeHost, info(), is_code(), test_action(), test_action_length_limit_counts_bytes(), test_config_is_atomic(), test_config_numbers_booleans_and_null_follow_the_loose_text_rules(), test_peers_doc() (+15 more)

### Community 8 - "SerialLink"
Cohesion: 0.06
Nodes (27): feed(), logMsg(), logSetup(), SerialLink, atLineStart_, baud_, fails_, fd_ (+19 more)

### Community 9 - "test_http.py"
Cohesion: 0.08
Nodes (38): exchange(), get(), parse_http(), read_all(), Response, test_edit_proof_endpoint(), test_setup_push_over_the_network(), connect() (+30 more)

### Community 10 - "ProtocolAdapter"
Cohesion: 0.09
Nodes (20): _as_bytes(), error_result(), handle_action(), handle_config(), handle_plan(), handle_plan_action(), handle_plan_skeleton(), handle_setup() (+12 more)

### Community 11 - "FakeHost"
Cohesion: 0.07
Nodes (20): FakeHost, actionResult, actionsApplied, battery_, cfg, count, dirty, events (+12 more)

### Community 12 - "Manager"
Cohesion: 0.07
Nodes (29): Manager, RecordingSink, collect(), listen_udp(), sealed_with(), test_announcements_on_the_wire(), test_change_broadcast_has_a_minimum_gap_and_heartbeat_is_periodic(), test_concurrent_identical_envelopes_are_accepted_exactly_once() (+21 more)

### Community 13 - "test_interop.py"
Cohesion: 0.17
Nodes (16): finish(), node_client(), node_process(), test_action_post_works_against_the_python_simulator(), test_both_simulators_report_the_same_document_shapes(), test_command_handlers_answer_exactly_like_the_cpp_reference(), test_config_and_plan_roundtrip_against_the_python_simulator(), test_each_sees_the_other_in_peers_json() (+8 more)

### Community 14 - "test_crypto.py"
Cohesion: 0.07
Nodes (30): begun(), begun_edit(), test_announcement_frames(), test_base64url_vectors(), test_begin_resets_everything_when_the_tokens_change(), test_clock_wraparound(), test_document_frames(), test_edit_check_order_matches_the_reference() (+22 more)

### Community 15 - "test_persistence.py"
Cohesion: 0.18
Nodes (13): make_component(), test_begin_raises_oserror_if_the_http_port_is_taken_and_leaves_nothing_open(), test_component_limit_and_ignored_ids(), test_loop_before_begin_is_a_noop(), start(), test_boot_counter_increments_once_per_start_and_did_and_riddle_are_stable(), test_damaged_state_does_not_prevent_starting(), test_default_riddle_id_is_only_a_first_start_default() (+5 more)

### Community 16 - "Json.cpp"
Cohesion: 0.11
Nodes (28): Cursor, i, n, s, DomParser, c_, limits_, nodes_ (+20 more)

### Community 17 - "Protocol.cpp"
Cohesion: 0.15
Nodes (30): appendEscaped(), appendUInt(), utf8SeqLen(), appendCommonDeviceFields(), appendStr(), buildComponentsDoc(), buildPeersDoc(), buildSecurityDoc() (+22 more)

### Community 18 - "test_store.py"
Cohesion: 0.10
Nodes (19): blob_with_emac(), emac_of(), fake_mac(), FakeSigner, make_blob(), test_adopt_emac_shape_rules(), test_adopt_equal_rev_tiebreak_converges(), test_adopt_needs_valid_mac_with_edit_token() (+11 more)

### Community 19 - "bare_status"
Cohesion: 0.17
Nodes (9): BackpressureTests, probe(), bare_status(), CommandTests, PersistenceTests, RobustnessTests, rss_kb(), SerialHostTestCase (+1 more)

### Community 20 - "SetupChange"
Cohesion: 0.06
Nodes (19): SetupChange, editToken, hasEditToken, hasToken, hasWifi, pass, ssid, token (+11 more)

### Community 21 - "entry.js"
Cohesion: 0.08
Nodes (30): esbuild, @noble/ciphers, @noble/hashes, B64U_INDEX, b64uEncode(), constantTimeEqual(), deriveEditKeys(), deriveKeys() (+22 more)

### Community 22 - "SerialHost"
Cohesion: 0.07
Nodes (19): SerialHost, device_, did_, kMinGetStateGapMs, known_, kOfflineMs, kPollMs, kRetryMs (+11 more)

### Community 23 - "escape_component_serial_host.cpp"
Cohesion: 0.10
Nodes (13): baudConstant(), defaultStateDir(), deriveDid(), exeDir(), FileStorage, dir_, main(), mkdirs() (+5 more)

### Community 24 - "device_storage.py"
Cohesion: 0.20
Nodes (16): _auth_token(), _b64(), _clear_edit_token(), _device_info(), _device_port(), _edit_token(), _project_option(), _reset_persistent_storage() (+8 more)

### Community 25 - "em_client.mjs"
Cohesion: 0.09
Nodes (18): b64u(), DEFAULT_TOKEN, deriveKeys(), Device, main(), SECRET_TOKEN, args, bProof (+10 more)

### Community 26 - "HardwareEsp32.cpp"
Cohesion: 0.11
Nodes (6): decodeBase64(), HardwareEsp32::NvsBlobs::read(), HardwareEsp32::NvsBlobs::write(), onApStation(), phaseName(), printableToken()

### Community 27 - "EscapeComponent"
Cohesion: 0.07
Nodes (9): EscapeComponent, _beginMs, _begun, _components, _device, _dirtyBeforeBegin, _host, _hw (+1 more)

### Community 28 - "ComponentSnapshot"
Cohesion: 0.06
Nodes (34): ComponentSnapshot, actionCount, actions, customConfig, customConfigCount, errorCount, errors, eventMsg (+26 more)

### Community 29 - "wait_for"
Cohesion: 0.10
Nodes (21): wait_for(), test_announcements_keep_the_uint32_counters_in_range(), test_connection_reset_while_responding_is_harmless(), test_everything_works_with_the_clock_just_before_the_32_bit_wrap(), test_host_hints_are_coalesced_and_verified(), test_random_http_garbage_never_kills_the_server(), pair(), test_devices_discover_each_other() (+13 more)

### Community 30 - "SecureTransport"
Cohesion: 0.07
Nodes (21): EditState, Custom, Invalid, Unset, SecureTransport, began_, did_, edit_ (+13 more)

### Community 31 - "_Host"
Cohesion: 0.08
Nodes (10): bounded(), ComponentSnapshot, CustomConfigDef, _Host, _is_http_url(), normalize_config_def(), plan_action_bit(), PlanAction (+2 more)

### Community 32 - "test_crypto.cpp"
Cohesion: 0.11
Nodes (20): hexDecode(), beginWith(), beginWithEdit(), hexOf(), test_announcement_frames(), test_clock_wraparound(), test_document_frames(), test_edit_envelope_vectors() (+12 more)

### Community 33 - "LocalComponent"
Cohesion: 0.08
Nodes (18): EscapeComponent::Host::snapshot(), LocalComponent, actionHandler, actionsCb, customConfigCb, customConfigSetCb, errorsCb, eventMsg (+10 more)

### Community 34 - "test_net.cpp"
Cohesion: 0.18
Nodes (14): nowMicros(), nowMillis(), body(), connectTo(), exchange(), test_back_to_back_rejections_never_get_503(), test_client_deadline_on_silent_server(), test_early_rejection_is_delivered_even_with_unsent_body() (+6 more)

### Community 35 - "Net.cpp"
Cohesion: 0.17
Nodes (8): headerValue(), makeAddress(), setNonBlocking(), UdpSocket, fd_, wouldBlock(), test_mdns_shared_record(), test_setup_network_dns()

### Community 36 - "Peers.cpp"
Cohesion: 0.12
Nodes (19): buildAnnouncementDoc(), didToText(), fieldHex8(), fieldText(), fieldUInt(), ipv4ToU32(), parseAnnouncement(), parseDid() (+11 more)

### Community 37 - "HttpServer::Connection"
Cohesion: 0.07
Nodes (26): HttpServer::Connection, body, continueSent, drained, drainStartMs, fd, gotBytes, head (+18 more)

### Community 38 - "SecureTransport"
Cohesion: 0.08
Nodes (5): b64u_decode(), b64u_encode(), KeyRole, SecureTransport, Library pieces (all importable from `escape_component`)

### Community 40 - "edit.test.mjs"
Cohesion: 0.20
Nodes (17): savedRev(), saveFromStub(), setEditTokenInUi(), vectors, pageKit(), enterEditMode(), openPage(), openPlan() (+9 more)

### Community 41 - "Host"
Cohesion: 0.10
Nodes (6): Host, actions, dev, name_, plan_, room_

### Community 42 - "SimSetupSink"
Cohesion: 0.13
Nodes (7): SimSetupSink, editToken_, logger_, pass_, ssid_, token_, tokenProblem()

### Community 43 - "PeerEntry"
Cohesion: 0.17
Nodes (12): PeerEntry, boot, ctr, did, ip, lastSeenMs, pmin, port (+4 more)

### Community 44 - "Override"
Cohesion: 0.09
Nodes (15): clampedInt(), Override, dirty, force, hasIdentity, hasPlan, hasRiddle, name (+7 more)

### Community 45 - "test_sim.py"
Cohesion: 0.13
Nodes (13): free_http_port(), test_begin_twice_close_twice_and_context_manager(), Sim, sim_factory(), factory(), test_battery_zero_is_not_reported_and_html_state(), test_config_and_identity_persist_across_restarts(), test_default_token_state_without_token_option() (+5 more)

### Community 46 - "HttpClient"
Cohesion: 0.09
Nodes (19): 5.6 Error body, HttpClient, body_, contentLength_, deadlineMs_, fd_, head_, maxBody_ (+11 more)

### Community 47 - ".find"
Cohesion: 0.17
Nodes (18): copyBounded(), isChangeBroadcastDue(), isHeartbeatDue(), info(), isCode(), parseObj(), test_action(), test_config_is_atomic() (+10 more)

### Community 48 - "FakeSink"
Cohesion: 0.11
Nodes (9): FakeSink, applied, last, open, phase, result, ssid, viaNetwork (+1 more)

### Community 49 - "HttpServer"
Cohesion: 0.13
Nodes (6): errorCodeFor(), HttpHandler, HttpServer, connections_, handler_, listenFd_

### Community 50 - "DeviceInfo"
Cohesion: 0.10
Nodes (17): DeviceInfo, battery, boot, did, edit, ip, nowMs, port (+9 more)

### Community 52 - "Any"
Cohesion: 0.28
Nodes (5): _Dom, json_text_loose(), JsonError, number_text(), parse_json()

### Community 53 - "__init__.py"
Cohesion: 0.05
Nodes (11): 6. Limits (`EscapeConfig`, mirrored in `/security.json` `limits`), BlobStorage, _default_state_dir(), EscapeConfig, FileStorage, MemoryStorage, SetupChange, SetupResult (+3 more)

### Community 54 - "test_device.cpp"
Cohesion: 0.32
Nodes (19): bodyOf(), http(), options(), pump(), statusOf(), test_discovery_and_authenticated_reads(), test_edit_proof_endpoint(), test_edit_token_guards_sending_plans() (+11 more)

### Community 55 - "client.cpp"
Cohesion: 0.18
Nodes (9): EscapeComponent::Host::applyAction(), EscapeComponent::Host::applyPlanAction(), EscapeComponent::Host::identity(), EscapeComponent::Host::pushEvent(), EscapeComponent::Host::setCustomConfigValue(), EscapeComponent::Host::setIdentity(), EscapeComponent::Host::setPlan(), EscapeComponent::Host::setRiddleId() (+1 more)

### Community 56 - "DevicePlatform"
Cohesion: 0.10
Nodes (8): Device::Device(), DevicePlatform, SerialPlatform, broadcast_, ip_, SimPlatform, broadcast_, ip_

### Community 57 - "MemoryStorage"
Cohesion: 0.10
Nodes (6): BlobStorage, MemoryStorage, capacity_, data_, failWrites_, writes_

### Community 58 - "SimHost"
Cohesion: 0.14
Nodes (7): logSetup(), SimHost, battery_, comps, device, didText, htmlState

### Community 59 - "test_base64.cpp"
Cohesion: 0.08
Nodes (18): runBase64Tests(), runCryptoTests(), runFuzzTests(), runHttpTests(), runJsonTests(), main(), runAll(), setUp() (+10 more)

### Community 60 - "test_fuzz.cpp"
Cohesion: 0.17
Nodes (12): jsonCorpus(), makeTransport(), mutate(), Rng, s, test_announcements_under_mutation(), test_handlers_survive_mutated_bodies(), test_json_dom_and_scanner_agree_under_mutation() (+4 more)

### Community 61 - "test_json.cpp"
Cohesion: 0.18
Nodes (15): parse(), ParseLimits, maxDepth, maxNodes, ok(), test_as_int(), test_duplicate_keys_first_wins(), test_escape_output() (+7 more)

### Community 62 - "escape_component_sim.cpp"
Cohesion: 0.14
Nodes (8): main(), editToken, token, parseArgs(), readFile(), sha256Hex8(), usageText(), broadcastForIp()

### Community 63 - "SecureTransport.cpp"
Cohesion: 0.32
Nodes (3): constantTimeEqual(), decimal(), isEditPath()

### Community 64 - "selfupgrade.test.mjs"
Cohesion: 0.13
Nodes (9): managerHtml, buildNewerSimulator(), executablePath, html, net, stub(), walk(), b64u() (+1 more)

### Community 65 - "hw_smoke.mjs"
Cohesion: 0.17
Nodes (16): SECRET_EDIT_TOKEN, args, check(), devs, hostileChecks(), mdnsCheck(), pair(), perDevice() (+8 more)

### Community 66 - "u32"
Cohesion: 0.06
Nodes (14): Announcement, build_announcement_doc(), build_mdns_answer(), is_change_broadcast_due(), is_edit_path(), is_heartbeat_due(), mdns_response_delay_ms(), OpenResult (+6 more)

### Community 67 - "Vec"
Cohesion: 0.10
Nodes (20): Vec, getDoc, getFrame, getNonce, getPath, kMac, kReq, kResp (+12 more)

### Community 68 - "escape_component_sim.py"
Cohesion: 0.07
Nodes (10): 5.2 `/status.json` DOC, build_parser(), load_config(), set_config(), parse_component(), main(), read_ui(), save_config() (+2 more)

### Community 69 - "Value"
Cohesion: 0.15
Nodes (14): appendInt(), appendInt64(), appendNumber(), appendUtf8(), stringify(), stringifyInto(), Value, arrayValue (+6 more)

### Community 70 - "Node"
Cohesion: 0.22
Nodes (6): Node, crypto, device, host, platform, storage

### Community 71 - "helpers.mjs"
Cohesion: 0.12
Nodes (9): freePort(), PORT_BASE, portFree(), root, running, simBinary, startSim(), taken (+1 more)

### Community 73 - "pytest"
Cohesion: 0.10
Nodes (9): component(), vectors(), test_base64url_is_strict(), test_hkdf_rfc5869(), isolated_sims(), Sims, up(), test_dom_limits() (+1 more)

### Community 75 - "test_store.cpp"
Cohesion: 0.15
Nodes (11): fnv1a32(), emacOf(), FakeSigner, enabled, makeBlob(), test_adopt_equal_rev_tiebreak_converges(), test_adopt_needs_valid_mac_with_edit_token(), test_adopt_rules() (+3 more)

### Community 76 - "cstring"
Cohesion: 0.15
Nodes (4): MbedTlsCryptoBackend, ByteRange, data, length

### Community 77 - "CryptoBackend"
Cohesion: 0.13
Nodes (6): CryptoBackend, editStateName(), hkdfSha256(), SecureTransport::SecureTransport(), secureZero(), tokenStateName()

### Community 78 - "hw_wrap_test.mjs"
Cohesion: 0.12
Nodes (12): A, B, b64u(), envBefore, idle, idleStart, idx, [ipA, ipB] (+4 more)

### Community 80 - "base64UrlEncode"
Cohesion: 0.18
Nodes (8): base64UrlDecode(), base64UrlDecodedLength(), base64UrlEncode(), decodeChar(), hexEncode(), KeyRole, Edit, Normal

### Community 81 - "Announcement"
Cohesion: 0.12
Nodes (17): AnnouncedSkeleton, hash, rev, roomKey, Announcement, boot, ctr, did (+9 more)

### Community 82 - "manager/setup.test.mjs"
Cohesion: 0.21
Nodes (5): b64u(), connect(), DEFAULT_TOKEN, keySet(), TestDevice

### Community 85 - "HttpRequest"
Cohesion: 0.07
Nodes (24): HttpRequest, body, contentLength, expectContinue, ifNoneMatch, method, origin, path (+16 more)

### Community 86 - "validate_setup_change"
Cohesion: 0.22
Nodes (6): is_setup_network_name(), _text_bytes(), valid_setup_token(), valid_wifi_password(), valid_wifi_ssid(), validate_setup_change()

### Community 87 - "Options"
Cohesion: 0.12
Nodes (16): Options, battery, broadcast, did, htmlState, httpPort, ip, managerHtml (+8 more)

### Community 88 - "Enum"
Cohesion: 0.09
Nodes (13): build_components_doc(), build_security_doc(), build_status_doc(), _clean(), _common_device_fields(), derive_keys(), DerivedKeys, DeviceInfo (+5 more)

### Community 89 - "Http.cpp"
Cohesion: 0.23
Nodes (12): formatResponseHead(), hexVal(), iequals(), originAllowed(), percentDecode(), queryParam(), statusText(), trim() (+4 more)

### Community 90 - "test_http.cpp"
Cohesion: 0.12
Nodes (22): HttpRequestParser, head_, req_, State, Body, Done, Error, Headers (+14 more)

### Community 92 - "Setup.cpp"
Cohesion: 0.39
Nodes (12): formValue(), isSetupNetworkName(), parseSetupForm(), parseSetupJson(), printable(), redirectTarget(), setupNetworkName(), validateSetupChange() (+4 more)

### Community 93 - "Options"
Cohesion: 0.13
Nodes (15): Options, baud, broadcast, did, editToken, httpPort, ip, managerHtml (+7 more)

### Community 95 - "DummyComponent"
Cohesion: 0.19
Nodes (11): DummyComponent, brightness, difficulty, errorActive, extra, label, step, initCustomConfig() (+3 more)

### Community 96 - "HostNetwork.hpp"
Cohesion: 0.15
Nodes (6): detectLanInterface(), HostInterface, broadcast, ip, name, routedSourceIp()

### Community 97 - "gen_vectors.mjs"
Cohesion: 0.15
Nodes (6): hkdf(), keysFor(), RFC-5869, out, root, targets

### Community 98 - "build_manager_crypto.mjs"
Cohesion: 0.15
Nodes (11): check, code, end, fail(), html, htmlFile, installed(), pkg (+3 more)

### Community 99 - "setup/setup.test.mjs"
Cohesion: 0.16
Nodes (8): executablePath, FAST, here, installFakeBoard(), receive(), respond(), L, open()

### Community 100 - "parse_announcement"
Cohesion: 0.11
Nodes (11): AnnouncedSkeleton, _detect_lan_interface(), _detect_local_ip(), _directed_broadcast_for(), ipv4_to_str(), json_int(), _linux_ipv4_interfaces(), parse_announcement() (+3 more)

### Community 101 - "EscapeManager wire protocol, level 2 ("proto 2")"
Cohesion: 0.05
Nodes (34): 1. Verified on hardware, 2. Bugs the hardware work found (all fixed, with tests where they can run on the PC), 3. Still open (needs equipment or access I did not have), 4. Deliberately postponed / not implemented, 5. Not hardware related, Functional, HARDWARE_TODO – hardware verification record and what is still open, Resources (esp-dummy, 240 MHz) (+26 more)

### Community 102 - "SimComponent"
Cohesion: 0.14
Nodes (14): SimComponent, brightness, difficulty, errorActive, eventMsg, eventSeq, label, name (+6 more)

### Community 103 - "Sink"
Cohesion: 0.16
Nodes (5): Sink, applied, last, tokens, viaNetwork

### Community 104 - "crypto.test.mjs"
Cohesion: 0.15
Nodes (8): RFC-4231, code, context, end, html, root, start, vectors

### Community 105 - "manager/package.json"
Cohesion: 0.15
Nodes (12): playwright-core, loadPlaywright(), description, devDependencies, playwright-core, main, name, private (+4 more)

### Community 106 - "DeviceOptions"
Cohesion: 0.15
Nodes (12): DeviceOptions, bootCounter, did, dnsPort, httpPort, mdnsHostname, mdnsPort, udpPort (+4 more)

### Community 107 - "test_setup.cpp"
Cohesion: 0.22
Nodes (9): buildDnsAnswer(), request(), test_dns_answers_everything_with_the_portal_address(), test_dns_ignores_garbage(), test_portal_pages(), test_portal_redirects_captive_probes(), test_portal_save(), test_portal_status_page() (+1 more)

### Community 108 - "http_get"
Cohesion: 0.24
Nodes (3): EditTokenTests, http_get(), NetworkTests

### Community 110 - "TestHandler"
Cohesion: 0.15
Nodes (5): TestHandler, big, handled, lastBody, lastOrigin

### Community 111 - "HttpResponse"
Cohesion: 0.22
Nodes (6): HttpRequest, HttpResponse, percent_decode(), _plain_error(), query_param(), valid_nonce()

### Community 112 - "RateLimiter"
Cohesion: 0.17
Nodes (9): RateLimiter, slots_, windowCount_, windowStart_, Slot, lastMs, source, tokens (+1 more)

### Community 113 - "_Http"
Cohesion: 0.16
Nodes (6): _Http, HttpHandler, Method, parse_request_head(), RouteInfo, _valid_target()

### Community 116 - "build_ui.py"
Cohesion: 0.11
Nodes (6): deterministic_gzip(), generate(), is_current(), render_cpp(), set_root(), ui_hash()

### Community 117 - "test_device_storage.py"
Cohesion: 0.21
Nodes (4): check(), FakeBoard, main(), run_env()

### Community 120 - "handleSetupPortal"
Cohesion: 0.40
Nodes (6): appendHtml(), formPage(), handleSetupPortal(), page(), phaseText(), statusPage()

### Community 121 - "LineFramer"
Cohesion: 0.20
Nodes (9): LineFramer, buf_, kMaxLine, mode_, oversize_, Mode, Collect, Discard (+1 more)

### Community 123 - "Mdns.hpp"
Cohesion: 0.19
Nodes (11): buildMdnsAnswer(), lower(), MdnsQuery, matches, suppressed, unicast, parseMdnsQuery(), rd16() (+3 more)

### Community 124 - "Device.cpp"
Cohesion: 0.14
Nodes (3): eqPath(), urlEncode(), ipToString()

### Community 125 - "SyncRequest"
Cohesion: 0.22
Nodes (7): SyncRequest, did, ip, pending, port, room, roomKey

### Community 127 - "EscapeManager"
Cohesion: 0.18
Nodes (9): Browsing the code (graphify), Development, EscapeManager, Mixed versions, Quick start, Repository layout, Security in one page, The flow plan ("Ablaufplan") (+1 more)

### Community 128 - "Result"
Cohesion: 0.18
Nodes (11): Result, Conflict, Invalid, KeyCollision, NotNewer, RoomLimit, StorageError, Stored (+3 more)

### Community 132 - "Client"
Cohesion: 0.25
Nodes (5): Client, crypto, did, lastRole, tr

### Community 133 - "Warn"
Cohesion: 0.29
Nodes (7): Warn, WarnBadJson, WarnBadState, WarnCount, WarnOversize, WarnQueue, WarnSave

### Community 136 - "setup/package.json"
Cohesion: 0.29
Nodes (6): description, main, name, private, type, version

### Community 138 - "find_fields"
Cohesion: 0.22
Nodes (6): find_field(), find_fields(), Scan, _scan_string(), _skip_value(), _unescape()

### Community 141 - "Platform"
Cohesion: 0.22
Nodes (4): Platform, setup, setupClient, up

### Community 142 - "Type"
Cohesion: 0.33
Nodes (6): Type, Array, Bool, Null, Number, Object

### Community 143 - "Known"
Cohesion: 0.33
Nodes (5): Known, id, name, riddle, room

### Community 145 - "SkeletonInfo"
Cohesion: 0.33
Nodes (5): roomKey(), SkeletonInfo, hash, rev, room

### Community 147 - "DerivedKeys"
Cohesion: 0.40
Nodes (5): DerivedKeys, mac, master, req, resp

### Community 148 - "OpenResult"
Cohesion: 0.40
Nodes (4): OpenResult, code, role, status

### Community 151 - "Result"
Cohesion: 0.40
Nodes (5): Result, Accepted, BadSource, Own, Replay

### Community 152 - "Scan"
Cohesion: 0.50
Nodes (4): Scan, Found, Invalid, Missing

### Community 153 - "ReplayEntry"
Cohesion: 0.50
Nodes (4): ReplayEntry, expiresMs, iv, used

### Community 154 - "SetupResult"
Cohesion: 0.50
Nodes (4): SetupResult, Invalid, Ok, Storage

### Community 155 - "Throttle"
Cohesion: 0.50
Nodes (4): Throttle, lastMs, suppressed, used

### Community 157 - "RouteInfo"
Cohesion: 0.67
Nodes (3): RouteInfo, found, maxBody

### Community 158 - "PlanAction"
Cohesion: 0.67
Nodes (3): PlanAction, Complete, Reset

### Community 161 - "Resource behaviour (the library lives inside another program)"
Cohesion: 0.22
Nodes (3): Configuring Wi-Fi and tokens without reflashing, Resource behaviour (the library lives inside another program), Using the library in your own program

## Knowledge Gaps
- **696 isolated node(s):** `step`, `errorActive`, `brightness`, `label`, `difficulty` (+691 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1449 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **36 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `isolated_sims()` connect `pytest` to `em_client.mjs`, `test_sim.py`, `test_interop.py`?**
  _High betweenness centrality (0.065) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `Manager` (e.g. with `test_everything_works_with_the_clock_just_before_the_32_bit_wrap()` and `Sim`) actually correct?**
  _`Manager` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `step`, `errorActive`, `brightness` to the rest of the system?**
  _696 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `escape_component.py` be split into smaller, more focused modules?**
  _Cohesion score 0.06153846153846154 - nodes in this community are weakly interconnected._
- **Why does `random_did()` connect `em_client.mjs` to `test_http.py`, `test_persistence.py`?**
  _High betweenness centrality (0.054) - this node is a cross-community bridge._
- **Should `EscapeComponent` be split into smaller, more focused modules?**
  _Cohesion score 0.06866002214839424 - nodes in this community are weakly interconnected._
- **Why does `EscapeComponent` connect `EscapeComponent` to `escape_component.py`, `u32`, `parse_announcement`, `SkeletonStore`, `EscapeManager wire protocol, level 2 ("proto 2")`, `SecureTransport`, `.begin`, `ProtocolAdapter`, `HttpResponse`, `._sync_job`, `test_serial_host.py`, `__init__.py`, `Enum`, `wait_for`, `_Host`?**
  _High betweenness centrality (0.053) - this node is a cross-community bridge._