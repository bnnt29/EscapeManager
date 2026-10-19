# Graph Report - EscapeManager  (2026-10-19)

## Corpus Check
- 131 files · ~210,865 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 12 file(s) not represented in the graph (top: .ino 4, (none) 3, .ini 2)

## Summary
- 3383 nodes · 6746 edges · 158 communities (124 shown, 34 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 553 edges (avg confidence: 0.86)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4000cea5`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- escape_component.py
- SkeletonStore
- SketchConfig
- test_store.cpp
- Device
- test_esp/test_main.cpp
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
- SkeletonStore
- EscapeComponent
- device_storage.py
- em_client.mjs
- string
- EscapeComponent
- ComponentSnapshot
- wait_for
- SecureTransport
- .__init__
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
- _Host
- test_sim.py
- HttpClient
- .find
- FakeSink
- HttpServer
- DeviceInfo
- SimPuzzle
- Any
- SerialHost
- test_device.cpp
- client.cpp
- DevicePlatform
- MemoryStorage
- Override
- unity
- test_fuzz.cpp
- test_json.cpp
- SecureTransport.cpp
- demo.js
- hw_smoke.mjs
- string
- main
- escape_component_sim.py
- Value
- Node
- helpers.mjs
- .handleGet
- Vec
- TokenState
- SimHost
- MbedTlsCryptoBackend.cpp
- CryptoBackend
- hw_wrap_test.mjs
- Host
- base64UrlEncode
- Announcement
- manager/setup.test.mjs
- test_serial_host.py
- HttpRequest
- Response
- SyncRequest
- __init__.py
- Compat.hpp
- test_http.cpp
- ProtocolAdapter
- Setup.cpp
- vectors.hpp
- Options
- Options
- escape_component_serial_host.cpp
- build_manager_crypto.mjs
- setup/setup.test.mjs
- SimComponent
- EscapeManager wire protocol, level 2 ("proto 2")
- .online
- Sink
- crypto.test.mjs
- manager/package.json
- DeviceOptions
- test_setup.cpp
- http_get
- FakeArduino
- TestHandler
- cstring
- RateLimiter
- runDeviceTests
- Host
- _Http
- build_ui.py
- sys
- selfupgrade.test.mjs
- HardwareEsp32.cpp
- gen_vectors.mjs
- LineFramer
- Mdns.hpp
- Device.cpp
- .start
- EscapeManager
- FileStorage
- escape_component_sim.cpp
- Warn
- CommandLineTests
- Client
- .processSerialLine
- Cleanup
- ReconnectTests
- setup/package.json
- Known
- HttpServer
- SimSetupSink
- NvsBlobs
- Platform
- Type
- DerivedKeys
- OpenResult
- Scan
- ReplayEntry
- SetupResult
- EscapeComponent::Host::customConfigDefs
- RouteInfo
- PlanAction
- run_serial_host.sh
- run_sim.sh
- Resource behaviour (the library lives inside another program)
- helpers.py
- EscapeManager

## God Nodes (most connected - your core abstractions)
1. `HardwareEsp32` - 98 edges
2. `Device` - 87 edges
3. `EscapeComponent` - 71 edges
4. `Manager` - 64 edges
5. `SerialHost` - 62 edges
6. `EscapeComponent` - 49 edges
7. `SecureTransport` - 49 edges
8. `SerialLink` - 43 edges
9. `SketchConfig` - 39 edges
10. `get()` - 39 edges

## Surprising Connections (you probably didn't know these)
- `6. Limits (`EscapeConfig`, mirrored in `/security.json` `limits`)` --references--> `EscapeConfig`  [INFERRED]
  PROTOCOL.md → extras/python/escape_component.py
- `test_setup_json()` --calls--> `parseSetupJson()`  [INFERRED]
  test/test_core/test_setup.cpp → src/protocol/Setup.cpp
- `Library pieces (all importable from `escape_component`)` --references--> `derive_keys()`  [INFERRED]
  extras/python/README.md → extras/python/escape_component.py
- `tokenProblem()` --calls--> `validSetupToken()`  [INFERRED]
  extras/sim/SimSetupSink.hpp → src/protocol/Setup.cpp
- `main()` --calls--> `nowMillis()`  [INFERRED]
  extras/sim/escape_component_serial_host.cpp → src/net/Clock.hpp

## Import Cycles
- None detected.

## Communities (158 total, 34 thin omitted)

### Community 0 - "escape_component.py"
Cohesion: 0.05
Nodes (58): _clean(), is_setup_network_name(), json_escape(), _lower_ascii(), MdnsQuery, parse_mdns_query(), _read_name(), setup_network_name() (+50 more)

### Community 1 - "SkeletonStore"
Cohesion: 0.07
Nodes (26): fnv1a32(), hex8(), parseHex8(), Result, Conflict, Invalid, KeyCollision, NotNewer (+18 more)

### Community 2 - "SketchConfig"
Cohesion: 0.11
Nodes (19): registerSketchConfig(), SketchConfig, allowWifiSleep, authInvalid, authToken, buttonPin, buttonPinSet, deferred (+11 more)

### Community 3 - "test_store.cpp"
Cohesion: 0.14
Nodes (10): emacOf(), FakeSigner, enabled, makeBlob(), test_adopt_equal_rev_tiebreak_converges(), test_adopt_needs_valid_mac_with_edit_token(), test_adopt_rules(), test_put_get_and_blob_format() (+2 more)

### Community 4 - "Device"
Cohesion: 0.04
Nodes (39): Device, begun_, client_, ctr_, didBytes_, dirty_, dns_, dnsTried_ (+31 more)

### Community 5 - "test_esp/test_main.cpp"
Cohesion: 0.18
Nodes (10): expectEdit(), expectToken(), runAll(), setUp(), test_edit_token_precedence(), test_invalid_sketch_token_is_never_replaced_by_something_weaker(), test_registering_defines_ignores_empty_values(), test_setup_network_password_precedence() (+2 more)

### Community 6 - "HardwareEsp32"
Cohesion: 0.04
Nodes (43): HardwareEsp32, _apAuto, _apBlocked, _apClients, _apName, _apPassword, _apUp, _attemptArmed (+35 more)

### Community 7 - "test_protocol.py"
Cohesion: 0.06
Nodes (23): FakeHost, info(), is_code(), test_action(), test_action_length_limit_counts_bytes(), test_config_is_atomic(), test_config_numbers_booleans_and_null_follow_the_loose_text_rules(), test_peers_doc() (+15 more)

### Community 8 - "SerialLink"
Cohesion: 0.07
Nodes (26): logMsg(), logSetup(), SerialLink, atLineStart_, baud_, fails_, fd_, framer_ (+18 more)

### Community 9 - "test_http.py"
Cohesion: 0.09
Nodes (35): exchange(), get(), parse_http(), read_all(), test_edit_proof_endpoint(), test_get_without_nonce_in_strict_mode(), connect(), test_authenticated_get_frames_and_viewer_mode() (+27 more)

### Community 10 - "ProtocolAdapter"
Cohesion: 0.05
Nodes (32): AnnouncedSkeleton, _as_bytes(), b64u_decode(), error_result(), find_fields(), handle_action(), handle_config(), handle_plan() (+24 more)

### Community 11 - "FakeHost"
Cohesion: 0.07
Nodes (20): FakeHost, actionResult, actionsApplied, battery_, cfg, count, dirty, events (+12 more)

### Community 12 - "Manager"
Cohesion: 0.06
Nodes (32): Manager, RecordingSink, collect(), listen_udp(), sealed_with(), test_announcements_on_the_wire(), test_change_broadcast_has_a_minimum_gap_and_heartbeat_is_periodic(), test_concurrent_identical_envelopes_are_accepted_exactly_once() (+24 more)

### Community 13 - "test_interop.py"
Cohesion: 0.12
Nodes (18): finish(), isolated_sims(), node_client(), node_process(), Sims, test_action_post_works_against_the_python_simulator(), test_both_simulators_report_the_same_document_shapes(), test_command_handlers_answer_exactly_like_the_cpp_reference() (+10 more)

### Community 14 - "test_crypto.py"
Cohesion: 0.07
Nodes (30): begun(), begun_edit(), test_announcement_frames(), test_base64url_vectors(), test_begin_resets_everything_when_the_tokens_change(), test_clock_wraparound(), test_document_frames(), test_edit_check_order_matches_the_reference() (+22 more)

### Community 15 - "test_persistence.py"
Cohesion: 0.17
Nodes (14): make_component(), random_did(), test_begin_raises_oserror_if_the_http_port_is_taken_and_leaves_nothing_open(), test_component_limit_and_ignored_ids(), test_loop_before_begin_is_a_noop(), start(), test_boot_counter_increments_once_per_start_and_did_and_riddle_are_stable(), test_damaged_state_does_not_prevent_starting() (+6 more)

### Community 16 - "Json.cpp"
Cohesion: 0.12
Nodes (29): Cursor, i, n, s, DomParser, c_, limits_, nodes_ (+21 more)

### Community 17 - "Protocol.cpp"
Cohesion: 0.16
Nodes (29): appendEscaped(), appendUInt(), appendCommonDeviceFields(), appendStr(), buildComponentsDoc(), buildPeersDoc(), buildSecurityDoc(), buildSkeletonIndexDoc() (+21 more)

### Community 18 - "test_store.py"
Cohesion: 0.10
Nodes (19): blob_with_emac(), emac_of(), fake_mac(), FakeSigner, make_blob(), test_adopt_emac_shape_rules(), test_adopt_equal_rev_tiebreak_converges(), test_adopt_needs_valid_mac_with_edit_token() (+11 more)

### Community 19 - "bare_status"
Cohesion: 0.18
Nodes (9): BackpressureTests, probe(), bare_status(), CommandTests, PersistenceTests, RobustnessTests, rss_kb(), SerialHostTestCase (+1 more)

### Community 20 - "SetupChange"
Cohesion: 0.06
Nodes (19): SetupChange, editToken, hasEditToken, hasToken, hasWifi, pass, ssid, token (+11 more)

### Community 21 - "entry.js"
Cohesion: 0.08
Nodes (30): esbuild, @noble/ciphers, @noble/hashes, B64U_INDEX, b64uEncode(), constantTimeEqual(), deriveEditKeys(), deriveKeys() (+22 more)

### Community 22 - "SkeletonStore"
Cohesion: 0.07
Nodes (17): build_announcement_doc(), build_skeleton_index_doc(), fnv1a32(), hex8(), _is_http_url(), json_validate(), jstr(), parse_hex8() (+9 more)

### Community 23 - "EscapeComponent"
Cohesion: 0.04
Nodes (19): build_components_doc(), build_peers_doc(), build_security_doc(), build_status_doc(), _common_device_fields(), _Component, DeviceInfo, EscapeComponent (+11 more)

### Community 24 - "device_storage.py"
Cohesion: 0.11
Nodes (21): _auth_token(), _b64(), _clear_edit_token(), _device_info(), _device_port(), _edit_token(), _project_option(), _reset_persistent_storage() (+13 more)

### Community 25 - "em_client.mjs"
Cohesion: 0.10
Nodes (16): b64u(), DEFAULT_TOKEN, Device, main(), SECRET_TOKEN, args, bProof, fresh() (+8 more)

### Community 26 - "string"
Cohesion: 0.21
Nodes (4): decodeBase64(), HardwareEsp32::NvsBlobs::read(), HardwareEsp32::NvsBlobs::write(), printableToken()

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
Cohesion: 0.09
Nodes (17): EditState, Custom, Invalid, Unset, SecureTransport, began_, did_, edit_ (+9 more)

### Community 31 - ".__init__"
Cohesion: 0.05
Nodes (17): Announcement, build_mdns_answer(), _default_state_dir(), _detect_lan_interface(), _detect_local_ip(), _directed_broadcast_for(), IngestResult, ipv4_to_str() (+9 more)

### Community 32 - "test_crypto.cpp"
Cohesion: 0.12
Nodes (18): hexDecode(), beginWith(), beginWithEdit(), hexOf(), test_announcement_frames(), test_clock_wraparound(), test_document_frames(), test_edit_envelope_vectors() (+10 more)

### Community 33 - "LocalComponent"
Cohesion: 0.08
Nodes (18): EscapeComponent::Host::snapshot(), LocalComponent, actionHandler, actionsCb, customConfigCb, customConfigSetCb, errorsCb, eventMsg (+10 more)

### Community 34 - "test_net.cpp"
Cohesion: 0.19
Nodes (14): nowMicros(), nowMillis(), body(), connectTo(), exchange(), test_back_to_back_rejections_never_get_503(), test_client_deadline_on_silent_server(), test_early_rejection_is_delivered_even_with_unsent_body() (+6 more)

### Community 35 - "Net.cpp"
Cohesion: 0.15
Nodes (9): headerValue(), ipToString(), makeAddress(), setNonBlocking(), UdpSocket, fd_, wouldBlock(), test_mdns_shared_record() (+1 more)

### Community 36 - "Peers.cpp"
Cohesion: 0.16
Nodes (18): roomKey, buildAnnouncementDoc(), didToText(), fieldHex8(), fieldText(), fieldUInt(), ipv4ToU32(), parseAnnouncement() (+10 more)

### Community 37 - "HttpServer::Connection"
Cohesion: 0.07
Nodes (26): HttpServer::Connection, body, continueSent, drained, drainStartMs, fd, gotBytes, head (+18 more)

### Community 38 - "SecureTransport"
Cohesion: 0.07
Nodes (4): b64u_encode(), KeyRole, SecureTransport, SkeletonSigner

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
Cohesion: 0.08
Nodes (19): PeerEntry, boot, ctr, did, ip, lastSeenMs, pmin, port (+11 more)

### Community 44 - "_Host"
Cohesion: 0.11
Nodes (5): bounded(), CustomConfigDef, _Host, normalize_config_def(), validate_custom_config_value()

### Community 45 - "test_sim.py"
Cohesion: 0.14
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

### Community 53 - "SerialHost"
Cohesion: 0.06
Nodes (26): SerialHost, device_, did_, kMinGetStateGapMs, known_, kOfflineMs, kPollMs, kRetryMs (+18 more)

### Community 54 - "test_device.cpp"
Cohesion: 0.32
Nodes (19): bodyOf(), http(), options(), pump(), statusOf(), test_discovery_and_authenticated_reads(), test_edit_proof_endpoint(), test_edit_token_guards_sending_plans() (+11 more)

### Community 55 - "client.cpp"
Cohesion: 0.14
Nodes (9): EscapeComponent::Host::applyAction(), EscapeComponent::Host::applyPlanAction(), EscapeComponent::Host::identity(), EscapeComponent::Host::pushEvent(), EscapeComponent::Host::setCustomConfigValue(), EscapeComponent::Host::setIdentity(), EscapeComponent::Host::setPlan(), EscapeComponent::Host::setRiddleId() (+1 more)

### Community 56 - "DevicePlatform"
Cohesion: 0.10
Nodes (8): SerialPlatform, broadcast_, ip_, SimPlatform, broadcast_, ip_, Device::Device(), DevicePlatform

### Community 57 - "MemoryStorage"
Cohesion: 0.10
Nodes (6): BlobStorage, MemoryStorage, capacity_, data_, failWrites_, writes_

### Community 58 - "Override"
Cohesion: 0.13
Nodes (13): clampedInt(), Override, dirty, force, hasIdentity, hasPlan, hasRiddle, name (+5 more)

### Community 59 - "unity"
Cohesion: 0.11
Nodes (12): runBase64Tests(), runCryptoTests(), runFuzzTests(), runHttpTests(), runJsonTests(), main(), runAll(), setUp() (+4 more)

### Community 60 - "test_fuzz.cpp"
Cohesion: 0.18
Nodes (13): jsonCorpus(), makeTransport(), mutate(), Rng, s, test_announcements_under_mutation(), test_handlers_survive_mutated_bodies(), test_http_parser_under_mutation() (+5 more)

### Community 61 - "test_json.cpp"
Cohesion: 0.19
Nodes (15): parse(), ParseLimits, maxDepth, maxNodes, ok(), test_as_int(), test_duplicate_keys_first_wins(), test_escape_output() (+7 more)

### Community 63 - "SecureTransport.cpp"
Cohesion: 0.29
Nodes (3): constantTimeEqual(), decimal(), isEditPath()

### Community 64 - "demo.js"
Cohesion: 0.14
Nodes (26): fleet(), changed(), componentDoc(), configOf(), deviceFetch(), doAction(), doConfig(), doPlanAction() (+18 more)

### Community 65 - "hw_smoke.mjs"
Cohesion: 0.17
Nodes (16): SECRET_EDIT_TOKEN, args, check(), devs, hostileChecks(), mdnsCheck(), pair(), perDevice() (+8 more)

### Community 66 - "string"
Cohesion: 0.17
Nodes (9): defaultStateDir(), deriveDid(), exeDir(), FileStorage, dir_, main(), token, readFile() (+1 more)

### Community 67 - "main"
Cohesion: 0.32
Nodes (6): main(), editToken, token, readFile(), sha256Hex8(), broadcastForIp()

### Community 68 - "escape_component_sim.py"
Cohesion: 0.18
Nodes (7): build_parser(), load_config(), set_config(), parse_component(), main(), read_ui(), save_config()

### Community 69 - "Value"
Cohesion: 0.14
Nodes (14): appendInt(), appendInt64(), appendNumber(), appendUtf8(), stringify(), stringifyInto(), Value, arrayValue (+6 more)

### Community 70 - "Node"
Cohesion: 0.22
Nodes (6): Node, crypto, device, host, platform, storage

### Community 71 - "helpers.mjs"
Cohesion: 0.12
Nodes (9): freePort(), PORT_BASE, portFree(), root, running, simBinary, startSim(), taken (+1 more)

### Community 73 - "Vec"
Cohesion: 0.10
Nodes (20): Vec, getDoc, getFrame, getNonce, getPath, kMac, kReq, kResp (+12 more)

### Community 74 - "TokenState"
Cohesion: 0.40
Nodes (4): TokenState, Custom, Default, Invalid

### Community 75 - "SimHost"
Cohesion: 0.14
Nodes (7): logSetup(), SimHost, battery_, comps, device, didText, htmlState

### Community 76 - "MbedTlsCryptoBackend.cpp"
Cohesion: 0.10
Nodes (5): OpenSslCryptoBackend, MbedTlsCryptoBackend, ByteRange, data, length

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
Cohesion: 0.16
Nodes (9): deriveKeys(), b64u(), connect(), DEFAULT_TOKEN, keySet(), TestDevice, managerHtml, b64u() (+1 more)

### Community 85 - "HttpRequest"
Cohesion: 0.07
Nodes (24): HttpRequest, body, contentLength, expectContinue, ifNoneMatch, method, origin, path (+16 more)

### Community 87 - "SyncRequest"
Cohesion: 0.25
Nodes (6): SyncRequest, did, ip, pending, port, room

### Community 88 - "__init__.py"
Cohesion: 0.03
Nodes (20): BlobStorage, ComponentSnapshot, derive_keys(), DerivedKeys, EditState, EscapeConfig, FileStorage, find_field() (+12 more)

### Community 90 - "test_http.cpp"
Cohesion: 0.12
Nodes (21): HttpRequestParser, head_, req_, State, Body, Done, Error, Headers (+13 more)

### Community 92 - "Setup.cpp"
Cohesion: 0.24
Nodes (18): appendHtml(), formPage(), formValue(), handleSetupPortal(), isSetupNetworkName(), page(), parseSetupForm(), parseSetupJson() (+10 more)

### Community 93 - "vectors.hpp"
Cohesion: 0.29
Nodes (6): B64, hex, text, Fnv, hash, text

### Community 94 - "Options"
Cohesion: 0.12
Nodes (16): Options, battery, broadcast, did, htmlState, httpPort, ip, managerHtml (+8 more)

### Community 95 - "Options"
Cohesion: 0.13
Nodes (15): Options, baud, broadcast, did, editToken, httpPort, ip, managerHtml (+7 more)

### Community 96 - "escape_component_serial_host.cpp"
Cohesion: 0.09
Nodes (4): baudConstant(), feed(), mkdirs(), parseArgs()

### Community 98 - "build_manager_crypto.mjs"
Cohesion: 0.15
Nodes (11): check, code, end, fail(), html, htmlFile, installed(), pkg (+3 more)

### Community 99 - "setup/setup.test.mjs"
Cohesion: 0.16
Nodes (8): executablePath, FAST, here, installFakeBoard(), receive(), respond(), L, open()

### Community 100 - "SimComponent"
Cohesion: 0.14
Nodes (14): SimComponent, brightness, difficulty, errorActive, eventMsg, eventSeq, label, name (+6 more)

### Community 101 - "EscapeManager wire protocol, level 2 ("proto 2")"
Cohesion: 0.07
Nodes (26): Constructor, Python implementation (proto 2), Simulator, Tests, Threading and robustness, Using it, 1. Compatibility contract, 2. Identity and counters (+18 more)

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
Cohesion: 0.12
Nodes (15): DeviceOptions, bootCounter, did, dnsPort, httpPort, mdnsHostname, mdnsPort, setupData (+7 more)

### Community 107 - "test_setup.cpp"
Cohesion: 0.22
Nodes (9): buildDnsAnswer(), request(), test_dns_answers_everything_with_the_portal_address(), test_dns_ignores_garbage(), test_portal_pages(), test_portal_redirects_captive_probes(), test_portal_save(), test_portal_status_page() (+1 more)

### Community 108 - "http_get"
Cohesion: 0.24
Nodes (3): EditTokenTests, http_get(), NetworkTests

### Community 110 - "TestHandler"
Cohesion: 0.15
Nodes (5): TestHandler, big, handled, lastBody, lastOrigin

### Community 111 - "cstring"
Cohesion: 0.22
Nodes (10): formatResponseHead(), hexVal(), iequals(), originAllowed(), percentDecode(), statusText(), trim(), validTarget() (+2 more)

### Community 112 - "RateLimiter"
Cohesion: 0.17
Nodes (9): RateLimiter, slots_, windowCount_, windowStart_, Slot, lastMs, source, tokens (+1 more)

### Community 115 - "_Http"
Cohesion: 0.16
Nodes (6): _Http, HttpHandler, Method, parse_request_head(), RouteInfo, _valid_target()

### Community 116 - "build_ui.py"
Cohesion: 0.26
Nodes (8): deterministic_gzip(), generate(), is_current(), page_current(), render_array(), render_cpp(), set_root(), ui_hash()

### Community 118 - "selfupgrade.test.mjs"
Cohesion: 0.08
Nodes (9): NAMES, executablePath, openPage(), buildNewerSimulator(), executablePath, html, net, stub() (+1 more)

### Community 119 - "HardwareEsp32.cpp"
Cohesion: 0.14
Nodes (3): due(), logLine(), onApStation()

### Community 120 - "gen_vectors.mjs"
Cohesion: 0.17
Nodes (6): hkdf(), keysFor(), RFC-5869, out, root, targets

### Community 121 - "LineFramer"
Cohesion: 0.20
Nodes (9): LineFramer, buf_, kMaxLine, mode_, oversize_, Mode, Collect, Discard (+1 more)

### Community 123 - "Mdns.hpp"
Cohesion: 0.19
Nodes (11): buildMdnsAnswer(), lower(), MdnsQuery, matches, suppressed, unicast, parseMdnsQuery(), rd16() (+3 more)

### Community 127 - "EscapeManager"
Cohesion: 0.11
Nodes (14): Arduino IDE (no PlatformIO needed), Boards that are not an ESP32, Browsing the code (graphify), Development, EscapeManager, Installation, License, Mixed versions (+6 more)

### Community 129 - "escape_component_sim.cpp"
Cohesion: 0.15
Nodes (8): parseArgs(), usageText(), detectLanInterface(), HostInterface, broadcast, ip, name, routedSourceIp()

### Community 130 - "Warn"
Cohesion: 0.29
Nodes (7): Warn, WarnBadJson, WarnBadState, WarnCount, WarnOversize, WarnQueue, WarnSave

### Community 132 - "Client"
Cohesion: 0.25
Nodes (5): Client, crypto, did, lastRole, tr

### Community 136 - "setup/package.json"
Cohesion: 0.29
Nodes (6): description, main, name, private, type, version

### Community 137 - "Known"
Cohesion: 0.33
Nodes (5): Known, id, name, riddle, room

### Community 138 - "HttpServer"
Cohesion: 0.11
Nodes (8): _Abort, _Connection, error_body(), _error_code_for(), format_response_head(), HttpServer, origin_allowed(), status_text()

### Community 141 - "Platform"
Cohesion: 0.22
Nodes (4): Platform, setup, setupClient, up

### Community 142 - "Type"
Cohesion: 0.33
Nodes (6): Type, Array, Bool, Null, Number, Object

### Community 147 - "DerivedKeys"
Cohesion: 0.40
Nodes (5): DerivedKeys, mac, master, req, resp

### Community 148 - "OpenResult"
Cohesion: 0.40
Nodes (4): OpenResult, code, role, status

### Community 152 - "Scan"
Cohesion: 0.50
Nodes (4): Scan, Found, Invalid, Missing

### Community 153 - "ReplayEntry"
Cohesion: 0.50
Nodes (4): ReplayEntry, expiresMs, iv, used

### Community 154 - "SetupResult"
Cohesion: 0.50
Nodes (4): SetupResult, Invalid, Ok, Storage

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
- **709 isolated node(s):** `ip`, `broadcast`, `name`, `token_`, `editToken_` (+704 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1487 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **34 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `isolated_sims()` connect `test_interop.py` to `escape_component.py`, `em_client.mjs`, `test_sim.py`?**
  _High betweenness centrality (0.074) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `Manager` (e.g. with `test_everything_works_with_the_clock_just_before_the_32_bit_wrap()` and `Sim`) actually correct?**
  _`Manager` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `ip`, `broadcast`, `name` to the rest of the system?**
  _709 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `escape_component.py` be split into smaller, more focused modules?**
  _Cohesion score 0.04675846242111302 - nodes in this community are weakly interconnected._
- **Why does `random_did()` connect `test_persistence.py` to `em_client.mjs`, `helpers.py`?**
  _High betweenness centrality (0.069) - this node is a cross-community bridge._
- **Should `SkeletonStore` be split into smaller, more focused modules?**
  _Cohesion score 0.07477288609364081 - nodes in this community are weakly interconnected._
- **Why does `SerialHost` connect `SerialHost` to `escape_component_serial_host.cpp`, `string`, `Warn`, `.online`, `SerialLink`, `Known`, `Override`?**
  _High betweenness centrality (0.049) - this node is a cross-community bridge._