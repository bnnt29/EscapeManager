# Graph Report - EscapeManager  (2026-10-19)

## Corpus Check
- 121 files · ~205,923 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 3, .ini 2, .csv 1)

## Summary
- 3288 nodes · 6548 edges · 155 communities (126 shown, 29 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 513 edges (avg confidence: 0.86)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `2b145723`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- escape_component.py
- SkeletonStore
- EscapeComponent
- HttpResponse
- Device
- SkeletonStore
- HardwareEsp32
- test_protocol.py
- SerialLink
- Manager
- ProtocolAdapter
- FakeHost
- test_device.py
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
- main
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
- UdpSocket
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
- Net.cpp
- DeviceInfo
- get
- Any
- .__init__
- test_device.cpp
- client.cpp
- DevicePlatform
- MemoryStorage
- SimHost
- test_base64.cpp
- test_fuzz.cpp
- test_json.cpp
- State
- SecureTransport.cpp
- selfupgrade.test.mjs
- hw_smoke.mjs
- PeerTable
- Vec
- escape_component_sim.py
- Value
- Node
- helpers.mjs
- isolated_sims
- TokenState
- test_store.cpp
- cstring
- CryptoBackend
- hw_wrap_test.mjs
- Host
- base64UrlEncode
- Announcement
- stub.mjs
- test_serial_host.py
- HttpResponse
- HttpHandler
- Options
- __init__.py
- Http.cpp
- test_http.cpp
- ProtocolAdapter
- Setup.cpp
- Options
- Response
- DummyComponent
- escape_component_serial_host.cpp
- gen_vectors.mjs
- setup/setup.test.mjs
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
- RateLimiter
- Host
- build_ui.py
- e2e.test.mjs
- .service
- handleSetupPortal
- LineFramer
- HttpServer
- Mdns.cpp
- Device.cpp
- SyncRequest
- .start
- EscapeManager
- Result
- SkeletonSigner
- CommandLineTests
- Client
- Warn
- Cleanup
- ReconnectTests
- setup/package.json
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
- EscapeComponent::Host::customConfigDefs
- RouteInfo
- PlanAction
- run_serial_host.sh
- run_sim.sh
- Resource behaviour (the library lives inside another program)
- helpers.py
- AGENTS.md
- arduino/README.md

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
- `test_query_and_percent_decoding()` --calls--> `queryParam()`  [INFERRED]
  test/test_core/test_http.cpp → src/protocol/Http.cpp
- `test_setup_json()` --calls--> `parseSetupJson()`  [INFERRED]
  test/test_core/test_setup.cpp → src/protocol/Setup.cpp
- `6. Limits (`EscapeConfig`, mirrored in `/security.json` `limits`)` --references--> `EscapeConfig`  [INFERRED]
  PROTOCOL.md → src/python/escape_component.py
- `test_client_deadline_on_silent_server()` --calls--> `nowMillis()`  [INFERRED]
  test/test_net/test_net.cpp → src/net/Clock.hpp
- `test_client_get()` --calls--> `nowMillis()`  [INFERRED]
  test/test_net/test_net.cpp → src/net/Clock.hpp

## Import Cycles
- None detected.

## Communities (155 total, 29 thin omitted)

### Community 0 - "escape_component.py"
Cohesion: 0.05
Nodes (59): derive_keys(), DerivedKeys, hkdf_sha256(), is_setup_network_name(), _lower_ascii(), MdnsQuery, parse_mdns_query(), _read_name() (+51 more)

### Community 1 - "SkeletonStore"
Cohesion: 0.18
Nodes (6): hex8(), parseHex8(), SkeletonStore, index_, signer_, validRoomName()

### Community 2 - "EscapeComponent"
Cohesion: 0.04
Nodes (9): build_mdns_answer(), _Component, EscapeComponent, run(), http_get(), is_change_broadcast_due(), is_heartbeat_due(), mdns_response_delay_ms() (+1 more)

### Community 3 - "HttpResponse"
Cohesion: 0.07
Nodes (18): _Abort, _Connection, error_body(), _error_code_for(), format_response_head(), _Http, HttpHandler, HttpRequest (+10 more)

### Community 4 - "Device"
Cohesion: 0.04
Nodes (39): Device, begun_, client_, ctr_, didBytes_, dirty_, dns_, dnsTried_ (+31 more)

### Community 5 - "SkeletonStore"
Cohesion: 0.05
Nodes (26): AnnouncedSkeleton, build_announcement_doc(), build_peers_doc(), build_skeleton_index_doc(), find_field(), find_fields(), fnv1a32(), hex8() (+18 more)

### Community 6 - "HardwareEsp32"
Cohesion: 0.04
Nodes (39): HardwareEsp32, _apAuto, _apClients, _apName, _apUp, _attemptArmed, _attemptStartMs, _buttonArmed (+31 more)

### Community 7 - "test_protocol.py"
Cohesion: 0.06
Nodes (23): FakeHost, info(), is_code(), test_action(), test_action_length_limit_counts_bytes(), test_config_is_atomic(), test_config_numbers_booleans_and_null_follow_the_loose_text_rules(), test_peers_doc() (+15 more)

### Community 8 - "SerialLink"
Cohesion: 0.06
Nodes (26): feed(), logMsg(), logSetup(), SerialLink, atLineStart_, baud_, fails_, fd_ (+18 more)

### Community 9 - "Manager"
Cohesion: 0.08
Nodes (36): exchange(), Manager, parse_http(), read_all(), test_connection_reset_while_responding_is_harmless(), test_edit_proof_endpoint(), connect(), test_authenticated_get_frames_and_viewer_mode() (+28 more)

### Community 10 - "ProtocolAdapter"
Cohesion: 0.10
Nodes (19): _as_bytes(), error_result(), handle_action(), handle_config(), handle_plan(), handle_plan_action(), handle_plan_skeleton(), handle_setup() (+11 more)

### Community 11 - "FakeHost"
Cohesion: 0.07
Nodes (20): FakeHost, actionResult, actionsApplied, battery_, cfg, count, dirty, events (+12 more)

### Community 12 - "test_device.py"
Cohesion: 0.07
Nodes (23): RecordingSink, collect(), listen_udp(), sealed_with(), test_announcements_keep_the_uint32_counters_in_range(), test_announcements_on_the_wire(), test_change_broadcast_has_a_minimum_gap_and_heartbeat_is_periodic(), test_concurrent_identical_envelopes_are_accepted_exactly_once() (+15 more)

### Community 13 - "test_interop.py"
Cohesion: 0.16
Nodes (17): finish(), node_client(), node_process(), test_action_post_works_against_the_python_simulator(), test_both_simulators_report_the_same_document_shapes(), test_command_handlers_answer_exactly_like_the_cpp_reference(), test_config_and_plan_roundtrip_against_the_python_simulator(), test_each_sees_the_other_in_peers_json() (+9 more)

### Community 14 - "test_crypto.py"
Cohesion: 0.07
Nodes (30): begun(), begun_edit(), test_announcement_frames(), test_base64url_vectors(), test_begin_resets_everything_when_the_tokens_change(), test_clock_wraparound(), test_document_frames(), test_edit_check_order_matches_the_reference() (+22 more)

### Community 15 - "test_persistence.py"
Cohesion: 0.17
Nodes (14): make_component(), random_did(), test_begin_raises_oserror_if_the_http_port_is_taken_and_leaves_nothing_open(), test_component_limit_and_ignored_ids(), test_loop_before_begin_is_a_noop(), start(), test_boot_counter_increments_once_per_start_and_did_and_riddle_are_stable(), test_damaged_state_does_not_prevent_starting() (+6 more)

### Community 16 - "Json.cpp"
Cohesion: 0.12
Nodes (30): appendUtf8(), Cursor, i, n, s, DomParser, c_, limits_ (+22 more)

### Community 17 - "Protocol.cpp"
Cohesion: 0.16
Nodes (29): appendEscaped(), appendUInt(), appendCommonDeviceFields(), appendStr(), buildComponentsDoc(), buildPeersDoc(), buildSecurityDoc(), buildSkeletonIndexDoc() (+21 more)

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
Cohesion: 0.06
Nodes (27): jsonString(), SerialHost, device_, did_, kMinGetStateGapMs, known_, kOfflineMs, kPollMs (+19 more)

### Community 23 - "main"
Cohesion: 0.16
Nodes (10): defaultStateDir(), deriveDid(), exeDir(), FileStorage, dir_, main(), readFile(), onDrop (+2 more)

### Community 24 - "device_storage.py"
Cohesion: 0.11
Nodes (20): _auth_token(), _b64(), _clear_edit_token(), _device_info(), _device_port(), _edit_token(), _project_option(), _reset_persistent_storage() (+12 more)

### Community 25 - "em_client.mjs"
Cohesion: 0.10
Nodes (16): b64u(), DEFAULT_TOKEN, Device, main(), SECRET_TOKEN, args, bProof, fresh() (+8 more)

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
Cohesion: 0.14
Nodes (15): wait_for(), pair(), test_devices_discover_each_other(), test_devices_without_an_edit_token_keep_and_pass_on_the_mac(), test_equal_revision_tiebreak_converges_across_devices(), test_failed_sync_backs_off_per_peer_and_room(), test_peer_expires_without_announcements(), test_peer_with_another_token_is_ignored() (+7 more)

### Community 30 - "SecureTransport"
Cohesion: 0.09
Nodes (17): EditState, Custom, Invalid, Unset, SecureTransport, began_, did_, edit_ (+9 more)

### Community 31 - "_Host"
Cohesion: 0.08
Nodes (11): bounded(), ComponentSnapshot, CustomConfigDef, _Host, _is_http_url(), normalize_config_def(), plan_action_bit(), PlanAction (+3 more)

### Community 32 - "test_crypto.cpp"
Cohesion: 0.11
Nodes (20): hexDecode(), beginWith(), beginWithEdit(), hexOf(), test_announcement_frames(), test_clock_wraparound(), test_document_frames(), test_edit_envelope_vectors() (+12 more)

### Community 33 - "LocalComponent"
Cohesion: 0.08
Nodes (18): EscapeComponent::Host::snapshot(), LocalComponent, actionHandler, actionsCb, customConfigCb, customConfigSetCb, errorsCb, eventMsg (+10 more)

### Community 34 - "test_net.cpp"
Cohesion: 0.17
Nodes (15): nowMicros(), nowMillis(), runDeviceTests(), body(), connectTo(), exchange(), main(), test_back_to_back_rejections_never_get_503() (+7 more)

### Community 35 - "UdpSocket"
Cohesion: 0.20
Nodes (6): makeAddress(), setNonBlocking(), UdpSocket, fd_, test_mdns_shared_record(), test_setup_network_dns()

### Community 36 - "Peers.cpp"
Cohesion: 0.12
Nodes (19): buildAnnouncementDoc(), didToText(), fieldHex8(), fieldText(), fieldUInt(), ipv4ToU32(), parseAnnouncement(), parseDid() (+11 more)

### Community 37 - "HttpServer::Connection"
Cohesion: 0.07
Nodes (26): HttpServer::Connection, body, continueSent, drained, drainStartMs, fd, gotBytes, head (+18 more)

### Community 38 - "SecureTransport"
Cohesion: 0.06
Nodes (9): b64u_decode(), b64u_encode(), is_edit_path(), KeyRole, OpenResult, s32(), SecureTransport, valid_nonce() (+1 more)

### Community 40 - "edit.test.mjs"
Cohesion: 0.18
Nodes (17): savedRev(), saveFromStub(), setEditTokenInUi(), vectors, pageKit(), enterEditMode(), openPage(), openPlan() (+9 more)

### Community 41 - "Host"
Cohesion: 0.11
Nodes (6): Host, actions, dev, name_, plan_, room_

### Community 42 - "SimSetupSink"
Cohesion: 0.13
Nodes (7): SimSetupSink, editToken_, logger_, pass_, ssid_, token_, tokenProblem()

### Community 43 - "PeerEntry"
Cohesion: 0.17
Nodes (12): PeerEntry, boot, ctr, did, ip, lastSeenMs, pmin, port (+4 more)

### Community 44 - "Override"
Cohesion: 0.20
Nodes (10): Override, dirty, force, hasIdentity, hasPlan, hasRiddle, name, plan (+2 more)

### Community 45 - "test_sim.py"
Cohesion: 0.14
Nodes (12): free_http_port(), test_begin_twice_close_twice_and_context_manager(), Sim, sim_factory(), factory(), test_battery_zero_is_not_reported_and_html_state(), test_config_and_identity_persist_across_restarts(), test_default_token_state_without_token_option() (+4 more)

### Community 46 - "HttpClient"
Cohesion: 0.14
Nodes (12): headerValue(), HttpClient, body_, contentLength_, deadlineMs_, fd_, head_, maxBody_ (+4 more)

### Community 47 - ".find"
Cohesion: 0.17
Nodes (18): copyBounded(), isChangeBroadcastDue(), isHeartbeatDue(), info(), isCode(), parseObj(), test_action(), test_config_is_atomic() (+10 more)

### Community 48 - "FakeSink"
Cohesion: 0.11
Nodes (9): FakeSink, applied, last, open, phase, result, ssid, viaNetwork (+1 more)

### Community 49 - "Net.cpp"
Cohesion: 0.16
Nodes (6): errorCodeFor(), HttpServer, connections_, handler_, listenFd_, wouldBlock()

### Community 50 - "DeviceInfo"
Cohesion: 0.10
Nodes (17): DeviceInfo, battery, boot, did, edit, ip, nowMs, port (+9 more)

### Community 51 - "get"
Cohesion: 0.13
Nodes (12): get(), test_get_without_nonce_in_strict_mode(), test_parallel_readers_writers_and_state_changes_stay_consistent(), reader(), test_random_http_garbage_never_kills_the_server(), test_frame_is_byte_exact_on_the_wire(), test_handler_exception_is_a_json_500_and_the_server_survives(), test_junk_udp_datagrams_do_not_kill_the_process() (+4 more)

### Community 52 - "Any"
Cohesion: 0.28
Nodes (5): _Dom, json_text_loose(), JsonError, number_text(), parse_json()

### Community 53 - ".__init__"
Cohesion: 0.05
Nodes (12): BlobStorage, _default_state_dir(), _detect_lan_interface(), _detect_local_ip(), _directed_broadcast_for(), FileStorage, ipv4_to_str(), _linux_ipv4_interfaces() (+4 more)

### Community 54 - "test_device.cpp"
Cohesion: 0.32
Nodes (19): bodyOf(), http(), options(), pump(), statusOf(), test_discovery_and_authenticated_reads(), test_edit_proof_endpoint(), test_edit_token_guards_sending_plans() (+11 more)

### Community 55 - "client.cpp"
Cohesion: 0.16
Nodes (9): EscapeComponent::Host::applyAction(), EscapeComponent::Host::applyPlanAction(), EscapeComponent::Host::identity(), EscapeComponent::Host::pushEvent(), EscapeComponent::Host::setCustomConfigValue(), EscapeComponent::Host::setIdentity(), EscapeComponent::Host::setPlan(), EscapeComponent::Host::setRiddleId() (+1 more)

### Community 56 - "DevicePlatform"
Cohesion: 0.10
Nodes (8): Device::Device(), DevicePlatform, SerialPlatform, broadcast_, ip_, SimPlatform, broadcast_, ip_

### Community 57 - "MemoryStorage"
Cohesion: 0.10
Nodes (6): BlobStorage, MemoryStorage, capacity_, data_, failWrites_, writes_

### Community 58 - "SimHost"
Cohesion: 0.08
Nodes (13): main(), FileStorage, dir_, editToken, token, readFile(), sha256Hex8(), SimHost (+5 more)

### Community 59 - "test_base64.cpp"
Cohesion: 0.08
Nodes (18): runBase64Tests(), runCryptoTests(), runFuzzTests(), runHttpTests(), runJsonTests(), main(), runAll(), setUp() (+10 more)

### Community 60 - "test_fuzz.cpp"
Cohesion: 0.17
Nodes (13): jsonCorpus(), makeTransport(), mutate(), Rng, s, test_announcements_under_mutation(), test_handlers_survive_mutated_bodies(), test_http_parser_under_mutation() (+5 more)

### Community 61 - "test_json.cpp"
Cohesion: 0.18
Nodes (15): parse(), ParseLimits, maxDepth, maxNodes, ok(), test_as_int(), test_duplicate_keys_first_wins(), test_escape_output() (+7 more)

### Community 62 - "State"
Cohesion: 0.25
Nodes (8): State, Connecting, Done, Failed, Idle, ReceivingBody, ReceivingHead, Sending

### Community 63 - "SecureTransport.cpp"
Cohesion: 0.29
Nodes (3): constantTimeEqual(), decimal(), isEditPath()

### Community 64 - "selfupgrade.test.mjs"
Cohesion: 0.15
Nodes (6): buildNewerSimulator(), executablePath, html, net, stub(), walk()

### Community 65 - "hw_smoke.mjs"
Cohesion: 0.17
Nodes (16): SECRET_EDIT_TOKEN, args, check(), devs, hostileChecks(), mdnsCheck(), pair(), perDevice() (+8 more)

### Community 66 - "PeerTable"
Cohesion: 0.18
Nodes (4): Announcement, IngestResult, PeerEntry, PeerTable

### Community 67 - "Vec"
Cohesion: 0.10
Nodes (20): Vec, getDoc, getFrame, getNonce, getPath, kMac, kReq, kResp (+12 more)

### Community 68 - "escape_component_sim.py"
Cohesion: 0.07
Nodes (10): 5.2 `/status.json` DOC, build_parser(), load_config(), set_config(), parse_component(), main(), read_ui(), save_config() (+2 more)

### Community 69 - "Value"
Cohesion: 0.13
Nodes (15): appendInt(), appendInt64(), appendNumber(), stringify(), stringifyInto(), Value, arrayValue, boolValue (+7 more)

### Community 70 - "Node"
Cohesion: 0.22
Nodes (6): Node, crypto, device, host, platform, storage

### Community 71 - "helpers.mjs"
Cohesion: 0.12
Nodes (9): freePort(), PORT_BASE, portFree(), root, running, simBinary, startSim(), taken (+1 more)

### Community 73 - "isolated_sims"
Cohesion: 0.24
Nodes (3): isolated_sims(), Sims, up()

### Community 74 - "TokenState"
Cohesion: 0.40
Nodes (4): TokenState, Custom, Default, Invalid

### Community 75 - "test_store.cpp"
Cohesion: 0.15
Nodes (11): fnv1a32(), emacOf(), FakeSigner, enabled, makeBlob(), test_adopt_equal_rev_tiebreak_converges(), test_adopt_needs_valid_mac_with_edit_token(), test_adopt_rules() (+3 more)

### Community 76 - "cstring"
Cohesion: 0.10
Nodes (5): MbedTlsCryptoBackend, ByteRange, data, length, OpenSslCryptoBackend

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

### Community 82 - "stub.mjs"
Cohesion: 0.17
Nodes (9): deriveKeys(), b64u(), connect(), DEFAULT_TOKEN, keySet(), TestDevice, managerHtml, b64u() (+1 more)

### Community 85 - "HttpResponse"
Cohesion: 0.17
Nodes (10): HttpResponse, body, contentType, etag, gzip, location, noStore, staticBody (+2 more)

### Community 87 - "Options"
Cohesion: 0.12
Nodes (16): Options, battery, broadcast, did, htmlState, httpPort, ip, managerHtml (+8 more)

### Community 88 - "__init__.py"
Cohesion: 0.05
Nodes (17): 6. Limits (`EscapeConfig`, mirrored in `/security.json` `limits`), build_components_doc(), build_security_doc(), build_status_doc(), _clean(), _common_device_fields(), DeviceInfo, EditState (+9 more)

### Community 89 - "Http.cpp"
Cohesion: 0.26
Nodes (11): formatResponseHead(), hexVal(), iequals(), originAllowed(), percentDecode(), queryParam(), statusText(), trim() (+3 more)

### Community 90 - "test_http.cpp"
Cohesion: 0.06
Nodes (40): HttpRequest, body, contentLength, expectContinue, ifNoneMatch, method, origin, path (+32 more)

### Community 92 - "Setup.cpp"
Cohesion: 0.39
Nodes (12): formValue(), isSetupNetworkName(), parseSetupForm(), parseSetupJson(), printable(), redirectTarget(), setupNetworkName(), validateSetupChange() (+4 more)

### Community 93 - "Options"
Cohesion: 0.11
Nodes (18): baudConstant(), Options, baud, broadcast, did, editToken, httpPort, ip (+10 more)

### Community 95 - "DummyComponent"
Cohesion: 0.18
Nodes (12): DummyComponent, brightness, difficulty, errorActive, extra, label, step, initCustomConfig() (+4 more)

### Community 96 - "escape_component_serial_host.cpp"
Cohesion: 0.07
Nodes (12): mkdirs(), logSetup(), parseArgs(), usageText(), broadcastForIp(), detectLanInterface(), HostInterface, broadcast (+4 more)

### Community 98 - "gen_vectors.mjs"
Cohesion: 0.08
Nodes (17): check, code, end, fail(), html, htmlFile, installed(), pkg (+9 more)

### Community 99 - "setup/setup.test.mjs"
Cohesion: 0.16
Nodes (8): executablePath, FAST, here, installFakeBoard(), receive(), respond(), L, open()

### Community 101 - "EscapeManager wire protocol, level 2 ("proto 2")"
Cohesion: 0.05
Nodes (35): 1. Verified on hardware, 2. Bugs the hardware work found (all fixed, with tests where they can run on the PC), 3. Still open (needs equipment or access I did not have), 4. Deliberately postponed / not implemented, 5. Not hardware related, Functional, HARDWARE_TODO – hardware verification record and what is still open, Resources (esp-dummy, 240 MHz) (+27 more)

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

### Community 112 - "RateLimiter"
Cohesion: 0.17
Nodes (9): RateLimiter, slots_, windowCount_, windowStart_, Slot, lastMs, source, tokens (+1 more)

### Community 116 - "build_ui.py"
Cohesion: 0.11
Nodes (6): deterministic_gzip(), generate(), is_current(), render_cpp(), set_root(), ui_hash()

### Community 120 - "handleSetupPortal"
Cohesion: 0.40
Nodes (6): appendHtml(), formPage(), handleSetupPortal(), page(), phaseText(), statusPage()

### Community 121 - "LineFramer"
Cohesion: 0.20
Nodes (9): LineFramer, buf_, kMaxLine, mode_, oversize_, Mode, Collect, Discard (+1 more)

### Community 123 - "Mdns.cpp"
Cohesion: 0.33
Nodes (7): buildMdnsAnswer(), lower(), parseMdnsQuery(), rd16(), rd32(), readName(), test_mdns_answer_bytes()

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

### Community 157 - "RouteInfo"
Cohesion: 0.67
Nodes (3): RouteInfo, found, maxBody

### Community 158 - "PlanAction"
Cohesion: 0.67
Nodes (3): PlanAction, Complete, Reset

### Community 161 - "Resource behaviour (the library lives inside another program)"
Cohesion: 0.22
Nodes (3): Configuring Wi-Fi and tokens without reflashing, Resource behaviour (the library lives inside another program), Using the library in your own program

### Community 162 - "helpers.py"
Cohesion: 0.16
Nodes (3): component(), vectors(), PostResult

## Knowledge Gaps
- **696 isolated node(s):** `step`, `errorActive`, `brightness`, `label`, `difficulty` (+691 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1449 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **29 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `isolated_sims()` connect `isolated_sims` to `escape_component.py`, `em_client.mjs`, `test_sim.py`, `test_interop.py`?**
  _High betweenness centrality (0.064) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `Manager` (e.g. with `test_everything_works_with_the_clock_just_before_the_32_bit_wrap()` and `Sim`) actually correct?**
  _`Manager` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `step`, `errorActive`, `brightness` to the rest of the system?**
  _696 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `escape_component.py` be split into smaller, more focused modules?**
  _Cohesion score 0.0454172366621067 - nodes in this community are weakly interconnected._
- **Why does `random_did()` connect `test_persistence.py` to `em_client.mjs`, `helpers.py`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Should `EscapeComponent` be split into smaller, more focused modules?**
  _Cohesion score 0.04095904095904096 - nodes in this community are weakly interconnected._
- **Why does `EscapeComponent` connect `EscapeComponent` to `escape_component.py`, `HttpResponse`, `SkeletonStore`, `EscapeManager wire protocol, level 2 ("proto 2")`, `SecureTransport`, `ProtocolAdapter`, `test_serial_host.py`, `.__init__`, `__init__.py`, `wait_for`, `_Host`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._