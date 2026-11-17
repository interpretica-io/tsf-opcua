# tsf-opcua — OPC UA Testing Framework

`tsf-opcua` is a Test Environment module for testing OPC Unified
Architecture (OPC UA) servers and applications — industrial devices,
PLCs, SCADA systems, IoT gateways and digital twins — from a Test Agent.
It acts as an OPC UA **client** running on the agent, with an optional
built-in **simulated server** for deterministic integration and
fault-injection tests. The protocol implementation is
[open62541](https://open62541.org/), linked and called in-process: the
module never shells out to an OPC UA command-line tool or a Python
script.

It is a testing library, not a production OPC UA SDK or a SCADA system.

## What it does

- **Connectivity & discovery** — open a SecureChannel and Session;
  `FindServers`, `GetEndpoints`; distinguish DNS / TCP / endpoint /
  channel / certificate / authentication / session / timeout failures,
  keeping the underlying StatusCode.
- **Address space** — browse references with continuation points,
  translate browse paths to NodeIds, read node attributes, resolve
  namespace URIs (indices are not assumed stable across restarts).
- **Data access** — read and write node values and attributes, one or
  many, with the full OPC UA scalar and array type set; each read keeps
  the value, StatusCode and source/server timestamps (a missing
  timestamp stays missing, never a local one).
- **Methods** — call a method with typed input arguments and read typed
  outputs, preserving the service and operation StatusCodes.
- **Subscriptions & monitored items** — data-change and event monitored
  items with sampling, queueing, deadband and monitoring-mode options;
  the API returns the server-revised parameters. Each delivered
  notification carries a local sequence number, the PublishResponse
  batch, the Overflow info bit and the timestamps, so a **missing**
  notification is distinguishable from a **late** one and from one
  **discarded** by the queue policy — loss is never inferred from a gap
  in values alone.
- **Events** — subscribe to an event notifier, select fields, receive
  and validate events.
- **Security** — recognise the OPC UA security policies, audit endpoints
  (insecure endpoint enabled, Mode None where prohibited, a username
  token offered unencrypted), anonymous read of protected data,
  unauthorized write, and a certificate accepted against policy; read
  certificate metadata and generate test certificates. Findings follow
  the tsf-cybersec model (stable id, subject, severity) without linking
  it.
- **Reliability** — disconnect/reconnect, wait for session recovery, and
  tell a recreated session (new authentication token) from a transparent
  resumption, using the connection counters.
- **Simulated server** — start a server, add variables and methods
  (built-in behaviours: echo, sum, delay, fail), change values as a
  device would, emit events, read its counters.
- **Performance** — time read/browse calls on the agent and emit the
  per-call samples for the suite to chart.

## Architecture

Three libraries, the tsf-data shape:

| Library | Runs on | Responsibility |
|---|---|---|
| `ta_opcua` | Test Agent | open62541 client, subscriptions, simulated server, certificates — a plain-C core (`ta_opcua_core.h`, no TE header) plus a thin TE adapter and handle registry (`ta_opcua.c`) |
| `rpcs_opcua` | Agent RPC server | the two uniform `opcua_*` RPCs over `ta_opcua` |
| `tapi_opcua` | Test Engine | the public testing API and the security findings model |

The agent owns the clients, secure channels, sessions, subscriptions,
monitored items and simulated servers; each is named to the engine by a
small integer handle. A client runs its own event-loop thread
(`UA_Client_run_iterate`), so subscription keepalives and reconnection
never stall behind a blocking operation. Values cross the RPC as text;
XDR carries no portable float and no NodeId, so both travel inside the
text and `tapi_opcua` parses them. Only bounded samples and reports
cross the wire — sessions and queues stay on the agent. A connection
secret (a password, a private key path) is carried in the connect
parameters and nowhere else: the agent never logs it.

The RPC program number is **47**.

## Example

```c
tapi_opcua_conn conn;
tapi_opcua_value value;
tapi_opcua_connect_opt opt = {
    .endpoint = "opc.tcp://192.0.2.10:4840",
    .security_policy = "basic256sha256",
    .security_mode = TAPI_OPCUA_MODE_SIGN_ENCRYPT,
    .request_timeout_ms = 10000,
};

CHECK_RC(tapi_opcua_connect(pco, &opt, &conn));
CHECK_RC(tapi_opcua_read(&conn, "ns=2;s=Temperature", &value));
if (value.type != TAPI_OPCUA_DOUBLE)
    TEST_VERDICT("Unexpected temperature data type");
if (value.data.f64 < -20.0 || value.data.f64 > 120.0)
    TEST_VERDICT("Temperature out of range");
tapi_opcua_value_free(&value);
tapi_opcua_disconnect(&conn);
```

## Building into a suite

`tsf-opcua` is an external TE repository. A suite references it in its
`conf/external.yml` and binds the three libraries — `ta_opcua` and
`rpcs_opcua` onto the agent (listed again in the RPC server application),
`tapi_opcua` onto the engine — and adds `ta_opcua/opcua_rpc.x.m4` to the
rpcxdr definitions of both platforms. The agent host needs open62541
with its development headers (Debian trixie: `libopen62541-1.4-dev`;
built from source with the OpenSSL backend for the encryption tests).
See the companion suite **tsf-opcua-ts**.

## Fast local check (no Test Environment)

The agent core carries no TE header, so it builds and runs on its own:

```sh
ci/core-test.sh      # build with ASan/UBSan, start the simulated server,
                     # drive a client against it, check the contracts
```

It needs open62541 found by `pkg-config`.

## License

MIT. See [LICENSE](LICENSE).
