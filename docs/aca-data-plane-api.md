# ACA Sandbox Data-Plane REST API (captured from LIVE Azure)

Captured by exercising the `aca` CLI (1.0.0-preview.1) with `--verbose` against a
real sandbox in Azure subscription NOCORE-RD, region `northeurope`, plus one
direct `curl` call (to force a 409 the CLI otherwise auto-recovers from). This
is the **undocumented preview data-plane REST surface** the ACA provider will
speak directly. All values below are real shapes with sensitive fields
scrubbed to `{placeholders}`.

Captured against `api-version=2026-02-01-preview`. Treat every field list as
"observed present", not necessarily exhaustive — the preview API may have
additional optional fields not exercised by this capture session.

## Base host / audience

- **Base host pattern:** `https://management.{region}.azuredevcompute.io`
  (region-specific; e.g. `https://management.northeurope.azuredevcompute.io`).
  This is also the value the CLI reports as `managementUrl` in every sandbox
  resource body.
- **Token audience (resource/scope):** `https://management.azuredevcompute.io`
  — **region-agnostic**, no `management.{region}.` regional hostname works as
  an AAD resource. Confirmed by probing `az account get-access-token
  --resource <candidate>`:
  - `https://management.northeurope.azuredevcompute.io` → `AADSTS500011: The
    resource principal ... was not found in the tenant` (regional hostname is
    NOT a valid resource/audience).
  - `https://management.azuredevcompute.io` → succeeds, returns a Bearer
    token with a valid `expiresOn`.
  - Decoding the resulting JWT's claims (locally, token itself never printed
    or persisted) shows `"scp": "AzureDevCompute.Management.ReadWrite.All"`,
    `"ver": "2.0"` — i.e. this is the correct data-plane scope. The token's
    `aud` claim is the resolved Application ID (a stable, non-secret GUID for
    the first-party "AzureDevCompute" service; not a subscription/resource
    GUID, so no placeholder needed, but omitted here since callers only need
    the resource **string**, not the resolved app id).
  - **Practical implication for client code:** request tokens with
    `credential.get_token(&["https://management.azuredevcompute.io"], ...)`,
    then call the **regional** `management.{region}.azuredevcompute.io` host
    with that token. Audience and host are deliberately different strings —
    do not conflate them.

## Common headers

Every authenticated request:
- `authorization: Bearer {token}`
- `x-ms-client-request-id: {client-generated-uuid}` (client-supplied, one per
  request, useful for correlating with `x-ms-request-id` in the response)
- `user-agent: aca-cli-1.0.0-preview.1 azsdk-rust-azure-containerapps-sandbox/0.1.0-beta.1 ({rust-version}; {os}; {arch})`
  — client code should set its own descriptive user-agent, this is just what
  the reference CLI sends.

`GET`/`DELETE` requests additionally send `accept: application/json` (DELETE
in this capture did NOT send `accept`, only `authorization`+`user-agent`+
`x-ms-client-request-id`). `PUT`/`POST` requests with a JSON body add
`content-type: application/json`; the file-write endpoint uses
`content-type: application/octet-stream` instead (raw bytes, not JSON).

Every response carries: `content-type` (`application/json; charset=utf-8` for
JSON bodies, `application/problem+json; charset=utf-8` for error bodies,
`application/octet-stream` for raw file bytes), `x-ms-request-id`,
`x-ms-client-request-id` (echoed back), `date`, `mise-correlation-id`.

All URL templates below omit the common query prefix
`?api-version=2026-02-01-preview` for brevity except where additional query
parameters are shown alongside it.

Placeholders used below: `{region}`, `{subscription}`, `{resourceGroup}`,
`{sandboxGroup}`, `{sandboxId}`.

---

## Endpoint map

| Op | Method | URL template |
|---|---|---|
| create | PUT | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes` |
| get | GET | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}` |
| list | GET | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes` |
| delete | DELETE | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}` |
| exec | POST | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}/executeShellCommand` |
| fs write / cp-upload | PUT | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}/files?path={urlencodedPath}&createDirs={bool}` |
| fs cat / cp-download | GET | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}/files?path={urlencodedPath}` |
| fs stat | GET | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}/files/stat?path={urlencodedPath}` |
| fs ls | GET | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}/files/list?path={urlencodedPath}` |
| egress set | POST | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}/egresspolicy` |
| stop (suspend) | POST | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}/stop` |
| resume | POST | `/subscriptions/{subscription}/resourceGroups/{resourceGroup}/sandboxGroups/{sandboxGroup}/sandboxes/{sandboxId}/resume` |

`fs cp` is **not** a separate endpoint: the CLI's `fs cp` command composes the
same `PUT .../files` (upload direction) and `GET .../files` (download
direction) calls used by `fs write`/`fs cat` — confirmed by capturing both
directions of `aca sandbox fs cp` with `--verbose`.

---

## create — `PUT .../sandboxes`

Request body (CLI issued `aca sandbox create --disk ubuntu` with no extra
flags, so these are server/CLI defaults):

```json
{
  "lifecycle": {
    "autoSuspendPolicy": {
      "enabled": true,
      "interval": 600,
      "mode": "Memory"
    }
  },
  "resources": {
    "cpu": "1000m",
    "memory": "2048Mi"
  },
  "sourcesRef": {
    "diskImage": {
      "isPublic": true,
      "name": "ubuntu"
    }
  }
}
```

Field types: `lifecycle.autoSuspendPolicy.enabled: bool`,
`.interval: number` (seconds), `.mode: string` (enum observed: `"Memory"`);
`resources.cpu: string` (millicpu, e.g. `"1000m"`), `.memory: string`
(e.g. `"2048Mi"`); `sourcesRef.diskImage.isPublic: bool`,
`.name: string` (image name, e.g. `"ubuntu"`).

Response (200) — full **Sandbox** resource:

```json
{
  "connections": [],
  "contentPackageDownloads": [],
  "createdAt": "{iso8601-timestamp}",
  "id": "{sandboxId}",
  "labels": {},
  "lifecycle": {
    "autoSuspendPolicy": { "enabled": true, "interval": 600, "mode": "Memory" }
  },
  "managementUrl": "https://management.{region}.azuredevcompute.io",
  "ports": [],
  "region": "{region}",
  "resources": { "cpu": "1000m", "disk": "20480Mi", "memory": "2048Mi" },
  "sourcesRef": {
    "diskImage": { "id": "{diskImageId}", "isPublic": false }
  },
  "state": "Running",
  "vmmType": "cloudhypervisor",
  "volumes": []
}
```

Note: the initial `PUT` response does **not** include `outboundIpAddresses`;
the very next `GET` (CLI polls once for confirmation) does. `sourcesRef.
diskImage.id` in the response is a resolved image UUID; `isPublic` flips to
`false` in the response even though the request said `true` (the resolved
concrete image is a private copy, not the public catalog entry).

---

## get — `GET .../sandboxes/{sandboxId}`

Same **Sandbox** shape as create's response, but includes
`outboundIpAddresses: array<string>` (the sandbox's outbound egress IPs,
10 observed):

```json
{
  "connections": [],
  "contentPackageDownloads": [],
  "createdAt": "{iso8601-timestamp}",
  "id": "{sandboxId}",
  "labels": {},
  "lifecycle": { "autoSuspendPolicy": { "enabled": true, "interval": 600, "mode": "Memory" } },
  "managementUrl": "https://management.{region}.azuredevcompute.io",
  "outboundIpAddresses": ["{ip}", "..."],
  "ports": [],
  "region": "{region}",
  "resources": { "cpu": "1000m", "disk": "20480Mi", "memory": "2048Mi" },
  "sourcesRef": { "diskImage": { "id": "{diskImageId}", "isPublic": false } },
  "state": "Running",
  "vmmType": "cloudhypervisor",
  "volumes": []
}
```

**`state` field — observed values:** `"Running"`, `"Stopped"`. When
`"Stopped"`, an additional `stateDetails` object appears:

```json
"stateDetails": {
  "stoppedAt": "{iso8601-timestamp}",
  "stoppedReason": "UserStopped"
}
```

`stateDetails` also carries a `snapshotId` sibling field on the sandbox once
it has been stopped at least once (see **stop**, below) — persists across a
subsequent resume, pointing at the last snapshot taken.

`GET` on a deleted (or never-existent) sandbox returns **404** with an
`application/problem+json` body — shape identical in structure to the 409
below (see **error shapes**):

```json
{
  "detail": "Requested document not found.",
  "errorCode": 1,
  "requestId": "{requestId}",
  "status": 404,
  "title": "SandboxNotFound",
  "traceId": "{traceId}"
}
```

---

## list — `GET .../sandboxes`

Response (200): a bare JSON array of **Sandbox** objects (same shape as
`get`'s response), `[]` when empty:

```json
[
  { "...": "one Sandbox object per element, same shape as GET" }
]
```

---

## delete — `DELETE .../sandboxes/{sandboxId}`

No request body. Response (200): empty object `{}`. The CLI then polls with
`GET .../sandboxes/{sandboxId}` until it observes `404 SandboxNotFound`
(shown above) to confirm deletion — deletion is asynchronous from the
caller's point of view even though the initial `DELETE` returns `200`
immediately.

---

## exec — `POST .../sandboxes/{sandboxId}/executeShellCommand`

Request body:

```json
{ "command": "true" }
```

`command: string` — a shell command line (not an argv array; single string
passed to a shell).

Response (200):

```json
{
  "executionTimeMs": 28,
  "exitCode": 0,
  "stderr": "",
  "stdout": ""
}
```

**Exec response field names (exact):** `executionTimeMs: number` (wall time
in milliseconds), `exitCode: number`, `stderr: string`, `stdout: string`.
No streaming — this is a synchronous, buffered exec; there is no separate
"exec create + poll" split observed for this simple case.

**Important CLI behavior note (not an API guarantee, but worth knowing for
client design):** `aca sandbox exec` transparently resumes a `Stopped`
sandbox before executing if it detects the sandbox isn't `Running` (prints
`Sandbox is Stopped, resuming...` / `Sandbox resumed`, then issues the
`POST .../resume` call from the client side before retrying
`executeShellCommand`). The raw REST API itself does **not** do this
auto-resume — calling `executeShellCommand` directly against a stopped
sandbox returns a 409 (see next section). Any client library replicating the
CLI's convenience behavior needs to implement this resume-then-retry itself.

---

## 409 GlobalSandboxNotRunning

Captured by calling `executeShellCommand` directly via `curl` (bypassing the
CLI's auto-resume) against a `Stopped` sandbox:

```
HTTP/2 409
content-type: application/problem+json; charset=utf-8
```

```json
{
  "title": "GlobalSandboxNotRunning",
  "status": 409,
  "detail": "Sandbox '{sandboxId}' is not in Running state",
  "callerMemberName": "Failure",
  "callerFilePath": "/mnt/vss/_work/1/s/src/Adc.Common.Core/Primitives/Result.cs",
  "errorCode": 501,
  "traceId": "{traceId}",
  "requestId": "{requestId}"
}
```

Error body shape (RFC7807-flavored `problem+json`, consistent across both
404 and 409 observed here): `title: string` (machine-usable error code, e.g.
`"GlobalSandboxNotRunning"`, `"SandboxNotFound"`), `status: number` (HTTP
status, duplicated in body), `detail: string` (human-readable, includes the
concrete resource id), `errorCode: number` (internal numeric code, distinct
per `title`), `traceId: string`, `requestId: string`. `SandboxNotFound` (404)
additionally omits `callerMemberName`/`callerFilePath` — those two fields
appear to be debug/diagnostic leakage specific to this error path and
shouldn't be relied on.

---

## fs write — `PUT .../sandboxes/{sandboxId}/files?path={urlencodedPath}&createDirs={bool}`

Headers: `content-type: application/octet-stream` (no `accept` header sent
by the CLI for this call). Request body: **raw file bytes**, not JSON.

Query params: `path: string` (destination path, URL-encoded, e.g.
`%2Fworkspace%2Ftest.txt`), `createDirs: bool` (create parent directories if
missing; CLI always sends `true`).

Response (200):

```json
{ "bytesWritten": 24, "success": true }
```

`bytesWritten: number`, `success: bool`.

---

## fs cat — `GET .../sandboxes/{sandboxId}/files?path={urlencodedPath}`

Query params: `path: string` (URL-encoded).

Response (200): **raw bytes**, not JSON —
`content-type: application/octet-stream`,
`content-disposition: attachment; filename={name}; filename*=UTF-8''{name}`,
`content-length: {bytes}`. Body is the file's raw content.

---

## fs stat — `GET .../sandboxes/{sandboxId}/files/stat?path={urlencodedPath}`

Response (200):

```json
{
  "isDir": false,
  "isSymlink": false,
  "mode": 420,
  "modifiedTime": 1788186744,
  "name": "test.txt",
  "path": "/workspace/test.txt",
  "size": 24
}
```

`isDir: bool`, `isSymlink: bool`, `mode: number` (POSIX file mode bits,
decimal — `420` = octal `0644`), `modifiedTime: number` (Unix epoch
**seconds**), `name: string` (basename), `path: string` (full path as
requested), `size: number` (bytes).

---

## fs ls — `GET .../sandboxes/{sandboxId}/files/list?path={urlencodedPath}`

Response (200):

```json
{
  "entries": [
    {
      "isDir": false,
      "isSymlink": false,
      "mode": 420,
      "modifiedTime": 1788186744,
      "name": "test.txt",
      "path": "/workspace/test.txt",
      "size": 24
    }
  ],
  "path": "/workspace"
}
```

`entries: array<FileStat>` (same per-entry shape as `fs stat`'s response
body), `path: string` (the requested directory, echoed back).

---

## fs cp (both directions)

Confirmed by running `aca sandbox fs cp <local> {sandboxId}:<remote>` and
the reverse, both with `--verbose`: **upload** issues exactly the same
`PUT .../files?path=...&createDirs=...` call as `fs write`; **download**
issues exactly the same `GET .../files?path=...` call as `fs cat`. There is
no dedicated `cp` REST endpoint — it's a CLI-side convenience wrapper.

---

## egress set — `POST .../sandboxes/{sandboxId}/egresspolicy`

Request body (from
`aca sandbox egress set --default=Deny --rule=github.com:Allow
--traffic-inspection=Full`):

```json
{
  "defaultAction": "Deny",
  "hostRules": [
    { "action": "Allow", "pattern": "github.com" }
  ],
  "trafficInspection": "Full"
}
```

`defaultAction: string` (enum observed: `"Allow"`, `"Deny"`),
`hostRules: array<{ action: string, pattern: string }>` (`action` same enum
as `defaultAction`; `pattern` is a host/domain match pattern),
`trafficInspection: string` (enum per `--help`: `Legacy`, `Full`, `Partial`,
`None`; `"Full"` observed).

Response (200) — echoes the policy back, but **nests it again** under an
`http` sub-object (protocol-specific policy; only `http` observed, likely
reserved for future protocol-specific egress policies):

```json
{
  "defaultAction": "Deny",
  "hostRules": [ { "action": "Allow", "pattern": "github.com" } ],
  "http": {
    "defaultAction": "Deny",
    "hostRules": [ { "action": "Allow", "pattern": "github.com" } ],
    "trafficInspection": "Full"
  },
  "trafficInspection": "Full"
}
```

This same nested `egressPolicy` object (with the `http` wrapper) reappears
embedded inside the **Sandbox** resource body once an egress policy has been
set (observed on the subsequent `resume` response — see below).

---

## stop (suspend) — `POST .../sandboxes/{sandboxId}/stop`

Request body: `{}` (empty JSON object).

Response (200) is **not** a Sandbox resource — it's a **Snapshot** resource,
since stopping takes a memory/disk snapshot:

```json
{
  "createdAtUtc": "{iso8601-timestamp}",
  "id": "{snapshotId}",
  "labels": {},
  "resources": { "cpu": "1000m", "disk": "20480Mi", "memory": "2048Mi" },
  "sandboxId": "{sandboxId}",
  "sizeInMB": 44,
  "vmmType": "cloudhypervisor"
}
```

`id: string` is the **snapshot's** UUID (distinct from `sandboxId`),
`sandboxId: string` back-references the sandbox that was stopped,
`sizeInMB: number` is the snapshot size. The CLI then polls
`GET .../sandboxes/{sandboxId}` until `state` becomes `"Stopped"` (the Sandbox
resource shape documented under **get**, now carrying `stateDetails` and a
`snapshotId` field equal to this Snapshot's `id`).

---

## resume — `POST .../sandboxes/{sandboxId}/resume`

Request body: `{}` (empty JSON object).

Response (200) is a full **Sandbox** resource (unlike `stop`, this returns
the sandbox directly, already reflecting `state: "Running"`), with extra
fields that only appear once the sandbox has an egress policy / has been
snapshotted at least once:

```json
{
  "coldStorageSizeInMB": 44,
  "connections": [],
  "contentPackageDownloads": [],
  "createdAt": "{iso8601-timestamp}",
  "egressPolicy": {
    "defaultAction": "Deny",
    "hostRules": [ { "action": "Allow", "pattern": "github.com" } ],
    "http": {
      "defaultAction": "Deny",
      "hostRules": [ { "action": "Allow", "pattern": "github.com" } ],
      "trafficInspection": "Full"
    },
    "trafficInspection": "Full"
  },
  "id": "{sandboxId}",
  "labels": {},
  "lifecycle": { "autoSuspendPolicy": { "enabled": true, "interval": 600, "mode": "Memory" } },
  "managementUrl": "https://management.{region}.azuredevcompute.io",
  "outboundIpAddresses": ["{ip}", "..."],
  "ports": [],
  "region": "{region}",
  "resources": { "cpu": "1000m", "disk": "20480Mi", "memory": "2048Mi" },
  "snapshotId": "{snapshotId}",
  "sourcesRef": { "diskImage": { "id": "{diskImageId}", "isPublic": false } },
  "state": "Running",
  "stateDetails": {
    "stoppedAt": "{iso8601-timestamp}",
    "stoppedReason": "UserStopped"
  },
  "vmmType": "cloudhypervisor",
  "volumes": []
}
```

New fields vs. the base Sandbox shape: `coldStorageSizeInMB: number`,
`egressPolicy: object` (present once a policy has been set — same nested
shape as **egress set**'s response), `snapshotId: string` (the snapshot the
sandbox was resumed from). `stateDetails` persists from the prior stop even
though `state` is now `"Running"` — treat `state` as the authoritative
current status field, not the presence/absence of `stateDetails`.

---

## Summary: endpoints captured

12 distinct method+URL-template operations exercised end-to-end against live
Azure: create, get, list, delete, exec, fs-write (+cp-upload), fs-cat
(+cp-download), fs-stat, fs-ls, egress-set, stop, resume. Plus two error
shapes captured live: 404 `SandboxNotFound` and 409
`GlobalSandboxNotRunning`.
