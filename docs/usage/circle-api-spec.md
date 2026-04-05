# Circle API Specification

Backend endpoints required to support `conseal/circle` device-registration ceremony.

`conseal/circle` does not make HTTP calls. The app provides transport; the library provides the cryptographic payloads. All binary fields (`wrappedAEK`, `sealedAEK`, `aekCommitment`) are base64-encoded strings over the wire.

---

## Authentication

Every endpoint requires the user to be authenticated. The spec does not prescribe a mechanism (session token, JWT, etc.) — that is the app's responsibility. Unauthenticated requests must return `401`.

---

## Data model

```
Circle
  aekCommitment  base64   SHA-256 of the raw AEK; set once by initCircle, never overwritten
  devices[]      Device[]

Device
  deviceId       string   UUID
  name           string?  optional
  platform       string?  optional
  registeredAt   ISO 8601
  wrappedAEK     base64   opaque to the server; one per device

JoinChallenge
  challengeId    string   derived from SHA-256(ephemeralPublicKey), single-use
  deviceId       string
  ephemeralPublicKey  base64 (raw uncompressed P-256 point, 65 bytes)
  createdAt      ISO 8601
  expiresAt      ISO 8601
  status         "pending" | "authorized" | "expired" | "denied"
  sealedAEK      base64?  set when status = "authorized"
```

---

## Endpoints

### `POST /circle/devices/join`

New device submits a join request. Creates a single-use `JoinChallenge`.

**Request**
```json
{
  "deviceId": "string",
  "ephemeralPublicKey": "base64",
  "createdAt": "ISO 8601",
  "deviceMeta": {
    "name": "string",
    "platform": "string"
  }
}
```

**Response `201`**
```json
{
  "challengeId": "string",
  "expiresAt": "ISO 8601"
}
```

**Errors**
- `409` — `deviceId` already registered in this circle
- `400` — missing required fields or malformed `ephemeralPublicKey`

**Server rules**
- `challengeId` must be derived from (or cryptographically bound to) `ephemeralPublicKey` — a challenge cannot be reused with a different key pair.
- TTL must be enforced server-side. Recommended: 5 minutes from `createdAt`.
- Store the full `ephemeralPublicKey` bytes; the authorizing device needs them to display the verification code.
- One pending challenge per deviceId at a time; reject or replace if a duplicate arrives.

---

### `GET /circle/devices/join/:challengeId`

New device polls for authorization status. May be called repeatedly until status changes from `pending`.

**Response — pending**
```json
{ "status": "pending" }
```

**Response — authorized**
```json
{
  "status": "authorized",
  "sealedAEK": "base64",
  "aekCommitment": "base64"
}
```

**Response — expired or denied**
```json
{ "status": "expired" | "denied" }
```

**Errors**
- `404` — unknown `challengeId`

---

### `POST /circle/devices/join/:challengeId/authorize`

Trusted device submits the `sealedAEK` for the new device after user confirmation.

**Request**
```json
{
  "sealedAEK": "base64"
}
```

`sealedAEK` is the JSON-serialized `{ ciphertext, iv, ephemeralPublicKey }` object returned by `authorizeJoin()`, base64-encoded.

**Response `200`**
```json
{ "ok": true }
```

**Errors**
- `404` — unknown `challengeId`
- `410` — challenge expired or already consumed
- `403` — requesting user is not a member of this circle

**Server rules**
- Set challenge `status = "authorized"` and store `sealedAEK`.
- Challenge is now consumed — any subsequent authorize call on the same `challengeId` must return `410`.
- Notify the new device (push, polling, or WebSocket) that it can proceed to `finalizeJoin`.

---

### `POST /circle/devices/:deviceId/wrapped-aek`

Device stores its `wrappedAEK` after `initCircle` or `finalizeJoin`.

**Request**
```json
{
  "wrappedAEK": "base64"
}
```

**Response `200`**
```json
{ "ok": true }
```

**Errors**
- `403` — `deviceId` does not belong to the authenticated user's circle

**Server rules**
- Overwrite the existing `wrappedAEK` for this device (supports re-key operations).
- Do not interpret the blob — it is opaque.

---

### `GET /circle/devices/:deviceId/wrapped-aek`

Device retrieves its `wrappedAEK` on a new session.

**Response `200`**
```json
{
  "wrappedAEK": "base64"
}
```

**Errors**
- `404` — device not found or `wrappedAEK` not yet stored

---

### `GET /circle/devices`

Returns all registered devices in the circle. Used to display the device management list and to let the authorizing device choose which request to approve.

**Response `200`**
```json
{
  "devices": [
    {
      "deviceId": "string",
      "name": "string",
      "platform": "string",
      "registeredAt": "ISO 8601"
    }
  ]
}
```

---

### `DELETE /circle/devices/:deviceId`

Removes a device from the circle. Deletes the device's `wrappedAEK` from the server.

**Response `200`**
```json
{ "ok": true }
```

**Errors**
- `403` — `deviceId` does not belong to the authenticated user's circle
- `400` — attempt to remove the only remaining device (optional guard)

**Server rules**
- After deletion, reject all subsequent API calls from `deviceId` with `403`.
- Notify the circle owner (push, email, in-app) when a revoked device attempts to contact a circle endpoint.
- The deleted device retains its local AEK copy; it is locked out of new data, not cryptographically revoked. Full revocation requires AEK rotation (out of scope for v1).

---

## `aekCommitment` management

`aekCommitment` is set once when the founding device calls `initCircle` and stores its `wrappedAEK`. It must be stored alongside the circle record and:

- Returned to new devices in `GET /circle/devices/join/:challengeId` when `status = "authorized"`.
- **Never overwritten** after initial creation — a server that allows overwrite enables key substitution attacks.

---

## Pending challenge list

Trusted devices need to know when a join request is waiting. Delivery options:

| Mechanism | Notes |
|-----------|-------|
| Push notification | Best UX; requires push token registration |
| WebSocket / SSE | Good for desktop/web; keep connection open |
| Polling `GET /circle/pending-joins` | Simplest to implement; acceptable latency |

A minimal `GET /circle/pending-joins` endpoint returning active challenges is sufficient for v1:

```json
{
  "pending": [
    {
      "challengeId": "string",
      "deviceId": "string",
      "deviceMeta": { "name": "string", "platform": "string" },
      "ephemeralPublicKey": "base64",
      "createdAt": "ISO 8601",
      "expiresAt": "ISO 8601"
    }
  ]
}
```

---

## Rate limiting (recommended)

| Endpoint | Limit |
|----------|-------|
| `POST /circle/devices/join` | 5 requests / 10 minutes per user |
| `GET /circle/devices/join/:challengeId` | 1 request / second per challengeId |
| `POST /circle/devices/join/:challengeId/authorize` | 3 attempts per challenge |

---

## Audit log (recommended)

Record the following events for the circle owner's security history:

- Device registered (deviceId, name, platform, IP, timestamp)
- Join authorized (authorizing deviceId, new deviceId, timestamp)
- Join denied / expired (deviceId, timestamp)
- Device removed (removed deviceId, removed by deviceId, timestamp)
- Revoked device contact attempt (deviceId, endpoint, timestamp)
