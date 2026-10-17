# Tatou API Documentation

## Request headers

Protected endpoints require `Authorization: Bearer <token>`. Authentication does
not use cookies, and the server does not emit permissive CORS headers.
`X-CSRF-Protection` is not required or checked by the current implementation.
Login and signup are public; RMAP authenticates clients using its encrypted PGP
handshake rather than a bearer token.

For example:

```http
DELETE /api/delete-document/42
Authorization: Bearer <token>
```

---

# Routes

- [create-user](#create-user) — **POST** `/api/create-user`
- [create-watermark](#create-watermark)
  - **POST** `/api/create-watermark/<int:document_id>`
  - **POST** `/api/create-watermark`
- [delete-document](#delete-document)
  - **DELETE** `/api/delete-document/<document_id>`
  - **DELETE, POST** `/api/delete-document`
- [get-document](#get-document)
  - **GET** `/api/get-document/<int:document_id>`
  - **GET** `/api/get-document`
- [get-version](#get-version) — **GET** `/api/get-version/<link>`
- [get-watermarking_methods](#get-watermarking-methods) — **GET** `/api/get-watermarking-methods`
- [healthz](#healthz) — **GET** `/healthz`
- [list-all-versions](#list-all-versions) — **GET** `/api/list-all-versions`
- [list-documents](#list-documents) — **GET** `/api/list-documents`
- [list-versions](#list-versions)
  - **GET** `/api/list-versions/<int:document_id>`
  - **GET** `/api/list-versions`
- [login](#login) — **POST** `/api/login`
- [read-watermark](#read-watermark)
  - **POST** `/api/read-watermark/<int:document_id>`
  - **POST** `/api/read-watermark`
- [upload-document](#upload-document) — **POST** `/api/upload-document`
- [rmap-initiate](#rmap-initiate) — **POST** `/api/rmap-initiate`
- [rmap-get-link](#rmap-get-link) — **POST** `/api/rmap-get-link`



## healthz

**Path**
`GET /healthz`

**Description**  
This endpoint checks the health of the server and confirms it is running.

**Parameters**  
_None_

**Return**
```json
{
  "message": <string>,
  "db_connected": <boolean>
}
```

**Specification**
 * The healthz endpoint MUST be accessible without authentication.
 * The response MUST always contain a "message" field of type string.
 * `db_connected` reports database connectivity; a false value still returns HTTP 200.
 
 ## create-user
 
**Path**
`POST /api/create-user`

**Description**  
This endpoint creates a new user account in the system.

**Parameters**
```json
{
  "login": <string>,
  "password": <string>,
  "email": <email>
}
```

**Return**
```json
{
  "id": <int>,
  "login": <string>,
  "email": <email>
}
```


**Specification**
 * The create-user endpoint MUST validate that username, password, and email are provided.
 * The response MUST include a unique id along with the created username and email.


## login

**Path**
`POST /api/login`

**Description**  
This endpoint authenticates a user with their credentials and returns a session token.

**Parameters**
```json
{
  "email": <string>,
  "password": <string>
}
```

**Return**
```json
{
  "token": <string>,
  "token_type": "bearer",
  "expires_in": <int>
}
```

**Specification**
 * The login endpoint MUST reject requests missing email or password.
 * The response MUST include a token string and its expiration date as an integer Time To Live in seconds.

**Failed-login limit**

Five failed logins are allowed per account and per connection IP in a rolling
60-second window. Further attempts return `429` with
`{"error": "too many login attempts; try again shortly"}` and a `Retry-After`
header between 1 and 60 seconds. Blocked requests do not extend the wait.
Successful logins do not consume the budget or clear earlier failures.
In-flight attempts reserve a slot so concurrent requests cannot bypass the limit.
Unknown accounts are also limited. Existing authentication tokens remain usable.

Known accounts are identified by their database ID, so equivalent email spellings
share a budget. The IP comes from the connection, not client-supplied forwarding
headers. Clients sharing a NAT address share the IP budget.
 
 ## upload-document

**Path**
`POST /api/upload-document`

**Description**  
This endpoint uploads a PDF document to the server and registers its metadata.

**Parameters**
```json
{
  "file": <pdf file>,
  "name": <string>
}
```

**Return**
```json
{
  "id": <string>,
  "name": <string>,
  "creation": <date ISO 8601>,
  "sha256": <string>,
  "size": <int>
}
```

**Specification**
 * Requires authentication
 * The upload-pdf endpoint MUST accept only files in PDF format.
 * The endpoint MUST reject documents above the configured upload limit with
   HTTP `413`.

## list-documents

**Path**
`GET /api/list-documents`

**Description**  
This endpoint lists all uploaded PDF documents along with their metadata.

**Parameters**  
_None_

**Return**
```json
{
  "documents": [
    {
      "id": <string>,
      "name": <string>,
      "creation": <date ISO 8601>,
      "sha256": <string>,
      "size": <int>
    }
  ]
}
```

**Specification**
 * Requires authentication
 * The response MUST return all documents of the user.
 
 ## list-versions

**Description**  
This endpoint lists all watermarked versions of a given PDF document along with their metadata.

**Path**
`GET /api/list-versions`

**Parameters**
```json
{
  "documentid": <int>
}
```

**Path**
`GET /api/list-versions/<int:document_id>`

**Parameters**  
_None_

**Return**
```json
{
  "versions": [
    {
      "id": <int>,
      "documentid": <int>,
      "link": <string>,
      "intended_for": <string>,
      "secret": <string>,
      "method": <string>
    }
  ]
}
```



**Specification**
 * Requires authentication
 * Ownership MUST be checked against the authenticated user's numeric ID, not login name.
 * Requests for another user's document or a nonexistent document return `200` with `{"versions": []}`.

 ## list-all-versions
 
**Path**
`GET /api/list-all-versions`

**Description**  
This endpoint lists all versions of all PDF documents for the authenticated user stored in the system.

**Parameters**  
_None_

**Return**
```json
{
  "versions": [
    {
      "id": <int>,
      "documentid": <int>,
      "link": <string>,
      "intended_for": <string>,
      "method": <string>
    }
  ]
}
```

Unlike `list-versions`, this listing does **not** include `secret` (the course
table lists it). This is the upstream implementation's behaviour; per-document
secrets remain available to the owner through `list-versions`.

**Specification**
 * Requires authentication
 * The response MUST contain only versions whose documents belong to the authenticated user's numeric ID, even when multiple accounts share a login name.

 ## get-document
 
**Description**  
This endpoint retrieves a PDF document by fetching a specific one when an `id` is provided.
 
**Path**
`GET /api/get-document`


**Parameters**
```json
{
  "id": <int>
}
```

**Path**
`GET /api/get-document/<int:document_id>`

**Return**
Inline PDF file in binary format.

**Specification**
 * Requires authentication
 
  ## get-watermarking-methods
 
**Description**  
This endpoint lists all available watermarking methods.
 
**Path**
`GET /api/get-watermarking-methods`


**Parameters**
_None_


**Return**
```json
{
    "count": <int>,
    "methods": [
        {
            "description":<string>,
            "name": <string>"
        }
    ]
}
```

**Specification**
 * The endpoint exposes exactly four choices: `davide-watermark`,
   `francesco-watermark`, `khaled-text-spacing-watermark`, and
   `group13-watermark` (the combined method).
 * `group13-watermark` applies the three component methods with the same
   secret and key. RMAP continues to default to this combined method; its
   configured method is independent of the manual watermarking interface.
 
   ## read-watermark
 
**Description**  
This endpoint reads information contain in a pdf document's watermark with the provided method.
 
**Path**
`POST /api/read-watermark`

**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>,
    "id": <int>
}
```
 
**Path**
`POST /api/read-watermark/<int:document_id>`


**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>
}
```


**Return**
```json
{
    "documentid": <int>,
    "secret": <string>,
    "method": <string>,
    "position": <string>
}
```

**Leak attribution (RMAP service account only)**
If the authenticated user owns the document configured as `RMAP_DOCUMENT_ID`
(the RMAP service account), the response also contains an `attribution`
field. The recovered secret is looked up in `Versions` for that document:
```json
{
    "documentid": <int>,
    "secret": <string>,
    "method": <string>,
    "position": <string>,
    "attribution": {"intended_for": <string>, "link": <string>} | null
}
```
`attribution` is `null` when no RMAP version has that secret. For every other
user the response is unchanged and has no `attribution` field.

If the method supports informed detection (`davide-watermark`,
`group13-watermark`) and the
secret cannot be read or matches no version, the leak's fingerprint is compared
with the RMAP source document and every version issued with that method. The
best match is returned when its score clears the method's threshold; `secret`
is then `null`. If nothing is read and nothing matches, the response is `400`,
as for a normal read. The fingerprint needs the watermark key and is never
available to other users, so the endpoint is not a public detection oracle.

With several colluding recipients (copies averaged together) the fingerprints
of all of them are present, but only the best-scoring version is returned.

**Status codes**
| Code | When |
|---|---|
| 201 | Watermark read (or, for the RMAP service account, attributed) |
| 400 | Missing `method`/`key`, or nothing readable with that key |
| 401 | Missing or invalid bearer token |
| 404 | Document does not exist or belongs to another user |
| 410 | Document file missing on disk |
| 503 | Database unavailable |
| 500 | Unknown `method` name (unhandled `KeyError` in the shared route; generic error body) |

A wrong key, an unmarked document and a stripped watermark all return the same
`400 {"error": "could not read watermark"}`, so the endpoint does not reveal
whether a document carries a watermark.

`position` is echoed back; the methods of the group ignore it (they mark every
suitable image, text run or page), except `khaled-text-spacing-watermark`,
which accepts only an empty position or `auto`. Maximum secret length:
128 UTF-8 bytes for `davide-watermark`, 64 for `francesco-watermark`, 48 for
`khaled-text-spacing-watermark` and `group13-watermark`.

**Specification**
 * The endpoint MUST return the secret read in the document, except for the
   RMAP service account's fingerprint-only matches described above (`secret: null`).


   ## create-watermark
 
**Description**  
This endpoint reads information contain in a pdf document's watermark with the provided method.
 
**Path**
`POST /api/create-watermark`

**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>,
    "secret": <string>,
    "intended_for": <string>,
    "id": <int>
}
```
 
**Path**
`POST /api/create-watermark<int:document_id>`


**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>,
    "secret": <string>,
    "intended_for": <string>
}
```


**Return**
```json
{
    "id": <int>,
    "documentid": <int>,
    "link": <string>,
    "intended_for": <string>,
    "method": <string>,
    "position": <string>,
    "filename": <string>,
    "size": <int>
}
```

**Specification**
 * Only the owner of a document should be able to create watermarked versions of their documents
 * The document owner MUST be able to list all versions of their documents and their intended recipients
 * The payload is a gpg encrypted JSON presented as ASCII armored base64, without any GPG headers.

## get-version

**Path**
`GET /api/get-version/<link>`

**Description**
Public download of a watermarked version (`application/pdf`). No token: the
32-hex link is a bearer secret (128 bits, unguessable). Anyone holding a link
can download that copy, so recipients must keep their link private. Unknown
links return `404`. Links are persistent.

 ## rmap-initiate
 
**Description**  
This endpoint receives GPG encrypted messages conforming to RMAP message 1.
 
**Path**
`POST /api/rmap-initiate`


**Parameters**
```json
{
    "payload": <ASCII_armored_base64>
}
```

should decrypt to:

```json
{
    "nonceClient": <u64>,
    "identity": <string>
}
```



**Return**
```json
{
    "payload": <ASCII_armored_base64>
}
```
should decrypt to:

```json
{
    "nonceClient": <u64>,
    "nonceServer": <u64>
}
```

**Specification**
 * The server SHOULD only respond to known identities.
 * All submitted group public keys MUST constitute valid identities.
 * The payload is a gpg encrypted JSON presented as ASCII armored base64, without any GPG headers.
 
  ## rmap-get-link
 
**Description**  
This endpoint receives GPG encrypted messages conforming to RMAP message 2.
 
**Path**
`POST /api/rmap-get-link`


**Parameters**
```json
{
    "payload": <ASCII_armored_base64>
}
```

should decrypt to:

```json
{
    "nonceServer": <u64>
}
```



**Return**
```json
{
    "payload": <ASCII_armored_base64>
}
```
should decrypt to:

```json
{
    "result":"<32-hex NonceClient||NonceServer>"
}
```

**Specification**
 * `get-version/<result>` SHOULD point to a watermarked version of a PDF specific to the group authenticated by the public key of the client.

## RMAP behaviour

**Status codes** (both routes return `{"error": <generic message>}` on failure;
details are only logged):

| Code | Route | When |
|---|---|---|
| 200 | both | Success |
| 400 | both | Non-JSON or malformed body, undecryptable payload, unknown identity, wrong `nonceServer` |
| 409 | rmap-get-link | Session already completed (replayed message 2) |
| 404 | rmap-get-link | RMAP source document not in the database |
| 410 | rmap-get-link | RMAP source file missing on disk |
| 500 | rmap-get-link | Watermarking failed: no link, no version row, no file |
| 503 | both | RMAP not configured, or database unavailable |

* **Identities** are the client key file names without `.asc`
  (`Group_07`, not `Group 07`). Keys are loaded at startup: adding or removing
  a key file takes effect after a server restart.
* **Sessions** between message 1 and message 2 live in the server process
  (single gunicorn worker). A restart drops them: the client gets `400` and
  simply starts a new handshake. Completed versions are stored in the database
  and survive restarts.
* **Keys**: recipients' PGP keys only authenticate the handshake. The watermark
  is keyed by the server-side `RMAP_WATERMARK_KEY`; no recipient key can read
  or detect any watermark, including the one in its own copy.

## RMAP configuration

RMAP is disabled unless all of the following are set at startup:

```dotenv
RMAP_SERVER_PUBLIC_KEY_PATH=/app/rmap-keys/server_public.asc
RMAP_SERVER_PRIVATE_KEY_PATH=/app/rmap-keys/server_private.asc
RMAP_CLIENT_KEYS_DIR=/app/rmap-keys/clients
RMAP_DOCUMENT_ID=42
RMAP_WATERMARK_METHOD=group13-watermark
RMAP_WATERMARK_KEY=<private-watermark-key>
# Optional when the server private key is protected:
RMAP_SERVER_KEY_PASSPHRASE=
# Preferred alternative: a mode-600 file, mounted read-only in the container.
RMAP_SERVER_KEY_PASSPHRASE_FILE=/app/rmap-keys/server_passphrase
```

Client public-key files in `RMAP_CLIENT_KEYS_DIR` define the accepted
identities: `Group_01.asc` registers `Group_01`. On each completed handshake,
Tatou watermarks the configured source document with the authenticated identity
and session link, inserts the new version, and uses the resulting 32-character RMAP link as its
`Versions.link`. The returned result is then fetched with
`GET /api/get-version/<result>`.

Compose mounts `RMAP_KEYS_HOST_DIR` (or `./rmap-keys` by default) read-only at
`/app/rmap-keys`; the directory and private keys are ignored by Git. Use the
passphrase file instead of the environment variable when the private key is
protected, and do not set both variables.
