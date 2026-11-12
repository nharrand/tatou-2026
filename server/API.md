# Tatou API Documentation

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
- [identify-document](#identify-document) — **POST** `/api/identify-document/<int:document_id>`
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
`GET /api/healthz`

**Description**  
This endpoint checks the health of the server and confirms it is running.

**Parameters**  
_None_

**Return**
```json
{
  "message": <string>
}
```

**Specification**
 * The healthz endpoint MUST be accessible without authentication.
 * The response MUST always contain a "message" field of type string.
 
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
      "id": <string>,
      "documentid": <string>,
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
 
 
 ## list-all-versions
 
**Path**
`GET /api/list-versions`

**Description**  
This endpoint lists all versions of all PDF documents for the authenticated user stored in the system.

**Parameters**  
_None_

**Return**
```json
{
  "versions": [
    {
      "id": <string>,
      "documentid": <string>,
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
 * The endpoint MUST return all methods in `watermarking_utils.METHODS`.
 
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
`POST /api/read-watermark<int:document_id>`


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

**Specification**
 * The endpoint MUST return the secret read in the document.


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

   ## identify-document

**Description**
This endpoint takes a PDF found "in the wild" (for example, a copy that leaked), reads its
watermark with the given method and key, and tells the owner of `document_id` which of their
own watermarked versions, if any, it matches. It exists so the owner never has to re-upload a
found document as if it were new content to be watermarked.

**Path**
`POST /api/identify-document/<int:document_id>`

**Parameters** (multipart/form-data)
```json
{
    "file": <binary PDF>,
    "method": <string>,
    "key": <string>,
    "position": <string, optional>
}
```

**Return**
```json
{
    "documentid": <int>,
    "method": <string>,
    "secret": <string>,
    "matches": [
        { "versionid": <int>, "intended_for": <string> }
    ]
}
```

**Errors**
Every failure returns `{"error": <string>}` with a 4xx/5xx status. `method` naming an
unregistered watermarking method MUST return 405.

**Specification**
 * The endpoint MUST require authentication (a valid bearer token), exactly as read-watermark and create-watermark do.
 * The endpoint MUST only match against versions of a `document_id` owned by the authenticated caller; a non-existent document and a document owned by someone else MUST produce the identical 404 response, so the error never reveals whether a given document id exists.
 * The endpoint MUST return HTTP 405 with `{"error": <string>}` when `method` does not name a method registered in `watermarking_utils.METHODS`, and MUST do so before the uploaded file is read or the key is used.
 * The uploaded file MUST be validated as a well-formed PDF by its content (the `%PDF-` header), not by its filename or declared content type, before it is handed to any watermark-reading code.
 * The uploaded file MUST be processed in memory only and MUST NOT be written to persistent storage, so the route cannot be used to plant files on the server or to exhaust disk space with attacker-supplied "leaked" documents.
 * Error responses (unknown method, wrong key, no watermark of this method present, corrupt upload) MUST NOT include the submitted key, the secret recovered from a failed attempt, or any filesystem path, so repeated probing gives the caller no signal beyond "it failed".
 * The `matches` array in a successful response MUST only ever contain versions of the requested `document_id` created with the requested `method`, and MUST expose only `versionid` and `intended_for` - never another version's `secret`, `key`, or storage `path`.
 * The size of the uploaded file SHOULD be bounded (the server already enforces `MAX_CONTENT_LENGTH` for every route) so a "leaked" file cannot be used for a memory/disk-exhaustion denial of service, and exceeding that bound SHOULD still produce a JSON error, not an HTML one.

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
 * Every client-side failure (missing or malformed payload, unknown identity) returns HTTP 400 with `{"error": "invalid request"}`, so the response does not reveal which identities are known.
 * The library keeps one pending session per identity. A second message 1 from the same identity replaces the first, and the first handshake's message 2 is then rejected with 400.
 
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
 * The link MUST NOT be returned unless the watermarked copy has been created and recorded in the database.
 * A session is single use: a replayed message 2 is rejected with HTTP 400 before any watermarking happens.
 * A message 2 that does not match a pending session, and any malformed payload, returns HTTP 400 with `{"error": "invalid request"}`.
