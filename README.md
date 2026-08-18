# KeepFlip eBay OAuth Function

This is the server-side eBay account-connection boundary for KeepFlip. It is
separate from `ebay-sold-comps`: it does not change valuation behavior or the
existing valuation prompt.

It exposes four routes on its Appwrite Function domain:

| Route | Access | Purpose |
| --- | --- | --- |
| `POST /connect` | Signed-in KeepFlip user | Creates a short-lived one-time state and returns the eBay consent URL. |
| `GET /oauth/ebay/callback` | eBay redirect only | Claims the state, exchanges the code on the server, encrypts token data, then returns to KeepFlip. |
| `GET /oauth/ebay/declined` | eBay redirect only | Marks a declined consent attempt and returns to KeepFlip. |
| `POST /status` | Signed-in KeepFlip user | Returns only whether the current user has an active eBay connection. |

The callback never puts an authorization code, OAuth state, access token,
refresh token, or eBay identity in a KeepFlip deep link. Its only successful
return is:

```text
keepflip://ebay/connected?status=connected
```

## Appwrite Function settings

Create a Function named **KeepFlip eBay Connection** with:

| Setting | Value |
| --- | --- |
| Function ID | `ebay_oauth` |
| Runtime | `node-22` |
| Entrypoint | `src/main.js` |
| Build command | `npm install` |
| Execute access | `Any` |
| Timeout | `30` seconds |
| Dynamic-key scopes | `rows.read`, `rows.write` only |
| Logging | enabled |

`Any` is necessary so eBay can reach the browser callback. The two Function
routes the app calls (`/connect` and `/status`) still verify the Appwrite user
JWT on the server before they do any work.

After deployment, copy the Function's generated HTTPS domain into the eBay
Developer Portal URLs:

```text
Accept URL:  https://<your-function-domain>/oauth/ebay/callback
Decline URL: https://<your-function-domain>/oauth/ebay/declined
```

eBay gives each environment its own redirect RuName. Enter those values in the
Function variables below; do not put secrets in a mobile `.env` file.

## Function variables

Add these in Appwrite Console → Function → Settings → Variables, then deploy a
new Function version.

| Variable | Value |
| --- | --- |
| `EBAY_OAUTH_ENVIRONMENT` | `sandbox` while testing, then `production` |
| `EBAY_CLIENT_ID` | Your matching eBay application Client ID |
| `EBAY_CLIENT_SECRET` | Your matching eBay application Client Secret |
| `EBAY_SANDBOX_RUNAME` | Sandbox RuName from eBay |
| `EBAY_PRODUCTION_RUNAME` | Production RuName from eBay |
| `EBAY_TOKEN_ENCRYPTION_KEY` | Stable Base64-encoded random 32-byte key |
| `EBAY_OAUTH_SCOPES` | Start with `https://api.ebay.com/oauth/api_scope` |

Mark the Client Secret and token encryption key as secrets. Keep every one of
these out of `EXPO_PUBLIC_*` variables and the app bundle.

In Windows PowerShell, make the encryption key once and store the result in the
Function variable:

```powershell
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)
```

Do not rotate that key casually: it is required later to decrypt already saved
eBay tokens for refresh or messaging.

## Required private TablesDB tables

Create both tables in database `keepflip` with **Row security enabled** and
**no table permissions**. The Function's dynamic key is the only reader and
writer. Do not reuse `marketplace_listings` or `marketplace_inquiries`; those
are KeepFlip's own marketplace data.

### Table: `ebay_oauth_states`

| Column | Type | Required | Values / size |
| --- | --- | --- | --- |
| `ownerId` | String | yes | 36 |
| `environment` | Enum | yes | `sandbox`, `production` |
| `status` | Enum | yes | `pending`, `processing`, `completed`, `failed`, `declined` |
| `scopeText` | Text | yes | OAuth scopes separated by spaces |
| `createdAt` | Datetime | yes | |
| `expiresAt` | Datetime | yes | |
| `claimedAt` | Datetime | no | |
| `completedAt` | Datetime | no | |
| `failureCode` | String | no | 64; safe internal code only |

No plaintext OAuth state is stored. The Function hashes the high-entropy state
into the Appwrite row ID, then atomically changes only a `pending` row to
`processing` before it talks to eBay.

### Table: `ebay_connections`

| Column | Type | Required | Values / size |
| --- | --- | --- | --- |
| `ownerId` | String | yes | 36 |
| `environment` | Enum | yes | `sandbox`, `production` |
| `status` | Enum | yes | `active`, `revoked`, `expired` |
| `tokenCiphertext` | Long text | yes | AES-256-GCM encrypted JSON only |
| `accessTokenExpiresAt` | Datetime | yes | |
| `refreshTokenExpiresAt` | Datetime | yes | |
| `scopeText` | Text | yes | granted scopes; no token |
| `createdAt` | Datetime | yes | |
| `updatedAt` | Datetime | yes | |
| `revokedAt` | Datetime | no | |

The Function uses deterministic row IDs, so a user has one connection per eBay
environment. It does not return `tokenCiphertext` to the app.

## Mobile handoff when you add the Connect eBay button

Call `POST /connect` through Appwrite, then launch the returned URL with
`WebBrowser.openAuthSessionAsync`. The app already owns the `keepflip` URL
scheme, so use this return URL:

```ts
Linking.createURL("ebay/connected", { scheme: "keepflip" })
```

When it receives `status=connected`, call `POST /status` through Appwrite to
confirm the signed-in KeepFlip user owns an active connection. Do not persist
OAuth material on the device.

## Verification

From this function folder:

```powershell
npm.cmd run check
npm.cmd test
```
