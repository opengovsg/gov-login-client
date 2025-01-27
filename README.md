![](sgid-logo.png)

# gov-login-client

[![npm version](https://badge.fury.io/js/@opengovsg%2Fsgid-client.svg)](https://badge.fury.io/js/@opengovsg%2Fgov-login-client)

The official TypeScript/JavaScript client for gov-login

This SDK is a fork of the [sgID SDK](https://github.com/opengovsg/sgid-client).

## CHANGELOG

See [Releases](https://github.com/opengovsg/gov-login-client/releases) for CHANGELOG and breaking changes.

## Installation

```bash
npm i @opengovsg/gov-login-client
```

## Usage

### Initialization

```typescript
import GovLoginClient from '@opengovsg/gov-login-client'

const client = new GovLoginClient({
  clientId: 'CLIENT-ID',
  clientSecret: 'cLiEnTsEcReT',
  redirectUri: 'http://localhost:3000/callback',
})
```

### Get Authorization URL

`client.authorizationUrl(state, scope, [nonce], [redirectUri])`

```typescript
const { url } = client.authorizationUrl(
  'state',
  ['openid', 'myinfo.nric_number'], // or space-concatenated string
  null, // defaults to randomly generated nonce if unspecified
  'http://localhost:3000/other_callback', // overrides redirect uri
)
```

### Token exchange

`async client.callback(code, [nonce], [redirectUri])`

```typescript
const { sub, accessToken } = await client.callback(
  'code', // auth code reuturned from redirect_url
  null,
  'http://localhost:3000/other_callback', // optional, unless overridden
)
```

### User info

`async client.userinfo(accessToken)`

```typescript
const { sub } = await client.userinfo('access_token')
```

## Supported Runtime and Environment

This library depends on [jose](https://www.npmjs.com/package/jose) npm package which currently supports [these Node.js versions](https://github.com/panva/jose/issues/262).
