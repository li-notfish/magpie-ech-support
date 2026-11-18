# magpie-ech-middleware

DNS over HTTPS (DoH) for [magpie](https://usemagpie.ai). The sidecar resolves
upstream A/AAAA addresses through encrypted DNS, connects to the returned IPs,
and forwards requests with normal TLS.

DoH encrypts DNS queries. Optional ECH support encrypts TLS SNI only when the
upstream's own HTTPS record publishes a valid configuration. Historical package
names and the `ech` provider ID remain for compatibility.

## Install and sign in

```sh
magpie plugin add github:li-notfish/magpie-ech-middleware
```

Go to Settings → Providers → **DoH** → sign in with the upstream HTTPS base URL,
API kind, and API key. Sign in again to add another upstream or key. Model routes
keep the compatible ID: `ech/<model>`. Chat Completions, Responses, Anthropic
Messages, Gemini, and streaming responses are supported.

To change an account, use its **Edit** button in the provider editor. The saved
address and API kind are prefilled. Leave the API key blank to keep it, or enter
a new key to replace it; no new login is needed. Saving affects only that
account. This requires a magpie version that supports editable plugin accounts.

## Options

Set plugin options with `magpie plugin options <name> '<json>'`:

| Option | Default | Purpose |
| --- | --- | --- |
| `port` | `8790` | Local sidecar port |
| `doh` | `""` | Custom DoH endpoints, comma-separated; empty uses built-ins |
| `ech` | `false` | Discover ECH from the upstream's HTTPS record and use it when available |

The default resolvers are queried concurrently; the first valid answer wins:

```text
https://223.5.5.5/resolve
https://1.12.12.12/dns-query
```

Their IP addresses avoid a bootstrap system DNS query for the resolver itself.

Use your own service:

```sh
magpie plugin options magpie-ech-middleware '{"doh":"https://doh.pub/dns-query"}'
```

Multiple comma-separated addresses **replace**, rather than extend, the built-in
list:

```sh
magpie plugin options magpie-ech-middleware '{"doh":"https://doh.pub/dns-query,https://dns.alidns.com/dns-query"}'
```

JSON DoH and RFC 8484 wire format are supported. Supply the complete query URL.
HTTPS is supported; HTTP is intended only for local or test resolvers because it
does not encrypt DNS. The system DNS may resolve a custom resolver's own hostname
to connect to it, but every **upstream** hostname is resolved exclusively through
DoH. Restart magpie after changing the endpoints.

## Optional ECH

```sh
magpie plugin options magpie-ech-middleware '{"ech":true}'
```

With `ech` enabled, the sidecar also queries the upstream's HTTPS (type 65)
record. It uses only the `ech` configuration actually published there; there is
no fixed Cloudflare configuration or provider-name guessing. Missing records or
failed discovery use ordinary TLS. If a published configuration is rejected, the
sidecar retries only with a new configuration supplied by the server and never
silently downgrades that connection to plaintext SNI.

Set `ech` back to `false` for DoH-only operation. Changing `doh` or `ech` requires
a magpie restart so the sidecar is restarted with the new flags.

## Request flow

1. The plugin writes signed-in upstreams to
   `<magpie directory>/magpie-ech-middleware/upstreams.json`.
2. A model listing or first request starts the sidecar.
3. The sidecar concurrently asks DoH for A and AAAA records and caches successful
   answers.
4. It connects to a returned IP and performs TLS with the original hostname.
   With `ech` enabled and a published configuration, TLS 1.3 ECH encrypts SNI;
   otherwise it performs an ordinary TLS handshake.
5. It forwards the request, including streaming responses.

The upstream file stays simple:

```json
{
  "api-example-com-v1-9f86d081": "https://api.example.com/v1"
}
```

Legacy `{ "url": "...", "ech": "..." }` values are read by URL only. The `ech`
setting is ignored and removed the next time the account is written. The
`echFallback` option, `ECH_SIDECAR_ECH_FALLBACK`, and
`ECH_SIDECAR_ALLOW_PLAIN` are no longer used. HTTP Host, TLS SNI, and certificate
verification retain the original upstream hostname.

## Running the sidecar directly

```sh
ech-sidecar.exe -upstreams-file upstreams.json -listen 127.0.0.1:8790 `
  -doh "https://doh.pub/dns-query" [-ech]
```

Omit `-doh` to use the built-in resolvers. `/_ech/health` is the retained
compatibility health-check path and does not contact an upstream.

The sidecar is downloaded per package version from the
[sidecar release](https://github.com/li-notfish/magpie-ech-middleware/releases/tag/sidecar).
Set `ECH_SIDECAR_PATH` to use your own binary, or place one in
`sidecar/bin/<platform>-<arch>/`. To build from source, use Go 1.26 or newer:

```sh
npm run build
```

Increment `package.json`'s `version` after changing `sidecar/` so existing
installations download the new binary.

## Troubleshooting

- **No models**: check the upstream address, API kind, key, and models endpoint;
  sign in again if an old account lacks an address.
- **ECH is unavailable**: enable `ech` and check that the upstream's HTTPS record
  actually contains `ech`; an orange cloud alone does not supply the client configuration.
- **DoH resolution fails**: check the full DoH URL and connectivity, or clear
  `doh` and restart to restore built-ins.
- **TLS certificate errors**: certificate verification stays enabled; check the
  upstream hostname and certificate.
- **The sidecar does not start**: check the local port, set `ECH_SIDECAR_PATH`,
  or run `npm run build`.
