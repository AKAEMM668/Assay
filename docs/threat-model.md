# Threat model

This page records security decisions that are not obvious from the code alone.
It exists so the reasoning behind a refusal can be reviewed and revisited, not
just the code that implements it.

## Non-public `home_domain` hosts (issue #76)

### The surface

`home_domain` is an issuer-controlled free-text field on a Stellar account.
Assay turns it into a URL (`https://<home_domain>/.well-known/stellar.toml`) and
fetches it. Horizon caps the field at 32 bytes, which limits but does not remove
the surface.

Any account can set `home_domain` to `localhost`, an internal hostname, or an
address that resolves into a private range. When Assay runs as a server — which
`assay serve` supports and the deployed API does — that makes the scanner a
request-forgery primitive against everything the server can reach, including
cloud instance metadata endpoints. The error text from a refused or failed fetch
is also echoed into the report and into hashed evidence.

### The decision

**Assay refuses non-public hosts.** It does not attempt to fetch them and then
report the failure.

The policy lives in `internal/sep1` and has two layers:

1. **Literal host policy** (`sep1.ClassifyHost`). Refuses loopback (`127.0.0.0/8`,
   `::1`), private IPv4 (`10/8`, `172.16/12`, `192.168/16`) and IPv6 (`fc00::/7`),
   link-local (`169.254/16`, `fe80::/10`), the cloud metadata address
   `169.254.169.254`, unspecified and multicast addresses, reserved ranges
   (`0.0.0.0/8`, `192.0.0.0/24`, `240.0.0.0/4`, `198.18/15`, the CGNAT range
   `100.64/10`), and names that cannot resolve publicly (`localhost`, a
   `*.localhost`/`*.local`/`*.internal`/`*.home.arpa` name, a bare single-label
   hostname). This layer is pure and runs before any request is made.
2. **Dial-time address policy** (`sep1.CheckDialAddress`, installed on the
   default fetcher's dialer). This runs on the concrete address a connection is
   about to use, so a hostname that *resolves* to a non-public address is
   refused at connect time.

### How a refusal is reported

A refusal is an Assay decision, not a source that failed. It is recorded as
attributed evidence with the same shape as a fetch failure but marked
`refused` (and `attempted`) programmatically, so a consumer can distinguish
"Assay declined to fetch this host" from "the host did not answer" without
parsing English. The domain check reports the accountability as `unverified`,
with reasoning that names the refusal.

### DNS-rebinding limits, stated honestly

- The dial-time guard checks the address the connection actually uses. There is
  no resolve-then-connect window between the check and the connection, because
  the check runs on the resolved address the dialer is about to connect to.
- **The guard is only as strong as the transport that carries it.** If a caller
  replaces `sep1.Fetcher.HTTP` or its `Transport`, the guard is gone. Tests do
  exactly this to point the fetcher at a local server; production code should
  not.
- The default transport deliberately does **not** honour `HTTP_PROXY` /
  `HTTPS_PROXY`, because a proxy would make the connection the guard exists to
  forbid.
- A redirect to a non-public host is caught on the next dial, because the same
  guarded transport serves every hop.
- This is not a full SSRF proxy: it does not inspect response bodies, does not
  restrict ports, and assumes the process has no other egress restrictions. It
  exists to make the obvious request-forgery primitive from issuer-controlled
  input impossible, not to secure an arbitrary server against every outbound
  request.

### Out of scope

- A full egress proxy or network namespace.
- Changing the 32-byte Horizon `home_domain` limit assumption.
