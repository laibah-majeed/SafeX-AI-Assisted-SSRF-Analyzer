# SSRF Research

## SSRF Definition

Server-Side Request Forgery (SSRF) is a vulnerability class in which an
attacker can influence the destination of an HTTP (or other protocol)
request that a server makes on the attacker's behalf. Instead of the
attacker's browser making the request, the *server* makes it — often from
a privileged network position the attacker could not otherwise reach
directly.

## Root Causes

- User input is used, directly or indirectly, to construct a URL or
  network destination that the server then requests.
- Insufficient or absent validation of that destination (scheme, host,
  port, path).
- Overly trusting internal network architecture — assuming that because a
  request originates from the application server, it is inherently safe.
- Blind trust in redirects: a server-side HTTP client that follows
  redirects without re-validating the final destination.

## How SSRF Happens

A typical vulnerable pattern looks like:

```text
GET /fetch?url=https://example.com/image.png
```

If the backend takes the `url` parameter and fetches it server-side without
restriction, an attacker can instead supply:

```text
GET /fetch?url=http://127.0.0.1:PORT/internal-only-endpoint
```

causing the server to make a request to a destination the attacker could
not otherwise reach — including loopback services, internal APIs, or (in
cloud environments) instance metadata endpoints.

## Common Scenarios

- "Fetch a URL and show a preview" features (link unfurling, image
  proxies, webhooks-as-a-service).
- PDF/document generators that fetch remote resources referenced in the
  input document.
- Import/integration features that fetch data from a user-supplied
  endpoint.
- Redirect-following HTTP clients used inside internal services.

## Impact

Depending on network architecture, SSRF can enable:

- Port scanning and service discovery on internal networks.
- Interaction with internal-only APIs or admin interfaces.
- Reading data from services that only trust requests from the internal
  network (no authentication).
- In cloud environments, potential access to instance metadata services,
  which is a well-known high-impact SSRF outcome — this project does not
  test for or target such endpoints, as that is out of scope for a local
  academic lab.

## Detection Methodology

Because SSRF often manifests only as a subtle change in server behavior,
detection typically relies on **behavioral comparison** rather than a
single definitive signal:

1. Establish a baseline: how does the endpoint normally behave?
2. Introduce controlled, safe variations of any suspected destination
   parameter.
3. Compare status code, response length, response body, and timing
   between baseline and variant requests.
4. Look for multiple, independent, repeatable differences — not a single
   anomalous result.

## False Positives

Response differences can occur for reasons unrelated to SSRF:

- Dynamic or personalized content that changes between requests.
- Caching (a cache miss vs. hit changes timing and sometimes content).
- Rate limiting or throttling kicking in on later requests.
- Authentication/session state expiring mid-test.
- General network jitter or backend load variance.

A robust detector treats a single differing signal as weak evidence and
requires corroboration across multiple signals before reporting a finding.

## False Negatives

SSRF detection based on observable response differences will miss:

- **Blind SSRF**, where the server makes the request but the outcome is
  never reflected in any observable response (no status/timing/body
  change reaches the client).
- SSRF reachable only via request bodies, headers, or parameters not
  present in the tested URL.
- SSRF behind authentication that the scanner does not have session
  context for.

## Prevention

- **Allowlist, don't denylist** destination hosts/schemes wherever
  possible.
- Resolve and validate the destination's IP address, rejecting loopback,
  link-local, and other internal ranges unless explicitly required.
- Validate redirect targets before following them (or disable automatic
  redirect-following and validate manually).
- Apply network segmentation so that even a successful SSRF cannot reach
  sensitive internal services.
- Run the fetching component with least privilege and minimal network
  egress.

## Remediation

Beyond the prevention measures above, teams should:

- Centralize outbound HTTP fetches through a single, monitored client or
  proxy rather than allowing ad hoc fetch code throughout the codebase.
- Log and alert on outbound requests to unexpected destinations.
- Add automated tests (including tools like this one, in a lab
  environment) to catch regressions as the codebase evolves.

## Secure Development Practices

- Treat any feature that fetches a URL on the server's behalf as a
  security-sensitive code path requiring review.
- Document which destinations a fetch feature is expected to reach, and
  enforce that expectation in code (allowlists), not just in
  documentation.
- Include SSRF-specific test cases in the team's security testing
  checklist for any new "fetch a URL" feature.
