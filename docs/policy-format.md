# Hermes local policy format

The local developer journey is: describe scope in YAML, mint a warrant, run the
agent, and exchange files when an operation needs a signature. No identity
service, hosted approval service, or cloud dependency is required.

A policy is an unsigned issuance template. It is not a grant or a runtime trust
source. The operator chooses the issuer, holder and session outside the policy.
The issuer signs capabilities, expiry, gates and approver public keys into a
warrant. Enforcement checks that warrant and signed operation approvals; it never
reads policy files or follows public-key file references.

## Version 2

```yaml
version: 2
name: service-maintenance
ttl: 20m
capabilities:
  get_service_status:
    service: {exact: example}
  restart_service:
    service: {exact: example}
approvals:
  keys:
    - ./keys/operator.pub
  gates:
    restart_service:
      always: true
```

Version 2 adds optional `approvals` to the existing version 1 scope format.
Version 1 continues rejecting approval fields. Unknown versions and fields are
errors. Capabilities retain their existing typed constraints. An `approvals`
section requires nonempty `keys` and `gates`:

- `keys`: distinct public-key files, absolute or relative to the resolved policy
  file's directory. Keys use the existing base64 public-key file format. There is
  no environment expansion, home interpolation, or task templating. Different
  paths containing the same public key are rejected as duplicate keys.
- `gates`: granted tool names mapped to exactly `{always: true}`. Gates cannot
  grant tools or arguments that capabilities do not permit.
- Any one listed key may approve. There is no configurable `threshold` field in
  this local format. Existing warrants' signed approval requirements are always
  respected, including warrants minted elsewhere with more than one signer.

Names are optional local labels, not verified human identities. Authorization
uses public keys. Show fingerprints when asking humans which key they trust.
Cloud can provide organizations, verified identities, groups and policy
administration without being necessary for local authorization.

`policy validate` validates syntax, key files and distinct decoded keys.
`policy show` displays the policy and resolved key fingerprints. Minting reads
key contents once and embeds them in the signed warrant. An authority request
created from this policy similarly freezes actual key bytes into a version 2
request; it never asks the approving controller to open policy-supplied paths.
Changing the policy or public-key files afterward cannot change that snapshot.

## Hermes YAML adapter, Tenuo SDK semantics

YAML is a Hermes-specific developer convenience. Temporal, LangChain and
LangGraph remain code-first and mint warrants using the SDK. This format does
not require those integrations to implement YAML support.

The Hermes layer validates document structure, resolves public-key files and
maps supported typed declarations to existing SDK constraint and builder APIs.
It does not evaluate constraints or gates, verify its own signature format, or
introduce another policy engine. Those semantics remain in Tenuo.

The current tenuo-python SDK exposes native constraint constructors and
`parse_strict_json`, which Hermes reuses for portable request/response parsing.
It does not currently expose a general YAML-to-warrant policy loader. The SDK's
MCP YAML loader configures argument extraction, not scope issuance; reusing that
as a policy compiler would give it a different meaning.

If a compatible SDK policy loader becomes available, delegate to it rather than
maintaining parallel parsers. No new SDK or Rust-core policy API is introduced
by this PR. Other integrations can continue building exactly the same warrants
in code, sharing SDK enforcement and gate semantics without sharing YAML.

### Conditional gates: later, using core semantics

The current parser deliberately rejects conditional gates. A useful future
extension is an exemption, for example:

```yaml
# Proposed extension; NOT accepted by the current version 2 parser.
gates:
  refund:
    exempt:
      amount_cents: {range: {min: 1, max: 5000}}
```

This should compile to core's existing `Exempt(Range(1, 5000))` argument gate:
matching calls do not need approval; other otherwise-authorized calls do.
Capability denial still denies, even if an exemption matches. Missing arguments,
multiple argument conditions, exemption narrowing during delegation and supported
constraint types must follow core exactly. Define conformance tests before
shipping the extension; do not invent integration-specific "fires when" logic.
Unsupported conditions must fail closed, never become ungated or silently map to
another gate type.

### Per-task values: keep them in code

A refund for a particular order may need an order ID and maximum amount looked
up at workflow start. That remains application-side issuance code. Avoid adding
expression evaluation, arbitrary interpolation, secret lookup, or framework
context into a common static policy format.

A later bridge can mint a parent warrant from platform policy, then explicitly
delegate a narrower child warrant for each task. The signed parent, not the YAML,
is the actual standing authority. Such children must stay within the parent's
capabilities, expiry and approval restrictions; delegation never bypasses a gate.
