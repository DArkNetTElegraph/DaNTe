# DaNTe Threat Model

> Status: draft (Phase 0). This document is normative: every later phase must
> state how it upholds or amends these guarantees. If an implementation cannot
> meet a guarantee here, the guarantee changes here first.

## 1. Goals

DaNTe exists to provide **private, anonymous, censorship-resistant communication
with no operator who can be compelled to surveil users**. Concretely:

- **Content confidentiality** — nobody but the intended recipients can read
  message or call content.
- **Forward secrecy (FS)** — compromise of long-term keys does not expose past
  content.
- **Post-compromise security (PCS)** — after a device compromise ends, future
  content becomes secret again once a fresh key exchange occurs.
- **Sender/recipient authenticity** — recipients can be certain who they are
  talking to (via key fingerprint verification).
- **Anonymity** — an identity is a bare keypair. Registration requires no phone
  number, email, payment, or invite from an existing user.
- **Tamper-evident key directory** — a malicious actor cannot silently swap a
  user's published public key without detection.
- **No project infrastructure** — there is no server the project operates and
  therefore none it can be forced to backdoor.

## 2. Assets

| Asset | Where it lives |
|---|---|
| Long-term identity private keys (Ed25519 sign, X25519 agree) | User device, encrypted keystore |
| DM session state (Double Ratchet chains) | User device, encrypted store |
| Group (MLS) secrets | Devices of current group members |
| Message / call plaintext | Sender + recipient devices only |
| Encrypted key backup | Wherever the user chooses to store the exported blob |
| Social graph (who talks to whom) | Partially observable to relays and network observers — see §5 |
| Ledger (identity records, server registry) | Public by design, replicated widely |

## 3. Adversaries

| # | Adversary | Capabilities assumed |
|---|---|---|
| A1 | **Passive network observer** | Sees all packets on links it controls (ISP, coffee-shop Wi-Fi, backbone tap). Cannot break modern crypto. |
| A2 | **Active network attacker** | A1 plus can drop, delay, reorder, replay, and inject packets; can MITM unauthenticated channels. |
| A3 | **Malicious / compromised relay** | Runs a relay node. Sees every envelope it stores or forwards and their timing/size. May lie, withhold, or selectively deliver. Does **not** have group membership unless separately invited. |
| A4 | **Malicious server admin / member-host** | Legitimately inside a server they host. Sees all plaintext of channels they are a member of (by design). May abuse roles, forge server-level metadata, retain history after others delete. |
| A5 | **Sybil / flood attacker** | Wants to mint millions of identities or servers to exhaust storage, pollute discovery, or drown out users. Has moderate but not unlimited CPU/RAM/bandwidth and many IPs. |
| A6 | **Ledger-equivocation attacker** | Tries to show different users different versions of the key directory (split view) to enable targeted key substitution. |
| A7 | **Endpoint attacker** | Has code execution or physical access on a target device, temporarily or permanently. |
| A8 | **Global passive adversary (GPA)** | Observes the entire network simultaneously; performs large-scale traffic-correlation / timing analysis. |
| A9 | **Coercion of a participant** | Legal or physical compulsion of a user or relay operator to hand over keys or data they actually hold. |

## 4. Guarantees vs. adversaries

| Guarantee | Holds against | Notes |
|---|---|---|
| DM content confidentiality | A1, A2, A3, A4, A5, A6, A8 | Broken only by A7 (endpoint) or A9 (coercion of a conversation participant). |
| DM forward secrecy | A1–A6, A8; **partial** vs A7 | Double Ratchet: content before a compromise stays secret; keys already on the device at compromise time are exposed until the next ratchet step. |
| DM post-compromise security | A7 (after access ends) | Requires both parties to exchange at least one new message post-compromise. |
| 1:1 call media confidentiality | A1, A2, A3, A5, A6, A8 | WebRTC DTLS-SRTP between the two peers. The SDP offer/answer (carrying each side's DTLS certificate fingerprint) travels inside a sealed-sender, sender-authenticated ratchet DM, so a relay cannot substitute its own DTLS identity for a MITM. Broken only by A7 / A9. Peer IP addresses are exposed to each other (and to any TURN relay, including a `--turn-listen` relay) — see §5.5. |
| Group call media confidentiality | A1, A2, A3, A5, A6, A8 | A channel group call is a **full mesh** of the 1:1 legs above, each its own DTLS-SRTP, so the relay never sees media. Membership is bound by an MLS group whose exporter secret (`Engine::group_call_key`) rotates on every join/leave. On Chromium browsers the SPA additionally wraps each Opus frame in AES-GCM keyed by that secret (an SFrame layer), so media stays confidential even to an SFU that forwards without decoding; where the browser lacks encoded transforms this is a silent no-op and the guarantee is exactly the mesh's per-leg DTLS-SRTP. Every participant learns every other participant's IP (mesh). An SFU media component (`crates/dante-sfu`) is opt-in via the relay's `sfu` feature and `dante serve --sfu`; see §5.10 for how enabling it changes the trust boundary. Not against A4 — a participant is in the call. |
| Group (channel/voice) content confidentiality | A1, A2, A3, A5, A6, A8 | **Not** against A4 — a member-host is inside the group and sees plaintext by design. |
| Group forward secrecy | A1–A3, A5, A6, A8; **partial** vs A7 | Channels and group calls each run one MLS group (RFC 9420); the MLS secret tree gives per-message forward secrecy. |
| Group **post-compromise security** | A7 (after access ends) | MLS rekeys the whole group on every add / remove, and any member can force a rekey by committing an update — a compromised member's key stops being useful once the group next changes. |
| Removed member loses access | A (the removed member) | The host commits an MLS remove; the group rekeys in O(log n) and the removed member is evicted (cannot process further messages). Re-admission works with a fresh KeyPackage. The host also republishes the channel's relay-side roster (§6) with the member dropped, so they can no longer write to the log either — holding the (non-rotating) `channel_id` is no longer enough on its own — and that roster update is itself gossiped to every relay in a federated mesh, not just the one the host happened to reach, so the enforcement isn't limited to a single relay. |
| Group message authorship (insider forgery) | A4 / any member | MLS binds every application message to its sender's leaf signature key; another member cannot forge a message as someone else. Channel membership **commits** are additionally accepted only from the recorded host identity (`process_from`). |
| Password-protected channel log | A3, and a leak of the `channel_id` capability | A channel created with a password wraps every relay-log frame in an outer XChaCha20-Poly1305 layer keyed by `Argon2id(password; server_root ‖ channel_id)`. A relay, or anyone who obtains only the `channel_id`, sees opaque blobs and cannot strip the wrapper. The wrapper key is static per `(channel, password)` and does not rotate with MLS epochs; a removed member still holds it but is MLS-evicted underneath, so cannot read the inner content. Never against A4 (a member has the password). Weaving the PSK into the MLS key schedule instead would add epoch rotation — a possible future hardening. |
| Recipient authenticity | A2, A3, A6 | Only after out-of-band fingerprint / safety-number verification. Trust-on-first-use (TOFU) before that is vulnerable to A2/A6. |
| Anonymity of identity | A3, A4, A5 | Identity carries no PII. See §5 for what still leaks. |
| Key-directory tamper-evidence | A6 | Consistency proofs + gossiped Merkle roots let clients detect a split view. Detection, not prevention — see §6. |
| Explicit key revocation | A7 (after the fact), A9 | The holder of a chain's current key can publish a terminal `IdentityRevoke` (kind 7). Every replica then resolves that identity to no usable key and rejects all later records for it, so honest peers stop encrypting to a stolen or retired key as soon as they sync. Does not recall messages already sent, and a relay withholding the revoke record from a victim is the split-view problem (A6, see §6). |
| Sybil resistance | A5 | Raised cost, not eliminated — see §6. |

## 5. Non-goals / explicit limitations

These are **out of scope**. Users must not rely on protections DaNTe does not
provide.

1. **Endpoint security (A7).** If your device is compromised, your messages are
   compromised. Full-disk encryption, OS patching, and device hygiene are the
   user's responsibility.
2. **Content secrecy from members (A4).** A person you let into a private channel
   can read and copy everything in it, and keep it after you delete it. "Private
   channel" means *access-controlled*, not *secret from the people with access*.
3. **Large-scale traffic analysis (A8).** DaNTe does not implement onion routing
   or cover traffic in its current design. A global observer can likely correlate
   who is talking to whom by timing and volume even though content is encrypted.
4. **Full metadata privacy.** Relays learn recipient hints, message sizes, and
   timing. The ledger publicly lists that an identity exists and when it was last
   active. The set of servers a client syncs with is observable to those relays.
   Sealed sender hides the *sender* from the relay, not the *recipient*.
   **Channel messages** are worse for metadata than DMs: they go to a per-
   channel relay log keyed by a stable `channel_id` (a 32-byte capability), so a
   relay sees which channel each opaque message belongs to, plus its size class
   and timing — it just cannot read the content (MLS encryption).
   Channel-log plaintexts are now padded to size buckets (64 B / 256 B / 1 KiB /
   …) before encryption, so the relay learns only a coarse bucket, not the
   exact length. The `channel_id` is shared only with members, but it does not
   rotate. With the `p2p` feature a posted frame is *also* gossiped on a topic
   derived from the `channel_id` (`dante/chan/<hex id>`): gossipsub peers on
   that topic — normally other channel members, but the mesh is best-effort —
   see the same opaque frame + timing the relay does, and the content stays
   MLS-encrypted. A `--relay dht` client also **rendezvous-hashes** each
   channel onto one relay (`H(relay_peer_id ‖ channel_id)`, lowest wins) and
   sends all of that channel's traffic there, so that one relay sees the whole
   channel's timing/size side channel — and, because the choice is a public
   function of the relay set and the `channel_id`, an observer who has both can
   compute which relay carries a given channel without watching traffic. **Federated relays** (a relay run with `--p2p-listen` +
   `--p2p-bootstrap`) replicate ledger records, prekey bundles, sealed-sender
   envelopes, last-resort key packages and channel-log frames among themselves
   over gossipsub, so *every relay in that set* sees the metadata a single
   relay would (recipient hint, size class, timing for envelopes; `channel_id`
   + size + timing for channel frames) — never the plaintext. An operator who
   wants to limit metadata exposure runs an unfederated relay (no
   `--p2p-listen`).
   **Custom server emoji** images are stored in the relay blob store
   **unencrypted** (keyed by SHA-256, 7-day TTL), exactly like Discord's — the
   relay and anyone with the hash can see the artwork. Only the message text
   referencing `:shortcode:` is E2E-encrypted; the shortcode→hash map travels
   inside the signed `ServerPolicy` over authenticated DMs.
   **Typing indicators** (DM and channel) add another activity-timing signal: an
   encrypted ephemeral control sent whenever the user is composing. They use a
   dedicated relay signal buffer (topic-keyed, ~12 s TTL, never logged, swept
   aggressively) rather than the mailbox or the channel log. Channel typing is
   AEAD'd under a static per-member key (in the `SenderKeyBundle`, rotated on
   removal) so it never touches the forward-secret message chain. A typing signal is never persisted, but
   it reveals "this identity is active right now" to the same parties that
   already see message timing; for DMs the relay also sees the per-pair topic
   `SHA-256("dante/typing/dm/v1" ‖ sorted idks)` (linkable to the pair only by
   someone who already knows both identity keys), and for channels it is another
   entry the relay observes on the `channel_id` side channel. It is therefore
   **opt-in** — the setting gates sending only; a non-broadcasting user still
   sees others.
   **Link previews (URL embeds)** are **opt-in and off by default**. When
   enabled, `dante serve` (the user's own process, not the browser) makes one
   metadata `GET` per linked URL — revealing this machine's IP to that site,
   like clicking the link would. It sends no cookies, runs no JavaScript, caps
   size/time/redirects, and refuses any target that resolves to a non-public
   address (loopback, LAN, `169.254.169.254`, …) so a crafted link cannot turn
   it into an SSRF probe. Enabling it also tells the relay nothing new.
   **Decided: build a relay-side unfurler that hides the client IP.** It is a
   real trust-model change, not a client tweak — the relay itself makes
   outbound HTTP requests on a client's behalf, a new capability an operator
   has to be willing to run, and a new thing for a client to trust that
   operator with (which URLs it fetched, when). Following this project's own
   pattern for every other capability that changes what a relay does or
   sees (TURN, the `sfu` feature, GIF search) — **off by default, the
   operator opts in explicitly** — not something a relay does just because
   it can. Not yet built.
   **GIF search (Tenor/Giphy)** is the same posture: **opt-in and off by
   default**, and further gated on the operator having configured a provider
   API key at all (`TENOR_API_KEY` / `GIPHY_API_KEY`) — most relays and
   self-hosted instances will simply not offer it. When on, a search sends
   the query text and this machine's IP to the configured provider; picking a
   result has `dante serve` fetch that one GIF once (host-allowlisted to the
   provider's own CDN on every hop, including any redirect — not just the
   initial URL — size- and time-capped) and store it as a blob keyed by
   SHA-256, exactly like a custom sticker — the message itself carries only
   the hash, so viewing the conversation later never re-contacts the
   provider. Enabling it tells the relay nothing new.
5. **Anonymity of network location.** DaNTe does not hide your IP address from
   peers you connect to directly or from relays. Run it over Tor/VPN if network-
   level anonymity is required. (A future phase may integrate transport-level
   anonymity; it is not a current guarantee.) In particular, a **1:1 call**
   discovers a direct path between the two peers, so each learns the other's IP;
   a call routed through a TURN server hides the peers' IPs from each other but
   exposes both to the TURN operator (who still cannot read the media — it is
   DTLS-SRTP). The DaNTe relay *issues* short-lived TURN credentials using the
   standard coturn `use-auth-secret` scheme (`HMAC-SHA1` over an expiry-stamped
   username), so a stock coturn is a drop-in TURN server. A relay run with
   `--turn-listen` also hosts the TURN server in-process — that operator then
   sees both call peers' IPs (still not the media). An operator who wants TURN
   handled by a separate, differently-run box omits `--turn-listen` and points
   `--turn` at it. The browser client is handed those credentials over its
   localhost API (`GET /api/ice`) so it can actually allocate a relay
   candidate — without them it gathers only host and srflx candidates and a
   call between two symmetric NATs never connects. That hands nothing to the
   page it did not already hold: the page drives the whole engine over the same
   localhost API, and the credential is a short-lived token good for relaying
   media and nothing else. It is re-minted from the relay when close to
   expiring rather than on every call, so a wedged relay cannot stall the
   client at call start.
6. **Availability against a resourced censor.** Bootstrap addresses can be
   blocked; a nation-state can disrupt the DHT. DaNTe aims for resilience, not
   invulnerability.
7. **Account recovery without the backup.** Lose your keystore and your recovery
   passphrase and the identity is gone. There is no operator to reset it.
8. **Abuse moderation at the network layer.** There is no global moderator.
   Moderation is per-server (admins/roles) and per-user (block lists). The
   per-user block list is **client-side and receive-side**: a blocked identity's
   DMs, channel messages and typing signals are dropped by the recipient's
   engine and it refuses to DM them, but the relay still carries the traffic and
   a modified client could ignore the list. The project cannot remove content
   from the network.
9. **Protection of a user from their own correspondents.** Screenshots,
   forwarding, and malicious clients by someone you are talking to are not
   preventable.
10. **SFU media routing (opt-in, browser-only, SFrame-gated).** A group-call
    SFU stack exists (`crates/dante-sfu`; relay feature `sfu`, off by default;
    see [`SFU.md`](SFU.md)) and the browser SPA can drive it through
    `dante serve --sfu`. When used, the media trust boundary changes: DTLS-SRTP
    terminates **at the SFU**, so its operator sees participants' IPs,
    join/leave and participant count, RTP headers, and packet sizes/timing
    (approximate talk activity). Audio content stays protected by the SPA's
    SFrame layer (AES-GCM per Opus frame under the channel's MLS
    `group_call_key`, which the SFU never holds). **The gate is enforced, not
    merely documented:** a room above the mesh limit is only entered in SFU
    mode when the browser exposes `createEncodedStreams` and the media key is
    armed; otherwise the join is refused with a visible explanation, so a
    client never sends plaintext Opus to an SFU. The desktop shell does not
    offer SFU mode at all — its native audio path has no SFrame equivalent,
    and until it does, enabling it would expose plaintext to the operator. The
    CLI/API engine path (`Engine::enable_sfu`) carries no SFrame layer either;
    it is for callers whose media is not content-sensitive to the relay.
    Traffic analysis (who talks when) is not hidden by SFrame, by either an
    SFU or a TURN relay. SFrame is Chromium-only: non-Chromium clients are
    refused in over-limit rooms rather than silently downgraded.

## 6. Known hard problems (tracked, not solved)

- **Sybil resistance (A5).** PoW on identity creation and on each liveness proof
  raises the unit and sustained cost of a fake population, and relays rate-limit
  announces per IP. A determined attacker with GPUs and many IPs can still create
  many identities. Mitigations layered over time: per-server invite/approval,
  difficulty auto-tuning, reputation hints. **No invite graph** is used globally
  because it would deanonymize newcomers.
- **Ledger equivocation (A6).** Clients gossip the Merkle root and demand
  consistency proofs, so a sustained split view is *detectable*. A short-lived
  targeted split against an isolated client is not *prevented*. A future
  witness-cosigning scheme (multiple independent signers attest the root) would
  narrow this.
- **First-contact authenticity.** Before fingerprint verification, adding a
  contact is TOFU and A2/A6 can substitute a key. The engine derives a
  Signal-style **safety number** per DM pair —
  `SHA-512("dante/safety-number/v1" ‖ min(idk) ‖ max(idk))` rendered as 60
  decimal digits — which both ends compute identically and compare out of band
  (`Engine::safety_number` / `set_verified` / `is_verified`, persisted; `chat`
  `/safety` and `/verify`). A confirmed pairing is pinned to the peer's current
  `idk`, so a later key rotation reverts the peer to unverified. The UI must
  make verification status unmistakable and unverified contacts visibly
  provisional; the `dante serve` surface for this is still to build.
- **Bootstrap trust and blocking.** The bootstrap set is a censorship chokepoint
  and a partition risk. Mitigate with many diverse addresses, DNS + in-repo
  distribution, and user-added peers.
- **Relay directory writes are unauthenticated (found in a pre-alpha security
  audit; all three of `PublishPrekeys`, `PublishKeyPackages`, and
  `PostToChannel` are now fixed for the ordinary client-facing wire — see
  each sub-bullet for what residual gaps remain).** `Request::PublishPrekeys`,
  `PublishKeyPackages`, and `PostToChannel` (`dante-relay/src/state.rs`) all
  originally derived the owning identity from attacker-supplied bytes with no
  signature check binding the writer to it.
  - **Prekeys — fixed.** Anyone could fetch a victim's real prekey bundle,
    keep every signed field, and republish it with the (unsigned)
    one-time-prekey list swapped for keys they generated, so a legitimate
    initiator would X3DH against an OTP the victim never held. Each OTP now
    carries its own Ed25519 signature (`PreKeyBundle::verify()`,
    domain-separated from `spk_sig`), so a substituted OTP fails verification
    even when it's re-signed-in-appearance by keeping the original bundle's
    other fields. `bundle.ik_pub` is also now checked against the ledger's own
    `agreement_key` for the peer before use in `send_content`.
  - **KeyPackages — the relay-write half and the gossip-path half are both
    fixed; a credential-binding gap remains.** `PublishKeyPackages` requires
    a signature from the claimed identity's ledger-attested key over the
    published batch, so an attacker can no longer flood or overwrite a
    victim's KeyPackage queue through the ordinary client-facing wire.
    `ingest_gossiped_keypackage` (the relay-to-relay federation path a
    KeyPackage can also arrive over) used to have no signature check at all
    — a malicious relay peer in the gossip mesh could seed a first
    KeyPackage for an identity that had never published one itself. It's now
    fixed the same way: the gossip payload is the *whole* originally-signed
    `PublishKeyPackages` request (not just the one item a sibling ends up
    keeping — the signature covers the batch as a unit and can't be checked
    piecemeal), and a sibling independently re-verifies that same signature
    against the ledger before adopting anything from it. What's still **not**
    covered: `dante-mls`'s KeyPackage credential itself still isn't bound to
    the publishing identity's `idk` (see the next bullet — a separate,
    still-open issue). The credential-on-use check described there gives
    even a hypothetical future signature-check bypass a backstop: a forged
    KeyPackage would still be rejected at add-time on credential mismatch,
    not just at publish/gossip-time on signature mismatch.
  - **PostToChannel — fixed via a relay-side channel roster, not just a
    signature, and the gossip path enforces it too.** A signature alone
    (`identity` + a per-post signature over `post_to_channel_challenge`, now
    required and checked against the ledger the same way `PublishKeyPackages`
    is) proves *who* is posting but not that they're *still a member* — the
    relay had no notion of channel membership at all before this fix, so it
    couldn't tell a current member from a removed one even once every poster
    was individually identifiable. Closing it needed a second, new
    mechanism: `Request::SetChannelRoster`, sent by the channel's host every
    time membership changes (an add or a remove — a full replacement of the
    member set each time, not a delta), signed by the channel's
    `server_root` key (the same key that already signs `ServerPolicy`,
    self-verifying, no ledger lookup needed). A channel's first
    `SetChannelRoster` permanently binds it to that `server_root` — a
    different key can never overwrite it — and each update's `version` must
    strictly increase, so an old roster (e.g. one from before a kick) can't
    be replayed to reinstate a removed member. `PostToChannel` now checks
    both: a valid signature from a real, ledger-known identity, **and** that
    identity's presence in the channel's current roster. Knowing
    `channel_id` — a bare 32-byte value, e.g. one leaked outside the app —
    is no longer sufficient on its own to write to it, closing the exact gap
    this section originally described. The engine pushes a fresh roster from
    the single chokepoint every membership mutation already goes through
    (`mls_add_member`, `remove_from_channel` — the latter is what
    `kick_from_server`, `sweep_inactive_members`, and voluntary `Leave` all
    call for every channel a member is removed from, so a kick already means
    "removed from every channel roster on the server", not just one), plus
    once at channel creation. The creation-time push is the one case treated
    as non-best-effort (propagates its error) rather than best-effort like
    the later ones — losing it would leave a brand-new channel permanently
    unpostable by anyone, including its own host, since no later mutation
    would ever be expected to re-send it.

    `ingest_gossiped_channel_frame` (the relay-to-relay federation path a
    channel frame can also arrive over) used to trust whatever a sibling
    relay handed it for a `channel_id`, with no check at all. It's now fixed
    two ways: (1) a gossiped frame carries the same `identity`/`sig` a direct
    `PostToChannel` does, verified against the ledger identically before
    it's accepted; (2) `Request::SetChannelRoster` updates are *also*
    gossiped (`ingest_gossiped_channel_roster`, same per-channel topic, same
    hijack/replay protection as the direct handler), so a relay that never
    receives a roster directly from a client — every client request for a
    given channel is pinned to one relay — still builds its own copy and can
    enforce membership on gossiped frames, not just on direct ones. One
    honest caveat on ordering: gossip delivery across topics isn't
    guaranteed to arrive in any particular order, so a relay that has a
    genuine signature for a frame but no roster registered *yet* for that
    channel accepts it on authorship alone rather than rejecting outright —
    it enforces membership as soon as it has a roster to enforce, not before.
    A relay that already holds a roster enforces it on every gossiped frame,
    same as the direct path.
- **MLS `KeyPackage`s carry no binding to the DaNTe identity that published
  them (found in the same audit; now fixed, both the "check it on use" half
  and the deeper cryptographic binding).** `dante-mls` previously paired
  caller-chosen credential bytes with a freshly generated, unrelated
  signature keypair via MLS's plain `BasicCredential` — nothing signed the
  credential with the publisher's `idk`, so a client could publish a
  KeyPackage (under its own correctly-signed `PublishKeyPackages` request)
  whose embedded credential named a different identity than the signer.
  Fixed in two layers:
  - **"Check it on use"**: every place the engine is about to trust a
    fetched KeyPackage enough to add its holder to a group
    (`mls_add_member`, `start_group_call`, the `GroupCallJoinRequest` admit
    path) calls `dante-mls`'s `key_package_identity` and refuses the add if
    the embedded credential doesn't match the peer id it was fetched for —
    the exploit path the audit named directly ("the engine adds a fetched
    `KeyPackage` to a group with no check that its credential equals the
    peer id it was fetched for").
  - **Deeper cryptographic binding**: `dante-mls` now defines its own MLS
    credential type (`CredentialType::Other`, RFC 9420 §5.3's own extension
    point for exactly this — OpenMLS treats every credential type as opaque
    bytes it "does not look into", so this needed no upstream change). Every
    credential DaNTe mints carries the identity bytes *and* a binding
    proof: the identity's own long-term Ed25519 (`idk`) signature over a
    domain-separated challenge covering that specific KeyPackage's
    fresh per-package MLS signature key.
    `Member::create` / `publish_key_package` now take the caller's real
    `idk` (its public key plus a signing closure, not a raw secret-key
    reference — matching the closure idiom already used elsewhere for
    crossing this crate boundary) to mint this. `key_package_identity`
    verifies the embedded signature for self-consistency (does `idk_pub`
    really sign for this exact identity + this exact leaf key) before
    returning anything, and now returns `idk_pub` alongside the identity so
    the engine can also check it against the ledger's current key for that
    identity — self-consistency alone only proves *some* real `idk` vouched
    for the credential, not that it's the *right* one; only the ledger says
    that. `dante-mls` has no ledger access, so that half stays in
    `dante-core` (the free function `key_package_binds_to`), layered on top
    the same way the wire-level checks already layer ledger access on top
    of self-contained signature verification elsewhere in this codebase.
    A KeyPackage whose credential doesn't carry a valid DaNTe binding at
    all is refused outright, not silently trusted as a legacy format, at
    every point the engine is about to add its holder to a group (`add()`
    on the founder/host side) — this is a wire-incompatible change to
    every previously-minted credential (including persisted, exported
    channel/group-call state, whose already-baked-in `BasicCredential`
    leaves `credential_identity` can never decode as a `DanteCredential`;
    `Member::import` now refuses to load such a group at all rather than
    silently restoring one with a dead roster), acceptable pre-1.0 per this
    project's stated policy that wire formats change without notice until
    1.0. **Joining is verified the same way, not left as an adder-side-only
    check.** `Pending::join` inspects every leaf in a Welcome's ratchet tree
    before ever building a live group from it, refusing the whole Welcome
    if any leaf's binding doesn't verify; `dante-core` then does the
    matching ledger cross-check (`Engine::member_bindings_match_ledger`,
    via `Member::member_bindings`) right after a successful join, refusing
    the join outright — same as if no KeyPackage had matched — if any
    member the ledger has ever had a chain for (`Ledger::has_any_entry_for_id`)
    resolves (`Ledger::idk_for_id`) to a key other than the one their
    credential claims, or resolves to no key at all (an evaporated or
    revoked identity does not get the benefit of the doubt below). A member
    the ledger has genuinely never seen — no chain at all, not merely an
    unresolvable one — is accepted on self-consistency alone rather than
    refusing the join outright: strict matching would also refuse any join
    pulling in an identity whose ledger record simply hasn't propagated to
    this client yet, which is plausible for someone this client has never
    interacted with. This is the same posture `dante-mls` itself takes
    without ledger access.
    **A later Commit that adds or updates a member is checked the same way,
    not left as a residual gap.** `Member::process_from` inspects every Add
    proposal in a Commit before ever merging it — self-consistency, plus the
    same `accept_new_member` ledger callback `dante-core` wires in
    (mirroring `member_bindings`'s split for the join case) — refusing the
    whole Commit if any proposed new member fails either check. Update
    proposals and a Commit's own "update path" (ordinary post-compromise-
    security key rotation) get a different, narrower check: self-consistency,
    plus that the new credential still names the *same* identity the leaf
    held before — no ledger involved, since the comparison is against the
    leaf's own prior state, not the ledger's copy of the identity. That
    closes the identity-hijack variant of this gap either way: a self-
    consistent credential swap that changes *who* a leaf claims to be, not
    just its key, is refused — a host, or any member, disguising an identity
    takeover as a routine key rotation.

    One more subtlety: the ledger check here (both this Add-proposal case
    and at join) matches by chain *membership*, not by the ledger's current
    tip key. A `DanteCredential` embeds whichever `idk_pub` was current when
    its leaf was minted, and that leaf's binding is immutable for its whole
    life — but the identity may rotate its `idk` afterward. Requiring tip
    equality would refuse a perfectly legitimate, long-standing member the
    moment they ever rotate; checking that the embedded `idk_pub` is *some*
    key that has ever belonged to that identity's chain preserves the actual
    property that matters — this is a real `idk`, linked to this identity,
    not a forgery — without that brittleness. A revoked or evaporated
    identity is refused regardless of chain membership.

    The host-initiated adds this doesn't cover (`mls_add_member`,
    `start_group_call`, the `GroupCallJoinRequest` admit path — anywhere
    `key_package_binds_to` runs, fetching one specific peer's KeyPackage to
    add them right now) deliberately keep strict tip equality instead: a
    KeyPackage can sit in `dante-core`'s own unused-publish pool for a while
    before it's fetched, so this has the same staleness-after-rotation
    brittleness the Add-proposal case above fixes — accepted knowingly here,
    not fixed, since loosening a check on an action initiated *right now*
    trades away more than the immutable-existing-leaf cases above do for the
    same benefit.

## 7. Cryptographic posture

- Key agreement: X25519. Signatures: Ed25519. AEAD: XChaCha20-Poly1305 (default)
  / AES-256-GCM. KDF: HKDF-SHA-256. Password hashing / PoW: Argon2id.
- 1:1: X3DH + Double Ratchet (FS + PCS).
- Groups: MLS / RFC 9420 via a vetted implementation (`OpenMLS`), with
  Argon2id-derived PSKs for password-gated servers.
- No home-rolled protocol constructions. Every primitive wrapper in
  `dante-crypto` ships with test vectors from the relevant RFC or reference
  implementation. Crypto-affecting changes require review via the
  `security-review` process, and an external audit precedes any `stable` tag.
- No telemetry is collected, ever.
