# dante-core

The orchestration engine every DaNTe client drives.

`Engine` owns one user's identity, a local ledger replica, a relay connection,
prekeys, live DM sessions, MLS channel memberships, hosted servers, calls,
contacts and an encrypted on-disk store. It is UI-agnostic — `dante-cli` and
the desktop shell are thin shells over it. `p2p` (libp2p DHT + gossip) is a
default feature; `--no-default-features` gives a relay-only client.

## Modules

| Module | Contents |
| --- | --- |
| `engine` | `Engine` and almost all behavior; `Inbound`, `ReceivedDm`, `CallUpdate`, `BootStep` / `BootProgress`, `SearchHit`, `Contact`, `TypingEvent`, … |
| `channel` | channel state: `ChannelInfo`, `ChannelMessage`, `ChannelReaction`, `ChannelControl` (MLS Welcome / Redeem / Policy / Kick / …), backlog, and the password-derived channel-log key |
| `store` | `PersistedState` plus the XChaCha20-Poly1305 sealed on-disk store (`save` / `load`) |
| `roles` | `Role`, signed `ServerPolicy`, permission bits, `effective_perms` |
| `invite` | `InviteToken` mint / verify / encode / link round-trip |
| `p2p` (feature) | DHT prekey fallback and ledger / channel gossipsub |

## API at a glance

- lifecycle: `Engine::connect` / `connect_with_progress`, `persist`, `sync`,
  `announce`, `announce_if_stale`, `prove_liveness`, `revoke_identity`,
  `publish_prekeys`, `publish_avatar` / `clear_avatar`, `publish_status` /
  `clear_status`, `avatar_hash_of`, `status_of`
- DMs: `send_dm`, `edit_dm`, `delete_dm`, `send_file`, `send_typing_dm`,
  `receive`, `receive_all`, `take_dm_edits`
- servers & channels: `create_server`, `create_channel`,
  `create_voice_channel`, `invite_to_channel`, `accept_channel_invite`,
  `send_channel`, `poll_channels`, edit / delete / reply / react / pin,
  `set_role` / `assign_role`, kick / ban / leave / rename / delete, discovery
  (`set_discoverable`, `join_discovered`)
- calls: `start_call`, `accept_call`, `hangup`, `poll_calls`,
  `send_call_audio` / `take_call_audio`, group calls
  (`start_group_call` / `join_group_call` / `leave_group_call` /
  `poll_group_calls`), and voice channels
  (`join_voice_channel` / `send_voice_signal` / `poll_voice`)
- contacts & safety: `add_contact`, `block` / `unblock`, `safety_number`,
  `set_verified`, `search`

## Persistence and restart

The store keeps identity state, DM sessions and prekey secrets, channel MLS
members, hosted-server keys, DM history, channel history (last 2000 lines) and
cursors. Stores survive restarts, and the old format keeps loading (a test
covers an old-store decode). Channel history persists each message's relay-log
`seq` (plus `reply_to` / `forwarded_from`), so restored and backfilled messages
can be reacted to, pinned, replied to and edited.

## Used by

`dante-cli` (chat / bot / serve) and `apps/dante-desktop`. Nothing else.

## Test

```sh
cargo test -p dante-core                 # 44 in-process-relay e2e tests
cargo test -p dante-core --features p2p  # plus DHT / gossip e2e
```

The e2e suite spins up an in-process `dante-relay` and drives two / three real
engines through DM handshake and files, restart persistence, invites and links,
roles and kicks, channel history, calls, voice channels and group-call rekey.
