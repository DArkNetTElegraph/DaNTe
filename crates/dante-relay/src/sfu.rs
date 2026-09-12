//! Relay-hosted SFU signalling (feature `sfu`).
//!
//! The relay carries SDP and ICE between a participant and a [`Sfu`] room.
//! Media itself does **not** traverse this path: each participant holds a
//! DTLS-SRTP connection to the SFU's own UDP endpoint, and the SFU forwards
//! only opaque RTP payloads. Authorization is possession of the 32-byte room
//! id, which is the same channel capability the channel log uses — the relay
//! never holds the MLS `group_call_key` or an SFrame key and cannot read media.
//!
//! Requests are handled by [`crate::state::RelayHandler`] before they reach
//! the relay state, because joining a room awaits WebRTC negotiation.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use dante_net::ratelimit::KeyedRateLimiter;
use dante_net::wire::{Request, Response};
use dante_sfu::{Sfu, SfuEvent};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

/// Default slots per room.
pub const DEFAULT_ROOM_SIZE: usize = 16;

/// Per-IP SFU request budget: `(capacity, refill/sec)`. Joins and ICE trickle
/// bursts fit comfortably; a flood does not. Pulls are the frequent call, so
/// the refill has to stay above a fast poll loop.
const SFU_RATE: (f64, f64) = (300.0, 120.0);
/// Concurrent rooms per relay. Each room is a handful of WebRTC connections,
/// so this bounds the relay's media-plane memory.
const MAX_ROOMS: usize = 64;
/// An SDP offer larger than this is not a real one.
const MAX_OFFER_BYTES: usize = 64 * 1024;
/// A single ICE candidate is well under a kilobyte; this is generous.
const MAX_CANDIDATE_BYTES: usize = 4 * 1024;

struct Room {
    sfu: Sfu,
    events: mpsc::UnboundedReceiver<SfuEvent>,
    /// ICE candidates the SFU gathered for each slot, waiting for a pull.
    ice: HashMap<usize, Vec<String>>,
}

impl Room {
    fn new(size: usize) -> Self {
        let (sfu, events) = Sfu::new(size);
        Self {
            sfu,
            events,
            ice: HashMap::new(),
        }
    }

    /// Move queued SFU events into the per-slot ICE queues. State changes are
    /// not surfaced: the participant sees connection state on its own leg.
    fn drain(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            if let SfuEvent::Ice { slot, candidate } = event {
                if !candidate.is_empty() {
                    self.ice.entry(slot).or_default().push(candidate);
                }
            }
        }
    }
}

/// All SFU rooms on this relay, keyed by channel id.
pub struct SfuRooms {
    room_size: usize,
    rooms: AsyncMutex<HashMap<[u8; 32], Room>>,
    /// Per-IP token bucket, checking requests sync (no await while held).
    rl: Mutex<KeyedRateLimiter<IpAddr>>,
}

impl Default for SfuRooms {
    fn default() -> Self {
        Self::new()
    }
}

impl SfuRooms {
    /// Rooms with the default slot count.
    pub fn new() -> Self {
        Self::with_room_size(DEFAULT_ROOM_SIZE)
    }

    /// Rooms with `room_size` slots (clamped to what the slot field can carry).
    pub fn with_room_size(room_size: usize) -> Self {
        Self {
            room_size: room_size.clamp(1, u8::MAX as usize),
            rooms: AsyncMutex::new(HashMap::new()),
            rl: Mutex::new(KeyedRateLimiter::new(SFU_RATE.0, SFU_RATE.1)),
        }
    }

    /// Serve an SFU request, or `None` if it is not one.
    pub async fn handle(&self, req: &Request, ip: IpAddr, now_ms: u64) -> Option<Response> {
        match req {
            Request::SfuJoin { room, offer } => Some(self.join(*room, offer, ip, now_ms).await),
            Request::SfuIce {
                room,
                slot,
                candidate,
            } => {
                if !self.allow(ip, now_ms) {
                    return Some(Response::Error("sfu: rate limited".into()));
                }
                Some(self.ice(*room, *slot, candidate).await)
            }
            Request::SfuPull { room, slot } => {
                if !self.allow(ip, now_ms) {
                    return Some(Response::Error("sfu: rate limited".into()));
                }
                Some(self.pull(*room, *slot).await)
            }
            Request::SfuLeave { room, slot } => {
                if !self.allow(ip, now_ms) {
                    return Some(Response::Error("sfu: rate limited".into()));
                }
                Some(self.leave(*room, *slot).await)
            }
            _ => None,
        }
    }

    /// Charge one token against `ip`.
    fn allow(&self, ip: IpAddr, now_ms: u64) -> bool {
        self.rl
            .lock()
            .expect("SFU rate limiter poisoned")
            .check(&ip, now_ms, 1.0)
    }

    async fn join(&self, room: [u8; 32], offer: &str, ip: IpAddr, now_ms: u64) -> Response {
        if offer.len() > MAX_OFFER_BYTES {
            return Response::Error("sfu: offer too large".into());
        }
        if !self.allow(ip, now_ms) {
            return Response::Error("sfu: rate limited".into());
        }
        // Cheap reclamation of buckets for IPs that have gone quiet.
        self.rl
            .lock()
            .expect("SFU rate limiter poisoned")
            .sweep(now_ms, 10 * 60 * 1000);

        let mut rooms = self.rooms.lock().await;
        if !rooms.contains_key(&room) && rooms.len() >= MAX_ROOMS {
            return Response::Error("sfu: too many rooms".into());
        }
        let entry = rooms
            .entry(room)
            .or_insert_with(|| Room::new(self.room_size));
        match entry.sfu.add_peer(offer).await {
            Ok((slot, answer)) => {
                entry.drain();
                Response::SfuAnswer {
                    slot: slot as u8,
                    answer,
                }
            }
            Err(e) => Response::Error(format!("sfu: {e}")),
        }
    }

    async fn ice(&self, room: [u8; 32], slot: u8, candidate: &str) -> Response {
        if candidate.len() > MAX_CANDIDATE_BYTES {
            return Response::Error("sfu: candidate too large".into());
        }
        let rooms = self.rooms.lock().await;
        let Some(entry) = rooms.get(&room) else {
            return Response::Error("sfu: no such room".into());
        };
        match entry.sfu.add_ice(slot as usize, candidate).await {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error(format!("sfu: {e}")),
        }
    }

    async fn pull(&self, room: [u8; 32], slot: u8) -> Response {
        let mut rooms = self.rooms.lock().await;
        let Some(entry) = rooms.get_mut(&room) else {
            return Response::SfuIce(Vec::new());
        };
        entry.drain();
        Response::SfuIce(entry.ice.remove(&(slot as usize)).unwrap_or_default())
    }

    async fn leave(&self, room: [u8; 32], slot: u8) -> Response {
        let mut rooms = self.rooms.lock().await;
        let Some(entry) = rooms.get_mut(&room) else {
            return Response::Ok;
        };
        let response = match entry.sfu.remove_peer(slot as usize).await {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error(format!("sfu: {e}")),
        };
        entry.drain();
        if entry.sfu.is_empty() {
            rooms.remove(&room);
        }
        response
    }

    /// Number of live rooms. Test-only.
    #[cfg(test)]
    async fn room_count(&self) -> usize {
        self.rooms.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use dante_voice::Call;

    use super::*;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    async fn offer(recv_slots: usize) -> String {
        let (_call, offer) = Call::offer_for_sfu(recv_slots, &[]).await.unwrap();
        offer
    }

    async fn join(rooms: &SfuRooms, room: [u8; 32], offer: &str, now: u64) -> Response {
        rooms
            .handle(
                &Request::SfuJoin {
                    room,
                    offer: offer.to_owned(),
                },
                ip(),
                now,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn join_assigns_slots_fills_and_removes_empty_rooms() {
        let rooms = SfuRooms::with_room_size(2);
        let room = [9u8; 32];
        let offer = offer(1).await;

        let r = join(&rooms, room, &offer, 1_000).await;
        let Response::SfuAnswer { slot, answer } = r else {
            panic!("expected an answer, got {r:?}");
        };
        assert_eq!(slot, 0);
        assert!(answer.contains("m=audio"), "answer carries media");
        assert_eq!(rooms.room_count().await, 1);

        let r = join(&rooms, room, &offer, 1_000).await;
        assert!(matches!(r, Response::SfuAnswer { slot: 1, .. }));

        // A third participant has nowhere to go.
        let r = join(&rooms, room, &offer, 1_000).await;
        assert!(matches!(r, Response::Error(_)), "room is full: {r:?}");

        // Leaving frees slots; the empty room is dropped.
        let r = rooms
            .handle(&Request::SfuLeave { room, slot: 0 }, ip(), 1_000)
            .await
            .unwrap();
        assert!(matches!(r, Response::Ok));
        assert_eq!(rooms.room_count().await, 1);
        let r = rooms
            .handle(&Request::SfuLeave { room, slot: 1 }, ip(), 1_000)
            .await
            .unwrap();
        assert!(matches!(r, Response::Ok));
        assert_eq!(rooms.room_count().await, 0);

        // Pulling a room that no longer exists is empty, not an error.
        let r = rooms
            .handle(&Request::SfuPull { room, slot: 0 }, ip(), 1_000)
            .await
            .unwrap();
        assert!(matches!(r, Response::SfuIce(v) if v.is_empty()));
    }

    #[tokio::test]
    async fn anonymous_rooms_are_separate_and_leave_is_idempotent() {
        let rooms = SfuRooms::with_room_size(2);
        let a = [1u8; 32];
        let b = [2u8; 32];
        let offer = offer(1).await;
        assert!(matches!(
            join(&rooms, a, &offer, 0).await,
            Response::SfuAnswer { slot: 0, .. }
        ));
        assert!(matches!(
            join(&rooms, b, &offer, 0).await,
            Response::SfuAnswer { slot: 0, .. }
        ));
        assert_eq!(rooms.room_count().await, 2);

        // Leaving a slot nobody holds is an error; leaving a dead room is Ok.
        let r = rooms
            .handle(&Request::SfuLeave { room: a, slot: 7 }, ip(), 0)
            .await
            .unwrap();
        assert!(matches!(r, Response::Error(_)));
        let r = rooms
            .handle(
                &Request::SfuLeave {
                    room: [3u8; 32],
                    slot: 0,
                },
                ip(),
                0,
            )
            .await
            .unwrap();
        assert!(matches!(r, Response::Ok));
    }

    #[tokio::test]
    async fn oversized_offer_is_rejected_before_any_room_is_created() {
        let rooms = SfuRooms::with_room_size(2);
        let big = "x".repeat(MAX_OFFER_BYTES + 1);
        let r = join(&rooms, [4u8; 32], &big, 0).await;
        assert!(matches!(r, Response::Error(_)), "got {r:?}");
        assert_eq!(rooms.room_count().await, 0);
    }

    #[tokio::test]
    async fn a_flood_from_one_ip_is_refused() {
        let rooms = SfuRooms::with_room_size(2);
        let room = [5u8; 32];
        // Same instant throughout, so the bucket never refills.
        let mut saw_refusal = false;
        for _ in 0..(SFU_RATE.0 as usize + 50) {
            let r = rooms
                .handle(&Request::SfuPull { room, slot: 0 }, ip(), 0)
                .await
                .unwrap();
            if matches!(r, Response::Error(_)) {
                saw_refusal = true;
                break;
            }
        }
        assert!(saw_refusal, "the bucket is finite");
    }
}
