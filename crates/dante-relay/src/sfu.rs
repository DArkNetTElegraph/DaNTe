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

use dante_net::wire::{Request, Response};
use dante_sfu::{Sfu, SfuEvent};
use tokio::sync::{mpsc, Mutex};

/// Default slots per room.
pub const DEFAULT_ROOM_SIZE: usize = 16;

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
    rooms: Mutex<HashMap<[u8; 32], Room>>,
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
            rooms: Mutex::new(HashMap::new()),
        }
    }

    /// Serve an SFU request, or `None` if it is not one.
    pub async fn handle(&self, req: &Request) -> Option<Response> {
        match req {
            Request::SfuJoin { room, offer } => Some(self.join(*room, offer).await),
            Request::SfuIce {
                room,
                slot,
                candidate,
            } => Some(self.ice(*room, *slot, candidate).await),
            Request::SfuPull { room, slot } => Some(self.pull(*room, *slot).await),
            Request::SfuLeave { room, slot } => Some(self.leave(*room, *slot).await),
            _ => None,
        }
    }

    async fn join(&self, room: [u8; 32], offer: &str) -> Response {
        let mut rooms = self.rooms.lock().await;
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
}
