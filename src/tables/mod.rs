mod reference;

use crate::{clock::Timestamp, forwarder::FaceToken, name::Name};

pub trait Tables {
    // FIB methods
    // Interests that have "name_prefix" will be forwarded to "face", possibly using "cost"
    //  for prioritisation. Call this again to update the cost.
    fn register_prefix(&mut self, name_prefix: Name<'_>, face: FaceToken, cost: u32);
    // Remove this prefix registration.
    fn unregister_prefix(&mut self, name_prefix: Name<'_>, face: FaceToken) -> bool;

    // PIT methods
    // Registers a newly-arrived interest and uses a forwarding strategy to determine the 
    //  faces to which this interest should be forwarded, if any.
    fn register_interest(
        &mut self,
        name: Name<'_>,
        can_be_prefix: bool,
        interest_lifetime: Option<u64>,
        nonce: [u8; 4],
        reply_to: FaceToken,
        now: Timestamp,
    ) -> impl Iterator<Item = FaceToken>;

    // Checks if the newly-arriving data satisfies any of the interests registered in the PIT
    //  and returns all faces the data packet should be sent to.
    fn satisfy_interests<H>(
        &mut self,
        name: Name<'_>,
        now: Timestamp,
        digest_computation: &mut H,
    ) -> impl Iterator<Item = FaceToken> where H: FnMut()->[u8; 32];

    // CS methods
    // Inserts the data packet into the cache 
    fn insert_data<'a>(
        &mut self,
        name: Name<'a>,
        digest: [u8; 32],
        freshness: u64,
        now: Timestamp,
        packet: &'a [u8],
    );

    // Checks the cache for stored data satisfyig the name and parameters
    fn get_data<'a>(
        &mut self,
        name: Name<'a>,
        can_be_prefix: bool,
        must_be_fresh: bool,
        now: Timestamp,
    ) -> Option<&[u8]>;

    // Common methods
    // Removes the face from all FIB and PIT entries
    fn unregister_face(&mut self, face: FaceToken);
    
    // Cleans up the internal state, for example removing stale PIT entries and cached data
    fn prune_if_needed(&mut self, now: Timestamp);
}
