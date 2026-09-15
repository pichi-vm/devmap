// SPDX-License-Identifier: Apache-2.0

use devmap_core::{Target, TargetEndpoint};
use std::{cell::RefCell, io, marker::PhantomData};

struct Endpoint<T> {
    sent: RefCell<Vec<String>>,
    reply: Option<String>,
    failed: bool,
    marker: PhantomData<T>,
}
impl<T> Endpoint<T> {
    fn new(reply: Option<&str>) -> Self {
        Self {
            sent: RefCell::new(Vec::new()),
            reply: reply.map(str::to_owned),
            failed: false,
            marker: PhantomData,
        }
    }
    fn expect(&self, messages: &[&str]) {
        assert_eq!(&*self.sent.borrow(), messages);
    }
}
impl<T: Target> TargetEndpoint for Endpoint<T> {
    type Target = T;
    fn message(&self, command: &str) -> io::Result<Option<String>> {
        self.sent.borrow_mut().push(command.into());
        if self.failed {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(self.reply.clone())
        }
    }
}

#[test]
fn dust_commands_and_reply_parsing_remain_in_the_owner_crate() {
    use devmap_dust::dm::{Commands as _, Target};
    let endpoint = Endpoint::<Target>::new(Some("countbadblocks: 2 badblock(s) found"));
    endpoint.add_bad_block(8).unwrap();
    endpoint.remove_bad_block(8).unwrap();
    endpoint.clear_bad_blocks().unwrap();
    assert_eq!(endpoint.count_bad_blocks().unwrap(), 2);
    endpoint.enable().unwrap();
    endpoint.disable().unwrap();
    endpoint.quiet().unwrap();
    endpoint.expect(&[
        "addbadblock 8",
        "removebadblock 8",
        "clearbadblocks",
        "countbadblocks",
        "enable",
        "disable",
        "quiet",
    ]);
    assert!(Endpoint::<Target>::new(None).count_bad_blocks().is_err());
    assert!(
        Endpoint::<Target>::new(Some("bad reply"))
            .count_bad_blocks()
            .is_err()
    );
    let mut failed = Endpoint::<Target>::new(None);
    failed.failed = true;
    assert_eq!(
        failed.enable().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn thin_pool_commands_keep_their_arguments_and_returned_root() {
    use devmap_thin_pool::dm::{Commands as _, Target};
    let endpoint = Endpoint::<Target>::new(Some("123"));
    endpoint.create_thin(4).unwrap();
    endpoint.create_snap(5, 4).unwrap();
    endpoint.delete(5).unwrap();
    endpoint.set_transaction_id(6, 7).unwrap();
    assert_eq!(endpoint.reserve_metadata_snap().unwrap(), 123);
    endpoint.release_metadata_snap().unwrap();
    endpoint.expect(&[
        "create_thin 4",
        "create_snap 5 4",
        "delete 5",
        "set_transaction_id 6 7",
        "reserve_metadata_snap",
        "release_metadata_snap",
    ]);
    assert!(
        Endpoint::<Target>::new(None)
            .reserve_metadata_snap()
            .is_err()
    );
}

#[test]
fn era_and_log_commands_are_encoded_by_their_crates() {
    use devmap_era::dm::Commands as _;
    use devmap_log_writes::dm::Commands as _;
    let era = Endpoint::<devmap_era::dm::Target>::new(None);
    era.checkpoint().unwrap();
    era.take_metadata_snap().unwrap();
    era.drop_metadata_snap().unwrap();
    era.expect(&["checkpoint", "take_metadata_snap", "drop_metadata_snap"]);
    let log = Endpoint::<devmap_log_writes::dm::Target>::new(None);
    log.mark("checkpoint-1").unwrap();
    log.expect(&["mark checkpoint-1"]);
}

#[test]
fn raid_cache_and_zoned_commands_need_only_the_shared_endpoint_interface() {
    use devmap_raid::dm::Commands as _;
    use devmap_writecache::dm::Commands as _;
    use devmap_zoned::dm::Commands as _;
    let raid = Endpoint::<devmap_raid::dm::Target>::new(None);
    raid.idle().unwrap();
    raid.frozen().unwrap();
    raid.resync().unwrap();
    raid.recover().unwrap();
    raid.check().unwrap();
    raid.repair().unwrap();
    raid.expect(&["idle", "frozen", "resync", "recover", "check", "repair"]);
    let cache = Endpoint::<devmap_writecache::dm::Target>::new(None);
    cache.flush().unwrap();
    cache.flush_on_suspend().unwrap();
    cache.cleaner().unwrap();
    cache.clear_stats().unwrap();
    cache.expect(&["flush", "flush_on_suspend", "cleaner", "clear_stats"]);
    let zoned = Endpoint::<devmap_zoned::dm::Target>::new(None);
    zoned.reclaim().unwrap();
    zoned.expect(&["reclaim"]);
}
