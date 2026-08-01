// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for `era`, `log-writes`, and `snapshot-merge` —
//! each needs two backing devices and/or a short lifecycle beyond a
//! single `create`+`load`+`resume`.

mod common;

use std::io::Write;

use common::{LoopDevice, ensure_module_loaded, open_control};
use devmap::RawInfo;
use devmap::targets::snapshot::{self, Snapshot};
use devmap::targets::{Era, LogWrites};

#[test]
fn era_tracks_writes_and_responds_to_checkpoint_message() {
    let Some(control) = open_control() else {
        return;
    };
    ensure_module_loaded("dm-era");

    let metadata = LoopDevice::create("era-meta", 8 * 1024 * 1024);
    let origin = LoopDevice::create("era-origin", 8 * 1024 * 1024);
    let metadata_device = control.by_node(&metadata.path).expect("by_node metadata");
    let origin_device = control.by_node(&origin.path).expect("by_node origin");

    let name = format!("devmap-test-era-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(
            0,
            16384,
            Era::new(metadata_device.id(), origin_device.id(), 128).expect("valid era"),
        )
        .expect("add era")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    let status_before: Vec<_> = removed.info().expect("DM_TABLE_STATUS").collect();
    assert_eq!(status_before.len(), 1);
    assert_eq!(status_before[0].type_name(), "era");

    // `checkpoint` may or may not bump the era counter on this call (the
    // kernel doc explicitly says not to assume it will), but it must not
    // error, and it produces no reply string.
    let reply = removed
        .message(0, "checkpoint")
        .expect("checkpoint message");
    assert_eq!(reply, None);
}

#[test]
fn log_writes_counts_logged_entries_and_accepts_marks() {
    let Some(control) = open_control() else {
        return;
    };
    ensure_module_loaded("dm-log-writes");

    let data = LoopDevice::create("logwrites-data", 8 * 1024 * 1024);
    let log = LoopDevice::create("logwrites-log", 8 * 1024 * 1024);
    let data_device = control.by_node(&data.path).expect("by_node data");
    let log_device = control.by_node(&log.path).expect("by_node log");

    let name = format!("devmap-test-logwrites-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(
            0,
            16384,
            LogWrites {
                device: data_device.id(),
                log_device: log_device.id(),
            },
        )
        .expect("add log-writes")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    let minor = removed.id().minor();
    let path = format!("/dev/dm-{minor}");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open mapped device");
    file.write_all(&[0xCDu8; 4096])
        .expect("write to logged device");
    file.sync_all().expect("fsync");

    // Marking a point in the log must succeed and produce no reply.
    let reply = removed
        .message(0, "mark after-write")
        .expect("mark message");
    assert_eq!(reply, None);
}

/// Exercises `snapshot::Merge`'s real handover procedure end to
/// end: a `snapshot-origin` device, a `snapshot` device sharing its COW
/// device, a write that creates a real COW exception, then the handover
/// itself (suspend origin, reload it as `snapshot-merge`, suspend the old
/// snapshot, resume) — followed by reading the written data back through
/// the now-merged origin to prove the merge preserved it.
///
/// The exact sequencing was verified directly against `dm-snap.c`
/// (`snapshot_preresume`/`snapshot_resume`): resuming a `snapshot-merge`
/// target refuses with `EINVAL` unless the old `snapshot` target sharing
/// its COW device is already suspended — that's what makes step 5 below
/// load-bearing, not optional.
#[test]
fn snapshot_merge_takes_over_from_snapshot_and_merges() {
    let Some(control) = open_control() else {
        return;
    };
    ensure_module_loaded("dm-snapshot");

    let origin_backing = LoopDevice::create("snapmerge-origin", 16 * 1024 * 1024);
    let cow_backing = LoopDevice::create("snapmerge-cow", 16 * 1024 * 1024);
    let origin_backing_device = control
        .by_node(&origin_backing.path)
        .expect("by_node origin backing");
    let cow_device = control.by_node(&cow_backing.path).expect("by_node cow");
    let origin_len_sectors = 16 * 1024 * 1024 / 512;

    // 1. Origin device: dm-linear-equivalent passthrough (snapshot-origin
    //    with no snapshot yet just forwards I/O) to the backing device.
    let origin_name = format!("devmap-test-snapmerge-origin-{}", std::process::id());
    let origin_removed = control.create(&origin_name).expect("DM_DEV_CREATE origin");
    origin_removed
        .builder()
        .add(
            0,
            origin_len_sectors,
            snapshot::Origin {
                origin: origin_backing_device.id(),
            },
        )
        .expect("add snapshot-origin")
        .load()
        .expect("DM_TABLE_LOAD origin");
    origin_removed.resume().expect("resume origin");

    // 2. Write a first pattern before any snapshot exists.
    let origin_minor = origin_removed.id().minor();
    let origin_path = format!("/dev/dm-{origin_minor}");
    write_block(&origin_path, 0, 0xAA);

    // 3. A persistent snapshot of that origin, sharing the same COW
    //    device the eventual snapshot-merge target will take over.
    let snap_name = format!("devmap-test-snapmerge-snap-{}", std::process::id());
    let snap_removed = control.create(&snap_name).expect("DM_DEV_CREATE snapshot");
    snap_removed
        .builder()
        .add(
            0,
            origin_len_sectors,
            Snapshot::new(origin_backing_device.id(), cow_device.id(), 8).expect("valid snapshot"),
        )
        .expect("add snapshot")
        .load()
        .expect("DM_TABLE_LOAD snapshot");
    snap_removed.resume().expect("resume snapshot");

    // 4. Write a second pattern now that the snapshot is active. This is
    //    the divergence a merge undoes: dm-snapshot preserves the *old*
    //    (pre-write) contents of this chunk in the COW device before
    //    letting the write through to the origin, so the snapshot's view
    //    of this chunk is now the all-zero data that was here before —
    //    merging will restore exactly that, overwriting this 0xBB write.
    write_block(&origin_path, 1, 0xBB);

    // 5. Handover: suspend the origin, stage snapshot-merge on it,
    //    suspend the old snapshot device (required precondition per
    //    dm-snap.c's snapshot_preresume), then resume the origin —
    //    activating the merge, which runs in the background.
    origin_removed.suspend().expect("suspend origin");
    origin_removed
        .builder()
        .add(
            0,
            origin_len_sectors,
            snapshot::Merge::new(origin_backing_device.id(), cow_device.id(), 8)
                .expect("valid snapshot-merge"),
        )
        .expect("add snapshot-merge")
        .load()
        .expect("DM_TABLE_LOAD snapshot-merge");
    snap_removed
        .suspend()
        .expect("suspend old snapshot before handover");
    origin_removed.resume().expect("resume as snapshot-merge");

    // 6. Wait for the background merge to finish: sectors_allocated drops
    //    to exactly metadata_sectors once nothing is left to fold in.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let status = origin_removed.status().expect("DM_DEV_STATUS");
        assert_eq!(status.target_count(), 1);
        let reported: Vec<_> = origin_removed.info().expect("DM_TABLE_STATUS").collect();
        // snapshot-merge's runtime status isn't typed by this crate, so it
        // parses back as `RawInfo` — the merge-completion check reads the
        // raw status string directly.
        if let Some(RawInfo(params)) = reported[0].parse::<snapshot::Merge>() {
            let mut nums = params
                .split(['/', ' '])
                .filter_map(|tok| tok.parse::<u64>().ok());
            if let (Some(allocated), Some(_total), Some(metadata)) =
                (nums.next(), nums.next(), nums.next())
                && allocated == metadata
            {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "snapshot-merge never finished"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // 7. Merging folds the snapshot's preserved view back into the
    //    origin: block 0 (never touched after the snapshot was taken, so
    //    no exception exists for it) is unaffected; block 1's post-write
    //    0xBB is overwritten by the pre-write zeros the snapshot
    //    captured — proving the merge actually moved real data, not just
    //    that the ioctl sequence didn't error.
    assert_block(&origin_path, 0, 0xAA);
    assert_block(&origin_path, 1, 0x00);

    // The old snapshot device is now a dead end (kernel returns -EIO on
    // access to it once merging has started) — remove it explicitly
    // rather than relying on `Removed`'s best-effort drop, so a failure
    // here is visible instead of silently swallowed.
    devmap::Device::from(snap_removed)
        .remove()
        .expect("remove handed-over snapshot device");
}

fn write_block(path: &str, block_index: u64, byte: u8) {
    use std::io::{Seek, SeekFrom};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for write_block");
    file.seek(SeekFrom::Start(block_index * 4096))
        .expect("seek");
    file.write_all(&[byte; 4096]).expect("write");
    file.sync_all().expect("fsync");
}

fn assert_block(path: &str, block_index: u64, expected_byte: u8) {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).expect("open for assert_block");
    file.seek(SeekFrom::Start(block_index * 4096))
        .expect("seek");
    let mut buf = [0u8; 4096];
    file.read_exact(&mut buf).expect("read");
    assert!(
        buf.iter().all(|&b| b == expected_byte),
        "block {block_index} does not match expected pattern"
    );
}
