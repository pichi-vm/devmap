// SPDX-License-Identifier: Apache-2.0

use devmap_core::{Control, DevId, Device, TableBuilder};
use devmap_integrity::{
    Header,
    dm::{Mode, Target},
};
use std::{cell::RefCell, io, path::PathBuf, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Create,
    Add,
    Load,
    Resume,
    Remove,
}

#[derive(Clone)]
struct Backend {
    path: PathBuf,
    log: Rc<RefCell<Vec<Step>>>,
    fail: Option<Step>,
    fail_cleanup: bool,
}
impl Backend {
    fn step(&self, step: Step) -> io::Result<()> {
        self.log.borrow_mut().push(step);
        if self.fail == Some(step) || (step == Step::Remove && self.fail_cleanup) {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("injected {step:?} failure"),
            ))
        } else {
            Ok(())
        }
    }
}
struct Handle(Backend);
struct Table(Backend);

impl Control for Backend {
    type Device = Handle;
    fn create(&self, _: &str) -> io::Result<Handle> {
        assert!(
            std::fs::read(&self.path).unwrap()[..4096]
                .iter()
                .all(|&byte| byte == 0)
        );
        self.step(Step::Create)?;
        Ok(Handle(self.clone()))
    }
}
impl Device for Handle {
    type TableBuilder = Table;
    fn builder(&self) -> Table {
        Table(self.0.clone())
    }
    fn resume(&self) -> io::Result<()> {
        use std::io::Write as _;
        self.0.step(Step::Resume)?;
        let mut bytes = [0; 24];
        bytes[..8].copy_from_slice(b"integrt\0");
        bytes[8] = 1;
        bytes[16..24].copy_from_slice(&1234u64.to_le_bytes());
        std::fs::OpenOptions::new()
            .write(true)
            .open(&self.0.path)?
            .write_all(&bytes)
    }
    fn remove(self) -> io::Result<()> {
        self.0.step(Step::Remove)
    }
    fn remove_deferred(self) -> io::Result<()> {
        self.0.step(Step::Remove)
    }
}
impl TableBuilder for Table {
    fn read_only(self) -> Self {
        self
    }
    fn add<T: devmap_core::Target + std::fmt::Display>(
        self,
        start: u64,
        length: u64,
        _: T,
    ) -> io::Result<Self> {
        assert_eq!((start, length), (0, 1));
        assert_eq!(T::NAME, "integrity");
        self.0.step(Step::Add)?;
        Ok(self)
    }
    fn load(self) -> io::Result<()> {
        self.0.step(Step::Load)
    }
}

#[test]
fn formatting_uses_backend_operations_and_one_header_reader() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), vec![0xaa; 8192]).unwrap();
    let backend = Backend {
        path: file.path().into(),
        log: Rc::default(),
        fail: None,
        fail_cleanup: false,
    };
    let target = Target::builder(DevId::new(7, 1).unwrap(), 0, Mode::Journaled).build();
    assert_eq!(
        target.format(&backend, "temporary", file.path()).unwrap(),
        1234
    );
    assert_eq!(
        *backend.log.borrow(),
        [
            Step::Create,
            Step::Add,
            Step::Load,
            Step::Resume,
            Step::Remove
        ]
    );
    assert_eq!(
        Header::open(std::fs::File::open(file.path()).unwrap())
            .unwrap()
            .data_sectors(),
        1234
    );
    assert!(
        std::fs::read(file.path()).unwrap()[4096..]
            .iter()
            .all(|&byte| byte == 0xaa)
    );
}

#[test]
fn failed_setup_attempts_cleanup_without_hiding_the_primary_error() {
    for fail in [Step::Create, Step::Add, Step::Load, Step::Resume] {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![0xaa; 8192]).unwrap();
        let backend = Backend {
            path: file.path().into(),
            log: Rc::default(),
            fail: Some(fail),
            fail_cleanup: false,
        };
        let target = Target::builder(DevId::new(7, 1).unwrap(), 0, Mode::Journaled).build();
        assert_eq!(
            target
                .format(&backend, "temporary", file.path())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            backend.log.borrow().last(),
            Some(if fail == Step::Create {
                &Step::Create
            } else {
                &Step::Remove
            })
        );
    }
}

#[test]
fn malformed_and_truncated_headers_are_rejected() {
    for bytes in [vec![], vec![0; 24]] {
        assert!(Header::open(std::io::Cursor::new(bytes)).is_err());
    }
}

#[test]
fn cleanup_failure_reports_the_remaining_device_and_retains_the_cause() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), vec![0xaa; 8192]).unwrap();
    let backend = Backend {
        path: file.path().into(),
        log: Rc::default(),
        fail: Some(Step::Load),
        fail_cleanup: true,
    };
    let target = Target::builder(DevId::new(7, 1).unwrap(), 0, Mode::Journaled).build();
    let error = target
        .format(&backend, "owned-temporary-device", file.path())
        .unwrap_err();
    assert!(error.to_string().contains("owned-temporary-device"));
    let cause = error
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
}
