//! The home thread of a broker, and the workers it starts.
//!
//! The home thread owns a descriptor table of its own ([`super::table`]), and so
//! do the workers: they are created with `CLONE_FILES`, which shares the table of
//! the thread that creates them. Everything that opens a file for the sandbox,
//! and closes its own copy once the sandbox has the descriptor, happens in that
//! table, where the close cannot release a POSIX lock the embedder holds. It is
//! also why none of this code calls `tracing`: it builds a
//! [`Diagnostic`] and hands it to the [`Outbox`], whose thread is in the
//! embedder's table.
//!
//! The launcher sends each sandboxed process's seccomp listener over a socket.
//! The home thread builds the [`Serving`] for it, starts its workers, and
//! acknowledges. When the launcher is gone the socket reaches its end and the home
//! thread returns; the workers go on until their listener is orphaned.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::check::Guard;
use super::diag::{Diagnostic, Outbox};
use super::filter::{self, Syscall};
use super::notify::{Listener, Reply};
use super::ops::{self, Call, Errno};
use super::pool::{Pool, PoolPlan};
use super::resolve::Caller;
use super::sink::DenialSink;
use super::table;

/// The most threads that serve one sandbox, however many calls block.
const MAX_WORKERS: usize = 256;

/// What every thread that serves a sandbox shares.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(super) guard: Guard,
    pub(super) pool: Option<Pool>,
    pub(super) sink: Arc<DenialSink>,
    rename_lock: RwLock<()>,
    proxy_port: Option<u16>,
    sync_wake_up: bool,
    diagnostics: Outbox,
}

/// The lock a call holds while it is served.
pub(crate) enum Held<'a> {
    /// Taken by a call that names no file.
    None,
    /// Taken by every call but a rename.
    Shared(#[allow(dead_code)] RwLockReadGuard<'a, ()>),
    /// Taken by a rename, so that no name changes under a call that checked it.
    Exclusive(#[allow(dead_code)] RwLockWriteGuard<'a, ()>),
}

impl Shared {
    /// Lock for serving `syscall`.
    pub(crate) fn hold_for(&self, syscall: Syscall) -> Held<'_> {
        // A connect to an inet address names no file and can take long, so it
        // must not hold up the renames that wait for the write side.
        if syscall == Syscall::Connect {
            return Held::None;
        }
        if matches!(
            syscall,
            Syscall::Rename | Syscall::Renameat | Syscall::Renameat2
        ) {
            Held::Exclusive(
                self.rename_lock
                    .write()
                    .unwrap_or_else(PoisonError::into_inner),
            )
        } else {
            Held::Shared(
                self.rename_lock
                    .read()
                    .unwrap_or_else(PoisonError::into_inner),
            )
        }
    }

    /// The shared side of the lock, for a call that turns out to name a file.
    pub(crate) fn read_lock(&self) -> Held<'_> {
        self.hold_for(Syscall::Open)
    }

    /// Whether a connection to `ip:port` is the one the sandbox may make.
    pub(crate) fn proxy_reachable(&self, ip: Ipv4Addr, port: u16) -> bool {
        ip == crate::network::PROXY_ADDRESS && self.proxy_port == Some(port)
    }

    /// Hand a diagnostic to the thread that emits them. Never waits.
    pub(crate) fn say(&self, diagnostic: Diagnostic) {
        self.diagnostics.say(diagnostic);
    }
}

/// The listener of one sandboxed process tree and the threads serving it.
#[derive(Debug)]
struct Serving {
    listener: Listener,
    shared: Arc<Shared>,
    idle: AtomicUsize,
    threads: AtomicUsize,
    base: usize,
}

/// What a handler needs to serve one call.
pub(crate) struct Context<'a> {
    serving: &'a Arc<Serving>,
}

impl Context<'_> {
    pub(crate) fn shared(&self) -> &Shared {
        &self.serving.shared
    }

    /// Make sure another thread is listening before this one blocks in a call
    /// that can take long, so that it never holds up the others.
    pub(crate) fn ensure_spare_worker(&self) {
        if self.serving.idle.load(Ordering::Acquire) == 0
            && self.serving.threads.load(Ordering::Acquire) < MAX_WORKERS
            && let Err(error) = spawn_worker(self.serving)
        {
            self.serving
                .shared
                .say(Diagnostic::error("broker: cannot start a worker").field("error", error));
        }
    }
}

fn spawn_worker(serving: &Arc<Serving>) -> io::Result<()> {
    serving.threads.fetch_add(1, Ordering::AcqRel);
    serving.idle.fetch_add(1, Ordering::AcqRel);
    let worker = Arc::clone(serving);
    let spawned = std::thread::Builder::new()
        .name("heel-broker".to_owned())
        .spawn(move || work(&worker));
    if let Err(error) = spawned {
        serving.threads.fetch_sub(1, Ordering::AcqRel);
        serving.idle.fetch_sub(1, Ordering::AcqRel);
        return Err(error);
    }
    Ok(())
}

fn work(serving: &Arc<Serving>) {
    // A thread of its own working directory and file creation mask, so serving
    // one call never changes what another sees.
    // SAFETY: `unshare(CLONE_FS)` takes a flag and touches only this thread.
    if unsafe { libc::unshare(libc::CLONE_FS) } != 0 {
        serving.shared.say(
            Diagnostic::error("broker: unshare(CLONE_FS) failed")
                .field("error", io::Error::last_os_error()),
        );
        serving.threads.fetch_sub(1, Ordering::AcqRel);
        serving.idle.fetch_sub(1, Ordering::AcqRel);
        return;
    }
    loop {
        match serving.listener.recv() {
            Ok(notification) => {
                serving.idle.fetch_sub(1, Ordering::AcqRel);
                serve(serving, &notification);
                let idle = serving.idle.fetch_add(1, Ordering::AcqRel) + 1;
                if serving.threads.load(Ordering::Acquire) > serving.base && idle > 1 {
                    break;
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => {}
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                if serving.listener.is_orphaned() {
                    break;
                }
            }
            Err(error) => {
                serving
                    .shared
                    .say(Diagnostic::error("broker: receive failed").field("error", error));
                break;
            }
        }
    }
    serving.idle.fetch_sub(1, Ordering::AcqRel);
    serving.threads.fetch_sub(1, Ordering::AcqRel);
}

fn serve(serving: &Arc<Serving>, notification: &libc::seccomp_notif) {
    let listener = &serving.listener;
    let id = notification.id;
    let Some(syscall) = filter::classify(notification.data.nr) else {
        serving.shared.say(
            Diagnostic::error("broker: a call the filter does not name")
                .field("nr", notification.data.nr),
        );
        let _ = listener.reply(id, Reply::Errno(libc::ENOSYS));
        return;
    };
    let caller = Caller::new(listener, id, notification.pid);
    let call = Call {
        syscall,
        args: notification.data.args,
        caller: &caller,
    };
    let context = Context { serving };
    let reply = match ops::serve(&context, &call) {
        Ok(reply) => reply,
        Err(Errno(errno)) => Reply::Errno(errno),
    };
    if let Err(error) = listener.reply(id, reply)
        && error.raw_os_error() != Some(libc::ENOENT)
    {
        serving
            .shared
            .say(Diagnostic::debug("broker: reply failed").field("error", error));
    }
}

/// What the home thread builds what it shares from.
pub(super) struct Setup {
    pub(super) guard: Guard,
    pub(super) pool: Option<PoolPlan>,
    pub(super) sink: Arc<DenialSink>,
    pub(super) proxy_port: Option<u16>,
    pub(super) sync_wake_up: bool,
    pub(super) diagnostics: Outbox,
}

/// Build what the workers share, from the pool's plan and the pool's
/// descriptors, which arrive first.
fn build(socket: &OwnedFd, setup: Setup) -> io::Result<Arc<Shared>> {
    let pool = match setup.pool {
        Some(plan) => {
            let held = table::recv_fds(socket.as_fd())?.ok_or_else(|| {
                io::Error::other("the launcher ended before it sent the inode pool's directories")
            })?;
            Some(
                Pool::from_parts(plan, held)
                    .map_err(|error| io::Error::other(error.to_string()))?,
            )
        }
        None => None,
    };
    Ok(Arc::new(Shared {
        guard: setup.guard,
        pool,
        sink: setup.sink,
        rename_lock: RwLock::new(()),
        proxy_port: setup.proxy_port,
        sync_wake_up: setup.sync_wake_up,
        diagnostics: setup.diagnostics,
    }))
}

/// Start serving the listener a sandboxed process sent.
fn adopt(shared: &Arc<Shared>, listener: Vec<OwnedFd>, workers: usize) -> io::Result<()> {
    let [listener] = <[OwnedFd; 1]>::try_from(listener)
        .map_err(|_| io::Error::other("a message carried more than one listener"))?;
    let listener = Listener::new(listener);
    if shared.sync_wake_up {
        listener.set_sync_wake_up()?;
    }
    let serving = Arc::new(Serving {
        listener,
        shared: Arc::clone(shared),
        idle: AtomicUsize::new(0),
        threads: AtomicUsize::new(0),
        base: workers,
    });
    for _ in 0..workers {
        spawn_worker(&serving)?;
    }
    Ok(())
}

/// The home thread: build the shared state, say so, then serve every listener
/// the launcher sends until its end of the socket closes.
///
/// Each result goes to `acknowledge` in order: the first for the setup, then
/// one for each listener.
pub(super) fn run(socket: &OwnedFd, setup: Setup, acknowledge: &Sender<io::Result<()>>) {
    let shared = match build(socket, setup) {
        Ok(shared) => shared,
        Err(error) => {
            let _ = acknowledge.send(Err(error));
            return;
        }
    };
    let _ = acknowledge.send(Ok(()));
    let workers = std::thread::available_parallelism().map_or(2, usize::from);
    loop {
        match table::recv_fds(socket.as_fd()) {
            Ok(Some(listener)) => {
                let _ = acknowledge.send(adopt(&shared, listener, workers));
            }
            Ok(None) => return,
            Err(error) => {
                let _ = acknowledge.send(Err(error));
                return;
            }
        }
    }
}
