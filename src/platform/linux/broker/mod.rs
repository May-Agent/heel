//! The broker: a supervisor that performs, for the sandboxed process, the calls
//! the host protection policies have to judge.
//!
//! Landlock cannot express "everything below here except this", and a rule it
//! has cannot be added to a process that is already restricted. So the sandbox's
//! own Landlock layer holds no right to change the filesystem at all, and every
//! call that creates, changes, removes or writes is stopped by seccomp and sent
//! here as a user notification. The broker judges it against the policy, by the
//! real path and inode it resolves to through directories it holds, performs it
//! itself, and hands the result back: the return value, or for an open a
//! descriptor installed in the caller.
//!
//! Two arrangements exist:
//!
//! * with a read or write denylist the full broker serves file calls, `connect`
//!   and `bind`, and the sandbox's Landlock layer is the broker's with writes
//!   taken away and the denied trees carved out;
//! * without one, a sandbox that may reach the network gets a broker for
//!   `connect` alone, which is what limits outbound TCP to the proxy's loopback
//!   address, a restriction Landlock can only express for a port.
//!
//! The broker lives in the embedder's process, on threads of four kinds:
//!
//! * the launcher (`heel-launcher`), in the embedder's descriptor table,
//!   forks every sandboxed process, so the sandbox's Landlock domain is a
//!   descendant of the launcher's, which is the broker's, and Landlock lets the
//!   broker read the memory of, and take descriptors from, the processes it
//!   serves. It receives each process's seccomp listener and hands it on;
//! * the log thread (`heel-broker-log`), also in the embedder's table, which
//!   emits what the other threads have to say, and ends once no thread that
//!   serves a sandbox is left;
//! * the home thread (`heel-broker-home`), started by the launcher after it was
//!   restricted, and the workers (`heel-broker`) it starts, which share its
//!   table. They open the files for the sandbox;
//! * the setup thread (`heel-broker-setup`), which lists the directories
//!   above and inside the denied paths while the broker is built.
//!
//! The last two kinds each have a descriptor table of their own, because a
//! POSIX lock the embedder holds on a file is released by any close of the file
//! in the embedder's table. See [`table`] for the rule and what it demands of
//! the code that runs on those threads.

mod check;
mod diag;
mod filter;
mod home;
mod net;
mod notify;
mod ops;
mod pool;
mod resolve;
pub(crate) mod sink;
mod table;

use std::collections::HashSet;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};

use landlock::Access as _;
use libc::sock_filter;

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::platform::linux::landlock_rules::{
    self, Carved, Planned, PreparedRuleset, REQUIRED_ABI, without_writes,
};

use check::Guard;
use diag::Diagnostic;
use filter::Coverage;
use pool::{Pool, PoolPlan};
use sink::DenialSink;

#[cfg(target_arch = "x86_64")]
pub(crate) use filter::x32_refusal;

/// A process to start through the launcher.
struct Job {
    command: Command,
    listener_socket: OwnedFd,
    reply: SyncSender<io::Result<Child>>,
}

/// The broker of one sandbox.
pub(crate) struct Broker {
    program: Vec<sock_filter>,
    /// Dropping the broker drops this, which ends the launcher, which closes its
    /// end of the home thread's socket and so ends the home thread. The workers
    /// go on until their listeners are orphaned, which serves a descendant that
    /// outlives the sandbox.
    jobs: Sender<Job>,
}

/// What the child runs between `fork` and `exec` to hand its listener over.
pub(crate) struct ChildHook {
    program: Vec<sock_filter>,
    socket: OwnedFd,
}

impl ChildHook {
    /// Install the notification filter and send its listener to the broker.
    /// Called from `pre_exec`, after the sandbox's Landlock layer.
    pub(crate) fn install(&self) -> io::Result<()> {
        // SAFETY: both `prctl` calls take integers by value.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let program = libc::sock_fprog {
            len: u16::try_from(self.program.len())
                .map_err(|_| io::Error::other("filter too long"))?,
            filter: self.program.as_ptr().cast_mut(),
        };
        let flags =
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER | libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
        // SAFETY: `program` points at `len` instructions that outlive the call.
        let listener = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                flags,
                &raw const program,
            )
        };
        if listener < 0 {
            return Err(io::Error::last_os_error());
        }
        let listener = listener as RawFd;
        // SAFETY: `listener` was returned by the call above and stays open until
        // it is closed below, after the send.
        let borrowed = unsafe { BorrowedFd::borrow_raw(listener) };
        let sent = table::send_fds(self.socket.as_fd(), &[borrowed]);
        // SAFETY: `listener` was returned by the call above and is not used again.
        unsafe { libc::close(listener) };
        sent
    }
}

/// `/proc/sys/kernel/yama/ptrace_scope`, when Yama is loaded.
const YAMA_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// The highest `kernel.yama.ptrace_scope` under which a parent can read its child.
const MAX_PTRACE_SCOPE: u8 = 1;

/// Refuse a kernel whose Yama setting stops a parent from reading its child.
fn check_ptrace_scope() -> Result<()> {
    match std::fs::read_to_string(YAMA_SCOPE) {
        Ok(text) => parse_ptrace_scope(&text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::path(YAMA_SCOPE, error)),
    }
}

/// Judge the contents of [`YAMA_SCOPE`].
fn parse_ptrace_scope(text: &str) -> Result<()> {
    let scope: u8 = text
        .trim()
        .parse()
        .map_err(|_| Error::InitFailed(format!("cannot read {YAMA_SCOPE}: {}", text.trim())))?;
    if scope > MAX_PTRACE_SCOPE {
        return Err(Error::PtraceScopeTooStrict {
            scope,
            max: MAX_PTRACE_SCOPE,
        });
    }
    Ok(())
}

/// What the setup thread worked out.
struct Prepared {
    carved: Carved,
    guard: Guard,
    pool: Option<PoolPlan>,
}

/// The setup thread's work: list the directories around the denied paths, make
/// the inode pool, and build the guard. Returns what it has to say whatever
/// came of it.
///
/// Runs on a thread with a descriptor table of its own, so it never calls
/// `tracing`. The pool's directory descriptors go to the starter over `socket`.
fn prepare(
    config: &SandboxConfigData,
    plan: &[Planned],
    abi: landlock::ABI,
    socket: &OwnedFd,
) -> (Vec<Diagnostic>, Result<Prepared>) {
    let mut log = Vec::new();
    let outcome = (|| {
        let denied: Vec<PathBuf> = match config.read_denylist() {
            Some(read) => {
                let resolved = read.resolve()?;
                resolved
                    .trees
                    .into_iter()
                    .filter(|tree| !resolved.sockets.contains(tree))
                    .collect()
            }
            None => Vec::new(),
        };
        let carved = landlock_rules::carve(plan.to_vec(), &denied, abi)?;
        let pool = if carved.ancestors.is_empty() {
            None
        } else {
            let (pool, held) = Pool::prepare(config.inode_pool(), &carved.ancestors, &mut log)?;
            // A pool that found no place anywhere has nothing to hand on.
            if pool.is_empty() {
                None
            } else {
                let held: Vec<BorrowedFd<'_>> = held.iter().map(AsFd::as_fd).collect();
                table::send_fds(socket.as_fd(), &held).map_err(|error| {
                    Error::InitFailed(format!("cannot hand the inode pool on: {error}"))
                })?;
                Some(pool)
            }
        };
        let ancestors: HashSet<PathBuf> = carved
            .ancestors
            .iter()
            .map(|ancestor| ancestor.path.clone())
            .collect();
        let pool_dirs = pool.as_ref().map_or_else(Vec::new, PoolPlan::directories);
        let guard = Guard::new(config, ancestors, pool_dirs)?;
        Ok(Prepared {
            carved,
            guard,
            pool,
        })
    })();
    (log, outcome)
}

/// An [`Error::InitFailed`] that says what was being done.
fn init(what: &'static str) -> impl FnOnce(io::Error) -> Error {
    move |error| Error::InitFailed(format!("{what}: {error}"))
}

/// Run `body` on the setup thread, which has a descriptor table of its own, with
/// the thread's end of a socket, and return what it returned with the other end.
fn on_the_setup_thread<R: Send>(body: impl FnOnce(&OwnedFd) -> R + Send) -> Result<(R, OwnedFd)> {
    let (ours, theirs) = table::socket_pair().map_err(init("cannot make the setup socket"))?;
    let done = std::thread::scope(|scope| {
        let setup = table::spawn_scoped(scope, "heel-broker-setup", theirs, |socket| body(&socket))
            .map_err(init("cannot start the broker's setup thread"))?;
        match setup.join() {
            Ok(Some(done)) => Ok(done),
            Ok(None) | Err(_) => Err(Error::InitFailed(
                "the broker's setup thread did not finish".to_owned(),
            )),
        }
    })?;
    Ok((done, ours))
}

/// Run [`prepare`] on the setup thread, with the descriptors it sends.
fn prepare_on_a_thread(
    config: &SandboxConfigData,
    plan: &[Planned],
    abi: landlock::ABI,
) -> Result<(Prepared, Vec<OwnedFd>)> {
    let ((log, outcome), ours) = on_the_setup_thread(|socket| prepare(config, plan, abi, socket))?;
    // Emitted here, in the embedder's table, whether or not the setup worked.
    for diagnostic in log {
        diagnostic.emit();
    }
    let prepared = outcome?;
    let held = match &prepared.pool {
        Some(_) => table::recv_fds(ours.as_fd())
            .map_err(init("cannot receive the inode pool's directories"))?
            .ok_or_else(|| {
                Error::InitFailed("the setup thread sent no inode pool directories".to_owned())
            })?,
        None => Vec::new(),
    };
    Ok((prepared, held))
}

impl Broker {
    /// The broker a configuration needs, if it needs one.
    pub(crate) fn new(
        config: &SandboxConfigData,
        proxy_port: Option<u16>,
        sink: Arc<DenialSink>,
    ) -> Result<Option<(Self, PreparedRuleset)>> {
        let denylists = config.read_denylist().is_some() || config.write_denylist().is_some();
        if !denylists && proxy_port.is_none() {
            return Ok(None);
        }
        notify::check_sizes()?;
        check_ptrace_scope()?;

        let abi = REQUIRED_ABI;
        let (sandbox_ruleset, guard, pool, held, broker_rules, coverage) = if denylists {
            let plan = landlock_rules::plan(config);
            let (prepared, held) = prepare_on_a_thread(config, &plan, abi)?;
            let Prepared {
                carved,
                guard,
                pool,
            } = prepared;
            let sandbox_rules = without_writes(&carved.rules, abi);
            let mut sandbox_ruleset = landlock_rules::instantiate(&sandbox_rules, proxy_port, abi)?;
            let reads = landlock_rules::read_rights(abi);
            if let Some(pool) = &pool {
                pool.grant(&held, &mut |fd, access| {
                    let access = access & reads;
                    if access.is_empty() {
                        Ok(())
                    } else {
                        sandbox_ruleset.add_inode(fd, access, abi)
                    }
                })?;
            }
            let pool_dirs = pool.as_ref().map_or_else(Vec::new, PoolPlan::directories);
            let mut broker_rules = plan;
            for directory in pool_dirs {
                broker_rules.push(Planned {
                    path: directory,
                    access: landlock::AccessFs::from_all(abi),
                    required: true,
                });
            }
            let coverage = Coverage {
                files: true,
                reads: guard.watches_reads(),
            };
            (
                sandbox_ruleset,
                guard,
                pool,
                held,
                Some(broker_rules),
                coverage,
            )
        } else {
            // Nothing here lists a user's directory: the guard reads only the
            // mount table, and there is no pool.
            let guard = Guard::new(config, HashSet::new(), Vec::new())?;
            (
                landlock_rules::build_ruleset(config, proxy_port)?,
                guard,
                None,
                Vec::new(),
                None,
                Coverage {
                    files: false,
                    reads: false,
                },
            )
        };

        let program = filter::build(coverage)?;
        let broker_ruleset = broker_rules
            .map(|rules| landlock_rules::instantiate(&rules, proxy_port, abi))
            .transpose()?;

        let diagnostics =
            diag::start().map_err(init("cannot start the broker's diagnostics thread"))?;
        let (jobs, queue) = channel();
        let (ready, started) = sync_channel(1);
        let launch = Launch {
            ruleset: broker_ruleset,
            held,
            setup: home::Setup {
                guard,
                pool,
                sink,
                proxy_port,
                sync_wake_up: config.broker_sync_wake_up(),
                diagnostics,
            },
        };
        std::thread::Builder::new()
            .name("heel-launcher".to_owned())
            .spawn(move || launcher(launch, &queue, &ready))
            .map_err(|error| Error::InitFailed(format!("cannot start the broker: {error}")))?;
        started
            .recv()
            .map_err(|_| Error::InitFailed("the broker's launcher exited".to_owned()))?
            .map_err(|error| Error::InitFailed(error.to_string()))?;

        tracing::info!(full = denylists, "broker started");
        Ok(Some((Self { program, jobs }, sandbox_ruleset)))
    }

    /// What a command needs to be served by this broker: the hook for its child
    /// and the end of the channel the broker receives the listener on.
    pub(crate) fn prepare(&self) -> io::Result<(ChildHook, OwnedFd)> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `socketpair` fills two descriptors.
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors are new and owned by nothing else.
        let (parent, child) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        Ok((
            ChildHook {
                program: self.program.clone(),
                socket: child,
            },
            parent,
        ))
    }

    /// Start `command` from the launcher thread and begin serving it.
    pub(crate) fn spawn(&self, command: Command, listener_socket: OwnedFd) -> io::Result<Child> {
        let (reply, result) = sync_channel(1);
        self.jobs
            .send(Job {
                command,
                listener_socket,
                reply,
            })
            .map_err(|_| io::Error::other("the broker's launcher exited"))?;
        result
            .recv()
            .map_err(|_| io::Error::other("the broker's launcher exited"))?
    }
}

/// What the launcher thread is started with.
struct Launch {
    ruleset: Option<PreparedRuleset>,
    /// The inode pool's directories, to send to the home thread.
    held: Vec<OwnedFd>,
    setup: home::Setup,
}

/// The launcher's end of the home thread.
struct HomeLink {
    socket: OwnedFd,
    acknowledgements: Receiver<io::Result<()>>,
}

/// Restrict this thread, start the home thread, and wait until it is ready.
fn start_home(launch: Launch) -> io::Result<HomeLink> {
    let Launch {
        ruleset,
        held,
        setup,
    } = launch;
    if let Some(ruleset) = ruleset {
        ruleset
            .restrict_self()
            .map_err(|error| io::Error::other(format!("cannot restrict the broker: {error}")))?;
    }
    let (ours, theirs) = table::socket_pair()?;
    let (acknowledge, acknowledgements) = channel();
    let has_pool = setup.pool.is_some();
    // Started after the restriction, so it is in the same Landlock domain.
    table::spawn("heel-broker-home", theirs, move |socket| {
        home::run(&socket, setup, &acknowledge);
    })
    .map_err(|error| io::Error::other(format!("cannot start the broker's home thread: {error}")))?;
    if has_pool {
        let held: Vec<BorrowedFd<'_>> = held.iter().map(AsFd::as_fd).collect();
        table::send_fds(ours.as_fd(), &held)?;
    }
    acknowledgements
        .recv()
        .map_err(|_| io::Error::other("the broker's home thread ended before it was ready"))??;
    Ok(HomeLink {
        socket: ours,
        acknowledgements,
    })
}

/// Start `job`'s process, hand its listener to the home thread, and wait until
/// the workers are listening.
fn start_job(home: &HomeLink, job: &mut Job) -> io::Result<Child> {
    let mut child = job.command.spawn()?;
    let handed_over = (|| {
        let listener = table::recv_fds(job.listener_socket.as_fd())?.ok_or_else(|| {
            io::Error::other("the sandboxed process ended before it handed over its listener")
        })?;
        let borrowed: Vec<BorrowedFd<'_>> = listener.iter().map(AsFd::as_fd).collect();
        table::send_fds(home.socket.as_fd(), &borrowed)?;
        // The launcher's own copy goes: the home thread's is the one that counts.
        drop(listener);
        home.acknowledgements
            .recv()
            .map_err(|_| io::Error::other("the broker's home thread ended"))?
    })();
    match handed_over {
        Ok(()) => Ok(child),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

/// The launcher thread: restricted once, then forking every sandboxed process.
///
/// Ends when the broker is dropped and the queue of jobs is empty.
fn launcher(launch: Launch, queue: &Receiver<Job>, ready: &SyncSender<io::Result<()>>) {
    let home = match start_home(launch) {
        Ok(home) => home,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    for mut job in queue {
        let outcome = start_job(&home, &mut job);
        let _ = job.reply.send(outcome);
    }
}

#[cfg(test)]
mod ptrace_scope_tests {
    use super::*;

    #[test]
    fn accepts_scopes_the_broker_works_under() {
        for text in ["0\n", "1\n"] {
            parse_ptrace_scope(text).unwrap();
        }
    }

    #[test]
    fn rejects_stricter_scopes_with_a_typed_error() {
        let error = parse_ptrace_scope("2\n").unwrap_err();
        assert!(matches!(
            error,
            Error::PtraceScopeTooStrict { scope: 2, max: 1 }
        ));
        let message = error.to_string();
        assert!(
            message.contains("kernel.yama.ptrace_scope is 2"),
            "{message}"
        );
        assert!(message.contains("needs 1 or lower"), "{message}");
        assert!(matches!(
            parse_ptrace_scope("3").unwrap_err(),
            Error::PtraceScopeTooStrict { scope: 3, .. }
        ));
    }

    #[test]
    fn garbage_is_not_a_scope() {
        assert!(matches!(
            parse_ptrace_scope("lots").unwrap_err(),
            Error::InitFailed(_)
        ));
    }
}

#[cfg(test)]
mod setup_thread_tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    use super::*;

    /// The setup thread lists the user's directories, so what it holds open must
    /// be its own: looked at from inside, as the setup runs.
    #[test]
    fn the_setup_thread_holds_null_and_its_socket_and_nothing_of_the_starters() {
        let held: Vec<File> = (0..40)
            .map(|_| File::open("/proc/self/stat").unwrap())
            .collect();
        let ((name, table, socket), _ours) = on_the_setup_thread(|socket| {
            (
                std::thread::current().name().map(str::to_owned),
                table::listing::thread_table(),
                socket.as_raw_fd(),
            )
        })
        .unwrap();
        assert_eq!(name.as_deref(), Some("heel-broker-setup"));
        let numbers: Vec<_> = table.iter().map(|(number, _)| *number).collect();
        assert_eq!(numbers, [0, 1, 2, socket], "{table:?}");
        for (number, target) in &table[..3] {
            assert_eq!(
                target,
                std::path::Path::new("/dev/null"),
                "descriptor {number}"
            );
        }
        assert!(
            held.iter().all(|file| file.as_raw_fd() > 2),
            "the test held descriptors that the setup thread could have inherited"
        );
        assert!(
            table::listing::thread_table().len() > held.len(),
            "the starter's own table is the large one"
        );
    }
}
