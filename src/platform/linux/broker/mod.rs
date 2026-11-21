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
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
use std::sync::{Arc, PoisonError, RwLock};

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

/// Jobs executed in order by the launcher thread over `home.socket`.
enum LauncherJob {
    Accept {
        listener_socket: OwnedFd,
        guard: Arc<Guard>,
        reply: SyncSender<io::Result<()>>,
    },
    GrantPool {
        ruleset_fd: OwnedFd,
        reply: Sender<Result<()>>,
    },
}

/// The broker of one sandbox.
pub(crate) struct Broker {
    program_bytes: RwLock<Vec<u8>>,
    /// Dropping the broker drops this, which ends the launcher, which closes its
    /// end of the home thread's socket and so ends the home thread.
    jobs: Sender<LauncherJob>,
    /// Current policy guard snapshot cloned into each newly spawned command.
    guard: RwLock<Arc<Guard>>,
    /// Directories holding pre-created inode pools, preserved across policy updates.
    pool_dirs: Vec<PathBuf>,
    denylists: bool,
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
        let guard = Guard::new(config, plan, ancestors, pool_dirs)?;
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
pub(crate) fn on_the_setup_thread<R: Send>(
    body: impl FnOnce(&OwnedFd) -> R + Send,
) -> Result<(R, OwnedFd)> {
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
        let (sandbox_ruleset, guard, pool, pool_dirs, held, coverage) = if denylists {
            let plan = landlock_rules::plan(config);
            let (prepared, held) = prepare_on_a_thread(config, &plan, abi)?;
            let Prepared {
                carved,
                guard,
                pool,
            } = prepared;
            let pool_dirs = pool.as_ref().map_or_else(Vec::new, PoolPlan::directories);
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
            let coverage = Coverage {
                files: true,
                reads: guard.watches_reads(),
            };
            (sandbox_ruleset, guard, pool, pool_dirs, held, coverage)
        } else {
            let plan = landlock_rules::plan(config);
            let guard = Guard::new(config, &plan, HashSet::new(), Vec::new())?;
            (
                landlock_rules::instantiate(&plan, proxy_port, abi)?,
                guard,
                None,
                Vec::new(),
                Vec::new(),
                Coverage {
                    files: false,
                    reads: false,
                },
            )
        };

        let program_bytes = RwLock::new(encode_coverage_program(coverage)?);

        let diagnostics =
            diag::start().map_err(init("cannot start the broker's diagnostics thread"))?;
        let guard = RwLock::new(Arc::new(guard));
        let (jobs, queue) = channel();
        let (home_commands, home_rx) = channel();
        let (ready, started) = sync_channel(1);
        let launch = Launch {
            held,
            home_commands: home_commands.clone(),
            setup: home::Setup {
                pool,
                sink,
                proxy_port,
                sync_wake_up: config.broker_sync_wake_up(),
                diagnostics,
                commands: home_rx,
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
        Ok(Some((
            Self {
                program_bytes,
                jobs,
                guard,
                pool_dirs,
                denylists,
            },
            sandbox_ruleset,
        )))
    }

    /// Raw `sock_filter` bytes of the seccomp notification filter.
    pub(crate) fn program_bytes(&self) -> Vec<u8> {
        self.program_bytes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Create the `(parent_socket, child_socket)` pair used to hand a listener
    /// descriptor from `pre_exec` to the broker.
    pub(crate) fn prepare_sockets(&self) -> io::Result<(OwnedFd, OwnedFd)> {
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
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    /// Receive a seccomp listener from `listener_socket` and start serving it
    /// under a launch-time snapshot of the current policy guard.
    pub(crate) fn accept_listener(&self, listener_socket: OwnedFd) -> io::Result<()> {
        let guard = Arc::clone(&self.guard.read().unwrap_or_else(PoisonError::into_inner));
        let (reply, result) = sync_channel(1);
        self.jobs
            .send(LauncherJob::Accept {
                listener_socket,
                guard,
                reply,
            })
            .map_err(|_| io::Error::other("the broker's launcher exited"))?;
        result
            .recv()
            .map_err(|_| io::Error::other("the broker's launcher exited"))?
    }

    /// Rebuild the Landlock ruleset and swap the broker's policy guard for
    /// commands spawned after this call, leaving already-running commands on
    /// the guard snapshot they launched with.
    pub(crate) fn rebuild_policy(
        &self,
        config: &SandboxConfigData,
        proxy_port: Option<u16>,
    ) -> Result<PreparedRuleset> {
        let abi = REQUIRED_ABI;
        let plan = landlock_rules::plan(config);
        if !self.denylists {
            let new_guard = Guard::new(config, &plan, HashSet::new(), Vec::new())?;
            let ruleset = landlock_rules::build_ruleset(config, proxy_port)?;
            *self.guard.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(new_guard);
            return Ok(ruleset);
        }

        let pool_dirs = self.pool_dirs.clone();
        let (outcome, _ours) = on_the_setup_thread(|_socket| -> Result<(Carved, Guard)> {
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
            let carved = landlock_rules::carve(plan.clone(), &denied, abi)?;
            let ancestors: HashSet<PathBuf> = carved
                .ancestors
                .iter()
                .map(|ancestor| ancestor.path.clone())
                .collect();
            let guard = Guard::new(config, &plan, ancestors, pool_dirs)?;
            Ok((carved, guard))
        })?;
        let (carved, new_guard) = outcome?;
        let sandbox_rules = without_writes(&carved.rules, abi);
        let ruleset = landlock_rules::instantiate(&sandbox_rules, proxy_port, abi)?;
        let ruleset_fd = ruleset.duplicate_fd()?;
        let (reply_tx, reply_rx) = channel();
        self.jobs
            .send(LauncherJob::GrantPool {
                ruleset_fd,
                reply: reply_tx,
            })
            .map_err(|_| Error::InitFailed("the broker's launcher exited".to_owned()))?;
        reply_rx
            .recv()
            .map_err(|_| Error::InitFailed("the broker's home thread exited".to_owned()))??;
        let new_program = encode_coverage_program(Coverage {
            files: true,
            reads: new_guard.watches_reads(),
        })?;
        *self
            .program_bytes
            .write()
            .unwrap_or_else(PoisonError::into_inner) = new_program;
        *self.guard.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(new_guard);
        Ok(ruleset)
    }
}

fn encode_coverage_program(coverage: Coverage) -> Result<Vec<u8>> {
    let program = filter::build(coverage)?;
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(program.as_slice()));
    for insn in &program {
        bytes.extend_from_slice(&insn.code.to_ne_bytes());
        bytes.push(insn.jt);
        bytes.push(insn.jf);
        bytes.extend_from_slice(&insn.k.to_ne_bytes());
    }
    Ok(bytes)
}

/// What the launcher thread is started with.
struct Launch {
    /// The inode pool's directories, to send to the home thread.
    held: Vec<OwnedFd>,
    home_commands: Sender<home::HomeCommand>,
    setup: home::Setup,
}

/// The launcher's end of the home thread.
struct HomeLink {
    socket: OwnedFd,
    commands: Sender<home::HomeCommand>,
    acknowledgements: Receiver<io::Result<()>>,
}

/// Start the home thread and wait until it is ready.
fn start_home(launch: Launch) -> io::Result<HomeLink> {
    let Launch {
        held,
        home_commands,
        setup,
    } = launch;
    let (ours, theirs) = table::socket_pair()?;
    let (acknowledge, acknowledgements) = channel();
    let has_pool = setup.pool.is_some();
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
        commands: home_commands,
        acknowledgements,
    })
}

fn hand_over_listener(
    home: &HomeLink,
    guard: Arc<Guard>,
    listener_socket: &OwnedFd,
) -> io::Result<()> {
    let listener = table::recv_fds(listener_socket.as_fd())?.ok_or_else(|| {
        io::Error::other("the sandboxed process ended before it handed over its listener")
    })?;
    home.commands
        .send(home::HomeCommand::Adopt { guard })
        .map_err(|_| io::Error::other("the broker's home thread ended"))?;
    let borrowed: Vec<BorrowedFd<'_>> = listener.iter().map(AsFd::as_fd).collect();
    table::send_fds(home.socket.as_fd(), &borrowed)?;
    drop(listener);
    home.acknowledgements
        .recv()
        .map_err(|_| io::Error::other("the broker's home thread ended"))?
}

/// The launcher thread: accepts seccomp listeners from sandboxed processes and
/// hands them to the home thread.
///
/// Ends when the broker is dropped and the queue of jobs is empty.
fn launcher(launch: Launch, queue: &Receiver<LauncherJob>, ready: &SyncSender<io::Result<()>>) {
    let home = match start_home(launch) {
        Ok(home) => home,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    for job in queue {
        match job {
            LauncherJob::Accept {
                listener_socket,
                guard,
                reply,
            } => {
                let outcome = hand_over_listener(&home, guard, &listener_socket);
                let _ = reply.send(outcome);
            }
            LauncherJob::GrantPool { ruleset_fd, reply } => {
                if home
                    .commands
                    .send(home::HomeCommand::GrantPool { reply })
                    .is_ok()
                {
                    let _ = table::send_fds(home.socket.as_fd(), &[ruleset_fd.as_fd()]);
                }
            }
        }
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
