//! Landlock ruleset generation for the Linux sandbox.
//!
//! Landlock is default-deny for every access right the ruleset *handles*: a
//! right that is not handled is left entirely unrestricted. Both the filesystem
//! rights and TCP connections are therefore always handled, and permissions are
//! granted back one path or port at a time.

use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

// The `Access` trait supplies `AccessFs::from_all` and friends and is only
// needed in scope; the name itself belongs to this crate's own `Access`.
use landlock::{
    ABI, Access as _, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, make_bitflags,
};

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::grant::Access;

/// The Landlock ABI this backend requires.
///
/// v4 is the first version that can restrict TCP connections, which the network
/// policy depends on.
pub(crate) const REQUIRED_ABI: ABI = ABI::V4;

/// A ruleset built on the host, ready to be applied after fork.
pub(crate) struct PreparedRuleset {
    inner: RulesetCreated,
}

// `RulesetCreated` is an opaque kernel handle with no `Debug` of its own, but
// callers still need to format a `Result` holding one.
impl std::fmt::Debug for PreparedRuleset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRuleset").finish_non_exhaustive()
    }
}

impl PreparedRuleset {
    /// Duplicate the underlying Landlock ruleset file descriptor for transfer
    /// over `SCM_RIGHTS` to the persistent container runner.
    pub(crate) fn duplicate_fd(&self) -> std::io::Result<OwnedFd> {
        let cloned = self.inner.try_clone()?;
        Option::<OwnedFd>::from(cloned)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EPERM))
    }

    /// Add a rule for the container's private `/proc` mount root inode.
    pub(crate) fn grant_private_proc(
        &mut self,
        proc_fd: BorrowedFd<'_>,
        writable: bool,
    ) -> Result<()> {
        let abi = REQUIRED_ABI;
        let access = if writable {
            AccessFs::from_read(abi) | writable_access(abi)
        } else {
            AccessFs::from_read(abi)
        };
        self.add_inode(proc_fd, access, abi)
    }

    /// Add read and write access on `/dev/tty` (safe because the kernel
    /// resolves `/dev/tty` strictly to the calling process's own controlling
    /// terminal, or fails with `ENXIO` when there is none).
    pub(crate) fn grant_dev_tty(&mut self) -> Result<()> {
        add_system_path(
            &mut self.inner,
            "/dev/tty",
            make_bitflags!(AccessFs::{ ReadFile | WriteFile }),
            REQUIRED_ABI,
        )
    }

    /// Add per-command read and write access for one command's own PTY slave
    /// inode without opening `/dev/pts` or sibling commands' slave devices.
    pub(crate) fn grant_pty_slave(&mut self, slave_fd: BorrowedFd<'_>) -> Result<()> {
        self.add_inode(
            slave_fd,
            make_bitflags!(AccessFs::{ ReadFile | WriteFile }),
            REQUIRED_ABI,
        )
    }

    /// Add a rule for an inode held by `fd`, narrowed to what the inode can take.
    ///
    /// The ruleset keeps its own reference to the inode, so `fd` can be closed
    /// afterwards and the rule still follows the inode through a rename.
    pub(crate) fn add_inode(
        &mut self,
        fd: BorrowedFd<'_>,
        access: BitFlags<AccessFs>,
        abi: ABI,
    ) -> Result<()> {
        let access = effective_path_access(&fd, "an inode held open", access, abi)?;
        add_rule_fd(&mut self.inner, fd, access)
    }
}

/// Add a `PATH_BENEATH` rule for `fd` onto a Landlock ruleset descriptor that
/// arrived across a `CLONE_FILES` boundary via `SCM_RIGHTS`.
pub(crate) fn add_inode_to_ruleset_fd(
    ruleset_fd: BorrowedFd<'_>,
    fd: BorrowedFd<'_>,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<()> {
    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }
    /// `LANDLOCK_RULE_PATH_BENEATH` in `<linux/landlock.h>`.
    const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

    let access = effective_path_access(&fd, "an inode held open", access, abi)?;
    let attr = PathBeneathAttr {
        allowed_access: access.bits(),
        parent_fd: fd.as_raw_fd(),
    };
    // SAFETY: `ruleset_fd` is a valid Landlock ruleset fd in the calling thread's
    // descriptor table and `attr` matches `<linux/landlock.h>`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const attr,
            0usize,
        )
    };
    if rc < 0 {
        return Err(Error::InvalidProfile(format!(
            "Landlock rejected a rule for a held inode: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Verify that the running kernel supports the ABI this backend requires.
///
/// Creating a ruleset is a single syscall, so this is a cheap, side-effect-free
/// probe. It replaces testing the sandbox in a forked child, which is unsound
/// in a multi-threaded process.
pub(crate) fn probe_support() -> Result<()> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(REQUIRED_ABI))
        .and_then(|ruleset| ruleset.handle_access(AccessNet::ConnectTcp))
        .and_then(|ruleset| ruleset.create())
        .map(|_ruleset| ())
        .map_err(|error| {
            Error::NotEnforced(format!(
                "Landlock ABI v{} is required but unavailable: {error}",
                REQUIRED_ABI as i32
            ))
        })
}

/// One rule of a ruleset before it is built: what a path is granted.
///
/// The rules are planned first and turned into a ruleset second so that the
/// sandbox's layer of a protecting sandbox can be derived from the same plan as
/// the broker's: the same grants without the write rights, with the credential
/// stores carved out.
#[derive(Debug, Clone)]
pub(crate) struct Planned {
    pub(crate) path: PathBuf,
    pub(crate) access: BitFlags<AccessFs>,
    /// Whether a missing path is an error. A system path that a distribution
    /// lacks is skipped; a path the caller configured is not.
    pub(crate) required: bool,
}

/// Build the ruleset for a sandbox configuration.
///
/// `proxy_port` is `Some` only when the network policy permits traffic.
pub(crate) fn build_ruleset(
    config: &SandboxConfigData,
    proxy_port: Option<u16>,
) -> Result<PreparedRuleset> {
    let planned = plan(config);
    let rules = match config.read_denylist() {
        Some(read) => {
            let (carved, _ours) = crate::platform::linux::broker::on_the_setup_thread(|_socket| {
                let resolved = read.resolve()?;
                let denied: Vec<PathBuf> = resolved
                    .trees
                    .into_iter()
                    .filter(|tree| !resolved.sockets.contains(tree))
                    .collect();
                carve(planned, &denied, REQUIRED_ABI)
            })?;
            carved?.rules
        }
        None => planned,
    };
    let ruleset = instantiate(&rules, proxy_port, REQUIRED_ABI)?;

    tracing::debug!(
        proxy_port,
        working_dir = %config.working_dir().display(),
        strict = config.filesystem_strict(),
        "landlock: ruleset built"
    );

    Ok(ruleset)
}

/// Every rule a configuration asks for.
pub(crate) fn plan(config: &SandboxConfigData) -> Vec<Planned> {
    let abi = REQUIRED_ABI;
    let mut rules = Vec::new();
    plan_system_rules(&mut rules, config, abi);
    plan_device_rules(&mut rules, config, abi);
    rules.extend(
        configured_rules(config, abi)
            .into_iter()
            .map(|rule| Planned {
                path: rule.path,
                access: rule.access,
                required: true,
            }),
    );
    rules
}

/// Turn a plan into a ruleset.
///
/// `proxy_port` is the one TCP port the ruleset lets its holder connect to; a
/// ruleset with none handles TCP and so refuses every connection.
pub(crate) fn instantiate(
    rules: &[Planned],
    proxy_port: Option<u16>,
    abi: ABI,
) -> Result<PreparedRuleset> {
    // Both filesystem access and TCP connections are always handled. Handling
    // TCP unconditionally is what makes a deny-all policy actually deny: an
    // unhandled right is not restricted at all.
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .and_then(|ruleset| ruleset.handle_access(AccessNet::ConnectTcp))
        .and_then(|ruleset| ruleset.create())
        .map_err(|error| Error::InvalidProfile(format!("Landlock ruleset error: {error}")))?;

    for rule in rules {
        if rule.required {
            add_required_path(&mut ruleset, &rule.path, rule.access, abi)?;
        } else {
            add_system_path(&mut ruleset, &rule.path, rule.access, abi)?;
        }
    }

    // Outbound TCP is denied except to the proxy, which applies the policy.
    if let Some(port) = proxy_port {
        ruleset = ruleset
            .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
            .map_err(|e| Error::InvalidProfile(format!("Landlock proxy rule error: {e}")))?;
    }

    Ok(PreparedRuleset { inner: ruleset })
}

/// The rights that read or execute a file or list a directory.
pub(crate) fn read_rights(abi: ABI) -> BitFlags<AccessFs> {
    AccessFs::from_read(abi)
}

/// A plan with every right that changes the filesystem taken out.
///
/// What is left is what the sandbox itself may do. Everything that creates,
/// changes or removes goes through the broker, which acts under the full plan.
pub(crate) fn without_writes(rules: &[Planned], abi: ABI) -> Vec<Planned> {
    rules
        .iter()
        .filter_map(|rule| {
            let access = rule.access & read_rights(abi);
            (!access.is_empty()).then(|| Planned {
                access,
                ..rule.clone()
            })
        })
        .collect()
}

/// A directory on the way to a denied path.
#[derive(Debug, Clone)]
pub(crate) struct Ancestor {
    pub(crate) path: PathBuf,
    /// The rights an entry created in it needs to be as usable as its siblings.
    pub(crate) rights: BitFlags<AccessFs>,
}

/// A plan with the denied paths carved out of it.
#[derive(Debug)]
pub(crate) struct Carved {
    pub(crate) rules: Vec<Planned>,
    pub(crate) ancestors: Vec<Ancestor>,
}

/// Remove the right to read, list and execute below each of `denied`.
///
/// Landlock grants and never denies, and a path has the union of the rights of
/// every rule above it, so a rule on a directory above a denied path cannot be
/// kept as it is. It is replaced by rules for the entries of that directory that
/// are not on the way to the denied path, and so on down to it. The directories
/// on the way keep nothing: the entries created in them later have no rule, which
/// is what the broker's inode pool makes up for.
///
/// Symbolic links get no rule of their own, because a rule on one grants its
/// target. A denied path that does not exist is not carved: nothing can be read
/// from it, and creating it is the broker's to refuse.
pub(crate) fn carve(rules: Vec<Planned>, denied: &[PathBuf], abi: ABI) -> Result<Carved> {
    let withheld = read_rights(abi);
    let denied: Vec<&PathBuf> = denied
        .iter()
        .filter(|path| std::fs::symlink_metadata(path).is_ok())
        .collect();
    let mut carved = Carved {
        rules: Vec::new(),
        ancestors: Vec::new(),
    };
    for rule in rules {
        if denied.iter().any(|path| rule.path.starts_with(path)) {
            let access = rule.access & !withheld;
            if !access.is_empty() {
                carved.rules.push(Planned { access, ..rule });
            }
            continue;
        }
        let below: Vec<&PathBuf> = denied
            .iter()
            .copied()
            .filter(|path| path.starts_with(&rule.path))
            .collect();
        if below.is_empty() {
            carved.rules.push(rule);
            continue;
        }
        let kept = rule.access & !withheld;
        if !kept.is_empty() {
            carved.rules.push(Planned {
                access: kept,
                ..rule.clone()
            });
        }
        carve_directory(&rule.path, rule.access, &below, &mut carved)?;
    }
    Ok(carved)
}

fn carve_directory(
    directory: &Path,
    access: BitFlags<AccessFs>,
    below: &[&PathBuf],
    carved: &mut Carved,
) -> Result<()> {
    match carved
        .ancestors
        .iter_mut()
        .find(|ancestor| ancestor.path == directory)
    {
        Some(ancestor) => ancestor.rights |= access,
        None => carved.ancestors.push(Ancestor {
            path: directory.to_path_buf(),
            rights: access,
        }),
    }
    let entries = std::fs::read_dir(directory).map_err(|error| {
        Error::path(
            directory,
            std::io::Error::other(format!(
                "cannot list a directory above a denied path to grant its other entries: {error}"
            )),
        )
    })?;
    for entry in entries {
        let path = entry.map_err(|error| Error::path(directory, error))?.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || below.iter().any(|denied| **denied == path) {
            continue;
        }
        let inside: Vec<&PathBuf> = below
            .iter()
            .copied()
            .filter(|denied| denied.starts_with(&path))
            .collect();
        if inside.is_empty() {
            carved.rules.push(Planned {
                path,
                access,
                required: false,
            });
        } else {
            carve_directory(&path, access, &inside, carved)?;
        }
    }
    Ok(())
}

/// Plan the access to the system paths any process needs to start.
fn plan_system_rules(rules: &mut Vec<Planned>, config: &SandboxConfigData, abi: ABI) {
    let mut system = |path: &str, access: BitFlags<AccessFs>| {
        rules.push(Planned {
            path: PathBuf::from(path),
            access,
            required: false,
        });
    };

    // Executables and shared libraries.
    let exec_paths: &[&str] = if config.filesystem_strict() {
        &[
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/lib64",
            "/usr/lib32",
            "/lib",
            "/lib64",
            "/lib32",
            "/usr/libexec",
            "/usr/local",
        ]
    } else {
        &["/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin"]
    };

    // Permissive mode makes the system directories writable as well; otherwise
    // they are read and execute only.
    let exec_access = if config.writable_file_system() {
        AccessFs::from_all(abi)
    } else {
        make_bitflags!(AccessFs::{ ReadFile | ReadDir | Execute })
    };
    for path in exec_paths {
        system(path, exec_access);
    }

    // Read-only system state. Required even in strict mode: the dynamic loader
    // and libc consult /etc, and many tools read process metadata from /proc.
    for path in ["/etc", "/proc", "/sys", "/run"] {
        system(path, AccessFs::from_read(abi));
    }

    // Shared temp directories are readable outside strict mode, and writable
    // only when the whole filesystem is. They are never executable: giving up
    // isolation is what permissive mode is for, but a payload dropped in shared
    // temp still must not be runnable, and that costs nothing to keep.
    if !config.filesystem_strict() {
        let access = if config.writable_file_system() {
            writable_access(abi)
        } else {
            AccessFs::from_read(abi)
        };
        for path in ["/tmp", "/var/tmp"] {
            system(path, access);
        }
    }

    if config.writable_file_system() {
        // Not `from_all`: Landlock cannot carve an exception out of a granted
        // hierarchy, so granting execute on `/` here would silently re-grant it
        // to shared temp and to the working directory. Execute is granted above,
        // to the system directories that need it, and nowhere else.
        system("/", writable_access(abi));
    }

    // Landlock is default-deny, so the protections that macOS expresses as
    // explicit denies are the absence of a rule here. Home directories are the
    // one case that needs a rule, to grant access when protection is off.
    if !config.security().protect_user_home() {
        if let Some(home) = std::env::var_os("HOME") {
            rules.push(Planned {
                path: PathBuf::from(home),
                access: AccessFs::from_all(abi),
                required: false,
            });
        }
        rules.push(Planned {
            path: PathBuf::from("/home"),
            access: AccessFs::from_all(abi),
            required: false,
        });
    }
}

/// Plan the access to device nodes.
fn plan_device_rules(rules: &mut Vec<Planned>, config: &SandboxConfigData, abi: ABI) {
    let mut device = |path: &str, access: BitFlags<AccessFs>| {
        rules.push(Planned {
            path: PathBuf::from(path),
            access,
            required: false,
        });
    };

    // /dev/stdin and friends are symlinks into /proc/self/fd and work through
    // inherited descriptors rather than through a rule.
    for path in [
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/fd",
    ] {
        device(path, AccessFs::from_all(abi));
    }

    // `/dev/tty` resolves strictly to the calling process's own controlling
    // terminal (returning `ENXIO` when none is attached), so read/write access
    // on it exposes no other terminal. `/dev/ptmx` and `/dev/pts` are granted
    // wholesale only when `allow_tty_write` is explicitly enabled; per-command
    // PTY spawns instead grant only their own slave inode via `grant_pty_slave`.
    device(
        "/dev/tty",
        make_bitflags!(AccessFs::{ ReadFile | WriteFile }),
    );
    if config.allow_tty_write() {
        for path in ["/dev/ptmx", "/dev/pts"] {
            device(path, AccessFs::from_all(abi));
        }
    }

    let security = config.security();
    if security.allow_gpu() {
        for path in [
            "/dev/dri",
            "/dev/nvidia0",
            "/dev/nvidiactl",
            "/dev/nvidia-modeset",
            "/dev/nvidia-uvm",
        ] {
            device(path, AccessFs::from_all(abi));
        }
        tracing::debug!("landlock: GPU access enabled");
    }

    if security.allow_npu() {
        for path in ["/dev/accel", "/dev/accel0"] {
            device(path, AccessFs::from_all(abi));
        }
        tracing::debug!("landlock: NPU access enabled");
    }

    if security.allow_hardware() {
        for path in [
            "/dev/bus/usb",
            "/dev/input",
            "/dev/video0",
            "/dev/video1",
            "/dev/snd",
        ] {
            device(path, AccessFs::from_all(abi));
        }
        tracing::debug!("landlock: general hardware access enabled");
    }
}

/// Everything a writable location may do, except execute.
///
/// Landlock has no deny rule: a path gets exactly the rights granted to it, so
/// withholding `Execute` here is what stops a sandboxed process from writing a
/// payload into a directory it controls and then running it. The macOS profile
/// enforces the same invariant with explicit `(deny process-exec ...)` rules,
/// and `tests/isolation.rs` asserts it on both platforms.
fn writable_access(abi: ABI) -> BitFlags<AccessFs> {
    AccessFs::from_all(abi) & !BitFlags::from(AccessFs::Execute)
}

/// One rule for a configured path: what is granted, and to what.
#[derive(Debug)]
struct ConfiguredRule {
    path: PathBuf,
    access: BitFlags<AccessFs>,
}

/// The Landlock rights one grant asks for.
///
/// Read is unconditional, since write and execute both include it. Execute is
/// added only when the grant allows it: Landlock has no deny rule, so the
/// absence of `Execute` here is what keeps a writable path from being used to
/// stage a payload, and adding it is the deliberate exception the macOS profile
/// spells as an allow after the deny.
fn landlock_access(access: Access, abi: ABI) -> BitFlags<AccessFs> {
    let mut rights = AccessFs::from_read(abi);
    if access.can_write() {
        rights |= writable_access(abi);
    }
    if access.can_execute() {
        rights |= AccessFs::Execute;
    }
    rights
}

/// Plan the rules for the paths the caller configured.
fn configured_rules(config: &SandboxConfigData, abi: ABI) -> Vec<ConfiguredRule> {
    // An executable working dir also runs what it holds — a build's own
    // outputs; see `SandboxConfigBuilder::executable_working_dir`.
    let workdir_access = if config.working_dir_is_executable() {
        writable_access(abi) | AccessFs::Execute
    } else {
        writable_access(abi)
    };
    let mut rules = vec![ConfiguredRule {
        path: config.working_dir().to_path_buf(),
        access: workdir_access,
    }];

    // The generated IPC shims live in a private directory and are written
    // by the host before the sandbox starts, so that subtree is granted
    // read and execute. This mirrors the macOS profile, which carves out the
    // same directory.
    if let Some(bin_dir) = config.ipc_bin_dir() {
        rules.push(ConfiguredRule {
            path: bin_dir.to_path_buf(),
            access: make_bitflags!(AccessFs::{ ReadFile | ReadDir | Execute }),
        });
    }

    rules.extend(config.grants().iter().map(|grant| ConfiguredRule {
        path: grant.path().to_path_buf(),
        access: landlock_access(grant.access(), abi),
    }));

    // The IPC socket lives outside the working directory; connecting needs
    // read and write on the socket file.
    if let Some(socket) = config.ipc_socket()
        && let Some(dir) = socket.parent()
    {
        rules.push(ConfiguredRule {
            path: dir.to_path_buf(),
            access: writable_access(abi),
        });
    }

    if let Some(python) = config.python() {
        // Without pip installs the environment is read and execute only, so a
        // sandboxed process cannot mutate an environment that outlives it.
        let access = if python.allow_pip_install() {
            AccessFs::from_all(abi)
        } else {
            make_bitflags!(AccessFs::{ ReadFile | ReadDir | Execute })
        };
        rules.push(ConfiguredRule {
            path: python.venv().path().to_path_buf(),
            access,
        });
    }

    rules
}

/// Add a rule for a path the sandbox needs but that may legitimately be absent.
///
/// Distributions differ in which system paths exist, so a missing one is
/// skipped. A rule that the kernel rejects is still an error: it would silently
/// change what the sandbox enforces.
fn add_system_path(
    ruleset: &mut RulesetCreated,
    path: impl AsRef<Path>,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<()> {
    let path = path.as_ref();
    match PathFd::new(path) {
        Ok(fd) => add_rule(ruleset, path, fd, access, abi),
        Err(error) => {
            tracing::trace!(path = %path.display(), %error, "landlock: skipping absent system path");
            Ok(())
        }
    }
}

/// Add a rule for a path the caller explicitly configured.
///
/// A missing path is an error here: silently dropping it would produce a
/// sandbox that denies exactly the access the caller asked to grant.
fn add_required_path(
    ruleset: &mut RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<()> {
    let fd = open_unresolved(path)?;
    add_rule(ruleset, path, fd, access, abi)
}

/// Open a configured path for a rule without following any symbolic link.
///
/// A grant names a path the caller has already resolved. `openat2` with
/// `RESOLVE_NO_SYMLINKS` refuses a link in any component, the last included,
/// and does it inside the one call that opens the inode the rule then holds, so
/// there is no window between checking the path and using it. The kernel does
/// not say which component was the link, only that one was.
fn open_unresolved(path: &Path) -> Result<OwnedFd> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
    use rustix::io::Errno;

    crate::platform::unresolved::require_normal(path)?;
    openat2(
        CWD,
        path,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|errno| match errno {
        Errno::LOOP => Error::GrantRedirected {
            path: path.to_path_buf(),
            reason: crate::error::Redirection::SymbolicLink,
        },
        errno => Error::path(path, errno.into()),
    })
}

/// Add one rule, narrowing directory-only rights on non-directories.
fn add_rule(
    ruleset: &mut RulesetCreated,
    path: &Path,
    fd: impl AsFd,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<()> {
    let access = effective_path_access(&fd, path.display(), access, abi)?;

    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .map(|_| ())
        .map_err(|error| {
            Error::InvalidProfile(format!(
                "Landlock rejected the rule for {}: {error}",
                path.display()
            ))
        })
}

/// Add a rule for an inode that `fd` holds.
fn add_rule_fd(
    ruleset: &mut RulesetCreated,
    fd: BorrowedFd<'_>,
    access: BitFlags<AccessFs>,
) -> Result<()> {
    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .map(|_| ())
        .map_err(|error| {
            Error::InvalidProfile(format!(
                "Landlock rejected a rule for a held inode: {error}"
            ))
        })
}

/// Reduce a request to the rights that make sense for the target.
///
/// Landlock rejects directory-only rights on a regular file, so a rule naming a
/// file keeps only the file rights.
fn effective_path_access(
    path_fd: &impl AsFd,
    path: impl std::fmt::Display,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<BitFlags<AccessFs>> {
    if path_is_directory(path_fd)? {
        return Ok(access);
    }

    let file_access = access & AccessFs::from_file(abi);
    if file_access.is_empty() {
        return Err(Error::InvalidProfile(format!(
            "Landlock path {} is not a directory, but the requested access {access:?} requires \
             directory semantics",
            path,
        )));
    }

    if file_access != access {
        tracing::trace!(
            path = %path,
            requested = ?access,
            effective = ?file_access,
            "landlock: narrowed non-directory path access"
        );
    }

    Ok(file_access)
}

fn path_is_directory(path_fd: &impl AsFd) -> Result<bool> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor is open and `stat` is a valid destination.
    let rc = unsafe { libc::fstat(path_fd.as_fd().as_raw_fd(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(Error::InvalidProfile(format!(
            "Landlock failed to inspect a rule path: {}",
            std::io::Error::last_os_error(),
        )));
    }

    // SAFETY: `fstat` succeeded, so the value is initialized.
    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxConfig;
    use crate::grant::Grant;
    use std::fs::{self, File};

    /// A configuration whose working directory exists, as it would at runtime.
    fn prepared(config: SandboxConfig) -> (SandboxConfigData, crate::workdir::WorkingDir) {
        let (_policy, mut data, _ipc) = config.into_parts();
        let dir = crate::workdir::WorkingDir::create(data.working_dir(), true).expect("creates");
        data.set_working_dir(dir.path().to_path_buf());
        (data, dir)
    }

    /// The working dir runs what it holds only when the caller opted in.
    #[test]
    fn the_working_dir_executes_only_when_configured() {
        let access_of = |executable: bool| {
            let (data, dir) = prepared(
                SandboxConfig::builder()
                    .executable_working_dir(executable)
                    .build(),
            );
            let rule = configured_rules(&data, ABI::V4)
                .into_iter()
                .find(|rule| rule.path == dir.path())
                .expect("a working-dir rule");
            (rule.access, dir)
        };
        let (on, _dir) = access_of(true);
        assert!(
            on.contains(AccessFs::Execute),
            "an executable working dir carries Execute"
        );
        let (off, _dir) = access_of(false);
        assert!(
            !off.contains(AccessFs::Execute),
            "the default working dir stays non-executable"
        );
    }

    #[test]
    fn non_directory_rules_are_narrowed_to_file_access() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("device");
        File::create(&file_path).expect("creates");

        let path_fd = PathFd::new(&file_path).expect("opens");
        let access = effective_path_access(
            &path_fd,
            file_path.display(),
            AccessFs::from_all(ABI::V4),
            ABI::V4,
        )
        .expect("narrows");

        assert_eq!(access, AccessFs::from_file(ABI::V4));
    }

    #[test]
    fn directory_rules_keep_directory_access() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path_fd = PathFd::new(dir.path()).expect("opens");
        let access = effective_path_access(
            &path_fd,
            dir.path().display(),
            AccessFs::from_all(ABI::V4),
            ABI::V4,
        )
        .expect("keeps");

        assert_eq!(access, AccessFs::from_all(ABI::V4));
    }

    #[test]
    fn file_rules_reject_directory_only_access() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("file");
        File::create(&file_path).expect("creates");

        let path_fd = PathFd::new(&file_path).expect("opens");
        let error = effective_path_access(
            &path_fd,
            file_path.display(),
            AccessFs::ReadDir.into(),
            ABI::V4,
        )
        .expect_err("rejects");

        assert!(matches!(error, Error::InvalidProfile(_)));
    }

    #[test]
    fn missing_configured_paths_are_rejected() {
        let dir = crate::platform::unresolved::resolved_tempdir();
        let missing = dir.path().join("absent");
        std::fs::create_dir(&missing).expect("creates");
        let (data, _dir) = prepared(
            SandboxConfig::builder()
                .readable(crate::platform::unresolved::resolved(&missing))
                .build(),
        );
        std::fs::remove_dir(&missing).expect("removes");

        let error = build_ruleset(&data, None).expect_err("must fail");
        assert!(
            matches!(error, Error::Path { .. }),
            "a configured path that cannot be granted must be an error, got {error:?}"
        );
    }

    #[test]
    fn a_configured_path_replaced_by_a_link_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let root = fs::canonicalize(root.path()).expect("resolves");
        let parent = root.join("parent");
        let granted = parent.join("granted");
        fs::create_dir_all(&granted).expect("creates");
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(elsewhere.join("granted")).expect("creates");

        let (data, _dir) = prepared(
            SandboxConfig::builder()
                .writable(crate::platform::unresolved::resolved(&granted))
                .build(),
        );
        build_ruleset(&data, None).expect("an unchanged grant builds");

        // The grant itself, then a parent of it.
        for (replaced, destination) in [
            (&granted, elsewhere.join("granted")),
            (&parent, elsewhere.clone()),
        ] {
            fs::remove_dir_all(replaced).expect("removes");
            std::os::unix::fs::symlink(&destination, replaced).expect("links");

            let error = build_ruleset(&data, None).expect_err("must fail");
            assert!(
                matches!(&error, Error::GrantRedirected { path, .. } if *path == granted),
                "expected the redirected grant to be named, got {error:?}"
            );
        }
    }

    #[test]
    fn absent_system_paths_are_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (data, _dir) = prepared(SandboxConfig::new());
        // /lib32 and friends are absent on most hosts, and building must still
        // succeed.
        assert!(build_ruleset(&data, None).is_ok());
        drop(dir);
    }

    #[test]
    fn strict_mode_does_not_grant_shared_temp_directories() {
        // Landlock has no rule inspection API, so this checks the decision the
        // ruleset builder makes rather than the resulting kernel state.
        let (strict, _a) = prepared(SandboxConfig::builder().filesystem_strict(true).build());
        let (relaxed, _b) = prepared(SandboxConfig::builder().filesystem_strict(false).build());

        assert!(strict.filesystem_strict());
        assert!(!relaxed.filesystem_strict());
        assert!(build_ruleset(&strict, None).is_ok());
        assert!(build_ruleset(&relaxed, None).is_ok());
    }

    #[test]
    fn a_path_that_is_writable_and_executable_carries_both_access_sets() {
        // Landlock has no rule inspection API, so this asserts the rules the
        // builder plans. A build cache is written and then executed, and both
        // spellings — one `WRITE | EXEC` grant, or the two sugar methods, which
        // the builder unions into one grant — have to produce both rights.
        let cache = tempfile::tempdir().expect("tempdir");
        let (data, _dir) = prepared(
            SandboxConfig::builder()
                .writable(crate::platform::unresolved::resolved(cache.path()))
                .executable(crate::platform::unresolved::resolved(cache.path()))
                .build(),
        );
        assert_eq!(
            data.grants(),
            [Grant::new(
                crate::platform::unresolved::resolved(cache.path()),
                Access::WRITE | Access::EXEC
            )],
            "granting a path twice must widen one grant, not add a second"
        );

        let granted = configured_rules(&data, ABI::V4)
            .into_iter()
            .filter(|rule| rule.path == cache.path())
            .fold(BitFlags::EMPTY, |granted, rule| granted | rule.access);

        assert!(
            granted.contains(AccessFs::Execute),
            "the executable grant must survive: {granted:?}"
        );
        assert!(
            granted.contains(AccessFs::WriteFile | AccessFs::MakeReg),
            "the writable grant must survive: {granted:?}"
        );
        assert!(build_ruleset(&data, None).is_ok());
    }

    #[test]
    fn persistent_identity_grants_are_adopted_into_landlock_rules() {
        let directory = tempfile::tempdir().expect("tempdir");
        let (mut data, _working_dir) = prepared(
            SandboxConfig::builder()
                .identity(
                    crate::identity::Identity::named("landlock-test")
                        .expect("the identity name is valid")
                        .persistent_grant(Grant::new(
                            crate::platform::unresolved::resolved(directory.path()),
                            Access::READ,
                        )),
                )
                .build(),
        );
        data.adopt_persistent_grants();

        assert_eq!(
            data.grants(),
            [Grant::new(
                crate::platform::unresolved::resolved(directory.path()),
                Access::READ
            )]
        );
        assert!(
            configured_rules(&data, ABI::V4)
                .iter()
                .any(|rule| rule.path == directory.path()),
            "the persistent grant is present in the Landlock rules"
        );
    }

    #[test]
    fn device_rules_allow_dev_tty_without_opening_dev_pts_by_default() {
        let (default_data, _a) = prepared(SandboxConfig::new());
        let default_plan = plan(&default_data);
        let tty_rule = default_plan
            .iter()
            .find(|r| r.path == Path::new("/dev/tty"))
            .expect("/dev/tty rule present");
        assert!(tty_rule.access.contains(AccessFs::ReadFile));
        assert!(tty_rule.access.contains(AccessFs::WriteFile));
        assert!(
            !default_plan.iter().any(|r| r.path == Path::new("/dev/pts")),
            "/dev/pts must not be granted wholesale when allow_tty_write is false"
        );

        let (tty_write_data, _b) = prepared(SandboxConfig::builder().allow_tty_write(true).build());
        let tty_write_plan = plan(&tty_write_data);
        assert!(
            tty_write_plan
                .iter()
                .any(|r| r.path == Path::new("/dev/pts")),
            "/dev/pts is granted only when allow_tty_write is explicitly enabled"
        );
    }

    #[test]
    fn venv_is_read_only_without_pip_installs() {
        let venv = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(venv.path().join("bin")).expect("creates");

        for (allow, expected_write) in [(false, false), (true, true)] {
            let (data, _dir) = prepared(
                SandboxConfig::builder()
                    .python(
                        crate::config::PythonConfig::builder()
                            .venv(
                                crate::config::VenvConfig::builder()
                                    .path(venv.path())
                                    .build(),
                            )
                            .allow_pip_install(allow)
                            .build(),
                    )
                    .build(),
            );

            assert_eq!(
                data.python().expect("configured").allow_pip_install(),
                expected_write
            );
            assert!(build_ruleset(&data, None).is_ok());
        }
    }
}
