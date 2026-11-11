//! The pool of inodes that serves new entries in the directories above a denied
//! path.
//!
//! Landlock binds a rule to an inode and the rule follows the inode through a
//! rename. Before the sandbox is restricted, empty files and directories are
//! created that each carry the rule an entry of that directory would need, and a
//! creation directly inside such a directory is served by renaming one of them
//! into place. After that the new entry reads, executes and takes nested
//! creations like its siblings, without a rule having to be added to a ruleset
//! that is already in force.
//!
//! The pool lives on the same filesystem as the directories it serves, because a
//! rename cannot cross one. Nothing the sandbox does may reach it: the guard
//! refuses every operation inside a pool directory.
//!
//! The pool is made in two halves, on two threads of different descriptor tables
//! (see [`super::table`]). [`Pool::prepare`] runs on the setup thread, which
//! lists and opens user directories: it clears stale pools, creates this pool's
//! directories and its entries, and returns a [`PoolPlan`], which holds only
//! names and paths and owns the removal of what was created until the pool takes
//! over, and one descriptor per directory, which cross to the thread that serves
//! the pool. The sandbox's Landlock rules for the entries are added from the plan
//! by the thread that builds the ruleset. [`Pool::from_parts`] runs on the
//! serving thread and gives the pool its descriptors.

use std::collections::BTreeMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use landlock::{AccessFs, BitFlags};
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use super::diag::Diagnostic;
use crate::config::InodePool;
use crate::error::{Error, Result};
use crate::platform::linux::landlock_rules::Ancestor;

/// What a pooled inode becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Directory,
}

/// Hands the sandbox's Landlock ruleset a rule for one pooled inode.
///
/// A rule binds to the inode, and the ruleset keeps its own reference to it, so
/// the pool holds no descriptor of an entry once the rule is in.
pub(crate) type Grant<'a> = dyn FnMut(BorrowedFd<'_>, BitFlags<AccessFs>) -> Result<()> + 'a;

#[derive(Debug)]
struct Group {
    directory: PathBuf,
    held: OwnedFd,
    members: Vec<PathBuf>,
    files: Mutex<Vec<String>>,
    directories: Mutex<Vec<String>>,
}

/// What the setup thread made for one filesystem.
#[derive(Debug)]
struct GroupPlan {
    directory: PathBuf,
    /// The rights every entry's rule carries.
    rights: BitFlags<AccessFs>,
    members: Vec<PathBuf>,
    files: Vec<String>,
    directories: Vec<String>,
}

/// A pool as the setup thread left it: paths and names, no descriptor.
///
/// Dropping it removes the directories it made, so a start that fails after the
/// pool was made leaves nothing behind. [`Pool::from_parts`] takes them over.
#[derive(Debug)]
pub(crate) struct PoolPlan {
    groups: Vec<GroupPlan>,
    capacity: InodePool,
}

impl PoolPlan {
    /// Whether no filesystem had a place for the pool.
    pub(crate) fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// The directories the pool lives in.
    pub(crate) fn directories(&self) -> Vec<PathBuf> {
        self.groups
            .iter()
            .map(|group| group.directory.clone())
            .collect()
    }

    /// Add the Landlock rule of every entry through `grant`.
    ///
    /// `held` are the descriptors [`Pool::prepare`] returned, in its order, as
    /// they arrived in the calling thread's table. Each entry is opened relative
    /// to its directory's descriptor, as a path descriptor that closes without
    /// touching any lock.
    pub(crate) fn grant(&self, held: &[OwnedFd], grant: &mut Grant<'_>) -> Result<()> {
        if held.len() != self.groups.len() {
            return Err(Error::InitFailed(format!(
                "the inode pool has {} directories and {} descriptors arrived for them",
                self.groups.len(),
                held.len()
            )));
        }
        for (group, held) in self.groups.iter().zip(held) {
            for name in group.files.iter().chain(&group.directories) {
                grant(
                    open_entry(held, name, &group.directory)?.as_fd(),
                    group.rights,
                )?;
            }
        }
        Ok(())
    }
}

impl Drop for PoolPlan {
    fn drop(&mut self) {
        for group in &self.groups {
            let _ = std::fs::remove_dir_all(&group.directory);
        }
    }
}

/// An inode taken from the pool, to be renamed into place.
#[derive(Debug)]
pub(crate) struct Pooled {
    group: usize,
    kind: Kind,
    name: String,
}

/// The pre-created inodes of one sandbox.
#[derive(Debug)]
pub(crate) struct Pool {
    groups: Vec<Group>,
    capacity: InodePool,
}

fn process_is_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks that the process exists.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Remove the pools that processes which have since exited left behind, in the
/// directory `root` holds.
///
/// Everything is relative to the descriptor, so a link planted under the
/// directory is unlinked rather than followed and nothing outside it is touched.
fn remove_stale(root: BorrowedFd<'_>, prefix: &str) {
    let Ok(listing) = rustix::fs::openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return;
    };
    let Ok(entries) = rustix::fs::Dir::new(listing) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(prefix) else {
            continue;
        };
        let pid = rest.split('-').next().and_then(|pid| pid.parse().ok());
        if pid.is_some_and(|pid| !process_is_alive(pid)) {
            let _ = remove_tree(root, name);
        }
    }
}

/// Remove `name` under `parent` and everything beneath it, unlinking any link
/// found instead of following it.
fn remove_tree(parent: BorrowedFd<'_>, name: &str) -> rustix::io::Result<()> {
    match rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty()) {
        Err(Errno::ISDIR | Errno::PERM) => {}
        result => return result,
    }
    let directory = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let children: Vec<String> = rustix::fs::Dir::read_from(&directory)?
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().ok().map(str::to_owned))
        .filter(|child| child != "." && child != "..")
        .collect();
    for child in children {
        remove_tree(directory.as_fd(), &child)?;
    }
    rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR)
}

/// The cache directory the pool prefers, opened once.
struct Cache {
    path: PathBuf,
    root: OwnedFd,
}

fn cache_directory() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::home_dir().map(|home| home.join(".cache")))
        .map(|path| path.join("heel"))
}

impl Pool {
    /// Make the pool for `ancestors`: the first half, run on the setup thread.
    ///
    /// Returns the plan and one descriptor per group, in the plan's order. The
    /// descriptors belong to the calling thread's table and go to the thread
    /// that serves the pool over a socket; they are never returned from the
    /// thread. What the setup has to say is added to `log`.
    pub(crate) fn prepare(
        capacity: InodePool,
        ancestors: &[Ancestor],
        log: &mut Vec<Diagnostic>,
    ) -> Result<(PoolPlan, Vec<OwnedFd>)> {
        let cache = cache_directory().and_then(|path| match open_or_create_directory(&path) {
            Ok(root) => {
                remove_stale(root.as_fd(), "pool-");
                Some(Cache { path, root })
            }
            Err(errno) => {
                log.push(
                    Diagnostic::warn(
                        "broker: the cache directory cannot hold the inode pool (a link stands \
                         in its path, or it cannot be made); using the filesystems of the \
                         protected paths instead",
                    )
                    .field("cache", path.display())
                    .field("errno", errno),
                );
                None
            }
        });
        let mut keyed: BTreeMap<(u64, u64), Vec<&Ancestor>> = BTreeMap::new();
        for ancestor in ancestors {
            let device = std::fs::metadata(&ancestor.path)
                .map_err(|error| Error::path(&ancestor.path, error))?
                .dev();
            keyed
                .entry((device, ancestor.rights.bits()))
                .or_default()
                .push(ancestor);
        }

        let mut plan = PoolPlan {
            groups: Vec::new(),
            capacity,
        };
        let mut held = Vec::new();
        for ((device, _), members) in keyed {
            let rights = members
                .iter()
                .fold(BitFlags::<AccessFs>::empty(), |all, ancestor| {
                    all | ancestor.rights
                });
            let Some(location) = locate(cache.as_ref(), device, &members, log) else {
                log.push(
                    Diagnostic::debug(
                        "broker: no place for an inode pool on this filesystem; new entries in \
                         its protected directories will fail",
                    )
                    .field("device", device),
                );
                continue;
            };
            // In the plan before it is filled, so that an error while filling
            // removes what was made.
            let index = plan.groups.len();
            plan.groups.push(GroupPlan {
                directory: location.path,
                rights,
                members: members
                    .iter()
                    .map(|ancestor| ancestor.path.clone())
                    .collect(),
                files: Vec::new(),
                directories: Vec::new(),
            });
            populate(&mut plan.groups[index], &location.held, capacity)?;
            held.push(location.held);
        }
        Ok((plan, held))
    }

    /// Take over the pool a plan describes: the second half, run on the thread
    /// that serves it, with `held` the descriptors [`Pool::prepare`] returned as
    /// they arrived in its table.
    pub(crate) fn from_parts(mut plan: PoolPlan, held: Vec<OwnedFd>) -> Result<Self> {
        if held.len() != plan.groups.len() {
            return Err(Error::InitFailed(format!(
                "the inode pool has {} directories and {} descriptors arrived for them",
                plan.groups.len(),
                held.len()
            )));
        }
        // Emptied, so the plan's drop removes nothing: the pool's does.
        let groups = std::mem::take(&mut plan.groups)
            .into_iter()
            .zip(held)
            .map(|(group, held)| Group {
                directory: group.directory,
                held,
                members: group.members,
                files: Mutex::new(group.files),
                directories: Mutex::new(group.directories),
            })
            .collect();
        Ok(Self {
            groups,
            capacity: plan.capacity,
        })
    }

    /// Take an inode of `kind` for a new entry in `directory`.
    ///
    /// `Err(true)` means the pool serves the directory and is out of that kind of
    /// inode; `Err(false)` that no pool serves it.
    pub(crate) fn acquire(
        &self,
        directory: &Path,
        kind: Kind,
    ) -> std::result::Result<Pooled, bool> {
        let Some(index) = self
            .groups
            .iter()
            .position(|group| group.members.iter().any(|member| member == directory))
        else {
            return Err(false);
        };
        let group = &self.groups[index];
        let list = match kind {
            Kind::File => &group.files,
            Kind::Directory => &group.directories,
        };
        let name = list
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .ok_or(true)?;
        Ok(Pooled {
            group: index,
            kind,
            name,
        })
    }

    /// Give back an inode that was not used.
    pub(crate) fn restore(&self, pooled: Pooled) {
        let group = &self.groups[pooled.group];
        let list = match pooled.kind {
            Kind::File => &group.files,
            Kind::Directory => &group.directories,
        };
        list.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(pooled.name);
    }

    /// The directory a pooled inode is in, and its name there.
    pub(crate) fn place<'a>(&'a self, pooled: &'a Pooled) -> (&'a OwnedFd, &'a str) {
        (&self.groups[pooled.group].held, &pooled.name)
    }

    /// The setting the pool's size comes from, for the message of a failure.
    pub(crate) fn describe(&self, kind: Kind) -> String {
        let (count, what) = match kind {
            Kind::File => (self.capacity.files(), "files"),
            Kind::Directory => (self.capacity.directories(), "directories"),
        };
        format!(
            "the inode pool of {count} {what} is used up; raise it with \
             SandboxConfigBuilder::inode_pool"
        )
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        for group in &self.groups {
            let _ = std::fs::remove_dir_all(&group.directory);
        }
    }
}

/// A pool directory, created and held without following any link.
struct Location {
    path: PathBuf,
    held: OwnedFd,
}

/// Open a directory as a path descriptor, refusing a link in any component.
///
/// The directories a pool lives in can be inside a tree the sandbox may write,
/// so a component swapped for a link between two steps must not move the pool.
/// Everything the pool does afterwards is relative to descriptors opened here.
fn open_directory(path: &Path) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat2(
        CWD,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
}

/// Open a directory like [`open_directory`], making the missing components of
/// it relative to the descriptor of the one above, so nothing is created
/// behind a link.
fn open_or_create_directory(path: &Path) -> rustix::io::Result<OwnedFd> {
    match open_directory(path) {
        Err(Errno::NOENT) => {}
        result => return result,
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Errno::NOENT);
    };
    let parent = open_or_create_directory(parent)?;
    match rustix::fs::mkdirat(&parent, name, Mode::RWXU) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(errno) => return Err(errno),
    }
    rustix::fs::openat(
        &parent,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Where the pool for filesystem `device` lives: the cache directory if that is
/// on it, otherwise a hidden directory in the shallowest member that can be
/// written to.
fn locate(
    cache: Option<&Cache>,
    device: u64,
    members: &[&Ancestor],
    log: &mut Vec<Diagnostic>,
) -> Option<Location> {
    if let Some(cache) = cache
        && rustix::fs::fstat(&cache.root).is_ok_and(|stat| stat.st_dev == device)
        && let Some(pool) = create_unique(cache.root.as_fd(), &cache.path, "pool-")
    {
        return Some(pool);
    }
    let mut shallowest: Vec<&Ancestor> = members.to_vec();
    shallowest.sort_by_key(|ancestor| ancestor.path.components().count());
    for ancestor in shallowest {
        match open_directory(&ancestor.path) {
            Ok(root) => {
                remove_stale(root.as_fd(), ".heel-pool-");
                if let Some(pool) = create_unique(root.as_fd(), &ancestor.path, ".heel-pool-") {
                    return Some(pool);
                }
            }
            Err(errno) => log.push(
                Diagnostic::debug(
                    "broker: cannot open a protected path's directory for the inode pool",
                )
                .field("path", ancestor.path.display())
                .field("errno", errno),
            ),
        }
    }
    None
}

/// Create `<prefix><pid>-<n>` in the directory `root` holds, for the first `n`
/// nobody holds. `path` is where `root` was opened, for naming the result.
///
/// Creation is exclusive, so every pool of every sandbox in every process is a
/// directory of its own, and one that exists is never taken over: its owner is
/// alive, or its pid was reused and `remove_stale` clears it once that process
/// is gone.
fn create_unique(root: BorrowedFd<'_>, path: &Path, prefix: &str) -> Option<Location> {
    let pid = std::process::id();
    for number in 0u32.. {
        let name = format!("{prefix}{pid}-{number}");
        match rustix::fs::mkdirat(root, &name, Mode::RWXU) {
            Ok(()) => {
                let held = rustix::fs::openat(
                    root,
                    &name,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .ok()?;
                return Some(Location {
                    path: path.join(name),
                    held,
                });
            }
            Err(Errno::EXIST) => {}
            Err(_) => return None,
        }
    }
    None
}

/// Create the entries of `group` in the directory `held` is the descriptor of,
/// and record their names in it.
fn populate(group: &mut GroupPlan, held: &OwnedFd, capacity: InodePool) -> Result<()> {
    let entry_error =
        |name: &str, errno: Errno| Error::path(group.directory.join(name), errno.into());

    let mut files = Vec::with_capacity(capacity.files());
    for number in 0..capacity.files() {
        let name = format!("f{number}");
        // Created and closed: the inode is heel's own, the exclusive creation
        // is the point, and the sandbox's rule for it is added from the plan.
        rustix::fs::openat(
            held,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|errno| entry_error(&name, errno))?;
        files.push(name);
    }
    let mut directories = Vec::with_capacity(capacity.directories());
    for number in 0..capacity.directories() {
        let name = format!("d{number}");
        rustix::fs::mkdirat(held, &name, Mode::RWXU).map_err(|errno| entry_error(&name, errno))?;
        directories.push(name);
    }
    group.files = files;
    group.directories = directories;
    Ok(())
}

/// Open `name` in the pool directory `held` as a path descriptor that follows
/// no link. `directory` names the pool for the error.
fn open_entry(held: &OwnedFd, name: &str, directory: &Path) -> Result<OwnedFd> {
    rustix::fs::openat(
        held,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| Error::path(directory.join(name), errno.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::landlock_rules::{REQUIRED_ABI, read_rights};

    fn ancestor(path: &Path) -> Ancestor {
        Ancestor {
            path: path.to_path_buf(),
            rights: read_rights(REQUIRED_ABI),
        }
    }

    fn prepared(root: &Path) -> (PoolPlan, Vec<OwnedFd>) {
        let mut log = Vec::new();
        let made = Pool::prepare(InodePool::new(2, 3), &[ancestor(root)], &mut log).unwrap();
        assert!(!made.0.is_empty(), "no place was found for the pool");
        made
    }

    /// The setup thread's half names what it made, and removes it unless the
    /// pool took it over, so a start that fails afterwards leaves nothing.
    #[test]
    fn a_plan_that_is_dropped_removes_the_directories_it_made() {
        let root = tempfile::tempdir().unwrap();
        let (plan, held) = prepared(root.path());
        let directories = plan.directories();
        assert_eq!(directories.len(), held.len());
        assert!(directories.iter().all(|directory| directory.is_dir()));
        drop(plan);
        assert!(directories.iter().all(|directory| !directory.exists()));
    }

    #[test]
    fn every_entry_of_the_plan_gets_its_rule_from_the_received_descriptors() {
        let root = tempfile::tempdir().unwrap();
        let (plan, held) = prepared(root.path());
        let mut granted = Vec::new();
        plan.grant(&held, &mut |fd, access| {
            granted.push((rustix::fs::fstat(fd).unwrap().st_mode, access));
            Ok(())
        })
        .unwrap();
        // Two files and three directories, each with the group's rights.
        assert_eq!(granted.len(), 5);
        assert!(
            granted
                .iter()
                .all(|(_, access)| *access == read_rights(REQUIRED_ABI))
        );
        let files = granted
            .iter()
            .filter(|(mode, _)| mode & libc::S_IFMT == libc::S_IFREG)
            .count();
        assert_eq!(files, 2);
        assert!(plan.grant(&[], &mut |_, _| Ok(())).is_err());
    }

    #[test]
    fn a_pool_that_took_over_the_plan_removes_the_directories_when_it_drops() {
        let root = tempfile::tempdir().unwrap();
        let (plan, held) = prepared(root.path());
        let directories = plan.directories();
        let pool = Pool::from_parts(plan, held).unwrap();
        assert!(directories.iter().all(|directory| directory.is_dir()));
        let served = pool.acquire(root.path(), Kind::File).unwrap();
        assert!(pool.place(&served).1.starts_with('f'));
        drop(pool);
        assert!(directories.iter().all(|directory| !directory.exists()));
    }

    #[test]
    fn descriptors_that_do_not_match_the_plan_are_refused_and_nothing_is_left() {
        let root = tempfile::tempdir().unwrap();
        let (plan, held) = prepared(root.path());
        let directories = plan.directories();
        drop(held);
        assert!(Pool::from_parts(plan, Vec::new()).is_err());
        assert!(directories.iter().all(|directory| !directory.exists()));
    }
}
