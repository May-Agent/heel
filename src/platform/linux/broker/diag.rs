//! What the broker's threads have to say.
//!
//! The threads that open files for the sandbox keep descriptor tables of their
//! own ([`super::table`]). A `tracing` subscriber is code of the embedder's: one
//! that writes to a `File` or a socket does it by descriptor number, and on such a
//! thread that number can name a file opened for the sandbox. So those threads
//! never call `tracing`; they build a [`Diagnostic`] and hand it to an [`Outbox`].
//!
//! The outbox is a bounded queue with a thread of its own, started from a thread
//! of the embedder's table, that does nothing but [emit](Diagnostic::emit) what
//! arrives. A sandboxed process can make the broker refuse as many calls as it
//! likes, and the embedder's subscriber can be slow or stuck, so a full queue
//! never holds a broker thread up: the diagnostic is dropped and counted, and the
//! emitting thread says how many were lost when it next gets the chance.

use std::borrow::Cow;
use std::fmt::{self, Display};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

/// How many diagnostics wait for the emitting thread.
///
/// One is a message of a few dozen bytes and a handful of short fields, a few
/// hundred bytes with the queue's own overhead, so a full queue is a fraction of
/// a mebibyte: more than the burst a sandbox's ordinary activity makes, and a
/// ceiling on what a sandbox that loops over refused calls can make the
/// embedder hold while its subscriber is stuck.
const CAPACITY: usize = 1024;

/// How serious a diagnostic is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    Error,
    Warn,
    Debug,
}

/// One thing a broker thread has to say, ready to be emitted elsewhere.
#[derive(Debug)]
pub(crate) struct Diagnostic {
    level: Level,
    message: Cow<'static, str>,
    fields: Vec<(&'static str, String)>,
}

impl Diagnostic {
    pub(crate) fn new(level: Level, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            level,
            message: message.into(),
            fields: Vec::new(),
        }
    }

    pub(crate) fn error(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Level::Error, message)
    }

    pub(crate) fn warn(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Level::Warn, message)
    }

    pub(crate) fn debug(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Level::Debug, message)
    }

    /// Add a field.
    #[must_use]
    pub(crate) fn field(mut self, name: &'static str, value: impl Display) -> Self {
        self.fields.push((name, value.to_string()));
        self
    }

    /// Emit it with `tracing`. Only ever called on a thread of the embedder's
    /// own descriptor table.
    pub(crate) fn emit(self) {
        let details = Details(&self.fields);
        let message = &*self.message;
        match self.level {
            Level::Error => tracing::error!(target: "heel::broker", %details, "{message}"),
            Level::Warn => tracing::warn!(target: "heel::broker", %details, "{message}"),
            Level::Debug => tracing::debug!(target: "heel::broker", %details, "{message}"),
        }
    }
}

/// The fields of a diagnostic, as `name=value` pairs.
struct Details<'a>(&'a [(&'static str, String)]);

impl Display for Details<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, (name, value)) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{name}={value}")?;
        }
        Ok(())
    }
}

/// Where the broker's threads put what they have to say. Cheap to clone.
#[derive(Clone, Debug)]
pub(crate) struct Outbox {
    queue: SyncSender<Diagnostic>,
    dropped: Arc<AtomicUsize>,
}

impl Outbox {
    /// Queue `diagnostic`, or count it as lost when the queue is full. Never
    /// waits, so it is safe on any broker thread.
    pub(crate) fn say(&self, diagnostic: Diagnostic) {
        match self.queue.try_send(diagnostic) {
            Ok(()) => {}
            // The emitting thread is gone only if the subscriber panicked on it;
            // the count is then the only trace left of what was said.
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The receiving end of an [`Outbox`].
struct Inbox {
    queue: Receiver<Diagnostic>,
    dropped: Arc<AtomicUsize>,
}

impl Inbox {
    /// Emit what arrives, and after each one say how many were lost since the
    /// last time, until every [`Outbox`] is gone.
    ///
    /// Diagnostics are dropped only while the queue is full, so some are always
    /// left to arrive after a drop and the count is reported once the queue has
    /// emptied enough to be heard.
    fn run(self) {
        for diagnostic in self.queue {
            diagnostic.emit();
            let lost = self.dropped.swap(0, Ordering::Relaxed);
            if lost > 0 {
                Diagnostic::warn("broker: diagnostics were dropped, the queue was full")
                    .field("count", lost)
                    .emit();
            }
        }
    }
}

fn channel(capacity: usize) -> (Outbox, Inbox) {
    let (queue, arrivals) = sync_channel(capacity);
    let dropped = Arc::new(AtomicUsize::new(0));
    (
        Outbox {
            queue,
            dropped: Arc::clone(&dropped),
        },
        Inbox {
            queue: arrivals,
            dropped,
        },
    )
}

/// Start the thread that emits what the broker's threads say, and return where
/// to send it.
///
/// Must be called from a thread of the embedder's own descriptor table, which the
/// new thread then shares. It ends when every clone of the outbox is gone, which
/// is when the last thread serving the sandbox has ended, so it outlives the
/// [`Broker`](super::Broker) for as long as a descendant of the sandbox is served.
pub(crate) fn start() -> io::Result<Outbox> {
    let (outbox, inbox) = channel(CAPACITY);
    std::thread::Builder::new()
        .name("heel-broker-log".to_owned())
        .spawn(move || inbox.run())?;
    Ok(outbox)
}

#[cfg(test)]
mod tests {
    /// What a spelling can be found in: the sources of the modules that run on the
    /// threads with a table of their own, up to their test modules.
    const SCANNED: &[(&str, &str)] = &[
        ("diag.rs", include_str!("diag.rs")),
        ("filter.rs", include_str!("filter.rs")),
        ("home.rs", include_str!("home.rs")),
        ("mod.rs", include_str!("mod.rs")),
        ("ops.rs", include_str!("ops.rs")),
        ("resolve.rs", include_str!("resolve.rs")),
        ("net.rs", include_str!("net.rs")),
        ("sink.rs", include_str!("sink.rs")),
        ("pool.rs", include_str!("pool.rs")),
        ("check.rs", include_str!("check.rs")),
        ("notify.rs", include_str!("notify.rs")),
        ("table.rs", include_str!("table.rs")),
        // Resolves the denylists on the setup thread.
        (
            "policy/resolve.rs",
            include_str!("../../../policy/resolve.rs"),
        ),
    ];

    /// The ways code can reach a subscriber, a log or a standard stream, which
    /// are the embedder's and act on descriptor numbers, and the spellings of a
    /// path that names the embedder's descriptors.
    const BANNED: &[&str] = &[
        "tracing::",
        "tracing!",
        "use tracing",
        "extern crate tracing",
        "log::",
        "eprintln!",
        "eprint!",
        "println!",
        "print!",
        "dbg!",
        "/dev/fd",
        "/proc/self/fd",
    ];

    /// The lines that may hold a banned spelling: those that only run on a
    /// thread of the embedder's own table (the thread that emits diagnostics, and
    /// the embedder's calling thread in `Broker::new`), and the one path that is
    /// meant to name the leader's table, in the check that a new table is not it.
    const EMBEDDER_TABLE_SITES: &[(&str, &str)] = &[
        ("table.rs", "format!(\"/proc/self/fd/{}\", fd.as_raw_fd())"),
        (
            "diag.rs",
            "Level::Error => tracing::error!(target: \"heel::broker\", %details, \"{message}\"),",
        ),
        (
            "diag.rs",
            "Level::Warn => tracing::warn!(target: \"heel::broker\", %details, \"{message}\"),",
        ),
        (
            "diag.rs",
            "Level::Debug => tracing::debug!(target: \"heel::broker\", %details, \"{message}\"),",
        ),
        (
            "mod.rs",
            "tracing::info!(full = denylists, \"broker started\");",
        ),
    ];

    /// The part of `landlock_rules.rs` the setup thread runs: listing the
    /// directories above the denied paths.
    fn carving() -> &'static str {
        let source = include_str!("../landlock_rules.rs");
        let start = source
            .find("pub(crate) fn carve(")
            .expect("the carve function is where this test looks for it");
        let end = source[start..]
            .find("/// Plan the access to the system paths")
            .expect("the function after the carving is where this test looks for it")
            + start;
        &source[start..end]
    }

    /// The code of a source file above its own `#[cfg(test)]` module.
    fn code(source: &str) -> &str {
        source.split("#[cfg(test)]").next().unwrap_or(source)
    }

    /// Whether `line` holds `spelling` as a token of its own: not the tail of a
    /// longer name, which `print!` is of `eprint!`.
    fn spells(line: &str, spelling: &str) -> bool {
        line.match_indices(spelling).any(|(at, _)| {
            let starts_a_name = spelling.starts_with(|c: char| c.is_alphanumeric());
            let before = line[..at].chars().next_back();
            !(starts_a_name && before.is_some_and(|c| c.is_alphanumeric() || c == '_'))
        })
    }

    /// Every banned spelling in the scanned code, as `file:line: text`, and the
    /// listed sites that were not found.
    fn findings<'a>(
        sources: impl Iterator<Item = (&'a str, &'a str)>,
        sites: &[(&str, &str)],
    ) -> (Vec<String>, Vec<String>) {
        let mut offenders = Vec::new();
        let mut seen = vec![false; sites.len()];
        for (name, source) in sources {
            for (number, line) in code(source).lines().enumerate() {
                let line = line.trim_start();
                if line.starts_with("//") || !BANNED.iter().any(|b| spells(line, b)) {
                    continue;
                }
                match sites
                    .iter()
                    .position(|(file, text)| *file == name && *text == line)
                {
                    Some(index) => seen[index] = true,
                    None => offenders.push(format!("{name}:{}: {line}", number + 1)),
                }
            }
        }
        let missing = sites
            .iter()
            .zip(seen)
            .filter(|(_, seen)| !seen)
            .map(|((file, text), _)| format!("{file}: {text}"))
            .collect();
        (offenders, missing)
    }

    /// A tripwire for the spellings in [`BANNED`], line by line; it is not a proof
    /// over the call graph. A call that reaches a subscriber through another
    /// function, a macro of another crate or a trait object passes it, and the
    /// review of what runs on these threads is what covers that.
    #[test]
    fn no_thread_with_a_table_of_its_own_names_a_subscriber_a_stream_or_the_embedders_descriptors()
    {
        let sources = SCANNED
            .iter()
            .copied()
            .chain(std::iter::once(("landlock_rules.rs (carve)", carving())));
        let (offenders, missing) = findings(sources, EMBEDDER_TABLE_SITES);
        assert!(
            offenders.is_empty(),
            "these run on a thread with a descriptor table of its own, where the embedder's \
             subscriber and descriptor numbers must not be used; build a Diagnostic, and \
             name a descriptor of the thread by table::thread_fd_path:\n{}",
            offenders.join("\n")
        );
        assert!(
            missing.is_empty(),
            "these listed sites are gone or changed; update EMBEDDER_TABLE_SITES:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn the_tripwire_trips_on_each_spelling_and_not_on_look_alikes() {
        for spelling in BANNED {
            let source = format!("    {spelling}x();\n");
            let (offenders, _) = findings(std::iter::once(("probe.rs", source.as_str())), &[]);
            assert_eq!(offenders.len(), 1, "{spelling}");
        }
        for harmless in [
            "    let blog::x = 1;",
            "    // println!(\"in a comment\");",
            "    let fingerprint = 1;",
            "    ops.catalog(1);",
        ] {
            let source = format!("{harmless}\n");
            let (offenders, _) = findings(std::iter::once(("probe.rs", source.as_str())), &[]);
            assert!(offenders.is_empty(), "{harmless}: {offenders:?}");
        }
    }

    #[test]
    fn a_diagnostic_carries_its_fields_to_the_emitter() {
        let diagnostic = super::Diagnostic::warn("broker: example")
            .field("path", "/tmp/x")
            .field("count", 3);
        assert_eq!(diagnostic.fields.len(), 2);
        assert_eq!(
            super::Details(&diagnostic.fields).to_string(),
            "path=/tmp/x count=3"
        );
    }

    #[test]
    fn a_full_queue_drops_what_does_not_fit_and_counts_it() {
        let (outbox, inbox) = super::channel(2);
        for number in 0..5 {
            outbox.say(super::Diagnostic::debug("broker: example").field("number", number));
        }
        assert_eq!(inbox.queue.try_iter().count(), 2);
        assert_eq!(
            inbox.dropped.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "three of the five did not fit"
        );
    }
}
