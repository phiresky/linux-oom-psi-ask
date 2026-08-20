//! psi-ask: an interactive userspace OOM handler.
//!
//! Watches kernel PSI (Pressure Stall Information) for memory pressure and,
//! instead of killing something automatically like systemd-oomd, presents the
//! biggest memory consumers and ASKS which one to kill.
//!
//! Detection: a PSI trigger ("some <stall_us> <window_us>" written to
//! /proc/pressure/memory) woken via poll(POLLPRI). Unprivileged triggers work
//! since kernel 6.5 when the window is a multiple of 2s. If trigger
//! registration fails, falls back to polling avg10 like psi-notify does.
//!
//! Self-protection (so the asker itself survives the pressure it reports):
//!   - mlockall(MCL_CURRENT | MCL_FUTURE): never swapped/reclaimed
//!   - /proc/self/oom_score_adj = -1000 (needs root/CAP_SYS_RESOURCE)
//!   - nice -20 (best effort)
//!   - buffers preallocated at startup; the hot path avoids fresh allocation
//! For full protection run it via ./run.sh (systemd-run with MemoryMin=,
//! OOMScoreAdjust=-1000, elevated CPU/IO weight).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write as IoWrite};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use gtk::prelude::*;
use gtk::{gdk, glib, Application, ApplicationWindow, Button, Label, ListBox, ScrolledWindow};
use gtk4 as gtk;
use gtk4_layer_shell::{KeyboardMode, Layer, LayerShell};

const PSI_MEMORY: &str = "/proc/pressure/memory";

fn millis(s: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_millis(s.parse()?))
}

fn secs(s: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(s.parse()?))
}

/// Watch PSI memory pressure and ask which process to kill.
///
/// An event needs two consecutive over-threshold windows (debounce). The
/// dialog is a gtk4-layer-shell overlay (Hyprland/wlroots/KDE) and falls
/// back to a normal window elsewhere. Run ./install-caps.sh once to let it
/// signal any process and set oom_score_adj=-1000 without root.
#[derive(clap::Parser, Debug, Clone)]
#[command(version)]
struct Config {
    /// PSI line to trigger on: "some" (any task stalled) or "full" (all)
    #[arg(long, default_value = "some", value_parser = ["some", "full"])]
    kind: String,

    /// Stall threshold within the window, in ms
    #[arg(long = "stall-ms", value_name = "MS", default_value = "500", value_parser = millis)]
    stall: Duration,

    /// Trigger window in seconds; unprivileged needs a multiple of 2
    #[arg(long = "window-s", value_name = "S", default_value = "2", value_parser = secs)]
    window: Duration,

    /// Quiet period after each prompt, in seconds
    #[arg(long = "cooldown-s", value_name = "S", default_value = "30", value_parser = secs)]
    cooldown: Duration,

    /// How many candidate processes to list
    #[arg(long, value_name = "N", default_value_t = 10)]
    top: usize,

    /// Dialog timeout in seconds (0 = wait forever); only dismisses once
    /// pressure is back under the threshold
    #[arg(long = "answer-timeout-s", value_name = "S", default_value = "60", value_parser = secs)]
    answer_timeout: Duration,

    /// Don't SIGSTOP the top offenders while the question is open
    #[arg(long = "no-pause", action = clap::ArgAction::SetFalse)]
    pause: bool,

    /// Normal decorated movable window instead of the layer-shell overlay
    #[arg(long = "window", action = clap::ArgAction::SetFalse)]
    overlay: bool,

    /// Also watch PATH/memory.pressure (relative to /sys/fs/cgroup;
    /// repeatable). Candidates are then limited to that cgroup's subtree.
    #[arg(long = "cgroup", value_name = "PATH")]
    cgroups: Vec<String>,

    /// Minutes of history shown in the dialog's chart
    #[arg(long = "chart-min", value_name = "N", default_value_t = 3,
          value_parser = clap::value_parser!(u64).range(1..))]
    chart_mins: u64,
}

// ---------------------------------------------------------------- protection

fn protect_self() {
    unsafe {
        // File capabilities mark the process non-dumpable, which hands
        // ownership of /proc/self/* to root — our own oom_score_adj write
        // would then fail on file permissions before the capability is even
        // checked. Restore dumpable so /proc/self belongs to us again.
        libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
        // ONFAULT: only pages we actually touch get locked — locking every
        // GTK mapping upfront blows through RLIMIT_MEMLOCK.
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT) != 0 {
            eprintln!(
                "warn: mlockall failed ({}); our pages can be reclaimed under pressure. \
                 Run ./install-caps.sh once (grants cap_ipc_lock)",
                io::Error::last_os_error()
            );
        }
        // Help us get CPU while the system is thrashing (cap_sys_nice).
        if libc::setpriority(libc::PRIO_PROCESS, 0, -20) != 0 {
            eprintln!("warn: could not set nice -20 (run ./install-caps.sh once)");
        }
    }
    // Make the kernel OOM killer never pick us. Lowering needs CAP_SYS_RESOURCE.
    if fs::write("/proc/self/oom_score_adj", "-1000").is_err() {
        eprintln!(
            "warn: could not set oom_score_adj=-1000 (needs CAP_SYS_RESOURCE); \
             run ./install-caps.sh once"
        );
    }
}

// ------------------------------------------------------------------- PSI I/O

/// One watched PSI file: the system-wide /proc/pressure/memory and/or any
/// number of cgroup memory.pressure files (the cgroup2 interface has the
/// same format and trigger semantics, like systemd-oomd uses).
struct PsiSource {
    /// "system" or the cgroup's name, shown in the dialog
    label: String,
    /// the pressure file, for re-reading stats
    pressure_path: String,
    /// cgroup directory — candidates are limited to its member processes
    cgroup_dir: Option<String>,
    /// armed trigger fd, or None = poll avg10 (fallback)
    trigger: Option<File>,
}

fn arm_trigger(path: &str, cfg: &Config) -> io::Result<File> {
    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    // The kernel wants the NUL included (write(fd, trig, strlen(trig) + 1)
    // in the psi.rst example); without it the write fails with EINVAL.
    let trigger = format!(
        "{} {} {}\0",
        cfg.kind,
        cfg.stall.as_micros(),
        cfg.window.as_micros()
    );
    f.write_all(trigger.as_bytes())?;
    Ok(f)
}

fn threshold_pct(cfg: &Config) -> f64 {
    cfg.stall.as_secs_f64() / cfg.window.as_secs_f64() * 100.0
}

fn setup_sources(cfg: &Config) -> Vec<PsiSource> {
    let mut out = Vec::new();
    match arm_trigger(PSI_MEMORY, cfg) {
        Ok(f) => {
            println!(
                "armed PSI trigger '{} {}ms/{}s' on {PSI_MEMORY}",
                cfg.kind,
                cfg.stall.as_millis(),
                cfg.window.as_secs()
            );
            out.push(PsiSource {
                label: "system".into(),
                pressure_path: PSI_MEMORY.into(),
                cgroup_dir: None,
                trigger: Some(f),
            });
        }
        Err(e) => {
            eprintln!(
                "warn: PSI trigger rejected ({e}); falling back to polling avg10 \
                 (threshold {:.1}%). Unprivileged triggers need kernel >= 6.5 \
                 and a window that is a multiple of 2s.",
                threshold_pct(cfg)
            );
            out.push(PsiSource {
                label: "system".into(),
                pressure_path: PSI_MEMORY.into(),
                cgroup_dir: None,
                trigger: None,
            });
        }
    }
    for cg in &cfg.cgroups {
        let dir = if cg.starts_with('/') {
            cg.clone()
        } else {
            format!("/sys/fs/cgroup/{cg}")
        };
        let path = format!("{dir}/memory.pressure");
        match arm_trigger(&path, cfg) {
            Ok(f) => {
                let label = dir.rsplit('/').next().unwrap_or(cg).to_string();
                println!("armed PSI trigger on cgroup {label} ({path})");
                out.push(PsiSource {
                    label,
                    pressure_path: path,
                    cgroup_dir: Some(dir),
                    trigger: Some(f),
                });
            }
            Err(e) => eprintln!("warn: skipping cgroup {cg}: {e}"),
        }
    }
    out
}

/// Read current pressure lines, e.g. "some avg10=1.23 ...\nfull avg10=...".
fn read_pressure(f: &mut File, buf: &mut String) -> io::Result<()> {
    f.seek(SeekFrom::Start(0))?;
    buf.clear();
    f.read_to_string(buf)?;
    Ok(())
}

fn avg10_of(kind: &str, psi_text: &str) -> f64 {
    psi_text
        .lines()
        .find(|l| l.starts_with(kind))
        .and_then(|l| l.split_whitespace().find_map(|t| t.strip_prefix("avg10=")))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0)
}

/// Parse the running stall counter ("total=<us>") for `kind`.
fn total_us_of(kind: &str, psi_text: &str) -> u64 {
    psi_text
        .lines()
        .find(|l| l.starts_with(kind))
        .and_then(|l| l.split_whitespace().find_map(|t| t.strip_prefix("total=")))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Block until one source fires. Returns its index, or None on unrecoverable
/// error. Sources whose fd dies (cgroup removed) are dropped along the way.
fn wait_for_pressure(sources: &mut Vec<PsiSource>, cfg: &Config, scratch: &mut String) -> Option<usize> {
    loop {
        if sources.is_empty() {
            eprintln!("error: no PSI sources left");
            return None;
        }
        let fds: Vec<(usize, libc::pollfd)> = sources
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                s.trigger.as_ref().map(|f| {
                    (i, libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLPRI, revents: 0 })
                })
            })
            .collect();
        let any_polled = fds.len() < sources.len();
        let timeout_ms = if any_polled { cfg.window.as_millis() as i32 } else { -1 };
        let mut raw: Vec<libc::pollfd> = fds.iter().map(|(_, p)| *p).collect();
        let r = unsafe { libc::poll(raw.as_mut_ptr(), raw.len() as libc::nfds_t, timeout_ms) };
        if r < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        if r > 0 {
            let mut dead: Vec<usize> = Vec::new();
            for (k, pfd) in raw.iter().enumerate() {
                let idx = fds[k].0;
                if pfd.revents & libc::POLLERR != 0 {
                    dead.push(idx);
                } else if pfd.revents & libc::POLLPRI != 0 {
                    return Some(idx);
                }
            }
            for idx in dead.into_iter().rev() {
                eprintln!("warn: PSI source '{}' vanished; dropping it", sources[idx].label);
                sources.remove(idx);
            }
            continue;
        }
        // Timeout: check the avg10 of fallback (poll-mode) sources.
        for (i, s) in sources.iter().enumerate() {
            if s.trigger.is_none() {
                if let Some(text) = slurp(&s.pressure_path, scratch) {
                    let text = text.to_string();
                    if avg10_of(&cfg.kind, &text) >= threshold_pct(cfg) {
                        return Some(i);
                    }
                }
            }
        }
    }
}

/// Debounce: the trigger fires on a single bad window; only treat it as a
/// real event if the NEXT window is also over the threshold. One noisy
/// allocation burst no longer summons the dialog.
fn confirm_pressure(source: &PsiSource, cfg: &Config, scratch: &mut String) -> bool {
    if source.trigger.is_none() {
        return true; // avg10 fallback is already smoothed
    }
    let Some(text) = slurp(&source.pressure_path, scratch) else { return false };
    let before = total_us_of(&cfg.kind, text);
    std::thread::sleep(cfg.window);
    let Some(text) = slurp(&source.pressure_path, scratch) else { return false };
    let after = total_us_of(&cfg.kind, text);
    after.saturating_sub(before) >= cfg.stall.as_micros() as u64
}

/// All pids in a cgroup subtree.
fn cgroup_pids(dir: &str, scratch: &mut String, out: &mut std::collections::HashSet<i32>) {
    if let Some(text) = slurp(&format!("{dir}/cgroup.procs"), scratch) {
        let pids: Vec<i32> = text.lines().filter_map(|l| l.trim().parse().ok()).collect();
        out.extend(pids);
    }
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if let Some(p) = e.path().to_str() {
                cgroup_pids(p, scratch, out);
            }
        }
    }
}

// ------------------------------------------------------------- pause/resume
//
// Like the macOS "out of application memory" dialog: stop the offenders
// while the question is open so the system stops thrashing, resume after.
// Paused pids live in a fixed global array so a SIGINT/SIGTERM handler can
// resume them with only async-signal-safe calls before exiting.

use std::sync::atomic::{AtomicI32, Ordering};

const MAX_PAUSED: usize = 64;
static PAUSED: [AtomicI32; MAX_PAUSED] = [const { AtomicI32::new(0) }; MAX_PAUSED];

extern "C" fn on_fatal_signal(_sig: libc::c_int) {
    for slot in &PAUSED {
        let pid = slot.load(Ordering::Relaxed);
        if pid > 0 {
            unsafe { libc::kill(pid, libc::SIGCONT) };
        }
    }
    unsafe { libc::_exit(130) };
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGINT, on_fatal_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_fatal_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_fatal_signal as *const () as libc::sighandler_t);
        // Aborts too: a panic inside a glib callback cannot unwind through
        // the C main loop and becomes abort(), and the allocator aborts on
        // OOM — exactly the regime we operate in. Without this, SIGSTOPped
        // victims would stay frozen forever.
        libc::signal(libc::SIGABRT, on_fatal_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGSEGV, on_fatal_signal as *const () as libc::sighandler_t);
    }
    // Unwinding panics (plain threads): resume before the default report.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        resume_all();
        default_hook(info);
    }));
}

fn pause_pid(pid: i32) -> bool {
    if unsafe { libc::kill(pid, libc::SIGSTOP) } != 0 {
        return false;
    }
    for slot in &PAUSED {
        if slot
            .compare_exchange(0, pid, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
    // No slot free; don't leave it stopped untracked.
    unsafe { libc::kill(pid, libc::SIGCONT) };
    false
}

/// SIGCONT everything we stopped. Also delivers any pending SIGTERM we sent:
/// a stopped process only handles SIGTERM once continued (SIGKILL needs no
/// resume).
fn resume_all() {
    for slot in &PAUSED {
        let pid = slot.swap(0, Ordering::Relaxed);
        if pid > 0 {
            unsafe { libc::kill(pid, libc::SIGCONT) };
        }
    }
}

/// The Wayland compositor renders our dialog — pausing it would freeze the
/// screen with the question on it. Find it as the owner of the
/// $WAYLAND_DISPLAY socket: /proc/net/unix gives the socket inodes bound to
/// that path, and the process holding one of them as an fd is the
/// compositor. (The ancestor-chain exemption doesn't cover it when psi-ask
/// runs as a systemd user service.)
fn wayland_compositor_pid() -> Option<i32> {
    let dir = std::env::var("XDG_RUNTIME_DIR").ok()?;
    let disp = std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".into());
    let path = if disp.starts_with('/') { disp } else { format!("{dir}/{disp}") };
    let unix = fs::read_to_string("/proc/net/unix").ok()?;
    let inodes: HashSet<&str> = unix
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let inode = f.nth(6)?;
            (f.next()? == path).then_some(inode)
        })
        .collect();
    if inodes.is_empty() {
        return None;
    }
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if let Some(t) = target.to_str() {
                    if t.strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                        .is_some_and(|ino| inodes.contains(ino))
                    {
                        return Some(pid);
                    }
                }
            }
        }
    }
    None
}

/// Processes the dialog itself depends on — never pause these regardless of
/// how much memory they use.
fn is_render_critical(comm: &str) -> bool {
    matches!(comm, "Xwayland" | "dbus-daemon" | "dbus-broker" | "systemd")
}

/// Our ancestor chain (terminal, shell, systemd-run, ...) — never pause
/// these or the user could no longer answer the prompt.
fn ancestor_pids(scratch: &mut String) -> Vec<i32> {
    let mut out = Vec::with_capacity(16);
    let mut pid = std::process::id() as i32;
    let mut path = String::with_capacity(32);
    while pid > 1 && out.len() < 32 {
        out.push(pid);
        path.clear();
        let _ = write!(path, "/proc/{pid}/status");
        let ppid = slurp(&path, scratch)
            .and_then(|s| s.lines().find(|l| l.starts_with("PPid:")))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok());
        match ppid {
            Some(p) => pid = p,
            None => break,
        }
    }
    out
}

// ----------------------------------------------------------------- processes

struct Candidate {
    pid: i32,
    comm: String,
    cmdline: String,
    rss_bytes: u64,
    oom_score: i32,
}

/// Read a small proc file into `buf`, returning it as &str. No allocation
/// beyond `buf`'s preallocated capacity in the common case.
fn slurp<'a>(path: &str, buf: &'a mut String) -> Option<&'a str> {
    buf.clear();
    File::open(path).ok()?.read_to_string(buf).ok()?;
    Some(buf.as_str())
}

fn collect_candidates(
    top: usize,
    page_size: u64,
    scratch: &mut String,
    filter: Option<&std::collections::HashSet<i32>>,
) -> Vec<Candidate> {
    let self_pid = std::process::id() as i32;
    let mut out: Vec<Candidate> = Vec::with_capacity(256);
    let Ok(dir) = fs::read_dir("/proc") else { return out };
    let mut path = String::with_capacity(64);
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if pid == self_pid || pid == 1 {
            continue;
        }
        if let Some(set) = filter {
            if !set.contains(&pid) {
                continue;
            }
        }
        // Kernel threads have an empty cmdline; skip them. Keep the full
        // cmdline: /proc/<pid>/comm is truncated to 15 chars by the kernel
        // (TASK_COMM_LEN), e.g. Firefox's "Isolated Web Co".
        path.clear();
        let _ = write!(path, "/proc/{pid}/cmdline");
        // Lossy, not read_to_string: argv can contain non-UTF-8 bytes (e.g. a
        // latin-1 filename), and a hard UTF-8 error would silently drop the
        // process from the list.
        let cmdline = match fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => {
                let s = String::from_utf8_lossy(&bytes);
                s.trim_end_matches('\0').replace('\0', " ").trim().to_string()
            }
            _ => continue, // kernel thread (empty) or process vanished
        };
        path.clear();
        let _ = write!(path, "/proc/{pid}/statm");
        let rss_pages: u64 = match slurp(&path, scratch)
            .and_then(|s| s.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
        {
            Some(v) => v,
            None => continue, // process vanished
        };
        path.clear();
        let _ = write!(path, "/proc/{pid}/oom_score");
        let oom_score = slurp(&path, scratch)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        path.clear();
        let _ = write!(path, "/proc/{pid}/comm");
        let comm = slurp(&path, scratch)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "?".into());
        out.push(Candidate {
            pid,
            comm,
            cmdline,
            rss_bytes: rss_pages * page_size,
            oom_score,
        });
    }
    out.sort_by(|a, b| b.rss_bytes.cmp(&a.rss_bytes));
    out.truncate(top);
    out
}

use std::fmt::Write as FmtWrite;

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1}{}", UNITS[u])
}

// ------------------------------------------------------------------- monitor
//
// Runs on a background thread. Waits for pressure, freezes the offenders,
// hands the candidate list to the GTK main thread, then blocks until the
// user has decided before re-arming.

struct DialogCandidate {
    pid: i32,
    comm: String,
    cmdline: String,
    rss_bytes: u64,
    oom_score: i32,
    paused: bool,
}

struct PressureEvent {
    /// "system" or the cgroup name that fired
    source: String,
    /// the pressure file that fired — the countdown gates on ITS avg10, not
    /// the global one (a thrashing cgroup must not be dismissed just because
    /// system-wide pressure looks fine, and vice versa)
    pressure_path: String,
    psi_line: String,
    cands: Vec<DialogCandidate>,
}

/// Returns whether the signal was delivered.
fn kill_pid(pid: i32, comm: &str, sig: i32) -> bool {
    let signame = if sig == libc::SIGKILL { "SIGKILL" } else { "SIGTERM" };
    let r = unsafe { libc::kill(pid, sig) };
    if r == 0 {
        println!("sent {signame} to {pid} ({comm})");
        true
    } else {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EPERM) {
            eprintln!(
                "error: no permission to signal {pid} ({comm}); run ./install-caps.sh once"
            );
        } else {
            eprintln!("error: kill({pid}) failed: {e}");
        }
        false
    }
}

fn monitor_loop(
    cfg: Config,
    ev_tx: async_channel::Sender<PressureEvent>,
    label_tx: async_channel::Sender<HashMap<i32, String>>,
    done_rx: mpsc::Receiver<()>,
) {
    let mut sources = setup_sources(&cfg);
    if sources.is_empty() {
        eprintln!("error: no usable PSI sources (kernel needs CONFIG_PSI)");
        std::process::exit(1);
    }
    // Preallocate the hot-path buffer now, while memory is easy to get.
    // mlockall(MCL_FUTURE) keeps it resident.
    let mut scratch = String::with_capacity(64 * 1024);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    // Found once: the compositor lives as long as our Wayland connection.
    let compositor = wayland_compositor_pid();
    if let Some(pid) = compositor {
        println!("compositor is pid {pid}; exempt from pausing");
    } else {
        eprintln!("warn: could not identify the Wayland compositor; relying on name-based pause exemptions");
    }

    loop {
        let Some(idx) = wait_for_pressure(&mut sources, &cfg, &mut scratch) else {
            eprintln!("error: pressure watcher failed; exiting");
            std::process::exit(1);
        };
        if !confirm_pressure(&sources[idx], &cfg, &mut scratch) {
            continue; // single-window blip, debounced away
        }
        let source = sources[idx].label.clone();
        let pressure_path = sources[idx].pressure_path.clone();
        let psi_line = slurp(&sources[idx].pressure_path, &mut scratch)
            .and_then(|s| s.lines().find(|l| l.starts_with(cfg.kind.as_str())))
            .unwrap_or("")
            .to_string();
        println!("=== MEMORY PRESSURE [{source}] {} === {psi_line}", chrono_now());

        let pid_filter = sources[idx].cgroup_dir.clone().map(|dir| {
            let mut set = std::collections::HashSet::new();
            cgroup_pids(&dir, &mut scratch, &mut set);
            set
        });
        let cands = collect_candidates(cfg.top, page_size, &mut scratch, pid_filter.as_ref());
        if !cands.is_empty() {
            // Firefox children need site-name enrichment via a memory-report
            // dump — which a SIGSTOPped Firefox could never produce. So when
            // enrichment runs, Firefox-family processes are NOT paused here;
            // the UI pauses them once the labels arrive.
            let is_ff =
                |c: &Candidate| c.cmdline.contains("-contentproc") || c.comm == "firefox";
            let ff_main = cands
                .iter()
                .find(|c| is_ff(c))
                .and_then(|c| find_firefox_main(c.pid, &mut scratch));

            // macOS-style: freeze the worst offenders while the question is
            // open so the machine stops digging deeper. Never our own
            // ancestor chain (terminal, compositor session leaders, ...).
            let ancestors = ancestor_pids(&mut scratch);
            let cands: Vec<DialogCandidate> = cands
                .into_iter()
                .enumerate()
                .map(|(i, c)| {
                    let paused = cfg.pause
                        && i < 5
                        && !(ff_main.is_some() && is_ff(&c))
                        && !ancestors.contains(&c.pid)
                        && Some(c.pid) != compositor
                        && !is_render_critical(&c.comm)
                        && pause_pid(c.pid);
                    DialogCandidate {
                        pid: c.pid,
                        comm: c.comm,
                        cmdline: c.cmdline,
                        rss_bytes: c.rss_bytes,
                        oom_score: c.oom_score,
                        paused,
                    }
                })
                .collect();
            // Resolve the cryptic Firefox child names to sites in the
            // background; the dialog updates in place when the report lands.
            if let Some(main_pid) = ff_main {
                let tx = label_tx.clone();
                std::thread::spawn(move || {
                    let labels = firefox_pid_labels(main_pid);
                    if !labels.is_empty() {
                        let _ = tx.send_blocking(labels);
                    }
                });
            }
            if ev_tx
                .send_blocking(PressureEvent { source, pressure_path, psi_line, cands })
                .is_err()
            {
                resume_all();
                return; // GUI is gone
            }
            // Block until the dialog is answered/dismissed (it resumes the
            // paused processes itself).
            if done_rx.recv().is_err() {
                resume_all();
                return;
            }
        }
        std::thread::sleep(cfg.cooldown);
        // Consume events that fired while the dialog was open; PSI triggers
        // are edge-based per window, so one zero-timeout poll per fd clears
        // the pending readiness.
        for s in &sources {
            if let Some(f) = &s.trigger {
                let mut pfd =
                    libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLPRI, revents: 0 };
                unsafe { libc::poll(&mut pfd, 1, 0) };
            }
        }
    }
}

// ------------------------------------------------------- firefox enrichment
//
// Firefox child processes all show a kernel-truncated comm ("Isolated Web
// Co"). Firefox's nsMemoryInfoDumper installs a SIGRTMIN handler that dumps
// an about:memory report to /tmp/unified-memory-report-*-<mainpid>.json.gz,
// whose process labels map pid → site ("webIsolated=https://discord.com
// (pid 981965)"). When a Firefox process appears in the candidate list we
// trigger that dump in a worker thread and live-update the dialog rows once
// it lands. Undocumented but stable since ~2013; parse defensively.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

fn find_firefox_main(mut pid: i32, scratch: &mut String) -> Option<i32> {
    for _ in 0..32 {
        let comm = slurp(&format!("/proc/{pid}/comm"), scratch)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if comm == "firefox" {
            return Some(pid);
        }
        let ppid: i32 = slurp(&format!("/proc/{pid}/status"), scratch)
            .and_then(|s| s.lines().find(|l| l.starts_with("PPid:")))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())?;
        if ppid <= 1 {
            return None;
        }
        pid = ppid;
    }
    None
}

/// "webIsolated=https://discord.com^userContextId=9" → "firefox · discord.com"
fn friendly_firefox_label(raw: &str) -> Option<String> {
    use std::sync::LazyLock;
    // web-content labels: <type>=<url>[^attributes]
    static WEB: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"^(?<type>webIsolated|webCOOP\+COEP|webServiceWorker|web)=(?:https?://)?(?<host>[^^\s]+)",
        )
        .unwrap()
    });
    let s = if let Some(c) = WEB.captures(raw) {
        let host = &c["host"];
        match &c["type"] {
            "webServiceWorker" => format!("{host} (service worker)"),
            _ => host.to_string(),
        }
    } else {
        match raw {
            "web" => "web content".into(),
            "extension" => "extensions".into(),
            "privilegedabout" => "about: pages".into(),
            r if r.starts_with("RDD") => "media decoder (RDD)".into(),
            r if r.starts_with("Socket") => "networking".into(),
            r if r.starts_with("Utility") => "utility".into(),
            r if r.starts_with("prealloc") => "preallocated content".into(),
            _ => return None, // Main Process etc. — keep existing name
        }
    };
    Some(format!("firefox · {s}"))
}

/// Pull every `"process": "<label> (pid N...)"` out of the report JSON
/// without a JSON parser (the labels contain no escapes).
fn parse_process_labels(json: &str, out: &mut HashMap<i32, String>) {
    use std::sync::LazyLock;
    static PROC: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#""process"\s*:\s*"(?<label>[^"]*)\(pid (?<pid>\d+)[^"]*""#).unwrap()
    });
    for c in PROC.captures_iter(json) {
        if let (Ok(pid), Some(friendly)) = (
            c["pid"].parse::<i32>(),
            friendly_firefox_label(c["label"].trim()),
        ) {
            out.insert(pid, friendly);
        }
    }
}

fn firefox_report_files(suffix: &str) -> HashSet<std::path::PathBuf> {
    let mut out = HashSet::new();
    if let Ok(dir) = fs::read_dir("/tmp") {
        for e in dir.flatten() {
            let name = e.file_name();
            let Some(n) = name.to_str() else { continue };
            if n.starts_with("unified-memory-report-") && n.ends_with(suffix) {
                out.insert(e.path());
            }
        }
    }
    out
}

fn firefox_pid_labels(main_pid: i32) -> HashMap<i32, String> {
    let mut out = HashMap::new();
    let suffix = format!("-{main_pid}.json.gz");
    let before = firefox_report_files(&suffix);
    if unsafe { libc::kill(main_pid, libc::SIGRTMIN()) } != 0 {
        return out;
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        for path in firefox_report_files(&suffix).difference(&before) {
            // A partial file fails gzip decoding; retry next round.
            let Ok(f) = File::open(path) else { continue };
            let mut json = String::new();
            use flate2::read::GzDecoder;
            if GzDecoder::new(f).read_to_string(&mut json).is_ok() {
                parse_process_labels(&json, &mut out);
                let _ = fs::remove_file(path); // large + contains browsing info
                return out;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_labels() {
        let json = r#"{"reports":[
            {"process":"webIsolated=https://discord.com (pid 111)","x":1},
            {"process":"webIsolated=https://google.com^userContextId=9 (pid 222)","x":1},
            {"process":"webCOOP+COEP=https://whatsapp.com (pid 333)","x":1},
            {"process":"webServiceWorker=https://element.io (pid 444)","x":1},
            {"process":"Main Process (pid 555)","x":1},
            {"process":"RDD (pid 666)","x":1},
            {"process":"Utility (pid 777, sandboxingKind 0)","x":1},
            {"process":"extension (pid 888)","x":1}
        ]}"#;
        let mut m = HashMap::new();
        parse_process_labels(json, &mut m);
        assert_eq!(m[&111], "firefox · discord.com");
        assert_eq!(m[&222], "firefox · google.com");
        assert_eq!(m[&333], "firefox · whatsapp.com");
        assert_eq!(m[&444], "firefox · element.io (service worker)");
        assert!(!m.contains_key(&555)); // Main Process keeps its name
        assert_eq!(m[&666], "firefox · media decoder (RDD)");
        assert_eq!(m[&777], "firefox · utility");
        assert_eq!(m[&888], "firefox · extensions");
    }
}

// ----------------------------------------------------------------- history
//
// A background thread samples memory pressure (avg10) and memory use every
// SAMPLE_SECS into a ring buffer covering the last 10 minutes, so the dialog
// can show how the system got here.

const SAMPLE_SECS: u64 = 2;
fn history_len(cfg: &Config) -> usize {
    ((cfg.chart_mins * 60 / SAMPLE_SECS) as usize).max(2)
}

#[derive(Clone, Copy)]
struct Sample {
    psi_pct: f32,
    mem_pct: f32,
}

type History = Arc<Mutex<VecDeque<Sample>>>;

fn mem_used_pct(scratch: &mut String) -> f32 {
    let Some(s) = slurp("/proc/meminfo", scratch) else { return 0.0 };
    let field = |name: &str| -> f64 {
        s.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0)
    };
    let (total, avail) = (field("MemTotal:"), field("MemAvailable:"));
    if total <= 0.0 {
        return 0.0;
    }
    (100.0 * (1.0 - avail / total)) as f32
}

fn sampler_loop(kind: String, hist: History, cap: usize) {
    let Ok(mut psi_file) = File::open(PSI_MEMORY) else { return };
    let mut scratch = String::with_capacity(8 * 1024);
    loop {
        let psi = if read_pressure(&mut psi_file, &mut scratch).is_ok() {
            avg10_of(&kind, &scratch) as f32
        } else {
            0.0
        };
        let mem = mem_used_pct(&mut scratch);
        {
            let mut h = hist.lock().unwrap();
            if h.len() >= cap {
                h.pop_front();
            }
            h.push_back(Sample { psi_pct: psi, mem_pct: mem });
        }
        std::thread::sleep(Duration::from_secs(SAMPLE_SECS));
    }
}

// ----------------------------------------------------------------------- GUI

const CSS: &str = "
.psi-title { font-size: 15pt; font-weight: bold; }
.psi-sub { color: alpha(currentColor, 0.6); font-size: 9pt; font-family: monospace; }
.psi-comm { font-weight: bold; }
.psi-meta { color: alpha(currentColor, 0.55); font-size: 9pt; }
.psi-rss { font-family: monospace; font-size: 11pt; }
.psi-paused { color: alpha(currentColor, 0.5); font-style: italic; }
.psi-countdown { color: alpha(currentColor, 0.6); }
window.psi-ask { border-radius: 12px; background-color: @theme_bg_color; }
";

struct Ui {
    window: ApplicationWindow,
    psi_label: Label,
    countdown_label: Label,
    list: ListBox,
    timer: RefCell<Option<glib::SourceId>>,
    remaining: Cell<u64>,
    active: Cell<bool>,
    done_tx: mpsc::Sender<()>,
    answer_timeout: Duration,
    /// avg10 % below which the timeout may dismiss the dialog
    dismiss_below: f64,
    /// PSI line kind ("some"/"full") for re-reading the source's avg10
    kind: String,
    /// pressure file of the event on display; the countdown gates on this
    event_pressure_path: RefCell<String>,
    /// preallocated buffer for the once-per-second pressure re-read
    psi_scratch: RefCell<String>,
    /// pid → (name label, paused) of the rows on display, for live renames
    row_names: RefCell<HashMap<i32, (Label, bool)>>,
}

fn name_markup(name: &str, paused: bool) -> String {
    let esc = glib::markup_escape_text(name);
    if paused {
        format!("<b>{esc}</b> <span alpha=\"55%\" style=\"italic\">(paused)</span>")
    } else {
        format!("<b>{esc}</b>")
    }
}

/// Act on the user's choice (or None = do nothing), unfreeze everything,
/// hide the dialog and let the monitor thread re-arm.
fn finish(ui: &Rc<Ui>, choice: Option<(i32, String, i32)>) {
    if !ui.active.get() {
        return;
    }
    match choice {
        Some((pid, comm, sig)) => {
            if !kill_pid(pid, &comm, sig) {
                // Signal not delivered (usually EPERM without caps): keep the
                // dialog open — closing would silently resume everything and
                // burn a cooldown while the pressure persists. Cancel the
                // auto-dismiss so the message stays visible; the user can try
                // another row or dismiss explicitly.
                if let Some(id) = ui.timer.borrow_mut().take() {
                    id.remove();
                }
                ui.countdown_label.set_text(&format!(
                    "Could not signal {pid} ({comm}) — run ./install-caps.sh once"
                ));
                return;
            }
        }
        None => println!("doing nothing."),
    }
    ui.active.set(false);
    if let Some(id) = ui.timer.borrow_mut().take() {
        id.remove();
    }
    // Always resume: survivors get unfrozen, and a SIGTERM we just sent is
    // only delivered once the stopped target is continued.
    resume_all();
    ui.window.set_visible(false);
    let _ = ui.done_tx.send(());
}

fn show_event(ui: &Rc<Ui>, ev: PressureEvent) {
    if ev.source == "system" {
        ui.psi_label.set_text(&ev.psi_line);
    } else {
        ui.psi_label.set_text(&format!("cgroup {}: {}", ev.source, ev.psi_line));
    }
    *ui.event_pressure_path.borrow_mut() = ev.pressure_path;
    while let Some(child) = ui.list.first_child() {
        ui.list.remove(&child);
    }
    ui.row_names.borrow_mut().clear();
    for c in ev.cands {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        row.set_margin_top(4);
        row.set_margin_bottom(4);
        row.set_margin_start(8);
        row.set_margin_end(8);

        let name_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
        // macOS-style: "firefox (paused)" right on the name
        let comm = Label::builder().use_markup(true).xalign(0.0).build();
        comm.set_markup(&name_markup(&c.comm, c.paused));
        ui.row_names.borrow_mut().insert(c.pid, (comm.clone(), c.paused));
        let meta = Label::builder()
            .label(format!("pid {} · oom score {} · {}", c.pid, c.oom_score, c.cmdline))
            .xalign(0.0)
            .css_classes(["psi-meta"])
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .max_width_chars(64)
            .build();
        // full command line on hover
        row.set_tooltip_text(Some(&c.cmdline));
        name_box.append(&comm);
        name_box.append(&meta);
        name_box.set_hexpand(true);
        row.append(&name_box);

        row.append(
            &Label::builder()
                .label(human(c.rss_bytes))
                .css_classes(["psi-rss"])
                .width_chars(8)
                .xalign(1.0)
                .build(),
        );

        let term = Button::with_label("Terminate");
        let kill = Button::with_label("Force kill");
        kill.add_css_class("destructive-action");
        let (pid, comm_s) = (c.pid, c.comm.clone());
        let ui2 = ui.clone();
        term.connect_clicked(move |_| finish(&ui2, Some((pid, comm_s.clone(), libc::SIGTERM))));
        let comm_s = c.comm.clone();
        let ui2 = ui.clone();
        kill.connect_clicked(move |_| finish(&ui2, Some((pid, comm_s.clone(), libc::SIGKILL))));
        row.append(&term);
        row.append(&kill);
        ui.list.append(&row);
    }

    ui.active.set(true);
    let secs = ui.answer_timeout.as_secs();
    if secs > 0 {
        ui.remaining.set(secs);
        ui.countdown_label.set_text(&format!("Doing nothing in {secs}s"));
        let ui2 = ui.clone();
        let id = glib::timeout_add_seconds_local(1, move || {
            // Only count down while pressure is actually easing; while it
            // stays over the threshold the dialog stays put. Read the avg10
            // of the source that fired (a cgroup's memory.pressure or the
            // global file) — the global history would let a still-thrashing
            // cgroup dialog dismiss itself, and unrelated global pressure
            // would pin a cgroup dialog open. If the file vanished (cgroup
            // removed), 0.0 lets the countdown run out normally.
            let current_psi = {
                let mut scratch = ui2.psi_scratch.borrow_mut();
                slurp(&ui2.event_pressure_path.borrow(), &mut scratch)
                    .map(|t| avg10_of(&ui2.kind, t))
                    .unwrap_or(0.0)
            };
            if current_psi >= ui2.dismiss_below {
                ui2.remaining.set(ui2.answer_timeout.as_secs());
                ui2.countdown_label
                    .set_text(&format!("Pressure still high ({current_psi:.0}%) — waiting"));
                return glib::ControlFlow::Continue;
            }
            let left = ui2.remaining.get().saturating_sub(1);
            ui2.remaining.set(left);
            if left == 0 {
                *ui2.timer.borrow_mut() = None;
                finish(&ui2, None);
                return glib::ControlFlow::Break;
            }
            ui2.countdown_label.set_text(&format!("Doing nothing in {left}s"));
            glib::ControlFlow::Continue
        });
        *ui.timer.borrow_mut() = Some(id);
    } else {
        ui.countdown_label.set_text("");
    }
    ui.window.present();
}

fn build_ui(
    app: &Application,
    cfg: &Config,
    hist: History,
    ev_rx: async_channel::Receiver<PressureEvent>,
    label_rx: async_channel::Receiver<HashMap<i32, String>>,
    done_tx: mpsc::Sender<()>,
) {
    let css = gtk::CssProvider::new();
    css.load_from_string(CSS);
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &css,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }

    let window = ApplicationWindow::builder()
        .application(app)
        .title("psi-ask — memory pressure")
        .default_width(620)
        .default_height(460)
        .build();
    // add_css_class, not builder css_classes: the latter would replace the
    // default "background" class and leave the window transparent.
    window.add_css_class("psi-ask");

    // Default: layer-shell always-on-top overlay (wlroots/KDE). Falls back
    // to a normal decorated window with --window or where layer-shell is
    // unsupported (GNOME).
    let overlay = cfg.overlay && gtk4_layer_shell::is_supported();
    if overlay {
        window.init_layer_shell();
        window.set_layer(Layer::Overlay);
        window.set_keyboard_mode(KeyboardMode::OnDemand);
        window.set_namespace(Some("psi-ask"));
    }

    let root = gtk::Box::new(gtk::Orientation::Vertical, 10);
    root.set_margin_top(16);
    root.set_margin_bottom(16);
    root.set_margin_start(16);
    root.set_margin_end(16);

    let header = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
    icon.set_pixel_size(40);
    header.append(&icon);
    let title_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
    title_box.append(
        &Label::builder()
            .label("Your system is running out of memory")
            .xalign(0.0)
            .css_classes(["psi-title"])
            .build(),
    );
    let psi_label = Label::builder().xalign(0.0).css_classes(["psi-sub"]).build();
    title_box.append(&psi_label);
    title_box.set_hexpand(true);
    header.append(&title_box);
    root.append(&header);

    // --- recent-history chart (--chart-min): pressure stall % and memory
    // used %, one
    // shared 0-100% axis. Colors are categorical slots 1+2 of the palette,
    // CVD-validated for both light and dark surfaces; the legend carries
    // identity in text, the colored dot is only the mark.
    let is_dark = {
        let c = window.color();
        0.299 * c.red() + 0.587 * c.green() + 0.114 * c.blue() > 0.5
    };
    let (psi_rgb, mem_rgb, psi_hex, mem_hex) = if is_dark {
        ((0x39, 0x87, 0xe5), (0xd9, 0x59, 0x26), "#3987e5", "#d95926")
    } else {
        ((0x2a, 0x78, 0xd6), (0xeb, 0x68, 0x34), "#2a78d6", "#eb6834")
    };
    let legend = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    for (hex, text) in [
        (psi_hex, "pressure stall (some avg10)"),
        (mem_hex, "memory used"),
    ] {
        let l = Label::builder().use_markup(true).css_classes(["psi-meta"]).build();
        l.set_markup(&format!("<span foreground=\"{hex}\">●</span> {text}"));
        legend.append(&l);
    }
    root.append(&legend);

    let chart = gtk::DrawingArea::new();
    chart.set_content_height(110);
    let hist2 = hist.clone();
    let hist_len = history_len(cfg);
    let past_label = format!("{} min ago", cfg.chart_mins);
    chart.set_draw_func(move |area, cr, w, h| {
        let samples: Vec<Sample> = hist2.lock().unwrap().iter().copied().collect();
        let fg = area.color();
        let (w, h) = (w as f64, h as f64);
        let (left, right, top, bottom) = (34.0, 8.0, 4.0, 14.0);
        let (px, py, pw, ph) = (left, top, w - left - right, h - top - bottom);
        let y_of = |pct: f64| py + ph * (1.0 - (pct / 100.0).clamp(0.0, 1.0));

        // recessive grid + sparse axis labels
        cr.set_line_width(1.0);
        cr.select_font_face("sans", gtk::cairo::FontSlant::Normal, gtk::cairo::FontWeight::Normal);
        cr.set_font_size(9.0);
        for pct in [0.0, 25.0, 50.0, 75.0, 100.0] {
            let y = y_of(pct).round() + 0.5;
            cr.set_source_rgba(fg.red().into(), fg.green().into(), fg.blue().into(), 0.08);
            cr.move_to(px, y);
            cr.line_to(px + pw, y);
            let _ = cr.stroke();
        }
        cr.set_source_rgba(fg.red().into(), fg.green().into(), fg.blue().into(), 0.55);
        for (pct, label) in [(0.0, "0"), (50.0, "50"), (100.0, "100%")] {
            cr.move_to(2.0, y_of(pct) + 3.0);
            let _ = cr.show_text(label);
        }
        cr.move_to(px, h - 3.0);
        let _ = cr.show_text(&past_label);
        cr.move_to(px + pw - 22.0, h - 3.0);
        let _ = cr.show_text("now");

        // series lines, newest sample anchored to the right edge
        if samples.len() >= 2 {
            let n = samples.len();
            let step = pw / (hist_len - 1) as f64;
            let x_of = |i: usize| px + pw - (n - 1 - i) as f64 * step;
            cr.set_line_width(2.0);
            cr.set_line_join(gtk::cairo::LineJoin::Round);
            cr.set_line_cap(gtk::cairo::LineCap::Round);
            let draw_series = |rgb: (i32, i32, i32), value: &dyn Fn(&Sample) -> f64| {
                cr.set_source_rgb(
                    rgb.0 as f64 / 255.0,
                    rgb.1 as f64 / 255.0,
                    rgb.2 as f64 / 255.0,
                );
                cr.move_to(x_of(0), y_of(value(&samples[0])));
                for (i, s) in samples.iter().enumerate().skip(1) {
                    cr.line_to(x_of(i), y_of(value(s)));
                }
                let _ = cr.stroke();
            };
            draw_series(mem_rgb, &|s| s.mem_pct as f64);
            draw_series(psi_rgb, &|s| s.psi_pct as f64);
        }
    });
    root.append(&chart);
    // keep the chart moving while the dialog is up (no-op while hidden)
    let chart2 = chart.clone();
    glib::timeout_add_seconds_local(SAMPLE_SECS as u32, move || {
        chart2.queue_draw();
        glib::ControlFlow::Continue
    });

    let list = ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::None);
    list.add_css_class("boxed-list");
    let scroll = ScrolledWindow::builder()
        .child(&list)
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    root.append(&scroll);

    let footer = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let countdown_label = Label::builder().css_classes(["psi-countdown"]).hexpand(true).xalign(0.0).build();
    footer.append(&countdown_label);
    let dismiss = Button::with_label("Do nothing (resume all)");
    dismiss.add_css_class("suggested-action");
    footer.append(&dismiss);
    root.append(&footer);

    window.set_child(Some(&root));

    let ui = Rc::new(Ui {
        window: window.clone(),
        psi_label,
        countdown_label,
        list,
        timer: RefCell::new(None),
        remaining: Cell::new(0),
        active: Cell::new(false),
        done_tx,
        answer_timeout: cfg.answer_timeout,
        dismiss_below: threshold_pct(cfg),
        kind: cfg.kind.clone(),
        event_pressure_path: RefCell::new(PSI_MEMORY.into()),
        psi_scratch: RefCell::new(String::with_capacity(8 * 1024)),
        row_names: RefCell::new(HashMap::new()),
    });

    // Firefox pid→site names arriving from the enrichment worker. These
    // processes were exempted from the upfront pause (a stopped Firefox
    // could not have produced the report), so pause them now — safe from
    // races with finish() since both run on the GTK main loop.
    let ui2 = ui.clone();
    let do_pause = cfg.pause;
    glib::spawn_future_local(async move {
        while let Ok(map) = label_rx.recv().await {
            if !ui2.active.get() {
                continue; // dialog already answered; stale result
            }
            let mut pause_budget = 5;
            let mut rn = ui2.row_names.borrow_mut();
            for (pid, name) in map {
                if let Some((label, paused)) = rn.get_mut(&pid) {
                    if do_pause && !*paused && pause_budget > 0 && pause_pid(pid) {
                        *paused = true;
                        pause_budget -= 1;
                    }
                    label.set_markup(&name_markup(&name, *paused));
                }
            }
        }
    });

    let ui2 = ui.clone();
    dismiss.connect_clicked(move |_| finish(&ui2, None));

    // Escape = do nothing; closing the window likewise counts as an answer.
    let keys = gtk::EventControllerKey::new();
    let ui2 = ui.clone();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Escape {
            finish(&ui2, None);
            glib::Propagation::Stop
        } else {
            glib::Propagation::Proceed
        }
    });
    window.add_controller(keys);
    let ui2 = ui.clone();
    window.connect_close_request(move |_| {
        finish(&ui2, None);
        glib::Propagation::Stop
    });

    // Realize once (invisible) so GTK's font/render caches are built and
    // mlocked now, not during a memory crunch.
    window.set_opacity(0.0);
    window.present();
    let ui2 = ui.clone();
    glib::idle_add_local_once(move || {
        ui2.window.set_visible(false);
        ui2.window.set_opacity(1.0);
    });

    glib::spawn_future_local(async move {
        while let Ok(ev) = ev_rx.recv().await {
            show_event(&ui, ev);
        }
    });
}

fn chrono_now() -> String {
    // HH:MM:SS from CLOCK_REALTIME without pulling in a date crate.
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&ts.tv_sec, &mut tm) };
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

// ---------------------------------------------------------------------- main

fn main() {
    let cfg = <Config as clap::Parser>::parse();
    protect_self();
    install_signal_handlers();

    // xdg-desktop-portal cannot introspect a capability-elevated process
    // (the /proc/<pid>/root ptrace-access check fails because our permitted
    // capability set exceeds the portal's), which yields AccessDenied
    // warnings and no settings. We are not sandboxed, so skip portals; GTK
    // then reads GSettings directly. Must be set before GTK initializes.
    let gdk_debug = match std::env::var("GDK_DEBUG") {
        Ok(v) if !v.is_empty() => format!("{v}:no-portals"),
        _ => "no-portals".into(),
    };
    std::env::set_var("GDK_DEBUG", gdk_debug);
    // Software rendering: a rarely-shown dialog doesn't need the GPU
    // pipeline, and skipping it saves ~25M RSS (Vulkan + Mesa's LLVM
    // shader compiler) plus one less subsystem to depend on mid-crunch.
    if std::env::var_os("GSK_RENDERER").is_none() {
        std::env::set_var("GSK_RENDERER", "cairo");
    }

    println!(
        "psi-ask watching {PSI_MEMORY} ({} {}ms/{}s window, cooldown {}s). Ctrl-C to quit.",
        cfg.kind,
        cfg.stall.as_millis(),
        cfg.window.as_secs(),
        cfg.cooldown.as_secs()
    );

    let (ev_tx, ev_rx) = async_channel::bounded::<PressureEvent>(1);
    let (label_tx, label_rx) = async_channel::bounded::<HashMap<i32, String>>(4);
    let (done_tx, done_rx) = mpsc::channel::<()>();
    {
        let cfg = cfg.clone();
        std::thread::spawn(move || monitor_loop(cfg, ev_tx, label_tx, done_rx));
    }
    let cap = history_len(&cfg);
    let hist: History = Arc::new(Mutex::new(VecDeque::with_capacity(cap)));
    {
        let (kind, hist) = (cfg.kind.clone(), hist.clone());
        std::thread::spawn(move || sampler_loop(kind, hist, cap));
    }

    let app = Application::builder()
        .application_id("dev.phire.psi-ask")
        .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
        .build();
    // The window stays hidden until pressure fires; hold the app open anyway.
    let hold: RefCell<Option<gtk::gio::ApplicationHoldGuard>> = RefCell::new(None);
    type Chans = (
        async_channel::Receiver<PressureEvent>,
        async_channel::Receiver<HashMap<i32, String>>,
        mpsc::Sender<()>,
    );
    let chan: RefCell<Option<Chans>> = RefCell::new(Some((ev_rx, label_rx, done_tx)));
    app.connect_activate(move |app| {
        *hold.borrow_mut() = Some(app.hold());
        if let Some((rx, lrx, tx)) = chan.borrow_mut().take() {
            build_ui(app, &cfg, hist.clone(), rx, lrx, tx);
        }
    });
    let code: i32 = app.run_with_args::<&str>(&[]).into();
    resume_all();
    std::process::exit(code);
}
