//! Privilege escalation for raw-socket scans.
//!
//! Several nmap scan types (SYN, UDP, OS detection, traceroute…) need
//! `CAP_NET_RAW`/`CAP_NET_ADMIN`, i.e. root. Rather than running the whole
//! GUI as root, we elevate only the nmap subprocess:
//!
//! * **Linux** — `pkexec` (PolicyKit) shows a graphical auth dialog and runs
//!   nmap as root while the GUI stays unprivileged. This is the recommended
//!   path. (Alternatively a sysadmin can `setcap cap_net_raw,cap_net_admin+eip
//!   $(which nmap)` once, after which no elevation is needed at all.)
//! * **macOS** — no pkexec; falls back to `sudo`, which needs a cached
//!   credential or an askpass helper. For day-to-day use, launch privileged
//!   scans from a terminal where `sudo` can prompt.

/// nmap flags that require raw sockets (and therefore root).
const PRIVILEGED_FLAGS: &[&str] = &[
    "-sS", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sU", "-sO", "-sY", "-sZ",
    "-O", "-A", "--traceroute",
];

/// Whether the given nmap arguments include a scan type that needs root.
pub fn needs_privileges(args: &[String]) -> bool {
    args.iter().any(|a| PRIVILEGED_FLAGS.contains(&a.as_str()))
}

/// Graphical privilege-escalation helper to prepend to the command, per OS.
pub fn elevator() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("pkexec")
    } else if cfg!(target_os = "macos") {
        Some("sudo")
    } else {
        None
    }
}
