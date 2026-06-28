//! Nmap Scripting Engine (NSE) categories and script-directory discovery.
//!
//! NSE scripts ship bundled with nmap (in its `scripts/` data dir); they are
//! not installed separately. We expose the standard *categories* — selecting
//! them composes a `--script cat1,cat2` flag — and annotate each with a danger
//! level so the UI can warn before running disruptive ones.

use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Danger {
    /// Won't crash or disrupt the target.
    Safe,
    /// May be flagged, noisy, or touch authentication / third parties.
    Caution,
    /// Can crash, brute-force, or actively exploit the target.
    Dangerous,
}

pub struct Category {
    pub name: &'static str,
    pub description: &'static str,
    pub danger: Danger,
}

use Danger::*;

/// The standard NSE categories, ordered roughly safest-first.
pub const CATEGORIES: &[Category] = &[
    Category { name: "default", description: "Standard useful scripts (same as -sC)", danger: Safe },
    Category { name: "safe", description: "Won't disrupt or crash the target", danger: Safe },
    Category { name: "discovery", description: "Learn more about hosts and the network", danger: Safe },
    Category { name: "version", description: "Refine version detection (with -sV)", danger: Safe },
    Category { name: "broadcast", description: "Discover hosts by broadcasting", danger: Safe },
    Category { name: "malware", description: "Detect backdoors and malware", danger: Safe },
    Category { name: "auth", description: "Authentication and credential checks", danger: Caution },
    Category { name: "vuln", description: "Check for known vulnerabilities", danger: Caution },
    Category { name: "intrusive", description: "May disrupt the target or be flagged", danger: Caution },
    Category { name: "external", description: "Sends target data to third-party services", danger: Caution },
    Category { name: "brute", description: "Brute-force credentials", danger: Dangerous },
    Category { name: "fuzzer", description: "Send unexpected input (slow, risky)", danger: Dangerous },
    Category { name: "dos", description: "Denial of service — can crash the target!", danger: Dangerous },
    Category { name: "exploit", description: "Actively exploit vulnerabilities", danger: Dangerous },
];

/// CSS class used to colour a category's indicator dot.
pub fn danger_css(danger: Danger) -> &'static str {
    match danger {
        Safe => "danger-safe",
        Caution => "danger-caution",
        Dangerous => "danger-dangerous",
    }
}

/// Locate nmap's scripts directory across common install layouts.
pub fn scripts_dir() -> Option<PathBuf> {
    if let Ok(d) = std::env::var("NMAPDIR") {
        let p = PathBuf::from(d).join("scripts");
        if p.is_dir() {
            return Some(p);
        }
    }
    const CANDIDATES: &[&str] = &[
        "/opt/homebrew/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
        "/usr/share/nmap/scripts",
        "/opt/local/share/nmap/scripts",
    ];
    CANDIDATES.iter().map(PathBuf::from).find(|p| p.is_dir())
}

/// Number of installed `.nse` scripts, if the directory can be found.
pub fn script_count() -> Option<usize> {
    Some(list_scripts().len())
}

/// Sorted names (without the `.nse` extension) of all installed scripts.
pub fn list_scripts() -> Vec<String> {
    let Some(dir) = scripts_dir() else {
        return Vec::new();
    };
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| {
            let path = e.path();
            if path.extension().is_some_and(|x| x == "nse") {
                path.file_stem().and_then(|s| s.to_str()).map(String::from)
            } else {
                None
            }
        })
        .collect();
    names.sort();
    names
}
