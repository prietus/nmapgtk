//! Scan profiles, modelled loosely after Zenmap's presets.
//!
//! Note: profiles using `-A`, `-O` or SYN scans require root privileges
//! (on macOS, run the app with `sudo`). The plain connect-scan profiles
//! work as a regular user.

pub struct Profile {
    pub name: &'static str,
    pub flags: &'static str,
    /// Section header this profile is grouped under in the menu
    /// (empty string = no header).
    pub section: &'static str,
}

pub const PROFILES: &[Profile] = &[
    Profile {
        name: "Quick scan",
        flags: "-T4 -F",
        section: "Quick",
    },
    Profile {
        name: "Quick scan plus",
        flags: "-sV -T4 -F --version-light",
        section: "Quick",
    },
    Profile {
        name: "TCP connect scan (no root)",
        flags: "-sT -T4 -F",
        section: "Quick",
    },
    Profile {
        name: "Intense scan",
        flags: "-T4 -A -v",
        section: "Thorough",
    },
    Profile {
        name: "Intense scan, all TCP ports",
        flags: "-p 1-65535 -T4 -A -v",
        section: "Thorough",
    },
    Profile {
        name: "Intense scan, no ping",
        flags: "-T4 -A -v -Pn",
        section: "Thorough",
    },
    Profile {
        name: "Intense scan plus UDP",
        flags: "-sS -sU -T4 -A -v",
        section: "Thorough",
    },
    Profile {
        name: "SYN stealth scan",
        flags: "-sS -T4",
        section: "Targeted",
    },
    Profile {
        name: "UDP scan",
        flags: "-sU -T4 -F",
        section: "Targeted",
    },
    Profile {
        name: "Service + version detection",
        flags: "-sV",
        section: "Targeted",
    },
    Profile {
        name: "OS detection",
        flags: "-O",
        section: "Targeted",
    },
    Profile {
        name: "Default scripts (safe)",
        flags: "-sV -sC",
        section: "Scripts (NSE)",
    },
    Profile {
        name: "Vulnerability scan",
        flags: "-sV --script vuln",
        section: "Scripts (NSE)",
    },
    Profile {
        name: "Ping scan (host discovery)",
        flags: "-sn",
        section: "Discovery",
    },
    Profile {
        name: "List scan (no packets)",
        flags: "-sL",
        section: "Discovery",
    },
    Profile {
        name: "Traceroute",
        flags: "-sn --traceroute",
        section: "Discovery",
    },
    Profile {
        name: "Regular scan",
        flags: "",
        section: "",
    },
    Profile {
        name: "Custom",
        flags: "",
        section: "",
    },
];

/// Index of the trailing "Custom" profile.
pub const CUSTOM_INDEX: u32 = (PROFILES.len() - 1) as u32;
