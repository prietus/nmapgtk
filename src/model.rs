//! Data model produced by parsing nmap XML output.

#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub hosts: Vec<Host>,
    /// Human-readable summary line from nmap's `<finished>` element.
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct Host {
    pub address: String,
    pub hostname: Option<String>,
    pub up: bool,
    pub os: Option<String>,
    pub ports: Vec<Port>,
}

impl Host {
    /// Hostname when known, otherwise the raw address.
    pub fn display_name(&self) -> &str {
        self.hostname.as_deref().unwrap_or(&self.address)
    }

    pub fn open_ports(&self) -> usize {
        self.ports.iter().filter(|p| p.state == "open").count()
    }
}

#[derive(Debug, Clone)]
pub struct Port {
    pub portid: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub product: String,
    pub version: String,
}

impl Port {
    /// e.g. "OpenSSH 9.6p1" — empty when nmap didn't fingerprint the service.
    pub fn service_detail(&self) -> String {
        let mut s = String::new();
        if !self.product.is_empty() {
            s.push_str(&self.product);
        }
        if !self.version.is_empty() {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(&self.version);
        }
        s
    }
}
