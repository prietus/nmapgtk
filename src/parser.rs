//! Parse nmap's XML output (`-oX -`) into our [`ScanResult`] model.

use crate::model::{Host, Port, ScanResult};
use roxmltree::{Document, Node, ParsingOptions};

pub fn parse(xml: &str) -> Result<ScanResult, String> {
    // nmap output always carries a `<!DOCTYPE nmaprun>`, which roxmltree
    // rejects unless DTDs are explicitly allowed.
    let opts = ParsingOptions {
        allow_dtd: true,
        ..ParsingOptions::default()
    };
    let doc = Document::parse_with_options(xml, opts).map_err(|e| e.to_string())?;
    let root = doc.root_element();

    let mut hosts = Vec::new();
    for host_node in root.children().filter(|n| n.has_tag_name("host")) {
        hosts.push(parse_host(host_node));
    }

    let summary = root
        .descendants()
        .find(|n| n.has_tag_name("finished"))
        .and_then(|n| n.attribute("summary"))
        .unwrap_or_default()
        .to_string();

    Ok(ScanResult { hosts, summary })
}

fn parse_host(node: Node) -> Host {
    let up = node
        .children()
        .find(|n| n.has_tag_name("status"))
        .and_then(|n| n.attribute("state"))
        .map(|s| s == "up")
        .unwrap_or(false);

    // Prefer a routable IP over a MAC address.
    let address = node
        .children()
        .filter(|n| n.has_tag_name("address"))
        .find(|n| matches!(n.attribute("addrtype"), Some("ipv4") | Some("ipv6")))
        .or_else(|| node.children().find(|n| n.has_tag_name("address")))
        .and_then(|n| n.attribute("addr"))
        .unwrap_or("?")
        .to_string();

    let hostname = node
        .children()
        .find(|n| n.has_tag_name("hostnames"))
        .and_then(|hn| hn.children().find(|n| n.has_tag_name("hostname")))
        .and_then(|n| n.attribute("name"))
        .map(|s| s.to_string());

    let os = node
        .children()
        .find(|n| n.has_tag_name("os"))
        .and_then(|osn| osn.children().find(|n| n.has_tag_name("osmatch")))
        .and_then(|n| n.attribute("name"))
        .map(|s| s.to_string());

    let mut ports = Vec::new();
    if let Some(ports_node) = node.children().find(|n| n.has_tag_name("ports")) {
        for p in ports_node.children().filter(|n| n.has_tag_name("port")) {
            ports.push(parse_port(p));
        }
    }

    Host {
        address,
        hostname,
        up,
        os,
        ports,
    }
}

fn parse_port(node: Node) -> Port {
    let portid = node
        .attribute("portid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let protocol = node.attribute("protocol").unwrap_or_default().to_string();

    let state = node
        .children()
        .find(|n| n.has_tag_name("state"))
        .and_then(|n| n.attribute("state"))
        .unwrap_or_default()
        .to_string();

    let svc = node.children().find(|n| n.has_tag_name("service"));
    let service = svc
        .and_then(|n| n.attribute("name"))
        .unwrap_or_default()
        .to_string();
    let product = svc
        .and_then(|n| n.attribute("product"))
        .unwrap_or_default()
        .to_string();
    let version = svc
        .and_then(|n| n.attribute("version"))
        .unwrap_or_default()
        .to_string();

    Port {
        portid,
        protocol,
        state,
        service,
        product,
        version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.99">
<hosthint><status state="up"/><address addr="45.33.32.156" addrtype="ipv4"/></hosthint>
<host>
<status state="up" reason="conn-refused"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
<hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6p1"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/></port>
</ports>
<os><osmatch name="Linux 5.X"/></os>
</host>
<runstats><finished summary="Nmap done: 1 host up"/></runstats>
</nmaprun>"#;

    #[test]
    fn parses_host_and_ports() {
        let r = parse(SAMPLE).expect("parse ok");
        assert_eq!(r.hosts.len(), 1, "hosthint must not be counted as a host");

        let h = &r.hosts[0];
        assert!(h.up);
        assert_eq!(h.address, "45.33.32.156"); // prefers ipv4 over mac
        assert_eq!(h.hostname.as_deref(), Some("scanme.nmap.org"));
        assert_eq!(h.display_name(), "scanme.nmap.org");
        assert_eq!(h.os.as_deref(), Some("Linux 5.X"));
        assert_eq!(h.open_ports(), 2);

        assert_eq!(h.ports.len(), 3);
        assert_eq!(h.ports[0].portid, 22);
        assert_eq!(h.ports[0].service_detail(), "OpenSSH 9.6p1");
        assert_eq!(h.ports[1].service_detail(), "Apache httpd");
        assert_eq!(h.ports[2].state, "filtered");

        assert_eq!(r.summary, "Nmap done: 1 host up");
    }
}
