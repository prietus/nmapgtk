# NmapGTK

A modern, visually pleasant [nmap](https://nmap.org) frontend built with Rust,
GTK4 and libadwaita — deliberately *not* like Zenmap.

NmapGTK wraps the `nmap` command-line scanner in a clean GNOME-style interface:
pick a scan profile (or hand-edit the command), watch the scan stream live, and
browse the results as a structured host/port table instead of raw text.

## Features

- **Scan profiles** — a sectioned menu of ready-made profiles (Quick, Thorough,
  Targeted, Scripts, Discovery) that compose the command for you.
- **Editable command line** — tweak the generated `nmap` invocation by hand;
  the profile flips to *Custom* automatically.
- **Live streaming output** — scan progress (`--stats-every`) and nmap's output
  stream into a log view while the scan runs.
- **Structured results** — results are parsed from nmap's XML into a host
  sidebar (up/down indicator) and a per-host port table with coloured
  open/closed/filtered state pills.
- **NSE script support** — pick whole NSE *categories* (with safe / caution /
  dangerous colour coding) or search and select individual installed scripts;
  both feed the `--script` flag.
- **Privilege handling** — a *Root* toggle prepends an elevator (`pkexec` on
  Linux, `sudo` on macOS) for scans that need raw sockets, and a banner warns
  when a privileged scan is selected without it.
- **Cancel** — a running scan can be stopped from the same button.
- **History & export** — recent scans are kept and can be restored; results can
  be exported as raw nmap XML or a plain-text report.

## Requirements

- A Rust toolchain (2021 edition).
- GTK4 and libadwaita development libraries.
- `nmap` installed and on your `PATH`. NSE scripts ship bundled with nmap; the
  scripts directory is auto-detected (or set via `$NMAPDIR`).

On macOS (Homebrew):

```sh
brew install gtk4 libadwaita nmap
```

On Debian/Ubuntu:

```sh
sudo apt install libgtk-4-dev libadwaita-1-dev nmap
```

## Building and running

```sh
cargo run
```

To run the test suite (XML parser and text-report rendering):

```sh
cargo test
```

### Installing on Linux

A `Makefile` installs the release binary, the `.desktop` launcher and the
application icon into the standard locations (and refreshes the icon/desktop
caches):

```sh
sudo make install              # into /usr/local
make install PREFIX=~/.local   # or a per-user prefix
```

The icon ships as PNGs in the `hicolor` theme under `data/icons/`; when running
straight from the source tree (`cargo run`) that directory is registered
automatically so the window still shows the icon without installing.

## Privileges

Some scan types — SYN stealth (`-sS`), UDP (`-sU`), OS detection (`-O`),
`-A`, `--traceroute` and friends — need raw-socket access and therefore root.
Enable the **Root** toggle to run nmap through `pkexec` (Linux) or `sudo`
(macOS). On macOS a GUI `sudo` cannot prompt for a password, so for those scans
either pre-cache credentials, configure an askpass helper, or launch from a
terminal with `sudo`.

## Architecture

| Module        | Responsibility                                              |
| ------------- | ----------------------------------------------------------- |
| `model.rs`    | `Host` / `Port` / `ScanResult` data types                   |
| `parser.rs`   | nmap XML → model (via `roxmltree`)                           |
| `nmap.rs`     | scan profiles, each tagged with a section                   |
| `nse.rs`      | NSE categories, danger levels, scripts-directory discovery  |
| `privilege.rs`| privileged-flag detection and elevator selection            |
| `window.rs`   | the libadwaita UI and scan orchestration                    |

nmap runs as a `gio::Subprocess` on the GLib main loop: XML is written to a
temporary file (`-oX`) and parsed on exit, while human-readable progress streams
over stdout.

## License

[MIT](LICENSE)
