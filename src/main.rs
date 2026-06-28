mod model;
mod nmap;
mod nse;
mod parser;
mod privilege;
mod window;

use gtk::prelude::*;
use gtk::{gdk, glib};

pub const APP_ID: &str = "io.github.nmapgtk";

fn main() -> glib::ExitCode {
    let app = adw::Application::builder()
        .application_id(APP_ID)
        .build();

    app.connect_startup(|_| {
        load_css();
        setup_icons();
    });
    app.connect_activate(window::build_ui);
    app.run()
}

/// Make the bundled application icon discoverable by GTK.
///
/// Windows are told to use the themed icon named after the app ID. When running
/// from a source checkout the system icon theme doesn't know about us yet, so we
/// also register the in-tree `data/icons` directory; an installed copy is found
/// via the standard `share/icons/hicolor` search path instead.
fn setup_icons() {
    if let Some(display) = gdk::Display::default() {
        let theme = gtk::IconTheme::for_display(&display);
        for path in icon_search_paths() {
            theme.add_search_path(path);
        }
    }
    gtk::Window::set_default_icon_name(APP_ID);
}

/// Directories to probe for `data/icons` when running uninstalled (dev builds):
/// relative to the current working directory, and relative to the project root
/// derived from the running binary (`target/<profile>/nmapgtk`).
fn icon_search_paths() -> Vec<std::path::PathBuf> {
    let mut paths = vec![std::path::PathBuf::from("data/icons")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(root) = exe.ancestors().nth(3) {
            paths.push(root.join("data/icons"));
        }
    }
    paths
}

fn load_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_string(include_str!("style.css"));
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}
