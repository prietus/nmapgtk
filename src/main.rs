mod model;
mod nmap;
mod nse;
mod parser;
mod privilege;
mod window;

use gtk::prelude::*;
use gtk::{gdk, glib};

const APP_ID: &str = "org.nmapgtk.NmapGTK";

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
    gtk::Window::set_default_icon_name(APP_ID);

    if let Some(display) = gdk::Display::default() {
        let theme = gtk::IconTheme::for_display(&display);
        let dev_icons = concat!(env!("CARGO_MANIFEST_DIR"), "/data/icons");
        if std::path::Path::new(dev_icons).is_dir() {
            theme.add_search_path(dev_icons);
        }
    }
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
