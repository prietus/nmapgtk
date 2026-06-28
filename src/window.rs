//! Main window: scan controls, live output, host sidebar and port detail.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gio, glib};

use crate::model::ScanResult;
use crate::{nmap, nse, parser, privilege};

/// Categories the user has ticked in the NSE selector.
type NseSelection = Rc<RefCell<BTreeSet<&'static str>>>;
/// Individual NSE scripts the user has ticked (names without `.nse`).
type NseScripts = Rc<RefCell<BTreeSet<String>>>;

/// A completed scan, kept for the history list and for export.
#[derive(Clone)]
struct ScanRecord {
    command: String,
    result: ScanResult,
    xml: String,
}

/// Shared references to the widgets that scan results need to update.
#[derive(Clone)]
struct Ui {
    stack: gtk::Stack,
    spinner: gtk::Spinner,
    scan_btn: gtk::Button,
    log_view: gtk::TextView,
    hosts_list: gtk::ListBox,
    ports_box: gtk::ListBox,
    target_entry: gtk::Entry,
    command_entry: gtk::Entry,
    detail_title: gtk::Label,
    detail_subtitle: gtk::Label,
    error_status: adw::StatusPage,
    toast: adw::ToastOverlay,
    result: Rc<RefCell<ScanResult>>,
    /// The currently running scan, if any (used to cancel it).
    current_proc: Rc<RefCell<Option<gio::Subprocess>>>,
    /// Set when the user cancels, so completion is treated as a cancel.
    cancelled: Rc<Cell<bool>>,
    /// True while we select a host row programmatically, so the auto-selection
    /// after a scan doesn't overwrite the user's target.
    auto_select: Rc<Cell<bool>>,
    /// Past scans, most recent first.
    history: Rc<RefCell<Vec<ScanRecord>>>,
    history_list: gtk::ListBox,
    history_btn: gtk::MenuButton,
    export_btn: gtk::MenuButton,
    /// Raw nmap XML of the currently displayed scan (for export).
    last_xml: Rc<RefCell<String>>,
}

pub fn build_ui(app: &adw::Application) {
    // --- Scan controls -----------------------------------------------------
    let target_entry = gtk::Entry::builder()
        .placeholder_text("Target  (e.g. scanme.nmap.org  or  192.168.1.0/24)")
        .hexpand(true)
        .build();

    // Profile picker: a MenuButton backed by a sectioned GMenu. The selected
    // index lives in `selected_profile`; a stateful "scan.profile" action drives
    // the radio indicator in the menu.
    let profile_btn = gtk::MenuButton::builder().hexpand(true).build();
    profile_btn.set_always_show_arrow(true);
    profile_btn.set_label(nmap::PROFILES[0].name);
    profile_btn.set_menu_model(Some(&build_profile_menu()));

    let selected_profile = Rc::new(Cell::new(0usize));
    let profile_action =
        gio::SimpleAction::new_stateful("profile", Some(glib::VariantTy::INT32), &0i32.to_variant());
    let action_group = gio::SimpleActionGroup::new();
    action_group.add_action(&profile_action);
    profile_btn.insert_action_group("scan", Some(&action_group));

    // NSE script selector: a MenuButton with a popover of category switches
    // plus a search over the individual installed scripts.
    let nse_selected: NseSelection = Rc::new(RefCell::new(BTreeSet::new()));
    let nse_scripts: NseScripts = Rc::new(RefCell::new(BTreeSet::new()));
    let all_scripts = Rc::new(nse::list_scripts());
    let scripts_btn = gtk::MenuButton::builder().build();
    scripts_btn.set_always_show_arrow(true);
    scripts_btn.set_label("Scripts");

    let root_toggle = gtk::ToggleButton::new();
    root_toggle.set_icon_name("channel-secure-symbolic");
    root_toggle.set_tooltip_text(Some("Run as root (pkexec on Linux)"));

    let scan_btn = gtk::Button::with_label("Scan");
    scan_btn.add_css_class("suggested-action");

    let command_entry = gtk::Entry::builder().hexpand(true).build();
    command_entry.add_css_class("mono");

    // Header bar actions: scan history + export.
    let history_list = gtk::ListBox::new();
    history_list.add_css_class("boxed-list");
    history_list.set_selection_mode(gtk::SelectionMode::None);
    let history_btn = gtk::MenuButton::builder()
        .icon_name("document-open-recent-symbolic")
        .tooltip_text("Scan history")
        .sensitive(false)
        .build();
    let export_btn = gtk::MenuButton::builder()
        .icon_name("document-save-symbolic")
        .tooltip_text("Export results")
        .sensitive(false)
        .build();

    let priv_banner = adw::Banner::builder()
        .title("This scan type needs root privileges")
        .button_label("Run as root")
        .build();

    // --- Result widgets ----------------------------------------------------
    let spinner = gtk::Spinner::new();
    spinner.set_size_request(20, 20);

    let log_view = gtk::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .left_margin(10)
        .right_margin(10)
        .top_margin(8)
        .bottom_margin(8)
        .build();

    let hosts_list = gtk::ListBox::new();
    hosts_list.add_css_class("navigation-sidebar");
    hosts_list.set_selection_mode(gtk::SelectionMode::Single);

    let ports_box = gtk::ListBox::new();
    ports_box.add_css_class("boxed-list");
    ports_box.set_selection_mode(gtk::SelectionMode::None);

    let detail_title = gtk::Label::new(None);
    detail_title.set_xalign(0.0);
    detail_title.add_css_class("title-2");

    let detail_subtitle = gtk::Label::new(None);
    detail_subtitle.set_xalign(0.0);
    detail_subtitle.set_wrap(true);
    detail_subtitle.add_css_class("dim-label");

    // --- Content stack: empty / scanning / results / error -----------------
    let stack = gtk::Stack::new();
    stack.set_transition_type(gtk::StackTransitionType::Crossfade);

    let empty = adw::StatusPage::builder()
        .icon_name("network-wired-symbolic")
        .title("Ready to scan")
        .description("Enter a target, pick a profile and press Scan.")
        .build();
    stack.add_named(&empty, Some("empty"));

    // Live-output page: a header with spinner + a streaming log.
    let scanning = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let scanning_head = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    scanning_head.set_margin_top(12);
    scanning_head.set_margin_bottom(12);
    scanning_head.set_margin_start(16);
    scanning_head.set_margin_end(16);
    scanning_head.append(&spinner);
    let scanning_label = gtk::Label::new(Some("Scanning…"));
    scanning_label.add_css_class("heading");
    scanning_head.append(&scanning_label);
    scanning.append(&scanning_head);
    let log_scroll = gtk::ScrolledWindow::builder()
        .child(&log_view)
        .vexpand(true)
        .margin_start(16)
        .margin_end(16)
        .margin_bottom(16)
        .build();
    log_scroll.add_css_class("card");
    scanning.append(&log_scroll);
    stack.add_named(&scanning, Some("scanning"));

    let results_inner = gtk::Box::new(gtk::Orientation::Vertical, 12);
    results_inner.append(&detail_title);
    results_inner.append(&detail_subtitle);
    results_inner.append(&ports_box);
    let clamp = adw::Clamp::builder()
        .maximum_size(760)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(12)
        .margin_end(12)
        .child(&results_inner)
        .build();
    let results_scroll = gtk::ScrolledWindow::builder()
        .child(&clamp)
        .vexpand(true)
        .build();
    stack.add_named(&results_scroll, Some("results"));

    let error_status = adw::StatusPage::builder()
        .icon_name("dialog-error-symbolic")
        .title("Scan failed")
        .build();
    stack.add_named(&error_status, Some("error"));

    stack.set_visible_child_name("empty");

    let ui = Ui {
        stack: stack.clone(),
        spinner: spinner.clone(),
        scan_btn: scan_btn.clone(),
        log_view: log_view.clone(),
        hosts_list: hosts_list.clone(),
        ports_box: ports_box.clone(),
        target_entry: target_entry.clone(),
        command_entry: command_entry.clone(),
        detail_title: detail_title.clone(),
        detail_subtitle: detail_subtitle.clone(),
        error_status: error_status.clone(),
        toast: adw::ToastOverlay::new(),
        result: Rc::new(RefCell::new(ScanResult::default())),
        current_proc: Rc::new(RefCell::new(None)),
        cancelled: Rc::new(Cell::new(false)),
        auto_select: Rc::new(Cell::new(false)),
        history: Rc::new(RefCell::new(Vec::new())),
        history_list: history_list.clone(),
        history_btn: history_btn.clone(),
        export_btn: export_btn.clone(),
        last_xml: Rc::new(RefCell::new(String::new())),
    };

    // --- Command composition wiring ----------------------------------------
    let programmatic = Rc::new(Cell::new(false));
    let compose: Rc<dyn Fn()> = Rc::new({
        let target = target_entry.clone();
        let selected = selected_profile.clone();
        let nse_cats = nse_selected.clone();
        let nse_scr = nse_scripts.clone();
        let cmd = command_entry.clone();
        let prog = programmatic.clone();
        move || {
            let idx = selected.get();
            let flags = nmap::PROFILES.get(idx).map(|p| p.flags).unwrap_or("");

            let mut parts: Vec<String> = Vec::new();
            if !flags.is_empty() {
                parts.push(flags.to_string());
            }
            let mut script_items: Vec<String> = Vec::new();
            script_items.extend(nse_cats.borrow().iter().map(|s| s.to_string()));
            script_items.extend(nse_scr.borrow().iter().cloned());
            if !script_items.is_empty() {
                parts.push(format!("--script {}", script_items.join(",")));
            }
            let target_text = target.text();
            if !target_text.is_empty() {
                parts.push(target_text.to_string());
            }

            prog.set(true);
            cmd.set_text(&parts.join(" "));
            prog.set(false);
        }
    });

    // Re-evaluate whether the current command needs root, and show the banner.
    let update_banner: Rc<dyn Fn()> = Rc::new({
        let cmd = command_entry.clone();
        let toggle = root_toggle.clone();
        let banner = priv_banner.clone();
        move || {
            let args = shlex::split(&cmd.text()).unwrap_or_default();
            let needs = privilege::needs_privileges(&args);
            banner.set_revealed(needs && !toggle.is_active());
        }
    });

    {
        let compose = compose.clone();
        let prog = programmatic.clone();
        target_entry.connect_changed(move |_| {
            if !prog.get() {
                compose();
            }
        });
    }
    {
        let compose = compose.clone();
        let prog = programmatic.clone();
        let selected = selected_profile.clone();
        let btn = profile_btn.clone();
        // Picking a profile from the menu updates the selection and the command.
        profile_action.connect_activate(move |action, param| {
            let Some(idx) = param.and_then(|v| v.get::<i32>()) else {
                return;
            };
            action.set_state(&idx.to_variant());
            selected.set(idx as usize);
            btn.set_label(nmap::PROFILES[idx as usize].name);
            if !prog.get() {
                compose();
            }
        });
    }
    {
        let prog = programmatic.clone();
        let selected = selected_profile.clone();
        let action = profile_action.clone();
        let btn = profile_btn.clone();
        let update_banner = update_banner.clone();
        // Editing the command by hand switches the profile to "Custom".
        command_entry.connect_changed(move |_| {
            update_banner();
            if prog.get() {
                return;
            }
            prog.set(true);
            selected.set(nmap::CUSTOM_INDEX as usize);
            action.set_state(&(nmap::CUSTOM_INDEX as i32).to_variant());
            btn.set_label(nmap::PROFILES[nmap::CUSTOM_INDEX as usize].name);
            prog.set(false);
        });
    }
    {
        let update_banner = update_banner.clone();
        root_toggle.connect_toggled(move |_| update_banner());
    }
    {
        let toggle = root_toggle.clone();
        priv_banner.connect_button_clicked(move |_| toggle.set_active(true));
    }
    // Wire the NSE popover now that `compose` exists.
    scripts_btn.set_popover(Some(&build_scripts_popover(
        &nse_selected,
        &nse_scripts,
        &all_scripts,
        &scripts_btn,
        &compose,
    )));

    compose(); // seed the command line from the default profile
    update_banner();

    // --- Scan / cancel trigger ---------------------------------------------
    {
        let ui = ui.clone();
        let cmd = command_entry.clone();
        let toggle = root_toggle.clone();
        scan_btn.connect_clicked(move |_| {
            let running = ui.current_proc.borrow().is_some();
            if running {
                ui.cancelled.set(true);
                if let Some(proc) = ui.current_proc.borrow().as_ref() {
                    proc.force_exit();
                }
            } else {
                run_scan(&ui, &cmd.text(), toggle.is_active());
            }
        });
    }
    {
        let btn = scan_btn.clone();
        command_entry.connect_activate(move |_| btn.emit_clicked());
    }
    {
        let btn = scan_btn.clone();
        target_entry.connect_activate(move |_| btn.emit_clicked());
    }

    // --- Host selection updates the port pane ------------------------------
    {
        let ui = ui.clone();
        hosts_list.connect_row_selected(move |_, row| {
            if let Some(row) = row {
                show_host_at(&ui, row.index());
            }
        });
    }

    // --- Layout ------------------------------------------------------------
    // A single centered, clamped form: target / actions / command share the
    // same left & right edges, with equal whitespace on both sides.
    let form = gtk::Box::new(gtk::Orientation::Vertical, 8);
    form.set_margin_top(10);
    form.set_margin_bottom(6);
    form.append(&target_entry);

    let action_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    action_row.append(&profile_btn);
    action_row.append(&scripts_btn);
    action_row.append(&root_toggle);
    action_row.append(&scan_btn);
    form.append(&action_row);

    let command_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let nmap_label = gtk::Label::new(Some("nmap"));
    nmap_label.add_css_class("dim-label");
    nmap_label.add_css_class("mono");
    command_row.append(&nmap_label);
    command_row.append(&command_entry);
    form.append(&command_row);

    let form_clamp = adw::Clamp::builder()
        .maximum_size(680)
        .margin_start(12)
        .margin_end(12)
        .child(&form)
        .build();

    // History popover: a scrollable list of past scans; activating one restores it.
    {
        let ui = ui.clone();
        history_list.connect_row_activated(move |_, row| {
            restore_history(&ui, row.index() as usize);
        });
    }
    let history_scroll = gtk::ScrolledWindow::builder()
        .child(&history_list)
        .propagate_natural_height(true)
        .max_content_height(400)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    let history_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    history_box.set_width_request(360);
    history_box.set_margin_top(8);
    history_box.set_margin_bottom(8);
    history_box.set_margin_start(8);
    history_box.set_margin_end(8);
    history_box.append(&history_scroll);
    history_btn.set_popover(Some(&gtk::Popover::builder().child(&history_box).build()));

    // Export popover: two flat buttons.
    let export_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
    export_box.set_margin_top(6);
    export_box.set_margin_bottom(6);
    export_box.set_margin_start(6);
    export_box.set_margin_end(6);
    let export_xml_btn = gtk::Button::with_label("Save as nmap XML");
    export_xml_btn.add_css_class("flat");
    let export_txt_btn = gtk::Button::with_label("Save as text report");
    export_txt_btn.add_css_class("flat");
    export_box.append(&export_xml_btn);
    export_box.append(&export_txt_btn);
    let export_popover = gtk::Popover::builder().child(&export_box).build();
    export_btn.set_popover(Some(&export_popover));
    {
        let ui = ui.clone();
        let pop = export_popover.clone();
        export_xml_btn.connect_clicked(move |_| {
            pop.popdown();
            export_xml(&ui);
        });
    }
    {
        let ui = ui.clone();
        let pop = export_popover.clone();
        export_txt_btn.connect_clicked(move |_| {
            pop.popdown();
            export_text(&ui);
        });
    }

    let header = adw::HeaderBar::new();
    header.pack_start(&history_btn);
    header.pack_end(&export_btn);

    let content_view = adw::ToolbarView::new();
    content_view.add_top_bar(&header);
    content_view.add_top_bar(&form_clamp);
    content_view.add_top_bar(&priv_banner);
    content_view.set_content(Some(&stack));
    let content_page = adw::NavigationPage::new(&content_view, "Results");

    let sidebar_view = adw::ToolbarView::new();
    let sidebar_header = adw::HeaderBar::new();
    sidebar_header.set_title_widget(Some(&adw::WindowTitle::new("Hosts", "")));
    sidebar_view.add_top_bar(&sidebar_header);
    let sidebar_scroll = gtk::ScrolledWindow::builder()
        .child(&hosts_list)
        .vexpand(true)
        .build();
    sidebar_view.set_content(Some(&sidebar_scroll));
    let sidebar_page = adw::NavigationPage::new(&sidebar_view, "Hosts");

    let split = adw::NavigationSplitView::new();
    split.set_sidebar(Some(&sidebar_page));
    split.set_content(Some(&content_page));
    split.set_min_sidebar_width(260.0);
    split.set_max_sidebar_width(340.0);

    ui.toast.set_child(Some(&split));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("NmapGTK")
        .default_width(1040)
        .default_height(700)
        .content(&ui.toast)
        .build();
    window.present();
}

/// Build a sectioned menu of scan profiles, grouped by consecutive `section`.
fn build_profile_menu() -> gio::Menu {
    let menu = gio::Menu::new();
    let mut i = 0;
    while i < nmap::PROFILES.len() {
        let section_name = nmap::PROFILES[i].section;
        let section = gio::Menu::new();
        while i < nmap::PROFILES.len() && nmap::PROFILES[i].section == section_name {
            let item = gio::MenuItem::new(Some(nmap::PROFILES[i].name), None);
            item.set_action_and_target_value(
                Some("scan.profile"),
                Some(&(i as i32).to_variant()),
            );
            section.append_item(&item);
            i += 1;
        }
        let label = (!section_name.is_empty()).then_some(section_name);
        menu.append_section(label, &section);
    }
    menu
}

/// How many search-result rows to render at once before asking to refine.
const MAX_SCRIPT_RESULTS: usize = 100;

/// Popover with NSE category switches plus a search over individual scripts.
fn build_scripts_popover(
    categories: &NseSelection,
    scripts: &NseScripts,
    all_scripts: &Rc<Vec<String>>,
    scripts_btn: &gtk::MenuButton,
    compose: &Rc<dyn Fn()>,
) -> gtk::Popover {
    let total = {
        let categories = categories.clone();
        let scripts = scripts.clone();
        move || categories.borrow().len() + scripts.borrow().len()
    };

    let content = gtk::Box::new(gtk::Orientation::Vertical, 8);
    content.set_margin_top(12);
    content.set_margin_bottom(12);
    content.set_margin_start(12);
    content.set_margin_end(12);
    content.set_width_request(360);

    let header = gtk::Label::new(Some("NSE scripts"));
    header.set_xalign(0.0);
    header.add_css_class("heading");
    content.append(&header);

    let count_text = match nse::script_count() {
        Some(n) => format!("{n} scripts installed"),
        None => "scripts auto-detected by nmap".to_string(),
    };
    let subtitle = gtk::Label::new(Some(&count_text));
    subtitle.set_xalign(0.0);
    subtitle.add_css_class("dim-label");
    subtitle.add_css_class("caption");
    content.append(&subtitle);

    let search = gtk::SearchEntry::new();
    search.set_placeholder_text(Some("Search individual scripts…"));
    content.append(&search);

    // --- Categories page ---
    let cat_list = gtk::ListBox::new();
    cat_list.add_css_class("boxed-list");
    cat_list.set_selection_mode(gtk::SelectionMode::None);

    let mut cat_rows: Vec<adw::SwitchRow> = Vec::new();
    for cat in nse::CATEGORIES {
        let row = adw::SwitchRow::builder()
            .title(cat.name)
            .subtitle(cat.description)
            .build();
        let dot = gtk::Label::new(Some("●"));
        dot.add_css_class(nse::danger_css(cat.danger));
        dot.set_valign(gtk::Align::Center);
        row.add_prefix(&dot);

        let categories = categories.clone();
        let scripts_btn = scripts_btn.clone();
        let compose = compose.clone();
        let total = total.clone();
        row.connect_active_notify(move |row| {
            {
                let mut set = categories.borrow_mut();
                if row.is_active() {
                    set.insert(cat.name);
                } else {
                    set.remove(cat.name);
                }
            }
            refresh_scripts_label(&scripts_btn, total());
            compose();
        });

        cat_list.append(&row);
        cat_rows.push(row);
    }

    // --- Search results page ---
    let results_list = gtk::ListBox::new();
    results_list.add_css_class("boxed-list");
    results_list.set_selection_mode(gtk::SelectionMode::None);

    let make_page = |child: &gtk::ListBox| {
        gtk::ScrolledWindow::builder()
            .child(child)
            .propagate_natural_height(true)
            .max_content_height(380)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build()
    };

    let stack = gtk::Stack::new();
    stack.add_named(&make_page(&cat_list), Some("categories"));
    stack.add_named(&make_page(&results_list), Some("search"));
    content.append(&stack);

    {
        let all_scripts = all_scripts.clone();
        let scripts = scripts.clone();
        let scripts_btn = scripts_btn.clone();
        let compose = compose.clone();
        let total = total.clone();
        let stack = stack.clone();
        let results_list = results_list.clone();
        search.connect_search_changed(move |entry| {
            clear_list(&results_list);
            let query = entry.text().to_lowercase();
            if query.is_empty() {
                stack.set_visible_child_name("categories");
                return;
            }
            stack.set_visible_child_name("search");

            let mut shown = 0;
            let mut matched = 0;
            for name in all_scripts.iter() {
                if !name.to_lowercase().contains(&query) {
                    continue;
                }
                matched += 1;
                if shown >= MAX_SCRIPT_RESULTS {
                    continue;
                }
                let row = adw::SwitchRow::builder().title(name).build();
                row.set_active(scripts.borrow().contains(name));

                let scripts = scripts.clone();
                let scripts_btn = scripts_btn.clone();
                let compose = compose.clone();
                let total = total.clone();
                let name = name.clone();
                row.connect_active_notify(move |row| {
                    {
                        let mut set = scripts.borrow_mut();
                        if row.is_active() {
                            set.insert(name.clone());
                        } else {
                            set.remove(&name);
                        }
                    }
                    refresh_scripts_label(&scripts_btn, total());
                    compose();
                });

                results_list.append(&row);
                shown += 1;
            }

            if matched == 0 {
                let row = adw::ActionRow::builder().title("No matching scripts").build();
                results_list.append(&row);
            } else if matched > shown {
                let row = adw::ActionRow::builder()
                    .title(format!("…and {} more — refine your search", matched - shown))
                    .build();
                results_list.append(&row);
            }
        });
    }

    // --- Clear all (resets both sets and the search) ---
    let clear = gtk::Button::with_label("Clear all");
    clear.add_css_class("flat");
    clear.set_margin_top(4);
    {
        let scripts = scripts.clone();
        let scripts_btn = scripts_btn.clone();
        let compose = compose.clone();
        let total = total.clone();
        let search = search.clone();
        clear.connect_clicked(move |_| {
            for row in &cat_rows {
                row.set_active(false); // notify handlers update categories + command
            }
            scripts.borrow_mut().clear();
            search.set_text(""); // back to the categories page, clears result rows
            refresh_scripts_label(&scripts_btn, total());
            compose();
        });
    }
    content.append(&clear);

    gtk::Popover::builder().child(&content).build()
}

fn refresh_scripts_label(btn: &gtk::MenuButton, count: usize) {
    if count == 0 {
        btn.set_label("Scripts");
    } else {
        btn.set_label(&format!("Scripts ({count})"));
    }
}

/// Maximum number of scans kept in history.
const MAX_HISTORY: usize = 20;

/// Record a finished scan into history and enable the history/export buttons.
fn record_scan(ui: &Ui, command: &str, xml: &str) {
    let record = ScanRecord {
        command: command.to_string(),
        result: ui.result.borrow().clone(),
        xml: xml.to_string(),
    };
    {
        let mut history = ui.history.borrow_mut();
        history.insert(0, record);
        history.truncate(MAX_HISTORY);
    }
    *ui.last_xml.borrow_mut() = xml.to_string();
    refresh_history(ui);
    ui.history_btn.set_sensitive(true);
    ui.export_btn.set_sensitive(true);
}

fn refresh_history(ui: &Ui) {
    clear_list(&ui.history_list);
    for record in ui.history.borrow().iter() {
        let hosts = record.result.hosts.len();
        let open: usize = record.result.hosts.iter().map(|h| h.open_ports()).sum();
        let row = adw::ActionRow::builder()
            .title(format!("nmap {}", record.command))
            .subtitle(format!("{hosts} host(s) · {open} open ports"))
            .activatable(true)
            .build();
        row.add_css_class("property");
        ui.history_list.append(&row);
    }
}

/// Restore a past scan's results and command line into the views.
fn restore_history(ui: &Ui, idx: usize) {
    let Some(record) = ui.history.borrow().get(idx).cloned() else {
        return;
    };
    *ui.result.borrow_mut() = record.result;
    *ui.last_xml.borrow_mut() = record.xml;
    ui.command_entry.set_text(&record.command);
    populate_hosts(ui);
    ui.history_btn.popdown();
}

fn export_xml(ui: &Ui) {
    let data = ui.last_xml.borrow().clone();
    if data.is_empty() {
        return;
    }
    save_to_file(ui, "scan.xml", "Export nmap XML", data.into_bytes());
}

fn export_text(ui: &Ui) {
    let report = text_report(&ui.result.borrow());
    save_to_file(ui, "scan.txt", "Export text report", report.into_bytes());
}

fn save_to_file(ui: &Ui, initial_name: &str, title: &str, data: Vec<u8>) {
    let dialog = gtk::FileDialog::builder()
        .initial_name(initial_name)
        .title(title)
        .modal(true)
        .build();
    let window = ui.export_btn.root().and_downcast::<gtk::Window>();
    let toast = ui.toast.clone();
    glib::spawn_future_local(async move {
        match dialog.save_future(window.as_ref()).await {
            Ok(file) => {
                if let Some(path) = file.path() {
                    match std::fs::write(&path, &data) {
                        Ok(()) => toast.add_toast(adw::Toast::new(&format!(
                            "Saved to {}",
                            path.display()
                        ))),
                        Err(e) => toast.add_toast(adw::Toast::new(&format!("Save failed: {e}"))),
                    }
                }
            }
            Err(_) => {} // user cancelled the dialog
        }
    });
}

/// Render the current scan as a plain-text report.
fn text_report(result: &ScanResult) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    if !result.summary.is_empty() {
        let _ = writeln!(out, "# {}\n", result.summary);
    }
    for host in &result.hosts {
        let name = match &host.hostname {
            Some(h) => format!("{h} ({})", host.address),
            None => host.address.clone(),
        };
        let _ = writeln!(out, "Host: {name}  [{}]", if host.up { "up" } else { "down" });
        if let Some(os) = &host.os {
            let _ = writeln!(out, "OS:   {os}");
        }
        if host.ports.is_empty() {
            let _ = writeln!(out, "  (no ports reported)");
        } else {
            let _ = writeln!(out, "  {:<10} {:<10} {}", "PORT", "STATE", "SERVICE");
            for p in &host.ports {
                let detail = p.service_detail();
                let svc = if detail.is_empty() {
                    p.service.clone()
                } else {
                    format!("{} ({detail})", p.service)
                };
                let _ = writeln!(
                    out,
                    "  {:<10} {:<10} {}",
                    format!("{}/{}", p.portid, p.protocol),
                    p.state,
                    svc
                );
            }
        }
        out.push('\n');
    }
    out
}

fn run_scan(ui: &Ui, command: &str, elevate: bool) {
    let Some(args) = shlex::split(command) else {
        finish_error(ui, "The command line could not be parsed (unbalanced quotes?).");
        return;
    };

    // nmap writes structured XML to a temp file; its human-readable progress
    // streams over stdout so we can show it live.
    let xml_path = std::env::temp_dir().join(format!("nmapgtk-{}.xml", std::process::id()));

    let mut nmap_argv: Vec<OsString> = Vec::with_capacity(args.len() + 5);
    nmap_argv.push("nmap".into());
    nmap_argv.extend(args.iter().map(OsString::from));
    if !args.iter().any(|a| a == "--stats-every") {
        nmap_argv.push("--stats-every".into());
        nmap_argv.push("2s".into());
    }
    nmap_argv.push("-oX".into());
    nmap_argv.push(xml_path.clone().into_os_string());

    let mut argv: Vec<OsString> = Vec::new();
    if elevate {
        match privilege::elevator() {
            Some(helper) => argv.push(helper.into()),
            None => {
                finish_error(ui, "No privilege-escalation helper available on this platform.");
                return;
            }
        }
    }
    argv.extend(nmap_argv);

    let argv_refs: Vec<&OsStr> = argv.iter().map(OsString::as_os_str).collect();
    let proc = match gio::Subprocess::newv(
        &argv_refs,
        gio::SubprocessFlags::STDOUT_PIPE | gio::SubprocessFlags::STDERR_MERGE,
    ) {
        Ok(p) => p,
        Err(e) => {
            finish_error(ui, &format!("Could not launch scan: {e}"));
            return;
        }
    };

    ui.log_view.buffer().set_text("");
    ui.cancelled.set(false);
    *ui.current_proc.borrow_mut() = Some(proc.clone());
    set_running(ui, true);
    ui.spinner.start();
    ui.stack.set_visible_child_name("scanning");

    let stdout = proc.stdout_pipe();
    let command = command.to_string();
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        // Stream stdout (stderr merged in) line by line into the log view.
        if let Some(stream) = stdout {
            let reader = gio::DataInputStream::new(&stream);
            loop {
                match reader.read_line_utf8_future(glib::Priority::DEFAULT).await {
                    Ok(Some(line)) => append_log(&ui.log_view, &line),
                    Ok(None) => break, // EOF
                    Err(e) => {
                        append_log(&ui.log_view, &format!("[stream error] {e}"));
                        break;
                    }
                }
            }
        }
        let _ = proc.wait_future().await;

        *ui.current_proc.borrow_mut() = None;
        ui.spinner.stop();
        set_running(&ui, false);

        if ui.cancelled.get() {
            ui.toast.add_toast(adw::Toast::new("Scan cancelled"));
            ui.stack.set_visible_child_name("empty");
            let _ = std::fs::remove_file(&xml_path);
            return;
        }

        // The scan finished — parse the XML it left behind.
        match std::fs::read_to_string(&xml_path) {
            Ok(xml) if xml.contains("<nmaprun") => match parser::parse(&xml) {
                Ok(result) => {
                    *ui.result.borrow_mut() = result;
                    populate_hosts(&ui);
                    record_scan(&ui, &command, &xml);
                }
                Err(e) => finish_error(&ui, &format!("Could not parse output: {e}")),
            },
            _ => {
                let log = log_text(&ui.log_view);
                let msg = if log.trim().is_empty() {
                    "nmap produced no output.".to_string()
                } else {
                    log.trim().to_string()
                };
                finish_error(&ui, &msg);
            }
        }
        let _ = std::fs::remove_file(&xml_path);
    });
}

/// Switch the primary button between "Scan" and "Cancel" modes.
fn set_running(ui: &Ui, running: bool) {
    if running {
        ui.scan_btn.set_label("Cancel");
        ui.scan_btn.remove_css_class("suggested-action");
        ui.scan_btn.add_css_class("destructive-action");
    } else {
        ui.scan_btn.set_label("Scan");
        ui.scan_btn.remove_css_class("destructive-action");
        ui.scan_btn.add_css_class("suggested-action");
    }
}

fn populate_hosts(ui: &Ui) {
    clear_list(&ui.hosts_list);

    let result = ui.result.borrow();
    if result.hosts.is_empty() {
        drop(result);
        ui.error_status
            .set_description(Some("No hosts found — they may be down or blocking probes."));
        ui.stack.set_visible_child_name("error");
        return;
    }

    for host in &result.hosts {
        let row = adw::ActionRow::new();
        row.set_title(host.display_name());
        let subtitle = match &host.hostname {
            Some(_) => host.address.clone(),
            None => format!("{} open ports", host.open_ports()),
        };
        row.set_subtitle(&subtitle);

        let dot = gtk::Label::new(Some("●"));
        dot.add_css_class(if host.up { "dot-up" } else { "dot-down" });
        row.add_prefix(&dot);

        let count = gtk::Label::new(Some(&format!("{}", host.open_ports())));
        count.add_css_class("dim-label");
        row.add_suffix(&count);

        ui.hosts_list.append(&row);
    }
    drop(result);

    if let Some(row) = ui.hosts_list.row_at_index(0) {
        // Auto-selecting the first host must not clobber the user's target.
        ui.auto_select.set(true);
        ui.hosts_list.select_row(Some(&row)); // fires show_host_at(0)
        ui.auto_select.set(false);
    }
    let summary = ui.result.borrow().summary.clone();
    if !summary.is_empty() {
        ui.toast.add_toast(adw::Toast::new(&summary));
    }
    ui.stack.set_visible_child_name("results");
}

fn show_host_at(ui: &Ui, idx: i32) {
    let result = ui.result.borrow();
    let Some(host) = result.hosts.get(idx as usize) else {
        return;
    };

    // A deliberate click on a host loads its address into the scan target,
    // ready to drill into it with a deeper profile.
    if !ui.auto_select.get() {
        ui.target_entry.set_text(&host.address);
    }

    ui.detail_title.set_text(host.display_name());
    let mut sub = host.address.clone();
    if let Some(os) = &host.os {
        sub = format!("{sub}  ·  {os}");
    }
    sub = format!("{sub}  ·  {} open ports", host.open_ports());
    ui.detail_subtitle.set_text(&sub);

    clear_list(&ui.ports_box);
    if host.ports.is_empty() {
        let row = adw::ActionRow::new();
        row.set_title("No ports reported");
        ui.ports_box.append(&row);
    }
    for port in &host.ports {
        let row = adw::ActionRow::new();
        row.set_title(&format!("{}/{}", port.portid, port.protocol));

        let detail = port.service_detail();
        let subtitle = match (port.service.as_str(), detail.as_str()) {
            ("", "") => "—".to_string(),
            (svc, "") => svc.to_string(),
            (svc, det) => format!("{svc}  ·  {det}"),
        };
        row.set_subtitle(&subtitle);

        let state = gtk::Label::new(Some(&port.state));
        state.add_css_class("state-pill");
        state.add_css_class(&format!("state-{}", port.state));
        state.set_valign(gtk::Align::Center);
        row.add_suffix(&state);

        ui.ports_box.append(&row);
    }
}

fn finish_error(ui: &Ui, message: &str) {
    ui.error_status.set_description(Some(message));
    ui.stack.set_visible_child_name("error");
}

fn append_log(view: &gtk::TextView, line: &str) {
    let buf = view.buffer();
    let mut end = buf.end_iter();
    buf.insert(&mut end, line);
    buf.insert(&mut end, "\n");
    let mark = buf.create_mark(None, &buf.end_iter(), false);
    view.scroll_mark_onscreen(&mark);
}

fn log_text(view: &gtk::TextView) -> String {
    let buf = view.buffer();
    buf.text(&buf.start_iter(), &buf.end_iter(), false)
        .to_string()
}

fn clear_list(list: &gtk::ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

#[cfg(test)]
mod tests {
    use super::text_report;
    use crate::model::{Host, Port, ScanResult};

    #[test]
    fn text_report_lists_hosts_and_ports() {
        let result = ScanResult {
            summary: "Nmap done: 1 host up".into(),
            hosts: vec![Host {
                address: "10.0.0.1".into(),
                hostname: Some("router".into()),
                up: true,
                os: Some("Linux 5.X".into()),
                ports: vec![
                    Port {
                        portid: 22,
                        protocol: "tcp".into(),
                        state: "open".into(),
                        service: "ssh".into(),
                        product: "OpenSSH".into(),
                        version: "9.6".into(),
                    },
                    Port {
                        portid: 80,
                        protocol: "tcp".into(),
                        state: "closed".into(),
                        service: "http".into(),
                        product: String::new(),
                        version: String::new(),
                    },
                ],
            }],
        };
        let report = text_report(&result);
        assert!(report.contains("# Nmap done: 1 host up"));
        assert!(report.contains("Host: router (10.0.0.1)  [up]"));
        assert!(report.contains("OS:   Linux 5.X"));
        assert!(report.contains("22/tcp"));
        assert!(report.contains("ssh (OpenSSH 9.6)"));
        // A service with no product/version shows just the bare name.
        assert!(report.contains("80/tcp"));
        assert!(report.contains("http"));
    }
}
