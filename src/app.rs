use std::collections::HashSet;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Align2, Color32, FontId, Frame, Id, Layout, Margin, RichText, ScrollArea, Sense,
    Stroke, TextEdit, Vec2,
};
use serde::{Deserialize, Serialize};

use crate::controller;
use crate::domain::{RiskLevel, SourceKind, SourceLocator, StartupEntry};
use crate::platform;
use crate::scan::{self, WorkerEvent};
use crate::{APP_NAME, APP_VERSION};

const PREFERENCES_KEY: &str = "win-startup-manager.preferences";
const EVENT_QUEUE_CAPACITY: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ThemeMode {
    Dark,
    Light,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Preferences {
    theme: ThemeMode,
    show_windows_items: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Dark,
            show_windows_items: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewFilter {
    All,
    Enabled,
    Disabled,
    Attention,
    Source(SourceKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Name,
    Source,
    Status,
}

impl SortMode {
    const fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Source => "Source",
            Self::Status => "Status",
        }
    }
}

#[derive(Debug, Clone)]
struct ScanWarning {
    source: SourceKind,
    message: String,
}

#[derive(Debug, Clone)]
enum Dialog {
    Confirm {
        entry: StartupEntry,
        desired_enabled: bool,
    },
    AdministratorRequired {
        entry: StartupEntry,
        desired_enabled: bool,
    },
    About,
    Warnings,
}

#[derive(Debug, Clone)]
struct Toast {
    message: String,
    error: bool,
    created: Instant,
}

#[derive(Clone, Copy)]
struct Palette {
    background: Color32,
    sidebar: Color32,
    surface: Color32,
    surface_hover: Color32,
    border: Color32,
    text: Color32,
    muted: Color32,
    accent: Color32,
    accent_soft: Color32,
    green: Color32,
    green_soft: Color32,
    amber: Color32,
    amber_soft: Color32,
    red: Color32,
    red_soft: Color32,
}

impl Palette {
    fn for_theme(theme: ThemeMode) -> Self {
        match theme {
            ThemeMode::Dark => Self {
                background: Color32::from_rgb(12, 16, 23),
                sidebar: Color32::from_rgb(16, 21, 30),
                surface: Color32::from_rgb(23, 29, 40),
                surface_hover: Color32::from_rgb(29, 37, 50),
                border: Color32::from_rgb(43, 53, 69),
                text: Color32::from_rgb(239, 243, 250),
                muted: Color32::from_rgb(145, 157, 177),
                accent: Color32::from_rgb(116, 104, 255),
                accent_soft: Color32::from_rgb(43, 40, 92),
                green: Color32::from_rgb(63, 210, 143),
                green_soft: Color32::from_rgb(25, 66, 54),
                amber: Color32::from_rgb(246, 187, 72),
                amber_soft: Color32::from_rgb(72, 57, 28),
                red: Color32::from_rgb(248, 106, 110),
                red_soft: Color32::from_rgb(75, 34, 40),
            },
            ThemeMode::Light => Self {
                background: Color32::from_rgb(244, 246, 250),
                sidebar: Color32::from_rgb(250, 251, 253),
                surface: Color32::WHITE,
                surface_hover: Color32::from_rgb(246, 248, 252),
                border: Color32::from_rgb(221, 226, 235),
                text: Color32::from_rgb(28, 34, 45),
                muted: Color32::from_rgb(102, 113, 132),
                accent: Color32::from_rgb(91, 76, 230),
                accent_soft: Color32::from_rgb(232, 229, 255),
                green: Color32::from_rgb(20, 157, 98),
                green_soft: Color32::from_rgb(224, 247, 237),
                amber: Color32::from_rgb(184, 119, 12),
                amber_soft: Color32::from_rgb(255, 243, 214),
                red: Color32::from_rgb(208, 65, 72),
                red_soft: Color32::from_rgb(255, 231, 232),
            },
        }
    }
}

pub struct StartupManagerApp {
    entries: Vec<StartupEntry>,
    sender: SyncSender<WorkerEvent>,
    receiver: Receiver<WorkerEvent>,
    scan_generation: u64,
    scanning: bool,
    active_providers: HashSet<SourceKind>,
    completed_providers: HashSet<SourceKind>,
    warnings: Vec<ScanWarning>,
    view: ViewFilter,
    sort: SortMode,
    search: String,
    selected_id: Option<String>,
    mutation_id: Option<String>,
    dialog: Option<Dialog>,
    toast: Option<Toast>,
    preferences: Preferences,
    elevated: bool,
    logo_texture: egui::TextureHandle,
}

impl StartupManagerApp {
    pub fn new(creation_context: &eframe::CreationContext<'_>) -> Self {
        let detected_theme = if creation_context.egui_ctx.theme() == egui::Theme::Dark {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        };
        let preferences = creation_context
            .storage
            .and_then(|storage| eframe::get_value::<Preferences>(storage, PREFERENCES_KEY))
            .unwrap_or(Preferences {
                theme: detected_theme,
                ..Preferences::default()
            });
        apply_theme(&creation_context.egui_ctx, preferences.theme);

        let logo_side = 256;
        let logo_rgba = crate::icon::app_icon_rgba(logo_side as u32);
        let logo_texture = creation_context.egui_ctx.load_texture(
            "wsm-logo",
            egui::ColorImage::from_rgba_unmultiplied([logo_side, logo_side], &logo_rgba),
            egui::TextureOptions::LINEAR,
        );

        let (sender, receiver) = sync_channel(EVENT_QUEUE_CAPACITY);
        let mut app = Self {
            entries: Vec::new(),
            sender,
            receiver,
            scan_generation: 0,
            scanning: false,
            active_providers: HashSet::new(),
            completed_providers: HashSet::new(),
            warnings: Vec::new(),
            view: ViewFilter::All,
            sort: SortMode::Name,
            search: String::new(),
            selected_id: None,
            mutation_id: None,
            dialog: None,
            toast: None,
            preferences,
            elevated: platform::is_process_elevated(),
            logo_texture,
        };
        app.start_scan(&creation_context.egui_ctx);
        app
    }

    fn start_scan(&mut self, context: &egui::Context) {
        if self.scanning {
            return;
        }
        self.scan_generation = self.scan_generation.wrapping_add(1);
        self.scanning = true;
        self.active_providers.clear();
        self.completed_providers.clear();
        self.warnings.clear();
        scan::spawn_scan(self.scan_generation, self.sender.clone(), context.clone());
    }

    fn process_worker_events(&mut self, context: &egui::Context) {
        let events: Vec<_> = self.receiver.try_iter().collect();
        let mut refresh_after_mutation = false;
        for event in events {
            match event {
                WorkerEvent::ProviderStarted { generation, source }
                    if generation == self.scan_generation =>
                {
                    self.active_providers.insert(source);
                }
                WorkerEvent::ProviderFinished {
                    generation,
                    source,
                    mut entries,
                    warnings,
                } if generation == self.scan_generation => {
                    self.entries.retain(|entry| entry.source != source);
                    self.entries.append(&mut entries);
                    self.sort_entries();
                    self.active_providers.remove(&source);
                    self.completed_providers.insert(source);
                    self.warnings.extend(
                        warnings
                            .into_iter()
                            .map(|message| ScanWarning { source, message }),
                    );
                }
                WorkerEvent::ScanFinished { generation } if generation == self.scan_generation => {
                    self.scanning = false;
                    self.active_providers.clear();
                    if self.entries.is_empty() {
                        self.toast("No startup entries were found.", false);
                    }
                }
                WorkerEvent::MutationFinished {
                    entry_id,
                    desired_enabled,
                    result,
                } => {
                    self.mutation_id = None;
                    match result {
                        Ok(()) => {
                            self.toast(
                                if desired_enabled {
                                    "Startup entry restored."
                                } else {
                                    "Startup entry will no longer start automatically."
                                },
                                false,
                            );
                            if self.selected_id.as_deref() == Some(&entry_id) {
                                self.selected_id = None;
                            }
                            refresh_after_mutation = true;
                        }
                        Err(error) => self.toast(error, true),
                    }
                }
                _ => {}
            }
        }
        if refresh_after_mutation {
            self.scanning = false;
            self.start_scan(context);
        }
    }

    fn sort_entries(&mut self) {
        match self.sort {
            SortMode::Name => self
                .entries
                .sort_by_cached_key(|entry| entry.name.to_lowercase()),
            SortMode::Source => self
                .entries
                .sort_by_cached_key(|entry| (entry.source.label(), entry.name.to_lowercase())),
            SortMode::Status => self
                .entries
                .sort_by_cached_key(|entry| (!entry.enabled, entry.name.to_lowercase())),
        }
    }

    fn toast(&mut self, message: impl Into<String>, error: bool) {
        self.toast = Some(Toast {
            message: message.into(),
            error,
            created: Instant::now(),
        });
    }

    fn visible_indices(&self) -> Vec<usize> {
        let query = self.search.trim().to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| self.preferences.show_windows_items || !entry.is_system)
            .filter(|(_, entry)| match self.view {
                ViewFilter::All => true,
                ViewFilter::Enabled => entry.enabled,
                ViewFilter::Disabled => !entry.enabled,
                ViewFilter::Attention => needs_attention(entry),
                ViewFilter::Source(source) => entry.source == source,
            })
            .filter(|(_, entry)| query.is_empty() || entry.search_text().contains(&query))
            .map(|(index, _)| index)
            .collect()
    }

    fn universe_entries(&self) -> impl Iterator<Item = &StartupEntry> {
        self.entries
            .iter()
            .filter(|entry| self.preferences.show_windows_items || !entry.is_system)
    }

    fn request_toggle(
        &mut self,
        context: &egui::Context,
        entry: StartupEntry,
        desired_enabled: bool,
    ) {
        if self.mutation_id.is_some() || !entry.can_toggle {
            return;
        }
        if entry.requires_admin && !self.elevated {
            self.dialog = Some(Dialog::AdministratorRequired {
                entry,
                desired_enabled,
            });
            return;
        }
        let needs_confirmation = entry.risk != RiskLevel::Normal
            || entry.source == SourceKind::ScheduledTask
            || !desired_enabled;
        if needs_confirmation {
            self.dialog = Some(Dialog::Confirm {
                entry,
                desired_enabled,
            });
        } else {
            self.begin_mutation(context, entry, desired_enabled);
        }
    }

    fn begin_mutation(
        &mut self,
        context: &egui::Context,
        entry: StartupEntry,
        desired_enabled: bool,
    ) {
        self.mutation_id = Some(entry.id.clone());
        controller::spawn_set_enabled(entry, desired_enabled, self.sender.clone(), context.clone());
    }

    fn sidebar(&mut self, root_ui: &mut egui::Ui, palette: Palette) {
        egui::Panel::left("navigation")
            .exact_size(224.0)
            .frame(
                Frame::new()
                    .fill(palette.sidebar)
                    .inner_margin(Margin::same(16))
                    .stroke(Stroke::new(1.0, palette.border)),
            )
            .show(root_ui, |ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add(egui::Image::new((
                        self.logo_texture.id(),
                        Vec2::splat(48.0),
                    )));
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Win Startup")
                                .size(16.0)
                                .strong()
                                .color(palette.text),
                        );
                        ui.label(RichText::new("MANAGER").size(9.0).color(palette.muted));
                    });
                });
                ui.add_space(28.0);

                ui.label(
                    RichText::new("OVERVIEW")
                        .size(10.0)
                        .strong()
                        .color(palette.muted),
                );
                ui.add_space(6.0);
                self.nav_item(
                    ui,
                    palette,
                    ViewFilter::All,
                    "All startup items",
                    self.count_for(ViewFilter::All),
                );
                self.nav_item(
                    ui,
                    palette,
                    ViewFilter::Enabled,
                    "Enabled",
                    self.count_for(ViewFilter::Enabled),
                );
                self.nav_item(
                    ui,
                    palette,
                    ViewFilter::Disabled,
                    "Prevented",
                    self.count_for(ViewFilter::Disabled),
                );
                self.nav_item(
                    ui,
                    palette,
                    ViewFilter::Attention,
                    "Needs attention",
                    self.count_for(ViewFilter::Attention),
                );

                ui.add_space(22.0);
                ui.label(
                    RichText::new("STARTS VIA")
                        .size(10.0)
                        .strong()
                        .color(palette.muted),
                );
                ui.add_space(6.0);
                for source in SourceKind::ALL {
                    self.nav_item(
                        ui,
                        palette,
                        ViewFilter::Source(source),
                        source.label(),
                        self.count_for(ViewFilter::Source(source)),
                    );
                }

                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    ui.add_space(4.0);
                    if ui
                        .add(
                            egui::Button::new(RichText::new("About & safety").color(palette.muted))
                                .frame(false),
                        )
                        .clicked()
                    {
                        self.dialog = Some(Dialog::About);
                    }
                    ui.horizontal(|ui| {
                        let changed = ui
                            .checkbox(
                                &mut self.preferences.show_windows_items,
                                RichText::new("Show Windows items").color(palette.muted),
                            )
                            .changed();
                        if changed {
                            self.selected_id = None;
                        }
                    });
                    ui.add_space(6.0);
                });
            });
    }

    fn nav_item(
        &mut self,
        ui: &mut egui::Ui,
        palette: Palette,
        filter: ViewFilter,
        label: &str,
        count: usize,
    ) {
        let selected = self.view == filter;
        let text_color = if selected {
            palette.text
        } else {
            palette.muted
        };
        let response = ui.add_sized(
            [ui.available_width(), 36.0],
            egui::Button::new(
                RichText::new(format!("{label}    {count}"))
                    .size(13.0)
                    .color(text_color),
            )
            .fill(if selected {
                palette.accent_soft
            } else {
                Color32::TRANSPARENT
            })
            .stroke(Stroke::NONE)
            .corner_radius(9.0),
        );
        if response.clicked() {
            self.view = filter;
        }
    }

    fn count_for(&self, filter: ViewFilter) -> usize {
        self.universe_entries()
            .filter(|entry| match filter {
                ViewFilter::All => true,
                ViewFilter::Enabled => entry.enabled,
                ViewFilter::Disabled => !entry.enabled,
                ViewFilter::Attention => needs_attention(entry),
                ViewFilter::Source(source) => entry.source == source,
            })
            .count()
    }

    fn details_panel(&mut self, root_ui: &mut egui::Ui, palette: Palette) {
        let Some(entry) = self
            .selected_id
            .as_ref()
            .and_then(|id| self.entries.iter().find(|entry| &entry.id == id))
            .cloned()
        else {
            return;
        };

        let context = root_ui.ctx().clone();
        egui::Panel::right("entry-details")
            .default_size(360.0)
            .min_size(310.0)
            .max_size(460.0)
            .resizable(true)
            .frame(
                Frame::new()
                    .fill(palette.sidebar)
                    .inner_margin(Margin::same(20))
                    .stroke(Stroke::new(1.0, palette.border)),
            )
            .show(root_ui, |ui| {
                egui::Sides::new().height(32.0).show(
                    ui,
                    |ui| {
                        ui.label(
                            RichText::new("Details")
                                .size(18.0)
                                .strong()
                                .color(palette.text),
                        );
                    },
                    |ui| {
                        if ui.button("Close").clicked() {
                            self.selected_id = None;
                        }
                    },
                );
                ui.add_space(20.0);
                source_avatar(ui, palette, entry.source, 52.0);
                ui.add_space(12.0);
                ui.label(
                    RichText::new(&entry.name)
                        .size(21.0)
                        .strong()
                        .color(palette.text),
                );
                if let Some(publisher) = &entry.publisher {
                    ui.label(RichText::new(publisher).size(12.0).color(palette.muted));
                }
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    chip(
                        ui,
                        palette,
                        entry.source.short_label(),
                        palette.accent,
                        palette.accent_soft,
                    );
                    chip(
                        ui,
                        palette,
                        entry.trigger.label(),
                        palette.muted,
                        palette.surface_hover,
                    );
                    status_chip(ui, palette, &entry);
                });

                ui.add_space(20.0);
                detail_section(ui, palette, "STARTUP COMMAND", &entry.command, true);
                detail_section(
                    ui,
                    palette,
                    "SOURCE LOCATION",
                    &entry.source_location(),
                    true,
                );
                detail_section(ui, palette, "SCOPE", entry.scope.label(), false);
                if let Some(description) = &entry.description {
                    detail_section(ui, palette, "WHAT THIS MEANS", description, false);
                }
                if entry.target_exists == Some(false) {
                    Frame::new()
                        .fill(palette.amber_soft)
                        .corner_radius(10.0)
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new("Target file not found")
                                    .strong()
                                    .color(palette.amber),
                            );
                            ui.label(
                                RichText::new("This may be a leftover startup entry.")
                                    .size(12.0)
                                    .color(palette.text),
                            );
                        });
                    ui.add_space(12.0);
                }

                ui.horizontal_wrapped(|ui| {
                    if ui.button("Copy command").clicked() {
                        ui.ctx().copy_text(entry.command.clone());
                        self.toast("Command copied.", false);
                    }
                    let reveal_path = match &entry.locator {
                        SourceLocator::StartupFolder { path, .. } => Some(path.as_path()),
                        _ => entry.display_executable(),
                    };
                    if let Some(path) = reveal_path
                        && ui.button("Reveal file").clicked()
                        && let Err(error) = platform::reveal_in_explorer(path)
                    {
                        self.toast(error.to_string(), true);
                    }
                });

                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    let busy = self.mutation_id.as_deref() == Some(&entry.id);
                    let label = if busy {
                        "Applying…"
                    } else if entry.enabled {
                        "Prevent automatic startup"
                    } else {
                        "Restore automatic startup"
                    };
                    let button =
                        egui::Button::new(RichText::new(label).strong().color(Color32::WHITE))
                            .fill(if entry.enabled {
                                palette.red
                            } else {
                                palette.accent
                            })
                            .corner_radius(10.0);
                    if ui
                        .add_enabled(entry.can_toggle && !busy, button)
                        .on_disabled_hover_text(protection_reason(&entry))
                        .clicked()
                    {
                        self.request_toggle(&context, entry.clone(), !entry.enabled);
                    }
                    ui.add_space(8.0);
                    if entry.requires_admin {
                        ui.label(
                            RichText::new("Administrator permission is required for this source.")
                                .size(11.0)
                                .color(palette.muted),
                        );
                    }
                });
            });
    }

    fn central_panel(&mut self, root_ui: &mut egui::Ui, palette: Palette) {
        let context = root_ui.ctx().clone();
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(palette.background)
                    .inner_margin(Margin::same(24)),
            )
            .show(root_ui, |ui| {
                self.header(ui, &context, palette);
                ui.add_space(18.0);
                if !self.warnings.is_empty() {
                    self.warning_banner(ui, palette);
                    ui.add_space(14.0);
                }
                self.summary_cards(ui, palette);
                ui.add_space(20.0);
                self.list_header(ui, palette);
                ui.add_space(10.0);
                self.entries_list(ui, &context, palette);
            });
    }

    fn header(&mut self, ui: &mut egui::Ui, context: &egui::Context, palette: Palette) {
        let heading = match self.view {
            ViewFilter::All => "Your startup, finally visible",
            ViewFilter::Enabled => "Enabled startup items",
            ViewFilter::Disabled => "Prevented startup items",
            ViewFilter::Attention => "Items that need attention",
            ViewFilter::Source(source) => source.label(),
        };
        egui::Sides::new()
            .height(56.0)
            .shrink_left()
            .truncate()
            .show(
                ui,
                |ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(heading)
                                .size(24.0)
                                .strong()
                                .color(palette.text),
                        );
                        ui.label(
                            RichText::new(
                                "See what launches, where it hides, and stay in control.",
                            )
                            .size(12.0)
                            .color(palette.muted),
                        );
                    });
                },
                |ui| {
                    let refresh = ui.add_enabled(
                        !self.scanning && self.mutation_id.is_none(),
                        egui::Button::new(if self.scanning {
                            "Scanning…"
                        } else {
                            "Rescan"
                        })
                        .fill(palette.surface)
                        .stroke(Stroke::new(1.0, palette.border))
                        .corner_radius(9.0),
                    );
                    if refresh.clicked() {
                        self.start_scan(context);
                    }

                    let theme_label = if self.preferences.theme == ThemeMode::Dark {
                        "Light"
                    } else {
                        "Dark"
                    };
                    if ui
                        .add(
                            egui::Button::new(theme_label)
                                .fill(palette.surface)
                                .stroke(Stroke::new(1.0, palette.border))
                                .corner_radius(9.0),
                        )
                        .clicked()
                    {
                        self.preferences.theme = match self.preferences.theme {
                            ThemeMode::Dark => ThemeMode::Light,
                            ThemeMode::Light => ThemeMode::Dark,
                        };
                        apply_theme(context, self.preferences.theme);
                    }

                    if self.elevated {
                        chip(
                            ui,
                            palette,
                            "Administrator",
                            palette.green,
                            palette.green_soft,
                        );
                    } else if ui
                        .add(
                            egui::Button::new("Run as administrator")
                                .fill(palette.surface)
                                .stroke(Stroke::new(1.0, palette.border))
                                .corner_radius(9.0),
                        )
                        .on_hover_text("Needed only for all-user entries, tasks, and services")
                        .clicked()
                    {
                        match platform::restart_elevated() {
                            Ok(()) => context.send_viewport_cmd(egui::ViewportCommand::Close),
                            Err(error) => self.toast(error.to_string(), true),
                        }
                    }
                },
            );
    }

    fn warning_banner(&mut self, ui: &mut egui::Ui, palette: Palette) {
        Frame::new()
            .fill(palette.amber_soft)
            .corner_radius(11.0)
            .inner_margin(Margin::symmetric(14, 10))
            .show(ui, |ui| {
                egui::Sides::new().height(26.0).shrink_left().show(
                    ui,
                    |ui| {
                        ui.label(
                            RichText::new("Scan completed with limited visibility")
                                .strong()
                                .color(palette.amber),
                        );
                        ui.label(
                            RichText::new(format!("{} warning(s)", self.warnings.len()))
                                .size(12.0)
                                .color(palette.text),
                        );
                    },
                    |ui| {
                        if ui.button("Review").clicked() {
                            self.dialog = Some(Dialog::Warnings);
                        }
                    },
                );
            });
    }

    fn summary_cards(&self, ui: &mut egui::Ui, palette: Palette) {
        let enabled = self
            .universe_entries()
            .filter(|entry| entry.enabled)
            .count();
        let disabled = self
            .universe_entries()
            .filter(|entry| !entry.enabled)
            .count();
        let attention = self
            .universe_entries()
            .filter(|entry| needs_attention(entry))
            .count();
        ui.columns(3, |columns| {
            summary_card(
                &mut columns[0],
                palette,
                "Active",
                enabled,
                palette.green,
                "Configured to launch",
            );
            summary_card(
                &mut columns[1],
                palette,
                "Prevented",
                disabled,
                palette.accent,
                "Reversible changes",
            );
            summary_card(
                &mut columns[2],
                palette,
                "Review",
                attention,
                palette.amber,
                "Missing or sensitive",
            );
        });
    }

    fn list_header(&mut self, ui: &mut egui::Ui, palette: Palette) {
        let scanning = self.scanning;
        let complete = self.completed_providers.len();
        egui::Sides::new()
            .height(38.0)
            .shrink_left()
            .truncate()
            .show(
                ui,
                |ui| {
                    ui.label(
                        RichText::new("Startup items")
                            .size(17.0)
                            .strong()
                            .color(palette.text),
                    );
                    if scanning {
                        ui.spinner();
                        ui.label(
                            RichText::new(format!(
                                "Checking sources… {complete}/{}",
                                SourceKind::ALL.len()
                            ))
                            .size(11.0)
                            .color(palette.muted),
                        );
                    }
                },
                |ui| {
                    ui.add_sized(
                        [260.0, 34.0],
                        TextEdit::singleline(&mut self.search)
                            .hint_text("Search apps, commands, sources…")
                            .margin(Vec2::new(10.0, 7.0)),
                    );
                    egui::ComboBox::from_id_salt("sort-mode")
                        .selected_text(format!("Sort: {}", self.sort.label()))
                        .show_ui(ui, |ui| {
                            for sort in [SortMode::Name, SortMode::Source, SortMode::Status] {
                                if ui
                                    .selectable_value(&mut self.sort, sort, sort.label())
                                    .changed()
                                {
                                    self.sort_entries();
                                }
                            }
                        });
                },
            );
    }

    fn entries_list(&mut self, ui: &mut egui::Ui, context: &egui::Context, palette: Palette) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            let scanning = self.scanning;
            ui.vertical_centered(|ui| {
                ui.add_space(64.0);
                if scanning {
                    ui.spinner();
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new("Looking beyond Task Manager…")
                            .size(16.0)
                            .strong()
                            .color(palette.text),
                    );
                    ui.label(
                        RichText::new("Registry, folders, scheduled tasks, and services")
                            .size(12.0)
                            .color(palette.muted),
                    );
                } else {
                    ui.label(
                        RichText::new("Nothing matches this view")
                            .size(17.0)
                            .strong()
                            .color(palette.text),
                    );
                    ui.label(
                        RichText::new("Try another filter or clear the search.")
                            .color(palette.muted),
                    );
                    if !self.search.is_empty() && ui.button("Clear search").clicked() {
                        self.search.clear();
                    }
                }
            });
            return;
        }

        let row_height = 78.0;
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, visible.len(), |ui, row_range| {
                for row in row_range {
                    let entry = self.entries[visible[row]].clone();
                    let selected = self.selected_id.as_deref() == Some(&entry.id);
                    let busy = self.mutation_id.as_deref() == Some(&entry.id);
                    let mut toggle_clicked = false;
                    let frame = Frame::new()
                        .fill(if selected {
                            palette.accent_soft
                        } else {
                            palette.surface
                        })
                        .stroke(Stroke::new(
                            1.0,
                            if selected {
                                palette.accent
                            } else {
                                palette.border
                            },
                        ))
                        .corner_radius(12.0)
                        .inner_margin(Margin::symmetric(14, 10))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            egui::Sides::new()
                                .height(46.0)
                                .shrink_left()
                                .truncate()
                                .show(
                                    ui,
                                    |ui| {
                                        source_avatar(ui, palette, entry.source, 42.0);
                                        ui.add_space(8.0);
                                        ui.vertical(|ui| {
                                            ui.label(
                                                RichText::new(&entry.name)
                                                    .size(14.0)
                                                    .strong()
                                                    .color(palette.text),
                                            );
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&entry.command)
                                                        .size(10.5)
                                                        .color(palette.muted),
                                                )
                                                .truncate(),
                                            );
                                        });
                                    },
                                    |ui| {
                                        if busy {
                                            ui.spinner();
                                        } else {
                                            let response = startup_switch(
                                                ui,
                                                palette,
                                                entry.enabled,
                                                entry.can_toggle,
                                            );
                                            if response.clicked() {
                                                toggle_clicked = true;
                                            }
                                        }
                                        status_chip(ui, palette, &entry);
                                        chip(
                                            ui,
                                            palette,
                                            entry.source.short_label(),
                                            palette.muted,
                                            palette.surface_hover,
                                        );
                                    },
                                );
                        });
                    let response = frame.response.interact(Sense::click());
                    if toggle_clicked {
                        self.request_toggle(context, entry.clone(), !entry.enabled);
                    } else if response.clicked() {
                        self.selected_id = Some(entry.id.clone());
                    }
                    ui.add_space(8.0);
                }
            });
    }

    fn show_dialog(&mut self, context: &egui::Context, palette: Palette) {
        let Some(dialog) = self.dialog.clone() else {
            return;
        };
        let title = match &dialog {
            Dialog::Confirm {
                desired_enabled: true,
                ..
            } => "Restore automatic startup?",
            Dialog::Confirm { .. } => "Prevent automatic startup?",
            Dialog::AdministratorRequired { .. } => "Administrator permission needed",
            Dialog::About => "About Win Startup Manager",
            Dialog::Warnings => "Scan warnings",
        };
        egui::Window::new(title)
            .id(Id::new("app-dialog"))
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .default_width(460.0)
            .frame(
                Frame::window(&context.global_style())
                    .fill(palette.surface)
                    .stroke(Stroke::new(1.0, palette.border))
                    .corner_radius(14.0)
                    .inner_margin(Margin::same(20)),
            )
            .show(context, |ui| match dialog {
                Dialog::Confirm {
                    entry,
                    desired_enabled,
                } => {
                    ui.label(
                        RichText::new(&entry.name)
                            .size(18.0)
                            .strong()
                            .color(palette.text),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(confirm_explanation(&entry, desired_enabled))
                            .size(12.0)
                            .color(palette.muted),
                    );
                    ui.add_space(16.0);
                    dialog_buttons(ui, "Cancel", if desired_enabled { "Restore" } else { "Prevent" }, |confirmed| {
                        self.dialog = None;
                        if confirmed {
                            self.begin_mutation(context, entry.clone(), desired_enabled);
                        }
                    });
                }
                Dialog::AdministratorRequired {
                    entry,
                    desired_enabled,
                } => {
                    ui.label(
                        RichText::new(format!("{} is an all-user or system-level entry.", entry.name))
                            .color(palette.text),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Windows requires a one-time UAC confirmation. After the app restarts, use the switch again; no background administrator service is installed.")
                            .size(12.0)
                            .color(palette.muted),
                    );
                    ui.add_space(16.0);
                    dialog_buttons(ui, "Cancel", "Restart as administrator", |confirmed| {
                        self.dialog = None;
                        if confirmed {
                            let _ = desired_enabled;
                            match platform::restart_elevated() {
                                Ok(()) => context.send_viewport_cmd(egui::ViewportCommand::Close),
                                Err(error) => self.toast(error.to_string(), true),
                            }
                        }
                    });
                }
                Dialog::About => {
                    ui.horizontal(|ui| {
                        ui.add(egui::Image::new((
                            self.logo_texture.id(),
                            Vec2::splat(84.0),
                        )));
                        ui.vertical(|ui| {
                            ui.add_space(14.0);
                            ui.label(
                                RichText::new(APP_NAME)
                                    .size(18.0)
                                    .strong()
                                    .color(palette.text),
                            );
                            ui.label(
                                RichText::new(format!("Version {APP_VERSION}"))
                                    .size(12.0)
                                    .color(palette.muted),
                            );
                        });
                    });
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new("A native, open-source Rust app that inspects registry Run entries, Startup folders, logon/boot scheduled tasks, and automatic services.")
                            .color(palette.text),
                    );
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new("Safety choices")
                            .strong()
                            .color(palette.accent),
                    );
                    ui.label(
                        RichText::new("• Current-user registry values and files are journaled before removal.\n• Machine-wide Registry and common Startup-folder entries are read-only in v0.1.\n• Scheduled tasks use Windows' supported Enabled flag.\n• Services are changed to Manual, never stopped or deleted.\n• Windows components and mixed-trigger tasks are locked by default.\n• The app never writes undocumented StartupApproved data.")
                            .size(12.0)
                            .color(palette.muted),
                    );
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if ui.button("Open Windows Startup settings").clicked()
                            && let Err(error) = platform::open_startup_settings()
                        {
                            self.toast(error.to_string(), true);
                        }
                        if ui.button("Close").clicked() {
                            self.dialog = None;
                        }
                    });
                }
                Dialog::Warnings => {
                    ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                        for warning in &self.warnings {
                            Frame::new()
                                .fill(palette.surface_hover)
                                .corner_radius(8.0)
                                .inner_margin(Margin::same(10))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(warning.source.label())
                                            .strong()
                                            .color(palette.amber),
                                    );
                                    ui.label(
                                        RichText::new(&warning.message)
                                            .size(11.0)
                                            .color(palette.text),
                                    );
                                });
                            ui.add_space(7.0);
                        }
                    });
                    if ui.button("Close").clicked() {
                        self.dialog = None;
                    }
                }
            });
    }

    fn show_toast(&mut self, context: &egui::Context, palette: Palette) {
        let Some(toast) = &self.toast else {
            return;
        };
        if toast.created.elapsed() > Duration::from_secs(5) {
            self.toast = None;
            return;
        }
        let fill = if toast.error {
            palette.red_soft
        } else {
            palette.green_soft
        };
        let accent = if toast.error {
            palette.red
        } else {
            palette.green
        };
        egui::Area::new(Id::new("toast"))
            .anchor(Align2::RIGHT_BOTTOM, Vec2::new(-22.0, -22.0))
            .order(egui::Order::Foreground)
            .show(context, |ui| {
                Frame::new()
                    .fill(fill)
                    .stroke(Stroke::new(1.0, accent))
                    .corner_radius(11.0)
                    .inner_margin(Margin::symmetric(14, 11))
                    .show(ui, |ui| {
                        ui.set_max_width(420.0);
                        ui.label(RichText::new(&toast.message).color(palette.text));
                    });
            });
        context.request_repaint_after(Duration::from_millis(250));
    }
}

impl eframe::App for StartupManagerApp {
    fn logic(&mut self, context: &egui::Context, _: &mut eframe::Frame) {
        self.process_worker_events(context);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        let palette = Palette::for_theme(self.preferences.theme);
        self.sidebar(ui, palette);
        self.details_panel(ui, palette);
        self.central_panel(ui, palette);
        self.show_dialog(&context, palette);
        self.show_toast(&context, palette);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, PREFERENCES_KEY, &self.preferences);
    }
}

fn apply_theme(context: &egui::Context, theme: ThemeMode) {
    let palette = Palette::for_theme(theme);
    let mut visuals = match theme {
        ThemeMode::Dark => egui::Visuals::dark(),
        ThemeMode::Light => egui::Visuals::light(),
    };
    visuals.panel_fill = palette.background;
    visuals.window_fill = palette.surface;
    visuals.faint_bg_color = palette.surface_hover;
    visuals.extreme_bg_color = palette.sidebar;
    visuals.override_text_color = Some(palette.text);
    visuals.selection.bg_fill = palette.accent;
    visuals.widgets.inactive.bg_fill = palette.surface;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, palette.border);
    visuals.widgets.hovered.bg_fill = palette.surface_hover;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, palette.accent);
    visuals.widgets.active.bg_fill = palette.accent_soft;
    visuals.window_corner_radius = 14.0.into();

    let egui_theme = match theme {
        ThemeMode::Dark => egui::Theme::Dark,
        ThemeMode::Light => egui::Theme::Light,
    };
    context.set_theme(egui_theme);
    let mut style = (*context.style_of(egui_theme)).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(12.0, 7.0);
    style
        .text_styles
        .insert(egui::TextStyle::Body, FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::proportional(12.0));
    context.set_style_of(egui_theme, style);
}

fn needs_attention(entry: &StartupEntry) -> bool {
    entry.target_exists == Some(false)
        || matches!(entry.risk, RiskLevel::Caution)
        || !entry.can_toggle && !entry.is_system
}

fn summary_card(
    ui: &mut egui::Ui,
    palette: Palette,
    label: &str,
    value: usize,
    accent: Color32,
    subtitle: &str,
) {
    Frame::new()
        .fill(palette.surface)
        .stroke(Stroke::new(1.0, palette.border))
        .corner_radius(12.0)
        .inner_margin(Margin::same(15))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let (dot, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                ui.painter().circle_filled(dot.center(), 4.0, accent);
                ui.label(RichText::new(label).size(12.0).color(palette.muted));
            });
            ui.label(
                RichText::new(value.to_string())
                    .size(26.0)
                    .strong()
                    .color(palette.text),
            );
            ui.label(RichText::new(subtitle).size(10.0).color(palette.muted));
        });
}

fn source_avatar(ui: &mut egui::Ui, palette: Palette, source: SourceKind, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let (letter, color) = match source {
        SourceKind::Registry => ("R", palette.accent),
        SourceKind::StartupFolder => ("F", palette.green),
        SourceKind::ScheduledTask => ("T", palette.amber),
        SourceKind::Service => ("S", palette.red),
    };
    ui.painter()
        .rect_filled(rect, size * 0.27, color.gamma_multiply(0.24));
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        letter,
        FontId::proportional(size * 0.42),
        color,
    );
}

fn chip(ui: &mut egui::Ui, _palette: Palette, label: &str, color: Color32, fill: Color32) {
    Frame::new()
        .fill(fill)
        .corner_radius(20.0)
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(10.0).strong().color(color));
        });
}

fn status_chip(ui: &mut egui::Ui, palette: Palette, entry: &StartupEntry) {
    let (label, color, fill) = if !entry.enabled {
        ("Prevented", palette.accent, palette.accent_soft)
    } else if entry.risk == RiskLevel::Protected {
        ("Protected", palette.muted, palette.surface_hover)
    } else if entry.target_exists == Some(false) {
        ("Missing", palette.amber, palette.amber_soft)
    } else {
        ("Active", palette.green, palette.green_soft)
    };
    chip(ui, palette, label, color, fill);
}

fn startup_switch(
    ui: &mut egui::Ui,
    palette: Palette,
    enabled: bool,
    interactive: bool,
) -> egui::Response {
    let desired_size = Vec2::new(46.0, 25.0);
    let sense = if interactive {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(desired_size, sense);
    let background = if !interactive {
        palette.border
    } else if enabled {
        palette.green
    } else {
        palette.muted
    };
    ui.painter()
        .rect_filled(rect, rect.height() / 2.0, background);
    let radius = 9.5;
    let center_x = if enabled {
        rect.right() - 13.0
    } else {
        rect.left() + 13.0
    };
    ui.painter().circle_filled(
        egui::pos2(center_x, rect.center().y),
        radius,
        Color32::WHITE,
    );
    let hint = if !interactive {
        "This entry is locked for safety"
    } else if enabled {
        "Prevent automatic startup"
    } else {
        "Restore automatic startup"
    };
    response.on_hover_text(hint)
}

fn detail_section(
    ui: &mut egui::Ui,
    palette: Palette,
    heading: &str,
    value: &str,
    monospace: bool,
) {
    ui.label(
        RichText::new(heading)
            .size(9.0)
            .strong()
            .color(palette.muted),
    );
    Frame::new()
        .fill(palette.surface)
        .stroke(Stroke::new(1.0, palette.border))
        .corner_radius(9.0)
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            let text = RichText::new(value)
                .size(if monospace { 10.5 } else { 12.0 })
                .color(palette.text);
            ui.add(egui::Label::new(if monospace { text.monospace() } else { text }).wrap());
        });
    ui.add_space(12.0);
}

fn protection_reason(entry: &StartupEntry) -> &'static str {
    if entry.is_system {
        "Windows components are read-only by default"
    } else if entry.source == SourceKind::ScheduledTask {
        "This task has other triggers; changing the whole task could affect unrelated behavior"
    } else {
        "This entry cannot be changed safely"
    }
}

fn confirm_explanation(entry: &StartupEntry, desired_enabled: bool) -> String {
    if desired_enabled {
        return match entry.source {
            SourceKind::Registry | SourceKind::StartupFolder => {
                "The exact saved startup data will be restored to its original location. The restore is refused if another item now occupies that location.".into()
            }
            SourceKind::ScheduledTask => {
                "Windows will re-enable this scheduled task. Its definition and triggers are not rewritten.".into()
            }
            SourceKind::Service => {
                "The service's original Automatic or Delayed Automatic start mode will be restored. The service is not started immediately.".into()
            }
        };
    }

    match entry.source {
        SourceKind::Registry => {
            "The exact registry value will be saved in a local recovery journal, then removed. You can restore it later.".into()
        }
        SourceKind::StartupFolder => {
            "The Startup-folder item will be moved intact into local recovery storage. You can restore it later.".into()
        }
        SourceKind::ScheduledTask => {
            "Windows will disable this whole task using its supported Enabled flag. The task definition will remain intact.".into()
        }
        SourceKind::Service => {
            "The service will change from Automatic to Manual for future boots. It will not be stopped now, deleted, or prevented from starting when its app explicitly needs it.".into()
        }
    }
}

fn dialog_buttons(
    ui: &mut egui::Ui,
    cancel_label: &str,
    confirm_label: &str,
    mut result: impl FnMut(bool),
) {
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        if ui.button(confirm_label).clicked() {
            result(true);
        }
        if ui.button(cancel_label).clicked() {
            result(false);
        }
    });
}
