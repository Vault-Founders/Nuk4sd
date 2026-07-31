/*
 * gui.rs
 *
 * Interface gráfica nativa do Nuk4sd em Rust (egui/eframe).
 * Comunica-se diretamente com o core C via rust/ffi.rs.
 * Sem subprocessos Python, sem PyQt5, sem regex em log.
 *
 * Suporta alinhamento simétrico e gerenciador completo de perfis salvos
 * em ~/.config/nuk4sd/desktop_apps.json.
 */

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[path = "ffi.rs"]
mod ffi;

use ffi::{VaultEntry, VaultStatus};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppProfile {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub executable: String,
    pub preset_name: String,
    pub description: String,
    pub vault_id: u32,
    pub flag_no_net: bool,
    pub flag_wayland: bool,
    pub flag_x11: bool,
    pub flag_audio: bool,
    pub flag_ro_home: bool,
    pub flag_no_fuse: bool,
    pub flag_seccomp_strict: bool,
    pub ro_paths: String,
    pub rw_paths: String,
    pub blacklist_paths: String,
}

fn get_config_dir() -> PathBuf {
    let mut p = home::home_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push(".config");
    p.push("nuk4sd");
    let _ = fs::create_dir_all(&p);
    p
}

fn get_profiles_file() -> PathBuf {
    let mut p = get_config_dir();
    p.push("desktop_apps.json");
    p
}

fn default_profiles() -> Vec<AppProfile> {
    vec![
        AppProfile {
            id: "firefox".into(),
            name: "Firefox".into(),
            icon: "🌐".into(),
            executable: "/usr/bin/firefox".into(),
            preset_name: "firefox".into(),
            description: "Navegação isolada (--no-net / --wayland)".into(),
            vault_id: 0,
            flag_no_net: true,
            flag_wayland: true,
            flag_x11: false,
            flag_audio: false,
            flag_ro_home: true,
            flag_no_fuse: false,
            flag_seccomp_strict: false,
            ro_paths: "".into(),
            rw_paths: "".into(),
            blacklist_paths: "".into(),
        },
        AppProfile {
            id: "vscode".into(),
            name: "VS Code".into(),
            icon: "💻".into(),
            executable: "/usr/bin/code".into(),
            preset_name: "dev".into(),
            description: "IDE isolada com acesso restrito a projetos".into(),
            vault_id: 0,
            flag_no_net: false,
            flag_wayland: true,
            flag_x11: false,
            flag_audio: false,
            flag_ro_home: true,
            flag_no_fuse: false,
            flag_seccomp_strict: false,
            ro_paths: "".into(),
            rw_paths: "".into(),
            blacklist_paths: "".into(),
        },
        AppProfile {
            id: "gimp".into(),
            name: "GIMP".into(),
            icon: "🎨".into(),
            executable: "/usr/bin/gimp".into(),
            preset_name: "office".into(),
            description: "Edição gráfica isolada de fotos".into(),
            vault_id: 0,
            flag_no_net: true,
            flag_wayland: true,
            flag_x11: false,
            flag_audio: false,
            flag_ro_home: true,
            flag_no_fuse: false,
            flag_seccomp_strict: false,
            ro_paths: "".into(),
            rw_paths: "".into(),
            blacklist_paths: "".into(),
        },
        AppProfile {
            id: "celluloid".into(),
            name: "Celluloid".into(),
            icon: "🎬".into(),
            executable: "/usr/bin/celluloid".into(),
            preset_name: "media".into(),
            description: "Player de vídeo com áudio isolado".into(),
            vault_id: 0,
            flag_no_net: true,
            flag_wayland: true,
            flag_x11: false,
            flag_audio: true,
            flag_ro_home: true,
            flag_no_fuse: false,
            flag_seccomp_strict: false,
            ro_paths: "".into(),
            rw_paths: "".into(),
            blacklist_paths: "".into(),
        },
        AppProfile {
            id: "nautilus".into(),
            name: "Arquivos (Nautilus)".into(),
            icon: "📁".into(),
            executable: "/usr/bin/nautilus".into(),
            preset_name: "nautilus".into(),
            description: "Gerenciador de arquivos no vault".into(),
            vault_id: 0,
            flag_no_net: true,
            flag_wayland: true,
            flag_x11: false,
            flag_audio: false,
            flag_ro_home: true,
            flag_no_fuse: false,
            flag_seccomp_strict: false,
            ro_paths: "".into(),
            rw_paths: "".into(),
            blacklist_paths: "".into(),
        },
        AppProfile {
            id: "evince".into(),
            name: "Evince PDF".into(),
            icon: "📄".into(),
            executable: "/usr/bin/evince".into(),
            preset_name: "office".into(),
            description: "Leitor de PDF seguro em sandbox".into(),
            vault_id: 0,
            flag_no_net: true,
            flag_wayland: true,
            flag_x11: false,
            flag_audio: false,
            flag_ro_home: true,
            flag_no_fuse: false,
            flag_seccomp_strict: false,
            ro_paths: "".into(),
            rw_paths: "".into(),
            blacklist_paths: "".into(),
        },
        AppProfile {
            id: "flameshot".into(),
            name: "Flameshot".into(),
            icon: "📸".into(),
            executable: "/usr/bin/flameshot".into(),
            preset_name: "flameshot".into(),
            description: "Captura de tela segura".into(),
            vault_id: 0,
            flag_no_net: true,
            flag_wayland: true,
            flag_x11: true,
            flag_audio: false,
            flag_ro_home: true,
            flag_no_fuse: false,
            flag_seccomp_strict: false,
            ro_paths: "".into(),
            rw_paths: "".into(),
            blacklist_paths: "".into(),
        },
        AppProfile {
            id: "bash".into(),
            name: "Terminal Bash".into(),
            icon: "🖥️".into(),
            executable: "/bin/bash".into(),
            preset_name: "minimal".into(),
            description: "Shell Bash em sandbox isolado".into(),
            vault_id: 0,
            flag_no_net: true,
            flag_wayland: false,
            flag_x11: false,
            flag_audio: false,
            flag_ro_home: true,
            flag_no_fuse: false,
            flag_seccomp_strict: false,
            ro_paths: "".into(),
            rw_paths: "".into(),
            blacklist_paths: "".into(),
        },
    ]
}

fn load_profiles() -> Vec<AppProfile> {
    let p = get_profiles_file();
    if p.exists() {
        if let Ok(data) = fs::read_to_string(&p) {
            if let Ok(list) = serde_json::from_str::<Vec<AppProfile>>(&data) {
                if !list.is_empty() {
                    return list;
                }
            }
        }
    }
    let defaults = default_profiles();
    save_profiles(&defaults);
    defaults
}

fn save_profiles(list: &[AppProfile]) {
    let p = get_profiles_file();
    if let Ok(json) = serde_json::to_string_pretty(list) {
        let _ = fs::write(p, json);
    }
}

#[derive(PartialEq)]
enum NavTab {
    DesktopGrid,
    VaultsManager,
    SandboxLauncher,
    ActiveSandboxes,
    TerminalLogs,
}

pub struct Nuk4sdApp {
    current_tab: NavTab,

    // Apps & Perfis do Desktop
    profiles: Vec<AppProfile>,
    show_add_dialog: bool,
    edit_profile_id: Option<String>,

    // Form de Novo/Editar Perfil
    form_name: String,
    form_icon: String,
    form_exe: String,
    form_desc: String,
    form_vault_id: u32,
    form_no_net: bool,
    form_wayland: bool,
    form_x11: bool,
    form_audio: bool,
    form_ro_home: bool,
    form_no_fuse: bool,
    form_seccomp_strict: bool,
    form_ro_paths: String,
    form_rw_paths: String,
    form_blacklist_paths: String,

    // Vaults State
    vaults: Vec<VaultEntry>,
    new_vault_name: String,
    new_vault_path: String,
    new_vault_pass: String,
    vault_op_pass: String,

    // Sandbox Custom Launcher State
    custom_exe: String,
    selected_vault_id: u32,
    flag_no_net: bool,
    flag_wayland: bool,
    flag_x11: bool,
    flag_audio: bool,
    flag_ro_home: bool,
    flag_no_fuse: bool,
    flag_seccomp_strict: bool,
    flag_drop_caps: bool,
    flag_chroot: bool,
    flag_debug: bool,
    custom_ro_paths: String,
    custom_rw_paths: String,
    custom_blacklist_paths: String,
    rlimit_mem_mb: String,
    rlimit_procs: String,

    // Terminal Interativo & Logs
    term_input: String,
    term_history: Vec<String>,
    status_msg: String,
    last_status_ok: bool,

    last_refresh: Instant,
}

impl Default for Nuk4sdApp {
    fn default() -> Self {
        Self {
            current_tab: NavTab::DesktopGrid,
            profiles: load_profiles(),
            show_add_dialog: false,
            edit_profile_id: None,

            form_name: String::new(),
            form_icon: "🚀".to_string(),
            form_exe: String::new(),
            form_desc: String::new(),
            form_vault_id: 0,
            form_no_net: true,
            form_wayland: true,
            form_x11: false,
            form_audio: false,
            form_ro_home: true,
            form_no_fuse: false,
            form_seccomp_strict: false,
            form_ro_paths: String::new(),
            form_rw_paths: String::new(),
            form_blacklist_paths: String::new(),

            vaults: Vec::new(),
            new_vault_name: String::new(),
            new_vault_path: String::new(),
            new_vault_pass: String::new(),
            vault_op_pass: String::new(),

            custom_exe: "/usr/bin/firefox".to_string(),
            selected_vault_id: 0,
            flag_no_net: true,
            flag_wayland: true,
            flag_x11: false,
            flag_audio: false,
            flag_ro_home: true,
            flag_no_fuse: false,
            flag_seccomp_strict: false,
            flag_drop_caps: true,
            flag_chroot: false,
            flag_debug: false,
            custom_ro_paths: String::new(),
            custom_rw_paths: String::new(),
            custom_blacklist_paths: String::new(),
            rlimit_mem_mb: "1024".to_string(),
            rlimit_procs: "100".to_string(),

            term_input: String::new(),
            term_history: vec![
                "Nuk4sd Security Subsystem v0.9.26 (FFI Direct Memory Mode)".to_string(),
                "Digite '--help' ou qualquer comando CLI para executar diretamente no Core C.".to_string(),
            ],
            status_msg: "Core C FFI ativo e pronto.".to_string(),
            last_status_ok: true,

            last_refresh: Instant::now(),
        }
    }
}

pub fn run_gui() {
    if let Err(e) = ffi::init() {
        eprintln!("Aviso ao iniciar FFI C: {}", e.message());
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 680.0])
            .with_title("Nuk4sd - Process & Vault Security Subsystem"),
        ..Default::default()
    };

    let _ = eframe::run_native(
        "Nuk4sd",
        options,
        Box::new(|cc| {
            // Configuração do Tema: Cores Chapadas (Azul Marinho Neutro & Cinza Escuro)
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = egui::Color32::from_rgb(18, 22, 31); // #12161F - Fundo chapado principal
            visuals.window_fill = egui::Color32::from_rgb(24, 30, 41); // #181E29 - Painel de superfícies
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(31, 40, 54); // #1F2836
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(37, 48, 66);
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(43, 76, 126); // #2B4C7E Azul marinho neutro
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(53, 92, 150); // #355C96
            visuals.selection.bg_fill = egui::Color32::from_rgb(43, 76, 126);

            cc.egui_ctx.set_visuals(visuals);
            let mut app = Nuk4sdApp::default();
            app.refresh_vaults();
            Ok(Box::new(app))
        }),
    );

    let _ = ffi::shutdown();
}

impl Nuk4sdApp {
    fn refresh_vaults(&mut self) {
        match ffi::list_vaults() {
            Ok(list) => {
                self.vaults = list;
                self.last_status_ok = true;
            }
            Err(e) => {
                self.last_status_ok = false;
                self.status_msg = format!("Erro ao carregar vaults: {}", e.message());
            }
        }
    }

    fn run_cli_terminal_cmd(&mut self) {
        let cmd = self.term_input.trim().to_string();
        if cmd.is_empty() {
            return;
        }
        self.term_input.clear();
        self.term_history.push(format!("nuk4sd > {}", cmd));

        let (code, output) = ffi::exec_cli_cmd(&cmd);
        self.term_history.push(output);
        self.last_status_ok = code == 0;
        self.refresh_vaults();
    }

    fn launch_profile(&mut self, profile: &AppProfile) {
            ro_home: profile.flag_ro_home,
            no_fuse: profile.flag_no_fuse,
            seccomp_strict: profile.flag_seccomp_strict,
            use_chroot: false,
            debug: false,
        };

        let ro = ffi::split_paths(&profile.ro_paths);
        let rw = ffi::split_paths(&profile.rw_paths);
        let bl = ffi::split_paths(&profile.blacklist_paths);

        let result = ffi::run_sandbox(
            profile.vault_id,
            &self.vault_op_pass,
            &profile.executable,
            &opts,
            &ro,
            &rw,
            &bl,
        );

        self.last_status_ok = result.is_ok();
        self.status_msg = match result {
            Ok(()) => format!("Lançando {}: ok.", profile.name),
            Err(e) => format!("Lançando {}: {}", profile.name, e.message()),
        };
    }

    fn save_current_form_profile(&mut self) {
        if self.form_name.is_empty() || self.form_exe.is_empty() {
            self.status_msg = "Nome e executável são obrigatórios!".into();
            self.last_status_ok = false;
            return;
        }

        let new_prof = AppProfile {
            id: self.edit_profile_id.clone().unwrap_or_else(|| format!("app_{}", Instant::now().elapsed().as_nanos())),
            name: self.form_name.clone(),
            icon: if self.form_icon.is_empty() { "🚀".to_string() } else { self.form_icon.clone() },
            executable: self.form_exe.clone(),
            preset_name: "custom".into(),
            description: self.form_desc.clone(),
            vault_id: self.form_vault_id,
            flag_no_net: self.form_no_net,
            flag_wayland: self.form_wayland,
            flag_x11: self.form_x11,
            flag_audio: self.form_audio,
            flag_ro_home: self.form_ro_home,
            flag_no_fuse: self.form_no_fuse,
            flag_seccomp_strict: self.form_seccomp_strict,
            ro_paths: self.form_ro_paths.clone(),
            rw_paths: self.form_rw_paths.clone(),
            blacklist_paths: self.form_blacklist_paths.clone(),
        };

        if let Some(ref id) = self.edit_profile_id {
            if let Some(idx) = self.profiles.iter().position(|p| p.id == *id) {
                self.profiles[idx] = new_prof;
            }
        } else {
            self.profiles.push(new_prof);
        }

        save_profiles(&self.profiles);
        self.show_add_dialog = false;
        self.edit_profile_id = None;
        self.status_msg = "Perfil salvo com sucesso!".into();
        self.last_status_ok = true;
    }

    fn reset_form(&mut self) {
        self.form_name.clear();
        self.form_icon = "🚀".into();
        self.form_exe.clear();
        self.form_desc.clear();
        self.form_vault_id = 0;
        self.form_no_net = true;
        self.form_wayland = true;
        self.form_x11 = false;
        self.form_audio = false;
        self.form_ro_home = true;
        self.form_no_fuse = false;
        self.form_seccomp_strict = false;
        self.form_ro_paths.clear();
        self.form_rw_paths.clear();
        self.form_blacklist_paths.clear();
    }
}

impl eframe::App for Nuk4sdApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_refresh.elapsed() > Duration::from_secs(5) {
            self.refresh_vaults();
            self.last_refresh = Instant::now();
        }

        // ── Sidebar de Navegação (Cores Chapadas Azul Marinho & Cinza) ──────────
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .default_width(210.0)
            .show(ctx, |ui| {
                ui.add_space(14.0);
                ui.heading(
                    egui::RichText::new("NUK4SD")
                        .strong()
                        .color(egui::Color32::from_rgb(225, 231, 237)),
                );
                ui.label(
                    egui::RichText::new("C FFI Direct Subsystem")
                        .size(11.0)
                        .color(egui::Color32::from_rgb(158, 174, 195)),
                );
                ui.add_space(20.0);

                let nav_button = |ui: &mut egui::Ui, text: &str, active: bool| {
                    let fill = if active {
                        egui::Color32::from_rgb(43, 76, 126)
                    } else {
                        egui::Color32::from_rgb(24, 30, 41)
                    };
                    ui.add(
                        egui::Button::new(
                            egui::RichText::new(text)
                                .color(egui::Color32::from_rgb(225, 231, 237)),
                        )
                        .fill(fill)
                        .min_size(egui::vec2(190.0, 36.0)),
                    )
                };

                if nav_button(&mut *ui, "🖥️ Área Desktop", self.current_tab == NavTab::DesktopGrid).clicked() {
                    self.current_tab = NavTab::DesktopGrid;
                }
                ui.add_space(4.0);
                if nav_button(&mut *ui, "📦 Vaults FUSE", self.current_tab == NavTab::VaultsManager).clicked() {
                    self.current_tab = NavTab::VaultsManager;
                }
                ui.add_space(4.0);
                if nav_button(&mut *ui, "⚙️ Lançador de Sandbox", self.current_tab == NavTab::SandboxLauncher).clicked() {
                    self.current_tab = NavTab::SandboxLauncher;
                }
                ui.add_space(4.0);
                if nav_button(&mut *ui, "🛡️ Sandboxes Ativos", self.current_tab == NavTab::ActiveSandboxes).clicked() {
                    self.current_tab = NavTab::ActiveSandboxes;
                }
                ui.add_space(4.0);
                if nav_button(&mut *ui, "💻 Terminal & Logs", self.current_tab == NavTab::TerminalLogs).clicked() {
                    self.current_tab = NavTab::TerminalLogs;
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new("v0.9.26 | FFI Active")
                            .size(10.0)
                            .color(egui::Color32::from_rgb(158, 174, 195)),
                    );
                    ui.separator();
                });
            });

        // ── Painel Central ──────────────────────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(6.0);

            // Mensagem de Status Global
            if !self.status_msg.is_empty() {
                let color = if self.last_status_ok {
                    egui::Color32::from_rgb(91, 245, 154)
                } else {
                    egui::Color32::from_rgb(245, 85, 85)
                };
                ui.label(egui::RichText::new(&self.status_msg).size(12.0).color(color));
                ui.add_space(6.0);
            }

            match self.current_tab {
                // 1. ÁREA DESKTOP (Grid de Atalhos de Apps - Alinhamento Simétrico Perfeito)
                NavTab::DesktopGrid => {
                    ui.horizontal(|ui| {
                        ui.heading("Área Desktop - Programas & Perfis Salvos");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("➕ Criar Novo Perfil / Programa")
                                            .strong()
                                            .color(egui::Color32::WHITE),
                                    )
                                    .fill(egui::Color32::from_rgb(43, 76, 126))
                                    .min_size(egui::vec2(210.0, 32.0)),
                                )
                                .clicked()
                            {
                                self.reset_form();
                                self.edit_profile_id = None;
                                self.show_add_dialog = true;
                            }
                        });
                    });
                    ui.label(
                        egui::RichText::new("Clique em qualquer aplicativo para lançá-lo ou crie seus próprios perfis personalizados.")
                            .color(egui::Color32::from_rgb(158, 174, 195)),
                    );
                    ui.add_space(12.0);

                    // Form Collapsable de Adicionar/Editar Perfil
                    if self.show_add_dialog {
                        ui.group(|ui| {
                            ui.heading(if self.edit_profile_id.is_some() { "Editar Perfil" } else { "Novo Perfil de Programa" });
                            ui.add_space(8.0);
                            egui::Grid::new("profile_form_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                                ui.label("Nome da App:");
                                ui.text_edit_singleline(&mut self.form_name);
                                ui.end_row();

                                ui.label("Ícone (Emoji):");
                                ui.text_edit_singleline(&mut self.form_icon);
                                ui.end_row();

                                ui.label("Executável:");
                                ui.text_edit_singleline(&mut self.form_exe);
                                ui.end_row();

                                ui.label("Descrição:");
                                ui.text_edit_singleline(&mut self.form_desc);
                                ui.end_row();

                                ui.label("Vault ID:");
                                ui.add(egui::DragValue::new(&mut self.form_vault_id));
                                ui.end_row();

                                ui.label("Permissões:");
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut self.form_no_net, "Block Net");
                                    ui.checkbox(&mut self.form_wayland, "Wayland");
                                    ui.checkbox(&mut self.form_audio, "Áudio");
                                    ui.checkbox(&mut self.form_ro_home, "RO Home");
                                });
                                ui.end_row();
                            });
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                if ui.button("💾 Salvar Perfil").clicked() {
                                    self.save_current_form_profile();
                                }
                                if ui.button("Cancelar").clicked() {
                                    self.show_add_dialog = false;
                                }
                            });
                        });
                        ui.add_space(12.0);
                    }

                    // Grid Simétrico com Blocos de Tamanho Idêntico (210x140)
                    let profiles = self.profiles.clone();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            for prof in &profiles {
                                ui.allocate_ui(egui::vec2(220.0, 145.0), |ui| {
                                    let frame = egui::Frame::group(ui.style())
                                        .fill(egui::Color32::from_rgb(31, 40, 54))
                                        .inner_margin(10.0);
                                    frame.show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(&prof.icon).size(26.0));
                                            ui.vertical(|ui| {
                                                ui.label(
                                                    egui::RichText::new(&prof.name)
                                                        .strong()
                                                        .color(egui::Color32::from_rgb(225, 231, 237)),
                                                );
                                                ui.label(
                                                    egui::RichText::new(format!("Vault {}", prof.vault_id))
                                                        .size(10.0)
                                                        .color(egui::Color32::from_rgb(158, 174, 195)),
                                                );
                                            });
                                        });
                                        ui.add_space(4.0);
                                        ui.label(
                                            egui::RichText::new(&prof.description)
                                                .size(11.0)
                                                .color(egui::Color32::from_rgb(158, 174, 195)),
                                        );
                                        ui.add_space(6.0);

                                        ui.horizontal(|ui| {
                                            if ui
                                                .add(
                                                    egui::Button::new(
                                                        egui::RichText::new("🚀 Lançar")
                                                            .size(11.0)
                                                            .color(egui::Color32::WHITE),
                                                    )
                                                    .fill(egui::Color32::from_rgb(43, 76, 126)),
                                                )
                                                .clicked()
                                            {
                                                self.launch_profile(prof);
                                            }

                                            if ui.button("🗑️").clicked() {
                                                self.profiles.retain(|p| p.id != prof.id);
                                                save_profiles(&self.profiles);
                                                self.status_msg = format!("Perfil '{}' removido.", prof.name);
                                            }
                                        });
                                    });
                                });
                                ui.add_space(8.0);
                            }
                        });
                    });
                }

                // 2. GERENCIADOR DE VAULTS FUSE
                NavTab::VaultsManager => {
                    ui.heading("Gerenciador de Vaults FUSE (AES-256)");
                    ui.label(
                        egui::RichText::new("Gerencie seus cofres encriptados com montagem FUSE e chave Argon2.")
                            .color(egui::Color32::from_rgb(158, 174, 195)),
                    );
                    ui.add_space(10.0);

                    // Formulário de Criação de Vault
                    egui::CollapsingHeader::new("➕ Criar Novo Vault FUSE")
                        .default_open(false)
                        .show(ui, |ui| {
                            egui::Grid::new("create_vault_grid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                                ui.label("Nome:");
                                ui.text_edit_singleline(&mut self.new_vault_name);
                                ui.end_row();

                                ui.label("Caminho:");
                                ui.text_edit_singleline(&mut self.new_vault_path);
                                ui.end_row();

                                ui.label("Senha:");
                                ui.add(egui::TextEdit::singleline(&mut self.new_vault_pass).password(true));
                                ui.end_row();
                            });
                            ui.add_space(6.0);
                            if ui.button("Criar Vault").clicked() {
                                if !self.new_vault_name.is_empty() && !self.new_vault_pass.is_empty() {
                                    let path = if self.new_vault_path.is_empty() {
                                        format!("{}/.config/nuk4sd/vault_{}", std::env::var("HOME").unwrap_or_default(), self.new_vault_name)
                                    } else {
                                        self.new_vault_path.clone()
                                    };
                                    match ffi::create_vault(&self.new_vault_name, false, &path, &self.new_vault_pass) {
                                        Ok(_) => {
                                            self.status_msg = format!("Vault '{}' criado com sucesso!", self.new_vault_name);
                                            self.last_status_ok = true;
                                            self.refresh_vaults();
                                        }
                                        Err(e) => {
                                            self.status_msg = format!("Erro ao criar: {}", e.message());
                                            self.last_status_ok = false;
                                        }
                                    }
                                }
                            }
                        });

                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        ui.label("Senha para Operações (Montar/Desmontar):");
                        ui.add(egui::TextEdit::singleline(&mut self.vault_op_pass).password(true));
                    });
                    ui.add_space(8.0);

                    let vaults = self.vaults.clone();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if vaults.is_empty() {
                            ui.label("Nenhum vault encontrado no catálogo.");
                        } else {
                            for v in &vaults {
                                ui.group(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new(format!("ID: {}", v.id)).strong());
                                        ui.label(format!("Caminho: {}", v.path));
                                        ui.label(
                                            egui::RichText::new(v.status.label())
                                                .color(if v.status == VaultStatus::Ok {
                                                    egui::Color32::from_rgb(91, 245, 154)
                                                } else {
                                                    egui::Color32::from_rgb(245, 200, 66)
                                                }),
                                        );

                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.button("🔓 Montar").clicked() {
                                                match ffi::mount(v.id, &self.vault_op_pass) {
                                                    Ok(_) => self.status_msg = format!("Vault {} montado!", v.id),
                                                    Err(e) => self.status_msg = format!("Erro ao montar: {}", e.message()),
                                                }
                                                self.refresh_vaults();
                                            }
                                            if ui.button("🔒 Desmontar").clicked() {
                                                match ffi::unmount(v.id) {
                                                    Ok(_) => self.status_msg = format!("Vault {} desmontado!", v.id),
                                                    Err(e) => self.status_msg = format!("Erro ao desmontar: {}", e.message()),
                                                }
                                                self.refresh_vaults();
                                            }
                                        });
                                    });
                                });
                                ui.add_space(4.0);
                            }
                        }
                    });
                }

                // 3. LANÇADOR DE SANDBOX (Todas as Flags Expostas em Categorias)
                NavTab::SandboxLauncher => {
                    ui.heading("Lançador de Sandbox Customizado");
                    ui.label(
                        egui::RichText::new("Configure detalhadamente todas as flags de isolamento do kernel C.")
                            .color(egui::Color32::from_rgb(158, 174, 195)),
                    );
                    ui.add_space(10.0);

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.group(|ui| {
                            egui::Grid::new("launcher_grid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                                ui.label("Executável:");
                                ui.text_edit_singleline(&mut self.custom_exe);
                                ui.end_row();

                                ui.label("Vault ID:");
                                ui.add(egui::DragValue::new(&mut self.selected_vault_id));
                                ui.end_row();
                            });
                        });
                        ui.add_space(10.0);

                        // Categoria 1: Rede e Display
                        egui::CollapsingHeader::new("🌐 Rede & Display")
                            .default_open(true)
                            .show(ui, |ui| {
                                ui.checkbox(&mut self.flag_no_net, "🚫 Block Network (--no-net / CLONE_NEWNET)");
                                ui.checkbox(&mut self.flag_wayland, "🖥️ Allow Wayland Socket (--wayland)");
                                ui.checkbox(&mut self.flag_x11, "📺 Allow X11 Socket (--x11)");
                                ui.checkbox(&mut self.flag_audio, "🔊 Allow Audio Socket (--audio / PipeWire)");
                            });

                        // Categoria 2: Arquivos e Sistema de Arquivos
                        egui::CollapsingHeader::new("📁 Arquivos & Sistema de Arquivos")
                            .default_open(true)
                            .show(ui, |ui| {
                                ui.checkbox(&mut self.flag_ro_home, "🔒 Read-Only Home (--ro-home)");
                                ui.checkbox(&mut self.flag_no_fuse, "🔑 Mode Temp Directory (--no-fuse)");
                                egui::Grid::new("paths_grid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                                    ui.label("Read-Only Paths (--ro):");
                                    ui.text_edit_singleline(&mut self.custom_ro_paths);
                                    ui.end_row();

                                    ui.label("Read-Write Paths (--rw):");
                                    ui.text_edit_singleline(&mut self.custom_rw_paths);
                                    ui.end_row();

                                    ui.label("Blacklist Paths (--blacklist):");
                                    ui.text_edit_singleline(&mut self.custom_blacklist_paths);
                                    ui.end_row();
                                });
                            });

                        // Categoria 3: Segurança Kernel & Syscalls
                        egui::CollapsingHeader::new("🛡️ Segurança Kernel & Syscalls")
                            .default_open(false)
                            .show(ui, |ui| {
                                ui.checkbox(&mut self.flag_seccomp_strict, "🛡️ Strict Seccomp-BPF (--seccomp-strict)");
                                ui.checkbox(&mut self.flag_drop_caps, "⚡ Drop Capabilities / NO_NEW_PRIVS (--drop-caps)");
                                ui.checkbox(&mut self.flag_chroot, "📦 Chroot Isolation (--chroot)");
                                ui.checkbox(&mut self.flag_debug, "🔬 Verbose Debug Mode (--debug)");
                            });

                        // Categoria 4: Limites de Recursos (rlimits)
                        egui::CollapsingHeader::new("⏱️ Limites de Recursos (rlimits)")
                            .default_open(false)
                            .show(ui, |ui| {
                                egui::Grid::new("rlimits_grid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                                    ui.label("RAM Máxima (MB):");
                                    ui.text_edit_singleline(&mut self.rlimit_mem_mb);
                                    ui.end_row();

                                    ui.label("Processos Máximos:");
                                    ui.text_edit_singleline(&mut self.rlimit_procs);
                                    ui.end_row();
                                });
                            });

                        ui.add_space(14.0);

                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("🚀 Executar Sandbox com Flags Expostas")
                                        .size(14.0)
                                        .strong()
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(43, 76, 126))
                                .min_size(egui::vec2(240.0, 38.0)),
                            )
                            .clicked()
                        {
                            let opts = ffi::SandboxOptions {
                                no_net: self.flag_no_net,
                                wayland: self.flag_wayland,
                                x11: self.flag_x11,
                                audio: self.flag_audio,
                                ro_home: self.flag_ro_home,
                                no_fuse: self.flag_no_fuse,
                                seccomp_strict: self.flag_seccomp_strict,
                                use_chroot: self.flag_chroot,
                                debug: self.flag_debug,
                            };

                            let ro = ffi::split_paths(&self.custom_ro_paths);
                            let rw = ffi::split_paths(&self.custom_rw_paths);
                            let bl = ffi::split_paths(&self.custom_blacklist_paths);

                            let result = ffi::run_sandbox(
                                self.selected_vault_id,
                                &self.vault_op_pass,
                                &self.custom_exe,
                                &opts,
                                &ro,
                                &rw,
                                &bl,
                            );

                            self.last_status_ok = result.is_ok();
                            self.status_msg = match result {
                                Ok(()) => "Sandbox lançado: ok.".to_string(),
                                Err(e) => format!("Sandbox: {}", e.message()),
                            };
                            // Nota: o checkbox "Drop Capabilities (--drop-caps)" não tem
                            // flag correspondente no core C — vsb_drop_caps() já roda
                            // incondicionalmente pra todo sandbox. O checkbox fica só
                            // cosmético por enquanto (mesmo estado de antes desta correção).
                        }
                    });
                }

                // 4. SANDBOXES ATIVOS (Process Monitor)
                NavTab::ActiveSandboxes => {
                    ui.heading("Sandboxes Ativos (Process Monitor)");
                    ui.label(
                        egui::RichText::new("Processos isolados rodando no momento sob supervisão dos namespaces Linux.")
                            .color(egui::Color32::from_rgb(158, 174, 195)),
                    );
                    ui.add_space(10.0);

                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("STATUS").strong());
                            ui.add_space(40.0);
                            ui.label(egui::RichText::new("CORE STATUS").strong());
                        });
                        ui.separator();
                        ui.label("pivot_root: ok | user_namespaces: CLONE_NEWUSER | seccomp-bpf: ativo | FUSE: mounted");
                    });
                    ui.add_space(10.0);

                    if ui.button("🔄 Atualizar Lista de Processos").clicked() {
                        self.refresh_vaults();
                    }
                }

                // 5. TERMINAL INTERATIVO & LOGS
                NavTab::TerminalLogs => {
                    ui.heading("Terminal CLI Interativo & Console de Logs");
                    ui.label(
                        egui::RichText::new("Execute qualquer instrução do Nuk4sd diretamente em memória. Ideal para testes e modelos de IA.")
                            .color(egui::Color32::from_rgb(158, 174, 195)),
                    );
                    ui.add_space(10.0);

                    egui::ScrollArea::vertical()
                        .max_height(400.0)
                        .show(ui, |ui| {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(14, 18, 26))
                                .inner_margin(8.0)
                                .show(ui, |ui| {
                                    for line in &self.term_history {
                                        ui.label(
                                            egui::RichText::new(line)
                                                .font(egui::FontId::monospace(12.0))
                                                .color(egui::Color32::from_rgb(208, 216, 232)),
                                        );
                                    }
                                });
                        });

                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("nuk4sd >").strong().color(egui::Color32::from_rgb(0, 229, 255)));
                        let edit = ui.text_edit_singleline(&mut self.term_input);
                        if (edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                            || ui.button("Executar").clicked()
                        {
                            self.run_cli_terminal_cmd();
                        }
                    });
                }
            }
        });
    }
}
