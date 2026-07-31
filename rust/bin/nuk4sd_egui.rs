/*
 * nuk4sd_egui.rs
 *
 * Protótipo de GUI em egui/eframe para o Nuk4sd.
 *
 * Diferença fundamental em relação a nuk4sd_gui.py:
 *   - nuk4sd_gui.py monta uma linha de comando (`Nuk4sd --vault N --run ...`),
 *     dispara um QProcess e depois faz regex na saída de log pra saber o
 *     que aconteceu.
 *   - Este binário chama `ffi::mount`, `ffi::status`, `ffi::list_vaults` etc.
 *     diretamente — mesmo processo, mesma memória, retorno tipado (enum
 *     VaultError / VaultStatus), sem nenhum texto pra reinterpretar.
 *
 * Build:
 *   cargo run --release --bin nuk4sd_egui
 *
 * Nota: algumas operações (mount, sandbox) pedem privilégios que o binário
 * Nuk4sd normal também pede (montagem FUSE inicial). Rode com o mesmo
 * usuário/sudo que você já usa hoje.
 */

#[path = "../ffi.rs"]
mod ffi;

use eframe::egui;
use ffi::{VaultEntry, VaultStatus};

fn main() -> eframe::Result<()> {
    if let Err(e) = ffi::init() {
        eprintln!("Falha ao iniciar o core C: {}", e.message());
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([880.0, 560.0]),
        ..Default::default()
    };

    let result = eframe::run_native(
        "Nuk4sd (egui)",
        options,
        Box::new(|_cc| Ok(Box::new(Nuk4sdApp::new()))),
    );

    let _ = ffi::shutdown();
    result
}

struct Nuk4sdApp {
    vaults: Vec<VaultEntry>,
    selected: Option<u32>,
    password: String,
    app_cmd: String,
    gui_mode: bool,
    last_message: String,
    last_ok: bool,
}

impl Nuk4sdApp {
    fn new() -> Self {
        let mut app = Self {
            vaults: Vec::new(),
            selected: None,
            password: String::new(),
            app_cmd: String::new(),
            gui_mode: true,
            last_message: String::new(),
            last_ok: true,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        match ffi::list_vaults() {
            Ok(v) => {
                self.vaults = v;
                self.last_ok = true;
                self.last_message = format!("{} vault(s) carregado(s) do catálogo.", self.vaults.len());
            }
            Err(e) => {
                self.last_ok = false;
                self.last_message = format!("Erro ao listar vaults: {}", e.message());
            }
        }
    }

    fn report(&mut self, action: &str, result: Result<(), ffi::VaultError>) {
        match result {
            Ok(()) => {
                self.last_ok = true;
                self.last_message = format!("{action}: ok.");
            }
            Err(e) => {
                self.last_ok = false;
                self.last_message = format!("{action}: {}", e.message());
            }
        }
        self.refresh();
    }
}

impl eframe::App for Nuk4sdApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Nuk4sd");
                ui.separator();
                if ui.button("🔄 Atualizar").clicked() {
                    self.refresh();
                }
            });
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let color = if self.last_ok {
                    egui::Color32::from_rgb(90, 200, 130)
                } else {
                    egui::Color32::from_rgb(220, 90, 90)
                };
                ui.colored_label(color, &self.last_message);
            });
        });

        egui::SidePanel::right("controls").min_width(260.0).show(ctx, |ui| {
            ui.heading("Ações");
            ui.add_space(6.0);

            ui.label("Vault selecionado:");
            ui.label(match self.selected {
                Some(id) => format!("#{id}"),
                None => "(nenhum)".to_string(),
            });

            ui.add_space(10.0);
            ui.label("Senha:");
            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("🔓 Mount").clicked() {
                    if let Some(id) = self.selected {
                        let r = ffi::mount(id, &self.password);
                        self.report("Mount", r);
                    }
                }
                if ui.button("🔒 Unmount").clicked() {
                    if let Some(id) = self.selected {
                        let r = ffi::unmount(id);
                        self.report("Unmount", r);
                    }
                }
            });

            ui.horizontal(|ui| {
                if ui.button("🔐 Encrypt").clicked() {
                    if let Some(id) = self.selected {
                        let r = ffi::encrypt(id, &self.password);
                        self.report("Encrypt", r);
                    }
                }
                if ui.button("🔑 Decrypt").clicked() {
                    if let Some(id) = self.selected {
                        let r = ffi::decrypt(id, &self.password);
                        self.report("Decrypt", r);
                    }
                }
            });

            ui.add_space(14.0);
            ui.separator();
            ui.label("Abrir sandbox:");
            ui.text_edit_singleline(&mut self.app_cmd);
            ui.checkbox(&mut self.gui_mode, "App gráfico (wayland/x11)");
            if ui.button("🚀 Rodar no sandbox").clicked() {
                if let Some(id) = self.selected {
                    let r = ffi::open_sandbox(id, &self.password, self.gui_mode, &self.app_cmd);
                    self.report("Sandbox", r);
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Vaults");
            ui.add_space(6.0);

            egui::Grid::new("vault_grid")
                .striped(true)
                .num_columns(3)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("ID");
                    ui.strong("Caminho");
                    ui.strong("Status");
                    ui.end_row();

                    let vaults = self.vaults.clone();
                    for v in &vaults {
                        let is_selected = self.selected == Some(v.id);
                        if ui.selectable_label(is_selected, format!("#{}", v.id)).clicked() {
                            self.selected = Some(v.id);
                        }
                        ui.label(&v.path);
                        ui.colored_label(status_color(v.status), v.status.label());
                        ui.end_row();
                    }
                });

            if self.vaults.is_empty() {
                ui.add_space(12.0);
                ui.label("Nenhum vault no catálogo (ou catálogo ainda não carregado).");
            }
        });
    }
}

fn status_color(s: VaultStatus) -> egui::Color32 {
    match s {
        VaultStatus::Ok => egui::Color32::from_rgb(90, 200, 130),
        VaultStatus::Locked => egui::Color32::from_rgb(230, 190, 80),
        VaultStatus::Alert => egui::Color32::from_rgb(220, 90, 90),
        VaultStatus::Deleted => egui::Color32::GRAY,
        VaultStatus::Unknown(_) => egui::Color32::LIGHT_BLUE,
    }
}
