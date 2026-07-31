/*
 * ffi.rs
 *
 * Safe Rust bindings for vault_ffi.c and vault_cli.c (core C).
 * All calls execute directly in memory via static linking.
 */

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

pub const VAULT_PATH_MAX: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VaultIdPathRaw {
    pub id: u32,
    pub path: [c_char; VAULT_PATH_MAX],
}

impl Default for VaultIdPathRaw {
    fn default() -> Self {
        VaultIdPathRaw {
            id: 0,
            path: [0; VAULT_PATH_MAX],
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultEntry {
    pub id: u32,
    pub path: String,
    pub status: VaultStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultStatus {
    Ok,
    Locked,
    Alert,
    Deleted,
    Unknown(i32),
}

impl VaultStatus {
    pub fn from_raw(v: c_int) -> Self {
        match v {
            0 => VaultStatus::Ok,
            1 => VaultStatus::Locked,
            2 => VaultStatus::Alert,
            3 => VaultStatus::Deleted,
            other => VaultStatus::Unknown(other),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            VaultStatus::Ok => "Montado / Ativo",
            VaultStatus::Locked => "Desmontado / Trancado",
            VaultStatus::Alert => "Alerta de Integridade",
            VaultStatus::Deleted => "Removido",
            VaultStatus::Unknown(_) => "Desconhecido",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    Ok,
    InvalidArgs,
    NoMemory,
    Io,
    Crypto,
    AuthFail,
    VaultLocked,
    VaultExists,
    VaultNotFound,
    PermDenied,
    CatalogFull,
    PathInvalid,
    PassRequired,
    Integrity,
    System,
    Unknown(i32),
}

impl VaultError {
    pub fn from_raw(v: c_int) -> Self {
        match v {
            0 => VaultError::Ok,
            -1 => VaultError::InvalidArgs,
            -2 => VaultError::NoMemory,
            -3 => VaultError::Io,
            -4 => VaultError::Crypto,
            -5 => VaultError::AuthFail,
            -6 => VaultError::VaultLocked,
            -7 => VaultError::VaultExists,
            -8 => VaultError::VaultNotFound,
            -9 => VaultError::PermDenied,
            -10 => VaultError::CatalogFull,
            -11 => VaultError::PathInvalid,
            -12 => VaultError::PassRequired,
            -13 => VaultError::Integrity,
            -14 => VaultError::System,
            other => VaultError::Unknown(other),
        }
    }

    pub fn message(&self) -> String {
        match self {
            VaultError::Ok => "Operação realizada com sucesso".into(),
            VaultError::InvalidArgs => "Argumentos inválidos".into(),
            VaultError::NoMemory => "Memória insuficiente".into(),
            VaultError::Io => "Erro de entrada/saída (I/O)".into(),
            VaultError::Crypto => "Erro de criptografia (OpenSSL/Argon2)".into(),
            VaultError::AuthFail => "Senha incorreta ou falha de autenticação".into(),
            VaultError::VaultLocked => "O vault está trancado".into(),
            VaultError::VaultExists => "O vault especificado já existe".into(),
            VaultError::VaultNotFound => "Vault não encontrado".into(),
            VaultError::PermDenied => "Permissão negada".into(),
            VaultError::CatalogFull => "Catálogo de vaults cheio".into(),
            VaultError::PathInvalid => "Caminho de arquivo inválido".into(),
            VaultError::PassRequired => "Senha é obrigatória".into(),
            VaultError::Integrity => "Falha na verificação de integridade".into(),
            VaultError::System => "Erro no subsistema do sistema operacional".into(),
            VaultError::Unknown(code) => format!("Erro desconhecido ({code})"),
        }
    }
}

pub type VResult = Result<(), VaultError>;

fn check(raw: c_int) -> VResult {
    let e = VaultError::from_raw(raw);
    if e == VaultError::Ok {
        Ok(())
    } else {
        Err(e)
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

extern "C" {
    fn vault_ffi_init() -> c_int;
    fn vault_ffi_shutdown() -> c_int;

    fn vault_create_ffi(
        name: *const c_char,
        vault_type: c_int,
        path: *const c_char,
        password: *const c_char,
    ) -> c_int;
    fn vault_delete_ffi(id: u32, password: *const c_char) -> c_int;

    fn vault_mount_ffi(id: u32, password: *const c_char) -> c_int;
    fn vault_unmount_ffi(id: u32) -> c_int;

    fn vault_encrypt_ffi(id: u32, password: *const c_char) -> c_int;
    fn vault_decrypt_ffi(id: u32, password: *const c_char) -> c_int;

    fn vault_get_status_ffi(id: u32) -> c_int;

    fn vault_sandbox_ffi(
        id: u32,
        password: *const c_char,
        gui_mode: c_int,
        app_cmd: *const c_char,
    ) -> c_int;

    fn vault_list_ids_ffi(out: *mut VaultIdPathRaw, out_cap: u32, out_count: *mut u32) -> c_int;
    fn vault_count_ffi() -> u32;

    fn vault_cli_parse_and_exec(argc: c_int, argv: *const *const c_char) -> c_int;

    /// Lança o sandbox com CliConfig preenchido direto por parâmetros tipados —
    /// sem string de linha de comando, sem join/split, sem getopt. Ver
    /// vault_cli.c para o porquê disso existir (bug de path com espaço).
    fn vault_sandbox_run_ffi(
        vault_id: u32,
        password: *const c_char,
        exec_path: *const c_char,
        no_net: bool,
        wayland: bool,
        x11: bool,
        audio: bool,
        ro_home: bool,
        no_fuse: bool,
        seccomp_strict: bool,
        use_chroot: bool,
        debug: bool,
        ro_paths: *const *const c_char,
        ro_count: u32,
        rw_paths: *const *const c_char,
        rw_count: u32,
        blacklist_paths: *const *const c_char,
        blacklist_count: u32,
    ) -> c_int;
}

pub fn init() -> VResult {
    unsafe { check(vault_ffi_init()) }
}

pub fn shutdown() -> VResult {
    unsafe { check(vault_ffi_shutdown()) }
}

pub fn create_vault(name: &str, protected: bool, path: &str, password: &str) -> VResult {
    let name_c = cstr(name);
    let path_c = cstr(path);
    let pass_c = cstr(password);
    let vtype = if protected { 1 } else { 0 };
    unsafe {
        check(vault_create_ffi(
            name_c.as_ptr(),
            vtype,
            path_c.as_ptr(),
            pass_c.as_ptr(),
        ))
    }
}

pub fn delete_vault(id: u32, password: &str) -> VResult {
    let pass_c = cstr(password);
    unsafe { check(vault_delete_ffi(id, pass_c.as_ptr())) }
}

pub fn mount(id: u32, password: &str) -> VResult {
    let pass_c = cstr(password);
    unsafe { check(vault_mount_ffi(id, pass_c.as_ptr())) }
}

pub fn unmount(id: u32) -> VResult {
    unsafe { check(vault_unmount_ffi(id)) }
}

pub fn encrypt(id: u32, password: &str) -> VResult {
    let pass_c = cstr(password);
    unsafe { check(vault_encrypt_ffi(id, pass_c.as_ptr())) }
}

pub fn decrypt(id: u32, password: &str) -> VResult {
    let pass_c = cstr(password);
    unsafe { check(vault_decrypt_ffi(id, pass_c.as_ptr())) }
}

pub fn open_sandbox(id: u32, password: &str, gui_mode: bool, app_cmd: &str) -> VResult {
    let pass_c = cstr(password);
    let cmd_c = cstr(app_cmd);
    unsafe {
        check(vault_sandbox_ffi(
            id,
            pass_c.as_ptr(),
            gui_mode as c_int,
            cmd_c.as_ptr(),
        ))
    }
}

pub fn status(id: u32) -> Result<VaultStatus, VaultError> {
    let raw = unsafe { vault_get_status_ffi(id) };
    if raw < 0 {
        Err(VaultError::from_raw(raw))
    } else {
        Ok(VaultStatus::from_raw(raw))
    }
}

pub fn list_vaults() -> Result<Vec<VaultEntry>, VaultError> {
    let cap = unsafe { vault_count_ffi() }.max(1);
    let mut raw = vec![VaultIdPathRaw::default(); cap as usize];
    let mut count: u32 = 0;

    let rc = unsafe { vault_list_ids_ffi(raw.as_mut_ptr(), cap, &mut count) };
    check(rc)?;

    let mut out = Vec::with_capacity(count as usize);
    for entry in raw.into_iter().take(count as usize) {
        let path = unsafe { CStr::from_ptr(entry.path.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let st = status(entry.id).unwrap_or(VaultStatus::Unknown(-999));
        out.push(VaultEntry {
            id: entry.id,
            path,
            status: st,
        });
    }
    Ok(out)
}

/// Opções de isolamento pra `run_sandbox`. Espelha os campos `iso_*`/`no_fuse`/
/// `seccomp_strict` de CliConfig que a GUI já expõe como checkboxes.
#[derive(Clone, Debug, Default)]
pub struct SandboxOptions {
    pub no_net: bool,
    pub wayland: bool,
    pub x11: bool,
    pub audio: bool,
    pub ro_home: bool,
    pub no_fuse: bool,
    pub seccomp_strict: bool,
    pub use_chroot: bool,
    pub debug: bool,
}

/// Aceita "um path por linha" ou "path, path, path" no mesmo campo de texto
/// que a GUI já usa — sem exigir mudar o widget. Espaço sozinho dentro de um
/// path nunca quebra nada aqui, porque cada elemento vira seu próprio
/// CString: não existe join(" ") + re-split em lugar nenhum deste caminho.
pub fn split_paths(field: &str) -> Vec<String> {
    field
        .split(['\n', ','])
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Constrói os CString + array de ponteiros pra uma lista de paths, mantendo
/// os CString vivos (o array de ponteiros só é válido enquanto eles existirem).
fn cstring_array(paths: &[String]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = paths.iter().map(|p| cstr(p)).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    (owned, ptrs)
}

/// Lança `exec_path` isolado no sandbox do vault `id`, com as opções e listas
/// de bind (ro/rw/blacklist) passadas como parâmetros tipados — substitui
/// por completo o antigo caminho "monta string --flag valor + exec_cli_cmd",
/// que quebrava com espaço em path/executável.
pub fn run_sandbox(
    id: u32,
    password: &str,
    exec_path: &str,
    opts: &SandboxOptions,
    ro_paths: &[String],
    rw_paths: &[String],
    blacklist_paths: &[String],
) -> VResult {
    let pass_c = cstr(password);
    let exec_c = cstr(exec_path);

    let (_ro_owned, ro_ptrs) = cstring_array(ro_paths);
    let (_rw_owned, rw_ptrs) = cstring_array(rw_paths);
    let (_bl_owned, bl_ptrs) = cstring_array(blacklist_paths);

    unsafe {
        check(vault_sandbox_run_ffi(
            id,
            pass_c.as_ptr(),
            exec_c.as_ptr(),
            opts.no_net,
            opts.wayland,
            opts.x11,
            opts.audio,
            opts.ro_home,
            opts.no_fuse,
            opts.seccomp_strict,
            opts.use_chroot,
            opts.debug,
            ro_ptrs.as_ptr(),
            ro_ptrs.len() as u32,
            rw_ptrs.as_ptr(),
            rw_ptrs.len() as u32,
            bl_ptrs.as_ptr(),
            bl_ptrs.len() as u32,
        ))
    }
    // _ro_owned/_rw_owned/_bl_owned seguram os CString vivos até aqui —
    // só dropam depois que vault_sandbox_run_ffi já retornou.
}

/// Executa qualquer linha de comando do Nuk4sd diretamente em memória no core C.
///
/// USO: só pelo terminal embutido da GUI, onde o próprio usuário digita
/// sintaxe de CLI de propósito (texto livre é a entrada certa ali). Pra
/// lançar sandbox a partir de campos estruturados da GUI (perfil salvo,
/// formulário de lançamento customizado), use `run_sandbox` — ela não
/// re-tokeniza nada, então path/executável com espaço nunca quebra.
pub fn exec_cli_cmd(cmd_line: &str) -> (i32, String) {
    let mut args: Vec<String> = vec!["Nuk4sd".to_string()];
    args.extend(cmd_line.split_whitespace().map(|s| s.to_string()));

    let c_args: Vec<CString> = args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap_or_default())
        .collect();

    let c_ptrs: Vec<*const c_char> = c_args.iter().map(|s| s.as_ptr()).collect();

    let exit_code = unsafe {
        vault_cli_parse_and_exec(c_ptrs.len() as c_int, c_ptrs.as_ptr())
    };

    (exit_code, format!("Comando executado: {} (retorno: {})", cmd_line, exit_code))
}

/// Callback C -> Rust para cópia segura de arquivos
#[no_mangle]
pub extern "C" fn rust_vault_copy_file(src: *const c_char, dst: *const c_char) -> c_int {
    if src.is_null() || dst.is_null() {
        return -1;
    }
    let src_str = match unsafe { CStr::from_ptr(src) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let dst_str = match unsafe { CStr::from_ptr(dst) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match std::fs::copy(src_str, dst_str) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

