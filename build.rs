use std::{env, process::Command as C};

fn main() {
    let o = env::var("OUT_DIR").unwrap();

    // Resolve include paths via pkg-config when available
    let fuse3_cflags = C::new("pkg-config")
        .args(["--cflags", "fuse3"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_default();

    let openssl_cflags = C::new("pkg-config")
        .args(["--cflags", "openssl"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_default();

    let sandbox = [
        "c_src/vault_crypto.c",
        "c_src/vault_catalog.c",
        "c_src/vault_monitor.c",
        "c_src/caps.c",
        "c_src/userns.c",
        "c_src/mounts.c",
        "c_src/rlimits.c",
        "c_src/seccomp.c",
        "c_src/jail.c",
        "c_src/common.c",
        "c_src/vault_engine.c",
        "c_src/vault_ffi.c",
        "c_src/vault_fuse.c",
        "c_src/vault_cli.c",   
        "c_src/vault_cli_log.c",
        "c_src/vault_health.c",
    ];

    let mut x = Vec::new();

    for i in sandbox {
        let f = i.rsplit('/').next().unwrap();
        let n = &f[..f.len() - 2];
        let p = format!("{}/{}.o", o, n);

        let mut cmd = C::new("gcc");
        cmd.args([
            "-Oz",                          // Máxima otimização de tamanho
            "-fno-asynchronous-unwind-tables",
            "-fno-unwind-tables",
            "-fdata-sections",              // Permite --gc-sections por dado
            "-ffunction-sections",          // Permite --gc-sections por função
            "-fmerge-all-constants",        // Funde constantes duplicadas
            "-fno-ident",                   // Remove .comment com versão do GCC
            "-fvisibility=hidden",          // Oculta símbolos internos do .a
            "-fno-plt",                     // Elimina trampolins PLT desnecessários
            "-fno-exceptions",              // Sem C++ exceptions (proj é C puro)
            "-D_FILE_OFFSET_BITS=64",
            "-DVAULT_FFI_BUILD",
            "-fPIC",
            "-c",
            "-I",
            "c_src",
            i,
            "-o",
            &p,
        ]);

        // Append pkg-config cflags (include dirs) if available
        for flag in fuse3_cflags.split_whitespace() {
            cmd.arg(flag);
        }
        for flag in openssl_cflags.split_whitespace() {
            cmd.arg(flag);
        }

        assert!(cmd.status().unwrap().success());

        x.push(p);
    }

    let l = format!("{}/libvault_security.a", o);

    assert!(C::new("ar")
        .args(["rcs", &l])
        .args(&x)
        .status()
        .unwrap()
        .success());

    println!("cargo:rustc-link-search=native={}", o);
    println!("cargo:rustc-link-lib=static=vault_security");

    println!("cargo:rustc-link-arg=-Wl,--gc-sections");  // Remove seções não usadas
    // println!("cargo:rustc-link-arg=-Wl,--strip-all");     // Remove TODOS os símbolos
    println!("cargo:rustc-link-arg=-Wl,--as-needed");    // Só linka libs realmente usadas
    println!("cargo:rustc-link-arg=-Wl,-z,norelro");     // Sem RELRO (reduz overhead ELF)

    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=seccomp");
    println!("cargo:rustc-link-lib=cap");
    println!("cargo:rustc-link-lib=fuse3");

    for i in sandbox {
        println!("cargo:rerun-if-changed={}", i);
    }
    println!("cargo:rerun-if-changed=c_src/vault_core.h");
    /* FIX: vault_cli.c #include "preset.h" e #include "vault_cli_log.h",
     * mas nenhum dos dois estava na lista de rerun-if-changed. Cargo só
     * reexecuta build.rs quando um path EXPLICITAMENTE listado muda — ele
     * não sabe (nem tem como saber, sem parsing de #include) que
     * vault_cli.c depende desses headers. Resultado: editar só preset.h
     * (ex: adicionar friendly_sandbox/permissive_sandbox ao CliConfig)
     * não disparava rebuild de vault_cli.o. O .a ficava com um
     * vault_cli.o compilado contra uma versão ANTIGA/menor do struct
     * (calloc(1, sizeof(*cfg)) alocando heap pequeno demais), enquanto o
     * preset.rs — sempre recompilado pelo Cargo normalmente — já usava o
     * struct novo/maior. Resultado: leitura fora do buffer alocado em
     * qualquer campo depois do array `binds[64]` (verbose, debug,
     * json_output, password) → segfault silencioso, só em builds
     * incrementais, nunca em build limpo (por isso não repetia sempre).
     */
    println!("cargo:rerun-if-changed=c_src/preset.h");
    println!("cargo:rerun-if-changed=c_src/vault_cli_log.h");
    /* Split de vault_sandbox.c em 7 arquivos (caps/userns/mounts/rlimits/
     * seccomp/jail/common) + header único sandbox.h — mesmo motivo do
     * preset.h acima: todos os 7 .c incluem sandbox.h, então ele precisa
     * estar aqui ou uma mudança nele passa despercebida pelo Cargo. */
    println!("cargo:rerun-if-changed=c_src/sandbox.h");
    println!("cargo:rerun-if-changed=c_src/vault_health.h");
}