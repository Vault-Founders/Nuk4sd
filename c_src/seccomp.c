/*
 * seccomp.c
 *
 * Nuk4sd — Hardened Sandbox — Layer 5: Seccomp-BPF
 * Extraído de vault_sandbox.c (split modular, estilo Firejail).
 */

#include "sandbox.h"

#ifdef __linux__

/* ─────────────────────────────────────────────────────────────────────────
 *  apply_seccomp_policy(): Seccomp-BPF — Layer 5
 *
 *  g_seccomp_strict=0 (padrão): allowlist completa, clone3 permitido
 *  g_seccomp_strict=1 : remove clone3, userfaultfd, shmget/shmat, sockets
 *  g_seccomp_allow_c3=1: mesmo em strict, re-adiciona clone3 (multithread)
 *
 *  g_seccomp_friendly=1 (--friendly-sandbox): libera SÓ um punhado de
 *  syscalls de "housekeeping" de arquivo (fsync/fdatasync/renameat2) que
 *  a allowlist padrão não tinha e que programas comuns usam pra gravar
 *  estado em disco com segurança (ex.: o erro do Glean/Firefox — "Could
 *  not write ... privileges to complete"). NÃO mexe em chroot/capset/
 *  mount/setuid/setgid — essas continuam EPERM independente desta flag.
 *  Ortogonal a g_seccomp_strict: pode ligar as duas ao mesmo tempo.
 *
 *  g_seccomp_permissive=1 (--permissive): libera chroot/capset/setuid/
 *  setgid no filtro — o mesmo caminho que o Firejail escolhe pra deixar
 *  o app GUI (Firefox, Chromium, etc.) montar o PRÓPRIO sandbox interno
 *  em vez de sempre falhar com EPERM. mount/pivot_root/ptrace continuam
 *  bloqueados independente desta flag — só o necessário pro sandbox do
 *  app em si é liberado. Ortogonal às outras duas flags.
 *
 *  Vulnerabilidade clone(CLONE_NEWUSER): bloqueada via argumento mascarado.
 *  Flags de namespace em clone() causam KILL imediato (não EPERM).
 * ───────────── */
static int g_seccomp_strict     = 0;
static int g_seccomp_allow_c3   = 0;
static int g_seccomp_friendly   = 0;
static int g_seccomp_permissive = 0;

static int apply_seccomp_policy(void)
{
    /* Ação default do filtro: antes era SCMP_ACT_KILL_PROCESS (mata na
     * hora qualquer syscall fora da allowlist). Trocado pra
     * ERRNO(EPERM): a proteção é idêntica — o kernel NUNCA executa a
     * syscall de qualquer jeito — mas agora o processo recebe um erro
     * normal (EPERM) em vez de ser morto com SIGSYS. Isso importa
     * porque programas bem-comportados (glibc, coreutils, Firefox)
     * costumam checar o retorno de syscalls "opcionais"/hint (ex:
     * readahead, fadvise64, statfs) e cair num fallback gracioso —
     * mas não esperam ser mortos por tentar. As syscalls REALMENTE
     * perigosas (kexec_load, ptrace, mount, unshare...) continuam
     * explicitamente bloqueadas logo abaixo, algumas com KILL_PROCESS
     * quando a tentativa em si já é forte indício de ataque. */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx)
    {
        perror("[SANDBOX] seccomp_init");
        return -1;
    }

    /* I/O */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);
    /* fadvise64 — coreutils 'cat'/'cp' chamam posix_fadvise() como hint
     * de leitura sequencial. Sem isso, 'cat' morre com SIGSYS
     * (syscall=221) antes de ler um único byte. Apenas um hint pro
     * kernel/page-cache, não concede acesso a nada novo. */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fadvise64), 0);
    /* readahead — mesma família de hint de I/O que fadvise64, usada por
     * apps grandes (confirmado: firefox-bin morre com SIGSYS,
     * syscall=187, ao carregar seus próprios arquivos/libs). */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readahead), 0);

    /* Files */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    /* statfs/fstatfs — glibc chama durante resolução de NSS (getpwuid/
     * getgrnam etc). Sem isso, utilitários triviais como 'id' morrem
     * com SIGSYS (syscall=137) mesmo sem tocar em nada sensível. */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatfs), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);

    /* Directories */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);

    /* Memory */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

    /* Processes */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);

    /* clone() com flags de namespace (CLONE_NEWUSER/NEWNS/NEWNET/NEWPID/
     * NEWUTS/NEWIPC/NEWCGROUP): liberado sem máscara de flags.
     *
     * Antes isso tinha uma MASKED_EQ bloqueando qualquer flag de
     * namespace — mas essa proteção já era furada na prática: clone3()
     * (a syscall que a glibc >= 2.34 realmente usa, ver ALLOW dela mais
     * abaixo) sempre foi liberada SEM nenhum filtro de argumento, então
     * qualquer programa moderno já contornava a máscara por completo.
     *
     * A proteção real contra escalada de privilégio não é "impedir a
     * chamada" — é o que já está em vigor independente de qualquer
     * namespace que o processo crie por conta própria:
     *   1) capabilities já zeradas (cap_set_proc(empty)) — o bounding
     *      set não recresce nunca, nem virando "root" de um namespace
     *      aninhado que o próprio processo criou;
     *   2) este filtro seccomp é *sticky* — herdado por qualquer
     *      processo filho e por qualquer namespace aninhado, sem forma
     *      de relaxar. mount()/ptrace()/chroot()/pivot_root() etc.
     *      continuam EPERM não importa em qual namespace o processo
     *      esteja rodando.
     *
     * Isso é o mesmo modelo usado pelo Bubblewrap (motor do Flatpak) e
     * pelo sandbox interno do próprio Firefox/Chromium em qualquer
     * Linux normal — ambos dependem de unshare(CLONE_NEWUSER) sem
     * privilégio, protegidos por capabilities vazias + NO_NEW_PRIVS,
     * não pela ausência da chamada. Sem isso liberado, o sandbox
     * interno do Firefox falha ("CanCreateUserNamespace() clone()
     * failure") e ele não consegue nem tentar abrir processos de
     * conteúdo isolados — o que é o comportamento oposto do que
     * queremos (queremos MAIS isolamento dentro do Firefox, não menos).
     *
     * Risco residual honesto: não é escalada de privilégio pelo modelo
     * de permissão (isso continua bloqueado pelos dois pontos acima) —
     * é a superfície de bugs de KERNEL no código de namespace não-
     * privilegiado, que tem histórico real de CVEs. Esse risco existe
     * no nível do host (sysctl kernel.unprivileged_userns_clone), não é
     * algo que o seccomp do Nuk4sd resolve sozinho. */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execveat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsid), 0);
    /* gettid (186) + tkill (200) — called by pthreads immediately on init */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tkill), 0);
    /* sigaltstack (131) — alternate signal stack, used by Firefox crash handler */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);
    /* getrusage (98) — resource usage, used by Firefox profiler / GC */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrusage), 0);
    /* rt_sigtimedwait (128), rt_sigqueueinfo (129) — signal helpers */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigtimedwait), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigqueueinfo), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_tgsigqueueinfo), 0);

    /* Signals */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigsuspend), 0);

    /* Identity */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups), 0);

    /* Sync */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);

    /* Libc init */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);

    /* Time */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    /* rseq (restartable sequences) — called automatically by glibc/busybox on startup */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0);

    /* Resource limits — used by sandbox layer 4 and read by shell */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit), 0);

    /* Modern filesystem syscalls used by busybox */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statx), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    /* memfd_create moved to conditional block below */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(link), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rmdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdirat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(truncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmodat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lchown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimes), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimensat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msync), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mincore), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getscheduler), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getparam), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getitimer), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setitimer), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pause), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_create), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_gettime), 0);

    /* System info — uname is called by busybox sh for prompt/hostname */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
    /* Note: gethostname/tcgetattr/tcsetattr are libc wrappers over uname/ioctl, already allowed */

    /* Process/session management used by shell job control */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresgid), 0);
    /* tcgetattr/tcsetattr are ioctl wrappers — ioctl already in allowlist */

    /* File copy / sendfile used by cp and similar builtins */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(copy_file_range), 0);

    /* Misc libc internals */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_getres), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_settime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(times), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);

    /* Poll / select — needed by interactive shell */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6), 0);

    /* Access / permissions */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat2), 0);

    /* prctl — busybox sh uses it to read process name / check caps */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);

    /* ── GUI / Browser syscalls (Firefox, Chromium, Electron) ─────────── *
     * These are required for modern multi-process browsers to start.      *
     * They do NOT grant privilege escalation (setuid/mount remain KILL).  */

    /* clone3: replaces clone() in glibc >= 2.34, used by Firefox/Chromium */
    if (!g_seccomp_strict || g_seccomp_allow_c3) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone3), 0);
    }

    if (!g_seccomp_strict) {
        /* Sockets — needed for Wayland/X11 IPC and browser inter-process comm */
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmmsg), 0);

        /* Shared memory — used by GPU/IPC in Chromium-based browsers */
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmget), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmctl), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmdt), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munlock), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlockall), 0);
        
        /* memfd_create — memory execution vector */
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(memfd_create), 0);
        /* userfaultfd (if it were allowed, we'd block it here) */
    }

    /* inotify — Firefox profile locking */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init1), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_add_watch), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_rm_watch), 0);

    /* futex_waitv / futex2 — modern threading */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex_waitv), 0);

    /* Scheduling — Firefox uses real-time hints for audio/video */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setscheduler), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setparam), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setaffinity), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getaffinity), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpriority), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpriority), 0);

    /* File locking — SQLite / profile databases */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flock), 0);

    /* ── --friendly-sandbox: syscalls de escrita segura em disco ─────────
     * fsync/fdatasync/renameat2 são o padrão clássico de "gravação
     * atômica de arquivo" (escreve num temp, fsync, rename por cima do
     * destino) usado por SQLite, glean_core (telemetria do Firefox),
     * bancos de config de várias libs GTK/glib. Sem eles o processo não
     * crasha, só perde silenciosamente a gravação — foi exatamente o
     * "[ERROR glean_core::core] Could not write ... to state file"
     * observado em teste. NÃO toca em chroot/capset/mount/setuid/setgid,
     * que continuam bloqueados independente desta flag. */
    if (g_seccomp_friendly) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fdatasync), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(renameat2), 0);
    }

    /* Extended attributes — used by some GTK/glib features */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fgetxattr), 0);

    /* openat2 — used by newer glibc / systemd resolver stubs */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat2), 0);

    /* close_range — glibc 2.34+ uses it to close fds efficiently */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close_range), 0);

    /* Misc modern syscalls used by JIT (SpiderMonkey / V8) */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 0);
    /* userfaultfd NÃO é liberado aqui de propósito — ver seção
     * "Blocked sandbox boundary operations" abaixo. É um primitivo
     * clássico de exploração de kernel (usado em boa parte dos CVEs
     * reais de escalada de privilégio via condições de corrida em
     * page fault); apps JIT como SpiderMonkey/V8 funcionam sem ele,
     * só perdem uma otimização específica de GC. Havia uma regra
     * ALLOW duplicada aqui antes, conflitando com o EPERM mais abaixo
     * — removida para eliminar a ambiguidade. */

    /* unshare()/setns(): liberados pelo mesmo motivo do clone() acima —
     * é exatamente isso que o sandbox interno do Firefox chama
     * (CanCreateUserNamespace(), visto no log como "clone() failure:
     * EPERM" antes desta mudança). A proteção real contra escape
     * continua sendo capabilities zeradas + o próprio filtro seccomp
     * (sticky, não relaxa em namespace aninhado) — ver comentário
     * longo junto do clone(), mais acima. */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unshare), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setns), 0);

    /* Fatal actions: strong indicators of sandbox escape attempt */
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(kexec_load), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_writev), 0);

    /* Blocked sandbox boundary operations — esta é a fronteira real:
     * mount/pivot_root continuam bloqueadas mesmo de dentro de um
     * namespace aninhado, porque o seccomp não é afetado por namespace
     * nenhum. Essas NUNCA são liberadas por nenhuma flag — não fazem
     * parte do sandbox interno de nenhum app, só serviriam pra escapar
     * do jail do Nuk4sd em si. */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(pivot_root), 0);

    /* ── --permissive: chroot/capset/setuid/setgid ────────────────────────
     * Essas quatro são exatamente o que um app GUI (Firefox, Chromium)
     * usa pra montar o PRÓPRIO sandbox interno de content-process — é
     * por isso que aparecem separadas do bloco acima. Sem --permissive,
     * ficam EPERM incondicional (padrão, mais restrito — igual sempre
     * foi). Com --permissive, ficam liberadas, seguindo a mesma escolha
     * que o Firejail faz: abrir mão de um pouco de força NESSE filtro
     * específico pra preservar a defesa em profundidade do app rodando
     * dentro. mount/pivot_root continuam bloqueados de qualquer jeito —
     * essas quatro syscalls sozinhas não dão fuga do jail do Nuk4sd. */
    if (g_seccomp_permissive) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chroot), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capset), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setuid), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgid), 0);
    } else {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(capset), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setuid), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setgid), 0);
    }

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(perf_event_open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(userfaultfd), 0);
    

    int ret = seccomp_load(ctx);
    if (ret != 0)
        perror("[SANDBOX] seccomp_load");
    seccomp_release(ctx);
    return ret;
}

int vsb_apply_seccomp(void) { return apply_seccomp_policy(); }

void vsb_set_seccomp_mode(int strict, int allow_c3, int friendly, int permissive) {
    g_seccomp_strict     = strict;
    g_seccomp_allow_c3   = allow_c3;
    g_seccomp_friendly   = friendly;
    g_seccomp_permissive = permissive;
}

#endif /* __linux__ */
