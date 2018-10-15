package syscalls

import "syscall"

var _ = syscall.Exit

var Name = map[uint64]string{
	syscall.SYS_EXIT:           "exit",           // { void sys_exit(int rval); }
	syscall.SYS_FORK:           "fork",           // { int sys_fork(void); }
	syscall.SYS_READ:           "read",           // { ssize_t sys_read(int fd, void *buf, size_t nbyte); }
	syscall.SYS_WRITE:          "write",          // { ssize_t sys_write(int fd, const void *buf, \
	syscall.SYS_OPEN:           "open",           // { int sys_open(const char *path, \
	syscall.SYS_CLOSE:          "close",          // { int sys_close(int fd); }
	syscall.SYS_GETENTROPY:     "getentropy",     // { int sys_getentropy(void *buf, size_t nbyte); }
	syscall.SYS___TFORK:        "__tfork",        // { int sys___tfork(const struct __tfork *param, \
	syscall.SYS_LINK:           "link",           // { int sys_link(const char *path, const char *link); }
	syscall.SYS_UNLINK:         "unlink",         // { int sys_unlink(const char *path); }
	syscall.SYS_WAIT4:          "wait4",          // { pid_t sys_wait4(pid_t pid, int *status, \
	syscall.SYS_CHDIR:          "chdir",          // { int sys_chdir(const char *path); }
	syscall.SYS_FCHDIR:         "fchdir",         // { int sys_fchdir(int fd); }
	syscall.SYS_MKNOD:          "mknod",          // { int sys_mknod(const char *path, mode_t mode, \
	syscall.SYS_CHMOD:          "chmod",          // { int sys_chmod(const char *path, mode_t mode); }
	syscall.SYS_CHOWN:          "chown",          // { int sys_chown(const char *path, uid_t uid, \
	syscall.SYS_OBREAK:         "obreak",         // { int sys_obreak(char *nsize); } break
	syscall.SYS_GETDTABLECOUNT: "getdtablecount", // { int sys_getdtablecount(void); }
	syscall.SYS_GETRUSAGE:      "getrusage",      // { int sys_getrusage(int who, \
	syscall.SYS_GETPID:         "getpid",         // { pid_t sys_getpid(void); }
	syscall.SYS_MOUNT:          "mount",          // { int sys_mount(const char *type, const char *path, \
	syscall.SYS_UNMOUNT:        "unmount",        // { int sys_unmount(const char *path, int flags); }
	syscall.SYS_SETUID:         "setuid",         // { int sys_setuid(uid_t uid); }
	syscall.SYS_GETUID:         "getuid",         // { uid_t sys_getuid(void); }
	syscall.SYS_GETEUID:        "geteuid",        // { uid_t sys_geteuid(void); }
	syscall.SYS_PTRACE:         "ptrace",         // { int sys_ptrace(int req, pid_t pid, caddr_t addr, \
	syscall.SYS_RECVMSG:        "recvmsg",        // { ssize_t sys_recvmsg(int s, struct msghdr *msg, \
	syscall.SYS_SENDMSG:        "sendmsg",        // { ssize_t sys_sendmsg(int s, \
	syscall.SYS_RECVFROM:       "recvfrom",       // { ssize_t sys_recvfrom(int s, void *buf, size_t len, \
	syscall.SYS_ACCEPT:         "accept",         // { int sys_accept(int s, struct sockaddr *name, \
	syscall.SYS_GETPEERNAME:    "getpeername",    // { int sys_getpeername(int fdes, struct sockaddr *asa, \
	syscall.SYS_GETSOCKNAME:    "getsockname",    // { int sys_getsockname(int fdes, struct sockaddr *asa, \
	syscall.SYS_ACCESS:         "access",         // { int sys_access(const char *path, int amode); }
	syscall.SYS_CHFLAGS:        "chflags",        // { int sys_chflags(const char *path, u_int flags); }
	syscall.SYS_FCHFLAGS:       "fchflags",       // { int sys_fchflags(int fd, u_int flags); }
	syscall.SYS_SYNC:           "sync",           // { void sys_sync(void); }
	syscall.SYS_STAT:           "stat",           // { int sys_stat(const char *path, struct stat *ub); }
	syscall.SYS_GETPPID:        "getppid",        // { pid_t sys_getppid(void); }
	syscall.SYS_LSTAT:          "lstat",          // { int sys_lstat(const char *path, struct stat *ub); }
	syscall.SYS_DUP:            "dup",            // { int sys_dup(int fd); }
	syscall.SYS_FSTATAT:        "fstatat",        // { int sys_fstatat(int fd, const char *path, \
	syscall.SYS_GETEGID:        "getegid",        // { gid_t sys_getegid(void); }
	syscall.SYS_PROFIL:         "profil",         // { int sys_profil(caddr_t samples, size_t size, \
	syscall.SYS_KTRACE:         "ktrace",         // { int sys_ktrace(const char *fname, int ops, \
	syscall.SYS_SIGACTION:      "sigaction",      // { int sys_sigaction(int signum, \
	syscall.SYS_GETGID:         "getgid",         // { gid_t sys_getgid(void); }
	syscall.SYS_SIGPROCMASK:    "sigprocmask",    // { int sys_sigprocmask(int how, sigset_t mask); }
	syscall.SYS_GETLOGIN:       "getlogin",       // { int sys_getlogin(char *namebuf, u_int namelen); }
	syscall.SYS_SETLOGIN:       "setlogin",       // { int sys_setlogin(const char *namebuf); }
	syscall.SYS_ACCT:           "acct",           // { int sys_acct(const char *path); }
	syscall.SYS_SIGPENDING:     "sigpending",     // { int sys_sigpending(void); }
	syscall.SYS_FSTAT:          "fstat",          // { int sys_fstat(int fd, struct stat *sb); }
	syscall.SYS_IOCTL:          "ioctl",          // { int sys_ioctl(int fd, \
	syscall.SYS_REBOOT:         "reboot",         // { int sys_reboot(int opt); }
	syscall.SYS_REVOKE:         "revoke",         // { int sys_revoke(const char *path); }
	syscall.SYS_SYMLINK:        "symlink",        // { int sys_symlink(const char *path, \
	syscall.SYS_READLINK:       "readlink",       // { ssize_t sys_readlink(const char *path, \
	syscall.SYS_EXECVE:         "execve",         // { int sys_execve(const char *path, \
	syscall.SYS_UMASK:          "umask",          // { mode_t sys_umask(mode_t newmask); }
	syscall.SYS_CHROOT:         "chroot",         // { int sys_chroot(const char *path); }
	syscall.SYS_GETFSSTAT:      "getfsstat",      // { int sys_getfsstat(struct statfs *buf, size_t bufsize, \
	syscall.SYS_STATFS:         "statfs",         // { int sys_statfs(const char *path, \
	syscall.SYS_FSTATFS:        "fstatfs",        // { int sys_fstatfs(int fd, struct statfs *buf); }
	syscall.SYS_FHSTATFS:       "fhstatfs",       // { int sys_fhstatfs(const fhandle_t *fhp, \
	syscall.SYS_VFORK:          "vfork",          // { int sys_vfork(void); }
	syscall.SYS_GETTIMEOFDAY:   "gettimeofday",   // { int sys_gettimeofday(struct timeval *tp, \
	syscall.SYS_SETTIMEOFDAY:   "settimeofday",   // { int sys_settimeofday(const struct timeval *tv, \
	syscall.SYS_SETITIMER:      "setitimer",      // { int sys_setitimer(int which, \
	syscall.SYS_GETITIMER:      "getitimer",      // { int sys_getitimer(int which, \
	syscall.SYS_SELECT:         "select",         // { int sys_select(int nd, fd_set *in, fd_set *ou, \
	syscall.SYS_KEVENT:         "kevent",         // { int sys_kevent(int fd, \
	syscall.SYS_MUNMAP:         "munmap",         // { int sys_munmap(void *addr, size_t len); }
	syscall.SYS_MPROTECT:       "mprotect",       // { int sys_mprotect(void *addr, size_t len, \
	syscall.SYS_MADVISE:        "madvise",        // { int sys_madvise(void *addr, size_t len, \
	syscall.SYS_UTIMES:         "utimes",         // { int sys_utimes(const char *path, \
	syscall.SYS_FUTIMES:        "futimes",        // { int sys_futimes(int fd, \
	syscall.SYS_MINCORE:        "mincore",        // { int sys_mincore(void *addr, size_t len, \
	syscall.SYS_GETGROUPS:      "getgroups",      // { int sys_getgroups(int gidsetsize, \
	syscall.SYS_SETGROUPS:      "setgroups",      // { int sys_setgroups(int gidsetsize, \
	syscall.SYS_GETPGRP:        "getpgrp",        // { int sys_getpgrp(void); }
	syscall.SYS_SETPGID:        "setpgid",        // { int sys_setpgid(pid_t pid, pid_t pgid); }
	syscall.SYS_SENDSYSLOG:     "sendsyslog",     // { int sys_sendsyslog(const void *buf, size_t nbyte); }
	syscall.SYS_UTIMENSAT:      "utimensat",      // { int sys_utimensat(int fd, const char *path, \
	syscall.SYS_FUTIMENS:       "futimens",       // { int sys_futimens(int fd, \
	syscall.SYS_CLOCK_GETTIME:  "clock_gettime",  // { int sys_clock_gettime(clockid_t clock_id, \
	syscall.SYS_CLOCK_SETTIME:  "clock_settime",  // { int sys_clock_settime(clockid_t clock_id, \
	syscall.SYS_CLOCK_GETRES:   "clock_getres",   // { int sys_clock_getres(clockid_t clock_id, \
	syscall.SYS_DUP2:           "dup2",           // { int sys_dup2(int from, int to); }
	syscall.SYS_NANOSLEEP:      "nanosleep",      // { int sys_nanosleep(const struct timespec *rqtp, \
	syscall.SYS_FCNTL:          "fcntl",          // { int sys_fcntl(int fd, int cmd, ... void *arg); }
	syscall.SYS_ACCEPT4:        "accept4",        // { int sys_accept4(int s, struct sockaddr *name, \
	syscall.SYS___THRSLEEP:     "__thrsleep",     // { int sys___thrsleep(const volatile void *ident, \
	syscall.SYS_FSYNC:          "fsync",          // { int sys_fsync(int fd); }
	syscall.SYS_SETPRIORITY:    "setpriority",    // { int sys_setpriority(int which, id_t who, int prio); }
	syscall.SYS_SOCKET:         "socket",         // { int sys_socket(int domain, int type, int protocol); }
	syscall.SYS_CONNECT:        "connect",        // { int sys_connect(int s, const struct sockaddr *name, \
	syscall.SYS_GETDENTS:       "getdents",       // { int sys_getdents(int fd, void *buf, size_t buflen); }
	syscall.SYS_GETPRIORITY:    "getpriority",    // { int sys_getpriority(int which, id_t who); }
	syscall.SYS_PIPE2:          "pipe2",          // { int sys_pipe2(int *fdp, int flags); }
	syscall.SYS_DUP3:           "dup3",           // { int sys_dup3(int from, int to, int flags); }
	syscall.SYS_SIGRETURN:      "sigreturn",      // { int sys_sigreturn(struct sigcontext *sigcntxp); }
	syscall.SYS_BIND:           "bind",           // { int sys_bind(int s, const struct sockaddr *name, \
	syscall.SYS_SETSOCKOPT:     "setsockopt",     // { int sys_setsockopt(int s, int level, int name, \
	syscall.SYS_LISTEN:         "listen",         // { int sys_listen(int s, int backlog); }
	syscall.SYS_CHFLAGSAT:      "chflagsat",      // { int sys_chflagsat(int fd, const char *path, \
	syscall.SYS_PPOLL:          "ppoll",          // { int sys_ppoll(struct pollfd *fds, \
	syscall.SYS_PSELECT:        "pselect",        // { int sys_pselect(int nd, fd_set *in, fd_set *ou, \
	syscall.SYS_SIGSUSPEND:     "sigsuspend",     // { int sys_sigsuspend(int mask); }
	syscall.SYS_GETSOCKOPT:     "getsockopt",     // { int sys_getsockopt(int s, int level, int name, \
	syscall.SYS_READV:          "readv",          // { ssize_t sys_readv(int fd, \
	syscall.SYS_WRITEV:         "writev",         // { ssize_t sys_writev(int fd, \
	syscall.SYS_KILL:           "kill",           // { int sys_kill(int pid, int signum); }
	syscall.SYS_FCHOWN:         "fchown",         // { int sys_fchown(int fd, uid_t uid, gid_t gid); }
	syscall.SYS_FCHMOD:         "fchmod",         // { int sys_fchmod(int fd, mode_t mode); }
	syscall.SYS_SETREUID:       "setreuid",       // { int sys_setreuid(uid_t ruid, uid_t euid); }
	syscall.SYS_SETREGID:       "setregid",       // { int sys_setregid(gid_t rgid, gid_t egid); }
	syscall.SYS_RENAME:         "rename",         // { int sys_rename(const char *from, const char *to); }
	syscall.SYS_FLOCK:          "flock",          // { int sys_flock(int fd, int how); }
	syscall.SYS_MKFIFO:         "mkfifo",         // { int sys_mkfifo(const char *path, mode_t mode); }
	syscall.SYS_SENDTO:         "sendto",         // { ssize_t sys_sendto(int s, const void *buf, \
	syscall.SYS_SHUTDOWN:       "shutdown",       // { int sys_shutdown(int s, int how); }
	syscall.SYS_SOCKETPAIR:     "socketpair",     // { int sys_socketpair(int domain, int type, \
	syscall.SYS_MKDIR:          "mkdir",          // { int sys_mkdir(const char *path, mode_t mode); }
	syscall.SYS_RMDIR:          "rmdir",          // { int sys_rmdir(const char *path); }
	syscall.SYS_ADJTIME:        "adjtime",        // { int sys_adjtime(const struct timeval *delta, \
	syscall.SYS_SETSID:         "setsid",         // { int sys_setsid(void); }
	syscall.SYS_QUOTACTL:       "quotactl",       // { int sys_quotactl(const char *path, int cmd, \
	syscall.SYS_NFSSVC:         "nfssvc",         // { int sys_nfssvc(int flag, void *argp); }
	syscall.SYS_GETFH:          "getfh",          // { int sys_getfh(const char *fname, fhandle_t *fhp); }
	syscall.SYS_SYSARCH:        "sysarch",        // { int sys_sysarch(int op, void *parms); }
	syscall.SYS_PREAD:          "pread",          // { ssize_t sys_pread(int fd, void *buf, \
	syscall.SYS_PWRITE:         "pwrite",         // { ssize_t sys_pwrite(int fd, const void *buf, \
	syscall.SYS_SETGID:         "setgid",         // { int sys_setgid(gid_t gid); }
	syscall.SYS_SETEGID:        "setegid",        // { int sys_setegid(gid_t egid); }
	syscall.SYS_SETEUID:        "seteuid",        // { int sys_seteuid(uid_t euid); }
	syscall.SYS_PATHCONF:       "pathconf",       // { long sys_pathconf(const char *path, int name); }
	syscall.SYS_FPATHCONF:      "fpathconf",      // { long sys_fpathconf(int fd, int name); }
	syscall.SYS_SWAPCTL:        "swapctl",        // { int sys_swapctl(int cmd, const void *arg, int misc); }
	syscall.SYS_GETRLIMIT:      "getrlimit",      // { int sys_getrlimit(int which, \
	syscall.SYS_SETRLIMIT:      "setrlimit",      // { int sys_setrlimit(int which, \
	syscall.SYS_MMAP:           "mmap",           // { void *sys_mmap(void *addr, size_t len, int prot, \
	syscall.SYS_LSEEK:          "lseek",          // { off_t sys_lseek(int fd, int pad, off_t offset, \
	syscall.SYS_TRUNCATE:       "truncate",       // { int sys_truncate(const char *path, int pad, \
	syscall.SYS_FTRUNCATE:      "ftruncate",      // { int sys_ftruncate(int fd, int pad, off_t length); }
	syscall.SYS___SYSCTL:       "__sysctl",       // { int sys___sysctl(const int *name, u_int namelen, \
	syscall.SYS_MLOCK:          "mlock",          // { int sys_mlock(const void *addr, size_t len); }
	syscall.SYS_MUNLOCK:        "munlock",        // { int sys_munlock(const void *addr, size_t len); }
	syscall.SYS_GETPGID:        "getpgid",        // { pid_t sys_getpgid(pid_t pid); }
	syscall.SYS_UTRACE:         "utrace",         // { int sys_utrace(const char *label, const void *addr, \
	syscall.SYS_SEMGET:         "semget",         // { int sys_semget(key_t key, int nsems, int semflg); }
	syscall.SYS_MSGGET:         "msgget",         // { int sys_msgget(key_t key, int msgflg); }
	syscall.SYS_MSGSND:         "msgsnd",         // { int sys_msgsnd(int msqid, const void *msgp, size_t msgsz, \
	syscall.SYS_MSGRCV:         "msgrcv",         // { int sys_msgrcv(int msqid, void *msgp, size_t msgsz, \
	syscall.SYS_SHMAT:          "shmat",          // { void *sys_shmat(int shmid, const void *shmaddr, \
	syscall.SYS_SHMDT:          "shmdt",          // { int sys_shmdt(const void *shmaddr); }
	syscall.SYS_MINHERIT:       "minherit",       // { int sys_minherit(void *addr, size_t len, \
	syscall.SYS_POLL:           "poll",           // { int sys_poll(struct pollfd *fds, \
	syscall.SYS_ISSETUGID:      "issetugid",      // { int sys_issetugid(void); }
	syscall.SYS_LCHOWN:         "lchown",         // { int sys_lchown(const char *path, uid_t uid, gid_t gid); }
	syscall.SYS_GETSID:         "getsid",         // { pid_t sys_getsid(pid_t pid); }
	syscall.SYS_MSYNC:          "msync",          // { int sys_msync(void *addr, size_t len, int flags); }
	syscall.SYS_PIPE:           "pipe",           // { int sys_pipe(int *fdp); }
	syscall.SYS_FHOPEN:         "fhopen",         // { int sys_fhopen(const fhandle_t *fhp, int flags); }
	syscall.SYS_PREADV:         "preadv",         // { ssize_t sys_preadv(int fd, \
	syscall.SYS_PWRITEV:        "pwritev",        // { ssize_t sys_pwritev(int fd, \
	syscall.SYS_KQUEUE:         "kqueue",         // { int sys_kqueue(void); }
	syscall.SYS_MLOCKALL:       "mlockall",       // { int sys_mlockall(int flags); }
	syscall.SYS_MUNLOCKALL:     "munlockall",     // { int sys_munlockall(void); }
	syscall.SYS_GETRESUID:      "getresuid",      // { int sys_getresuid(uid_t *ruid, uid_t *euid, \
	syscall.SYS_SETRESUID:      "setresuid",      // { int sys_setresuid(uid_t ruid, uid_t euid, \
	syscall.SYS_GETRESGID:      "getresgid",      // { int sys_getresgid(gid_t *rgid, gid_t *egid, \
	syscall.SYS_SETRESGID:      "setresgid",      // { int sys_setresgid(gid_t rgid, gid_t egid, \
	syscall.SYS_MQUERY:         "mquery",         // { void *sys_mquery(void *addr, size_t len, int prot, \
	syscall.SYS_CLOSEFROM:      "closefrom",      // { int sys_closefrom(int fd); }
	syscall.SYS_SIGALTSTACK:    "sigaltstack",    // { int sys_sigaltstack(const struct sigaltstack *nss, \
	syscall.SYS_SHMGET:         "shmget",         // { int sys_shmget(key_t key, size_t size, int shmflg); }
	syscall.SYS_SEMOP:          "semop",          // { int sys_semop(int semid, struct sembuf *sops, \
	syscall.SYS_FHSTAT:         "fhstat",         // { int sys_fhstat(const fhandle_t *fhp, \
	syscall.SYS___SEMCTL:       "__semctl",       // { int sys___semctl(int semid, int semnum, int cmd, \
	syscall.SYS_SHMCTL:         "shmctl",         // { int sys_shmctl(int shmid, int cmd, \
	syscall.SYS_MSGCTL:         "msgctl",         // { int sys_msgctl(int msqid, int cmd, \
	syscall.SYS_SCHED_YIELD:    "sched_yield",    // { int sys_sched_yield(void); }
	syscall.SYS_GETTHRID:       "getthrid",       // { pid_t sys_getthrid(void); }
	syscall.SYS___THRWAKEUP:    "__thrwakeup",    // { int sys___thrwakeup(const volatile void *ident, \
	syscall.SYS___THREXIT:      "__threxit",      // { void sys___threxit(pid_t *notdead); }
	syscall.SYS___THRSIGDIVERT: "__thrsigdivert", // { int sys___thrsigdivert(sigset_t sigmask, \
	syscall.SYS___GETCWD:       "__getcwd",       // { int sys___getcwd(char *buf, size_t len); }
	syscall.SYS_ADJFREQ:        "adjfreq",        // { int sys_adjfreq(const int64_t *freq, \
	syscall.SYS_SETRTABLE:      "setrtable",      // { int sys_setrtable(int rtableid); }
	syscall.SYS_GETRTABLE:      "getrtable",      // { int sys_getrtable(void); }
	syscall.SYS_FACCESSAT:      "faccessat",      // { int sys_faccessat(int fd, const char *path, \
	syscall.SYS_FCHMODAT:       "fchmodat",       // { int sys_fchmodat(int fd, const char *path, \
	syscall.SYS_FCHOWNAT:       "fchownat",       // { int sys_fchownat(int fd, const char *path, \
	syscall.SYS_LINKAT:         "linkat",         // { int sys_linkat(int fd1, const char *path1, int fd2, \
	syscall.SYS_MKDIRAT:        "mkdirat",        // { int sys_mkdirat(int fd, const char *path, \
	syscall.SYS_MKFIFOAT:       "mkfifoat",       // { int sys_mkfifoat(int fd, const char *path, \
	syscall.SYS_MKNODAT:        "mknodat",        // { int sys_mknodat(int fd, const char *path, \
	syscall.SYS_OPENAT:         "openat",         // { int sys_openat(int fd, const char *path, int flags, \
	syscall.SYS_READLINKAT:     "readlinkat",     // { ssize_t sys_readlinkat(int fd, const char *path, \
	syscall.SYS_RENAMEAT:       "renameat",       // { int sys_renameat(int fromfd, const char *from, \
	syscall.SYS_SYMLINKAT:      "symlinkat",      // { int sys_symlinkat(const char *path, int fd, \
	syscall.SYS_UNLINKAT:       "unlinkat",       // { int sys_unlinkat(int fd, const char *path, \
	syscall.SYS___SET_TCB:      "__set_tcb",      // { void sys___set_tcb(void *tcb); }
	syscall.SYS___GET_TCB:      "__get_tcb",      // { void *sys___get_tcb(void); }
}
