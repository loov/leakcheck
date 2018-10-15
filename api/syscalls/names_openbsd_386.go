package syscalls

import "golang.org/x/sys/unix"

var _ = unix.Exit

var Name = map[uint64]string{
	unix.SYS_EXIT:           "exit",           // { void sys_exit(int rval); }
	unix.SYS_FORK:           "fork",           // { int sys_fork(void); }
	unix.SYS_READ:           "read",           // { ssize_t sys_read(int fd, void *buf, size_t nbyte); }
	unix.SYS_WRITE:          "write",          // { ssize_t sys_write(int fd, const void *buf, \
	unix.SYS_OPEN:           "open",           // { int sys_open(const char *path, \
	unix.SYS_CLOSE:          "close",          // { int sys_close(int fd); }
	unix.SYS___TFORK:        "__tfork",        // { int sys___tfork(const struct __tfork *param, \
	unix.SYS_LINK:           "link",           // { int sys_link(const char *path, const char *link); }
	unix.SYS_UNLINK:         "unlink",         // { int sys_unlink(const char *path); }
	unix.SYS_WAIT4:          "wait4",          // { pid_t sys_wait4(pid_t pid, int *status, \
	unix.SYS_CHDIR:          "chdir",          // { int sys_chdir(const char *path); }
	unix.SYS_FCHDIR:         "fchdir",         // { int sys_fchdir(int fd); }
	unix.SYS_MKNOD:          "mknod",          // { int sys_mknod(const char *path, mode_t mode, \
	unix.SYS_CHMOD:          "chmod",          // { int sys_chmod(const char *path, mode_t mode); }
	unix.SYS_CHOWN:          "chown",          // { int sys_chown(const char *path, uid_t uid, \
	unix.SYS_OBREAK:         "obreak",         // { int sys_obreak(char *nsize); } break
	unix.SYS_GETDTABLECOUNT: "getdtablecount", // { int sys_getdtablecount(void); }
	unix.SYS_GETRUSAGE:      "getrusage",      // { int sys_getrusage(int who, \
	unix.SYS_GETPID:         "getpid",         // { pid_t sys_getpid(void); }
	unix.SYS_MOUNT:          "mount",          // { int sys_mount(const char *type, const char *path, \
	unix.SYS_UNMOUNT:        "unmount",        // { int sys_unmount(const char *path, int flags); }
	unix.SYS_SETUID:         "setuid",         // { int sys_setuid(uid_t uid); }
	unix.SYS_GETUID:         "getuid",         // { uid_t sys_getuid(void); }
	unix.SYS_GETEUID:        "geteuid",        // { uid_t sys_geteuid(void); }
	unix.SYS_PTRACE:         "ptrace",         // { int sys_ptrace(int req, pid_t pid, caddr_t addr, \
	unix.SYS_RECVMSG:        "recvmsg",        // { ssize_t sys_recvmsg(int s, struct msghdr *msg, \
	unix.SYS_SENDMSG:        "sendmsg",        // { ssize_t sys_sendmsg(int s, \
	unix.SYS_RECVFROM:       "recvfrom",       // { ssize_t sys_recvfrom(int s, void *buf, size_t len, \
	unix.SYS_ACCEPT:         "accept",         // { int sys_accept(int s, struct sockaddr *name, \
	unix.SYS_GETPEERNAME:    "getpeername",    // { int sys_getpeername(int fdes, struct sockaddr *asa, \
	unix.SYS_GETSOCKNAME:    "getsockname",    // { int sys_getsockname(int fdes, struct sockaddr *asa, \
	unix.SYS_ACCESS:         "access",         // { int sys_access(const char *path, int flags); }
	unix.SYS_CHFLAGS:        "chflags",        // { int sys_chflags(const char *path, u_int flags); }
	unix.SYS_FCHFLAGS:       "fchflags",       // { int sys_fchflags(int fd, u_int flags); }
	unix.SYS_SYNC:           "sync",           // { void sys_sync(void); }
	unix.SYS_KILL:           "kill",           // { int sys_kill(int pid, int signum); }
	unix.SYS_STAT:           "stat",           // { int sys_stat(const char *path, struct stat *ub); }
	unix.SYS_GETPPID:        "getppid",        // { pid_t sys_getppid(void); }
	unix.SYS_LSTAT:          "lstat",          // { int sys_lstat(const char *path, struct stat *ub); }
	unix.SYS_DUP:            "dup",            // { int sys_dup(int fd); }
	unix.SYS_FSTATAT:        "fstatat",        // { int sys_fstatat(int fd, const char *path, \
	unix.SYS_GETEGID:        "getegid",        // { gid_t sys_getegid(void); }
	unix.SYS_PROFIL:         "profil",         // { int sys_profil(caddr_t samples, size_t size, \
	unix.SYS_KTRACE:         "ktrace",         // { int sys_ktrace(const char *fname, int ops, \
	unix.SYS_SIGACTION:      "sigaction",      // { int sys_sigaction(int signum, \
	unix.SYS_GETGID:         "getgid",         // { gid_t sys_getgid(void); }
	unix.SYS_SIGPROCMASK:    "sigprocmask",    // { int sys_sigprocmask(int how, sigset_t mask); }
	unix.SYS_GETLOGIN:       "getlogin",       // { int sys_getlogin(char *namebuf, u_int namelen); }
	unix.SYS_SETLOGIN:       "setlogin",       // { int sys_setlogin(const char *namebuf); }
	unix.SYS_ACCT:           "acct",           // { int sys_acct(const char *path); }
	unix.SYS_SIGPENDING:     "sigpending",     // { int sys_sigpending(void); }
	unix.SYS_FSTAT:          "fstat",          // { int sys_fstat(int fd, struct stat *sb); }
	unix.SYS_IOCTL:          "ioctl",          // { int sys_ioctl(int fd, \
	unix.SYS_REBOOT:         "reboot",         // { int sys_reboot(int opt); }
	unix.SYS_REVOKE:         "revoke",         // { int sys_revoke(const char *path); }
	unix.SYS_SYMLINK:        "symlink",        // { int sys_symlink(const char *path, \
	unix.SYS_READLINK:       "readlink",       // { int sys_readlink(const char *path, char *buf, \
	unix.SYS_EXECVE:         "execve",         // { int sys_execve(const char *path, \
	unix.SYS_UMASK:          "umask",          // { mode_t sys_umask(mode_t newmask); }
	unix.SYS_CHROOT:         "chroot",         // { int sys_chroot(const char *path); }
	unix.SYS_GETFSSTAT:      "getfsstat",      // { int sys_getfsstat(struct statfs *buf, size_t bufsize, \
	unix.SYS_STATFS:         "statfs",         // { int sys_statfs(const char *path, \
	unix.SYS_FSTATFS:        "fstatfs",        // { int sys_fstatfs(int fd, struct statfs *buf); }
	unix.SYS_FHSTATFS:       "fhstatfs",       // { int sys_fhstatfs(const fhandle_t *fhp, \
	unix.SYS_VFORK:          "vfork",          // { int sys_vfork(void); }
	unix.SYS_GETTIMEOFDAY:   "gettimeofday",   // { int sys_gettimeofday(struct timeval *tp, \
	unix.SYS_SETTIMEOFDAY:   "settimeofday",   // { int sys_settimeofday(const struct timeval *tv, \
	unix.SYS_SETITIMER:      "setitimer",      // { int sys_setitimer(int which, \
	unix.SYS_GETITIMER:      "getitimer",      // { int sys_getitimer(int which, \
	unix.SYS_SELECT:         "select",         // { int sys_select(int nd, fd_set *in, fd_set *ou, \
	unix.SYS_KEVENT:         "kevent",         // { int sys_kevent(int fd, \
	unix.SYS_MUNMAP:         "munmap",         // { int sys_munmap(void *addr, size_t len); }
	unix.SYS_MPROTECT:       "mprotect",       // { int sys_mprotect(void *addr, size_t len, \
	unix.SYS_MADVISE:        "madvise",        // { int sys_madvise(void *addr, size_t len, \
	unix.SYS_UTIMES:         "utimes",         // { int sys_utimes(const char *path, \
	unix.SYS_FUTIMES:        "futimes",        // { int sys_futimes(int fd, \
	unix.SYS_MINCORE:        "mincore",        // { int sys_mincore(void *addr, size_t len, \
	unix.SYS_GETGROUPS:      "getgroups",      // { int sys_getgroups(int gidsetsize, \
	unix.SYS_SETGROUPS:      "setgroups",      // { int sys_setgroups(int gidsetsize, \
	unix.SYS_GETPGRP:        "getpgrp",        // { int sys_getpgrp(void); }
	unix.SYS_SETPGID:        "setpgid",        // { int sys_setpgid(pid_t pid, int pgid); }
	unix.SYS_UTIMENSAT:      "utimensat",      // { int sys_utimensat(int fd, const char *path, \
	unix.SYS_FUTIMENS:       "futimens",       // { int sys_futimens(int fd, \
	unix.SYS_CLOCK_GETTIME:  "clock_gettime",  // { int sys_clock_gettime(clockid_t clock_id, \
	unix.SYS_CLOCK_SETTIME:  "clock_settime",  // { int sys_clock_settime(clockid_t clock_id, \
	unix.SYS_CLOCK_GETRES:   "clock_getres",   // { int sys_clock_getres(clockid_t clock_id, \
	unix.SYS_DUP2:           "dup2",           // { int sys_dup2(int from, int to); }
	unix.SYS_NANOSLEEP:      "nanosleep",      // { int sys_nanosleep(const struct timespec *rqtp, \
	unix.SYS_FCNTL:          "fcntl",          // { int sys_fcntl(int fd, int cmd, ... void *arg); }
	unix.SYS___THRSLEEP:     "__thrsleep",     // { int sys___thrsleep(const volatile void *ident, \
	unix.SYS_FSYNC:          "fsync",          // { int sys_fsync(int fd); }
	unix.SYS_SETPRIORITY:    "setpriority",    // { int sys_setpriority(int which, id_t who, int prio); }
	unix.SYS_SOCKET:         "socket",         // { int sys_socket(int domain, int type, int protocol); }
	unix.SYS_CONNECT:        "connect",        // { int sys_connect(int s, const struct sockaddr *name, \
	unix.SYS_GETDENTS:       "getdents",       // { int sys_getdents(int fd, void *buf, size_t buflen); }
	unix.SYS_GETPRIORITY:    "getpriority",    // { int sys_getpriority(int which, id_t who); }
	unix.SYS_SIGRETURN:      "sigreturn",      // { int sys_sigreturn(struct sigcontext *sigcntxp); }
	unix.SYS_BIND:           "bind",           // { int sys_bind(int s, const struct sockaddr *name, \
	unix.SYS_SETSOCKOPT:     "setsockopt",     // { int sys_setsockopt(int s, int level, int name, \
	unix.SYS_LISTEN:         "listen",         // { int sys_listen(int s, int backlog); }
	unix.SYS_PPOLL:          "ppoll",          // { int sys_ppoll(struct pollfd *fds, \
	unix.SYS_PSELECT:        "pselect",        // { int sys_pselect(int nd, fd_set *in, fd_set *ou, \
	unix.SYS_SIGSUSPEND:     "sigsuspend",     // { int sys_sigsuspend(int mask); }
	unix.SYS_GETSOCKOPT:     "getsockopt",     // { int sys_getsockopt(int s, int level, int name, \
	unix.SYS_READV:          "readv",          // { ssize_t sys_readv(int fd, \
	unix.SYS_WRITEV:         "writev",         // { ssize_t sys_writev(int fd, \
	unix.SYS_FCHOWN:         "fchown",         // { int sys_fchown(int fd, uid_t uid, gid_t gid); }
	unix.SYS_FCHMOD:         "fchmod",         // { int sys_fchmod(int fd, mode_t mode); }
	unix.SYS_SETREUID:       "setreuid",       // { int sys_setreuid(uid_t ruid, uid_t euid); }
	unix.SYS_SETREGID:       "setregid",       // { int sys_setregid(gid_t rgid, gid_t egid); }
	unix.SYS_RENAME:         "rename",         // { int sys_rename(const char *from, const char *to); }
	unix.SYS_FLOCK:          "flock",          // { int sys_flock(int fd, int how); }
	unix.SYS_MKFIFO:         "mkfifo",         // { int sys_mkfifo(const char *path, mode_t mode); }
	unix.SYS_SENDTO:         "sendto",         // { ssize_t sys_sendto(int s, const void *buf, \
	unix.SYS_SHUTDOWN:       "shutdown",       // { int sys_shutdown(int s, int how); }
	unix.SYS_SOCKETPAIR:     "socketpair",     // { int sys_socketpair(int domain, int type, \
	unix.SYS_MKDIR:          "mkdir",          // { int sys_mkdir(const char *path, mode_t mode); }
	unix.SYS_RMDIR:          "rmdir",          // { int sys_rmdir(const char *path); }
	unix.SYS_ADJTIME:        "adjtime",        // { int sys_adjtime(const struct timeval *delta, \
	unix.SYS_SETSID:         "setsid",         // { int sys_setsid(void); }
	unix.SYS_QUOTACTL:       "quotactl",       // { int sys_quotactl(const char *path, int cmd, \
	unix.SYS_NFSSVC:         "nfssvc",         // { int sys_nfssvc(int flag, void *argp); }
	unix.SYS_GETFH:          "getfh",          // { int sys_getfh(const char *fname, fhandle_t *fhp); }
	unix.SYS_SYSARCH:        "sysarch",        // { int sys_sysarch(int op, void *parms); }
	unix.SYS_PREAD:          "pread",          // { ssize_t sys_pread(int fd, void *buf, \
	unix.SYS_PWRITE:         "pwrite",         // { ssize_t sys_pwrite(int fd, const void *buf, \
	unix.SYS_SETGID:         "setgid",         // { int sys_setgid(gid_t gid); }
	unix.SYS_SETEGID:        "setegid",        // { int sys_setegid(gid_t egid); }
	unix.SYS_SETEUID:        "seteuid",        // { int sys_seteuid(uid_t euid); }
	unix.SYS_PATHCONF:       "pathconf",       // { long sys_pathconf(const char *path, int name); }
	unix.SYS_FPATHCONF:      "fpathconf",      // { long sys_fpathconf(int fd, int name); }
	unix.SYS_SWAPCTL:        "swapctl",        // { int sys_swapctl(int cmd, const void *arg, int misc); }
	unix.SYS_GETRLIMIT:      "getrlimit",      // { int sys_getrlimit(int which, \
	unix.SYS_SETRLIMIT:      "setrlimit",      // { int sys_setrlimit(int which, \
	unix.SYS_MMAP:           "mmap",           // { void *sys_mmap(void *addr, size_t len, int prot, \
	unix.SYS_LSEEK:          "lseek",          // { off_t sys_lseek(int fd, int pad, off_t offset, \
	unix.SYS_TRUNCATE:       "truncate",       // { int sys_truncate(const char *path, int pad, \
	unix.SYS_FTRUNCATE:      "ftruncate",      // { int sys_ftruncate(int fd, int pad, off_t length); }
	unix.SYS___SYSCTL:       "__sysctl",       // { int sys___sysctl(const int *name, u_int namelen, \
	unix.SYS_MLOCK:          "mlock",          // { int sys_mlock(const void *addr, size_t len); }
	unix.SYS_MUNLOCK:        "munlock",        // { int sys_munlock(const void *addr, size_t len); }
	unix.SYS_GETPGID:        "getpgid",        // { pid_t sys_getpgid(pid_t pid); }
	unix.SYS_UTRACE:         "utrace",         // { int sys_utrace(const char *label, const void *addr, \
	unix.SYS_SEMGET:         "semget",         // { int sys_semget(key_t key, int nsems, int semflg); }
	unix.SYS_MSGGET:         "msgget",         // { int sys_msgget(key_t key, int msgflg); }
	unix.SYS_MSGSND:         "msgsnd",         // { int sys_msgsnd(int msqid, const void *msgp, size_t msgsz, \
	unix.SYS_MSGRCV:         "msgrcv",         // { int sys_msgrcv(int msqid, void *msgp, size_t msgsz, \
	unix.SYS_SHMAT:          "shmat",          // { void *sys_shmat(int shmid, const void *shmaddr, \
	unix.SYS_SHMDT:          "shmdt",          // { int sys_shmdt(const void *shmaddr); }
	unix.SYS_MINHERIT:       "minherit",       // { int sys_minherit(void *addr, size_t len, \
	unix.SYS_POLL:           "poll",           // { int sys_poll(struct pollfd *fds, \
	unix.SYS_ISSETUGID:      "issetugid",      // { int sys_issetugid(void); }
	unix.SYS_LCHOWN:         "lchown",         // { int sys_lchown(const char *path, uid_t uid, gid_t gid); }
	unix.SYS_GETSID:         "getsid",         // { pid_t sys_getsid(pid_t pid); }
	unix.SYS_MSYNC:          "msync",          // { int sys_msync(void *addr, size_t len, int flags); }
	unix.SYS_PIPE:           "pipe",           // { int sys_pipe(int *fdp); }
	unix.SYS_FHOPEN:         "fhopen",         // { int sys_fhopen(const fhandle_t *fhp, int flags); }
	unix.SYS_PREADV:         "preadv",         // { ssize_t sys_preadv(int fd, \
	unix.SYS_PWRITEV:        "pwritev",        // { ssize_t sys_pwritev(int fd, \
	unix.SYS_KQUEUE:         "kqueue",         // { int sys_kqueue(void); }
	unix.SYS_MLOCKALL:       "mlockall",       // { int sys_mlockall(int flags); }
	unix.SYS_MUNLOCKALL:     "munlockall",     // { int sys_munlockall(void); }
	unix.SYS_GETRESUID:      "getresuid",      // { int sys_getresuid(uid_t *ruid, uid_t *euid, \
	unix.SYS_SETRESUID:      "setresuid",      // { int sys_setresuid(uid_t ruid, uid_t euid, \
	unix.SYS_GETRESGID:      "getresgid",      // { int sys_getresgid(gid_t *rgid, gid_t *egid, \
	unix.SYS_SETRESGID:      "setresgid",      // { int sys_setresgid(gid_t rgid, gid_t egid, \
	unix.SYS_MQUERY:         "mquery",         // { void *sys_mquery(void *addr, size_t len, int prot, \
	unix.SYS_CLOSEFROM:      "closefrom",      // { int sys_closefrom(int fd); }
	unix.SYS_SIGALTSTACK:    "sigaltstack",    // { int sys_sigaltstack(const struct sigaltstack *nss, \
	unix.SYS_SHMGET:         "shmget",         // { int sys_shmget(key_t key, size_t size, int shmflg); }
	unix.SYS_SEMOP:          "semop",          // { int sys_semop(int semid, struct sembuf *sops, \
	unix.SYS_FHSTAT:         "fhstat",         // { int sys_fhstat(const fhandle_t *fhp, \
	unix.SYS___SEMCTL:       "__semctl",       // { int sys___semctl(int semid, int semnum, int cmd, \
	unix.SYS_SHMCTL:         "shmctl",         // { int sys_shmctl(int shmid, int cmd, \
	unix.SYS_MSGCTL:         "msgctl",         // { int sys_msgctl(int msqid, int cmd, \
	unix.SYS_SCHED_YIELD:    "sched_yield",    // { int sys_sched_yield(void); }
	unix.SYS_GETTHRID:       "getthrid",       // { pid_t sys_getthrid(void); }
	unix.SYS___THRWAKEUP:    "__thrwakeup",    // { int sys___thrwakeup(const volatile void *ident, \
	unix.SYS___THREXIT:      "__threxit",      // { void sys___threxit(pid_t *notdead); }
	unix.SYS___THRSIGDIVERT: "__thrsigdivert", // { int sys___thrsigdivert(sigset_t sigmask, \
	unix.SYS___GETCWD:       "__getcwd",       // { int sys___getcwd(char *buf, size_t len); }
	unix.SYS_ADJFREQ:        "adjfreq",        // { int sys_adjfreq(const int64_t *freq, \
	unix.SYS_SETRTABLE:      "setrtable",      // { int sys_setrtable(int rtableid); }
	unix.SYS_GETRTABLE:      "getrtable",      // { int sys_getrtable(void); }
	unix.SYS_FACCESSAT:      "faccessat",      // { int sys_faccessat(int fd, const char *path, \
	unix.SYS_FCHMODAT:       "fchmodat",       // { int sys_fchmodat(int fd, const char *path, \
	unix.SYS_FCHOWNAT:       "fchownat",       // { int sys_fchownat(int fd, const char *path, \
	unix.SYS_LINKAT:         "linkat",         // { int sys_linkat(int fd1, const char *path1, int fd2, \
	unix.SYS_MKDIRAT:        "mkdirat",        // { int sys_mkdirat(int fd, const char *path, \
	unix.SYS_MKFIFOAT:       "mkfifoat",       // { int sys_mkfifoat(int fd, const char *path, \
	unix.SYS_MKNODAT:        "mknodat",        // { int sys_mknodat(int fd, const char *path, \
	unix.SYS_OPENAT:         "openat",         // { int sys_openat(int fd, const char *path, int flags, \
	unix.SYS_READLINKAT:     "readlinkat",     // { ssize_t sys_readlinkat(int fd, const char *path, \
	unix.SYS_RENAMEAT:       "renameat",       // { int sys_renameat(int fromfd, const char *from, \
	unix.SYS_SYMLINKAT:      "symlinkat",      // { int sys_symlinkat(const char *path, int fd, \
	unix.SYS_UNLINKAT:       "unlinkat",       // { int sys_unlinkat(int fd, const char *path, \
	unix.SYS___SET_TCB:      "__set_tcb",      // { void sys___set_tcb(void *tcb); }
	unix.SYS___GET_TCB:      "__get_tcb",      // { void *sys___get_tcb(void); }
}
