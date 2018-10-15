package syscalls

import "syscall"

var _ = syscall.Exit

var Name = map[uint64]string{
	syscall.SYS_EXIT:                 "exit",                 // { void|sys||exit(int rval); }
	syscall.SYS_FORK:                 "fork",                 // { int|sys||fork(void); }
	syscall.SYS_READ:                 "read",                 // { ssize_t|sys||read(int fd, void *buf, size_t nbyte); }
	syscall.SYS_WRITE:                "write",                // { ssize_t|sys||write(int fd, const void *buf, size_t nbyte); }
	syscall.SYS_OPEN:                 "open",                 // { int|sys||open(const char *path, int flags, ... mode_t mode); }
	syscall.SYS_CLOSE:                "close",                // { int|sys||close(int fd); }
	syscall.SYS_LINK:                 "link",                 // { int|sys||link(const char *path, const char *link); }
	syscall.SYS_UNLINK:               "unlink",               // { int|sys||unlink(const char *path); }
	syscall.SYS_CHDIR:                "chdir",                // { int|sys||chdir(const char *path); }
	syscall.SYS_FCHDIR:               "fchdir",               // { int|sys||fchdir(int fd); }
	syscall.SYS_CHMOD:                "chmod",                // { int|sys||chmod(const char *path, mode_t mode); }
	syscall.SYS_CHOWN:                "chown",                // { int|sys||chown(const char *path, uid_t uid, gid_t gid); }
	syscall.SYS_BREAK:                "break",                // { int|sys||obreak(char *nsize); }
	syscall.SYS_GETPID:               "getpid",               // { pid_t|sys||getpid_with_ppid(void); }
	syscall.SYS_UNMOUNT:              "unmount",              // { int|sys||unmount(const char *path, int flags); }
	syscall.SYS_SETUID:               "setuid",               // { int|sys||setuid(uid_t uid); }
	syscall.SYS_GETUID:               "getuid",               // { uid_t|sys||getuid_with_euid(void); }
	syscall.SYS_GETEUID:              "geteuid",              // { uid_t|sys||geteuid(void); }
	syscall.SYS_PTRACE:               "ptrace",               // { int|sys||ptrace(int req, pid_t pid, void *addr, int data); }
	syscall.SYS_RECVMSG:              "recvmsg",              // { ssize_t|sys||recvmsg(int s, struct msghdr *msg, int flags); }
	syscall.SYS_SENDMSG:              "sendmsg",              // { ssize_t|sys||sendmsg(int s, const struct msghdr *msg, int flags); }
	syscall.SYS_RECVFROM:             "recvfrom",             // { ssize_t|sys||recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlenaddr); }
	syscall.SYS_ACCEPT:               "accept",               // { int|sys||accept(int s, struct sockaddr *name, socklen_t *anamelen); }
	syscall.SYS_GETPEERNAME:          "getpeername",          // { int|sys||getpeername(int fdes, struct sockaddr *asa, socklen_t *alen); }
	syscall.SYS_GETSOCKNAME:          "getsockname",          // { int|sys||getsockname(int fdes, struct sockaddr *asa, socklen_t *alen); }
	syscall.SYS_ACCESS:               "access",               // { int|sys||access(const char *path, int flags); }
	syscall.SYS_CHFLAGS:              "chflags",              // { int|sys||chflags(const char *path, u_long flags); }
	syscall.SYS_FCHFLAGS:             "fchflags",             // { int|sys||fchflags(int fd, u_long flags); }
	syscall.SYS_SYNC:                 "sync",                 // { void|sys||sync(void); }
	syscall.SYS_KILL:                 "kill",                 // { int|sys||kill(pid_t pid, int signum); }
	syscall.SYS_GETPPID:              "getppid",              // { pid_t|sys||getppid(void); }
	syscall.SYS_DUP:                  "dup",                  // { int|sys||dup(int fd); }
	syscall.SYS_PIPE:                 "pipe",                 // { int|sys||pipe(void); }
	syscall.SYS_GETEGID:              "getegid",              // { gid_t|sys||getegid(void); }
	syscall.SYS_PROFIL:               "profil",               // { int|sys||profil(char *samples, size_t size, u_long offset, u_int scale); }
	syscall.SYS_KTRACE:               "ktrace",               // { int|sys||ktrace(const char *fname, int ops, int facs, pid_t pid); }
	syscall.SYS_GETGID:               "getgid",               // { gid_t|sys||getgid_with_egid(void); }
	syscall.SYS___GETLOGIN:           "__getlogin",           // { int|sys||__getlogin(char *namebuf, size_t namelen); }
	syscall.SYS___SETLOGIN:           "__setlogin",           // { int|sys||__setlogin(const char *namebuf); }
	syscall.SYS_ACCT:                 "acct",                 // { int|sys||acct(const char *path); }
	syscall.SYS_IOCTL:                "ioctl",                // { int|sys||ioctl(int fd, u_long com, ... void *data); }
	syscall.SYS_REVOKE:               "revoke",               // { int|sys||revoke(const char *path); }
	syscall.SYS_SYMLINK:              "symlink",              // { int|sys||symlink(const char *path, const char *link); }
	syscall.SYS_READLINK:             "readlink",             // { ssize_t|sys||readlink(const char *path, char *buf, size_t count); }
	syscall.SYS_EXECVE:               "execve",               // { int|sys||execve(const char *path, char * const *argp, char * const *envp); }
	syscall.SYS_UMASK:                "umask",                // { mode_t|sys||umask(mode_t newmask); }
	syscall.SYS_CHROOT:               "chroot",               // { int|sys||chroot(const char *path); }
	syscall.SYS_VFORK:                "vfork",                // { int|sys||vfork(void); }
	syscall.SYS_SBRK:                 "sbrk",                 // { int|sys||sbrk(intptr_t incr); }
	syscall.SYS_SSTK:                 "sstk",                 // { int|sys||sstk(int incr); }
	syscall.SYS_VADVISE:              "vadvise",              // { int|sys||ovadvise(int anom); }
	syscall.SYS_MUNMAP:               "munmap",               // { int|sys||munmap(void *addr, size_t len); }
	syscall.SYS_MPROTECT:             "mprotect",             // { int|sys||mprotect(void *addr, size_t len, int prot); }
	syscall.SYS_MADVISE:              "madvise",              // { int|sys||madvise(void *addr, size_t len, int behav); }
	syscall.SYS_MINCORE:              "mincore",              // { int|sys||mincore(void *addr, size_t len, char *vec); }
	syscall.SYS_GETGROUPS:            "getgroups",            // { int|sys||getgroups(int gidsetsize, gid_t *gidset); }
	syscall.SYS_SETGROUPS:            "setgroups",            // { int|sys||setgroups(int gidsetsize, const gid_t *gidset); }
	syscall.SYS_GETPGRP:              "getpgrp",              // { int|sys||getpgrp(void); }
	syscall.SYS_SETPGID:              "setpgid",              // { int|sys||setpgid(pid_t pid, pid_t pgid); }
	syscall.SYS_DUP2:                 "dup2",                 // { int|sys||dup2(int from, int to); }
	syscall.SYS_FCNTL:                "fcntl",                // { int|sys||fcntl(int fd, int cmd, ... void *arg); }
	syscall.SYS_FSYNC:                "fsync",                // { int|sys||fsync(int fd); }
	syscall.SYS_SETPRIORITY:          "setpriority",          // { int|sys||setpriority(int which, id_t who, int prio); }
	syscall.SYS_CONNECT:              "connect",              // { int|sys||connect(int s, const struct sockaddr *name, socklen_t namelen); }
	syscall.SYS_GETPRIORITY:          "getpriority",          // { int|sys||getpriority(int which, id_t who); }
	syscall.SYS_BIND:                 "bind",                 // { int|sys||bind(int s, const struct sockaddr *name, socklen_t namelen); }
	syscall.SYS_SETSOCKOPT:           "setsockopt",           // { int|sys||setsockopt(int s, int level, int name, const void *val, socklen_t valsize); }
	syscall.SYS_LISTEN:               "listen",               // { int|sys||listen(int s, int backlog); }
	syscall.SYS_GETSOCKOPT:           "getsockopt",           // { int|sys||getsockopt(int s, int level, int name, void *val, socklen_t *avalsize); }
	syscall.SYS_READV:                "readv",                // { ssize_t|sys||readv(int fd, const struct iovec *iovp, int iovcnt); }
	syscall.SYS_WRITEV:               "writev",               // { ssize_t|sys||writev(int fd, const struct iovec *iovp, int iovcnt); }
	syscall.SYS_FCHOWN:               "fchown",               // { int|sys||fchown(int fd, uid_t uid, gid_t gid); }
	syscall.SYS_FCHMOD:               "fchmod",               // { int|sys||fchmod(int fd, mode_t mode); }
	syscall.SYS_SETREUID:             "setreuid",             // { int|sys||setreuid(uid_t ruid, uid_t euid); }
	syscall.SYS_SETREGID:             "setregid",             // { int|sys||setregid(gid_t rgid, gid_t egid); }
	syscall.SYS_RENAME:               "rename",               // { int|sys||rename(const char *from, const char *to); }
	syscall.SYS_FLOCK:                "flock",                // { int|sys||flock(int fd, int how); }
	syscall.SYS_MKFIFO:               "mkfifo",               // { int|sys||mkfifo(const char *path, mode_t mode); }
	syscall.SYS_SENDTO:               "sendto",               // { ssize_t|sys||sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen); }
	syscall.SYS_SHUTDOWN:             "shutdown",             // { int|sys||shutdown(int s, int how); }
	syscall.SYS_SOCKETPAIR:           "socketpair",           // { int|sys||socketpair(int domain, int type, int protocol, int *rsv); }
	syscall.SYS_MKDIR:                "mkdir",                // { int|sys||mkdir(const char *path, mode_t mode); }
	syscall.SYS_RMDIR:                "rmdir",                // { int|sys||rmdir(const char *path); }
	syscall.SYS_SETSID:               "setsid",               // { int|sys||setsid(void); }
	syscall.SYS_SYSARCH:              "sysarch",              // { int|sys||sysarch(int op, void *parms); }
	syscall.SYS_PREAD:                "pread",                // { ssize_t|sys||pread(int fd, void *buf, size_t nbyte, int PAD, off_t offset); }
	syscall.SYS_PWRITE:               "pwrite",               // { ssize_t|sys||pwrite(int fd, const void *buf, size_t nbyte, int PAD, off_t offset); }
	syscall.SYS_NTP_ADJTIME:          "ntp_adjtime",          // { int|sys||ntp_adjtime(struct timex *tp); }
	syscall.SYS_SETGID:               "setgid",               // { int|sys||setgid(gid_t gid); }
	syscall.SYS_SETEGID:              "setegid",              // { int|sys||setegid(gid_t egid); }
	syscall.SYS_SETEUID:              "seteuid",              // { int|sys||seteuid(uid_t euid); }
	syscall.SYS_PATHCONF:             "pathconf",             // { long|sys||pathconf(const char *path, int name); }
	syscall.SYS_FPATHCONF:            "fpathconf",            // { long|sys||fpathconf(int fd, int name); }
	syscall.SYS_GETRLIMIT:            "getrlimit",            // { int|sys||getrlimit(int which, struct rlimit *rlp); }
	syscall.SYS_SETRLIMIT:            "setrlimit",            // { int|sys||setrlimit(int which, const struct rlimit *rlp); }
	syscall.SYS_MMAP:                 "mmap",                 // { void *|sys||mmap(void *addr, size_t len, int prot, int flags, int fd, long PAD, off_t pos); }
	syscall.SYS_LSEEK:                "lseek",                // { off_t|sys||lseek(int fd, int PAD, off_t offset, int whence); }
	syscall.SYS_TRUNCATE:             "truncate",             // { int|sys||truncate(const char *path, int PAD, off_t length); }
	syscall.SYS_FTRUNCATE:            "ftruncate",            // { int|sys||ftruncate(int fd, int PAD, off_t length); }
	syscall.SYS___SYSCTL:             "__sysctl",             // { int|sys||__sysctl(const int *name, u_int namelen, void *old, size_t *oldlenp, const void *new, size_t newlen); }
	syscall.SYS_MLOCK:                "mlock",                // { int|sys||mlock(const void *addr, size_t len); }
	syscall.SYS_MUNLOCK:              "munlock",              // { int|sys||munlock(const void *addr, size_t len); }
	syscall.SYS_UNDELETE:             "undelete",             // { int|sys||undelete(const char *path); }
	syscall.SYS_GETPGID:              "getpgid",              // { pid_t|sys||getpgid(pid_t pid); }
	syscall.SYS_REBOOT:               "reboot",               // { int|sys||reboot(int opt, char *bootstr); }
	syscall.SYS_POLL:                 "poll",                 // { int|sys||poll(struct pollfd *fds, u_int nfds, int timeout); }
	syscall.SYS_SEMGET:               "semget",               // { int|sys||semget(key_t key, int nsems, int semflg); }
	syscall.SYS_SEMOP:                "semop",                // { int|sys||semop(int semid, struct sembuf *sops, size_t nsops); }
	syscall.SYS_SEMCONFIG:            "semconfig",            // { int|sys||semconfig(int flag); }
	syscall.SYS_MSGGET:               "msgget",               // { int|sys||msgget(key_t key, int msgflg); }
	syscall.SYS_MSGSND:               "msgsnd",               // { int|sys||msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); }
	syscall.SYS_MSGRCV:               "msgrcv",               // { ssize_t|sys||msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); }
	syscall.SYS_SHMAT:                "shmat",                // { void *|sys||shmat(int shmid, const void *shmaddr, int shmflg); }
	syscall.SYS_SHMDT:                "shmdt",                // { int|sys||shmdt(const void *shmaddr); }
	syscall.SYS_SHMGET:               "shmget",               // { int|sys||shmget(key_t key, size_t size, int shmflg); }
	syscall.SYS_TIMER_CREATE:         "timer_create",         // { int|sys||timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid); }
	syscall.SYS_TIMER_DELETE:         "timer_delete",         // { int|sys||timer_delete(timer_t timerid); }
	syscall.SYS_TIMER_GETOVERRUN:     "timer_getoverrun",     // { int|sys||timer_getoverrun(timer_t timerid); }
	syscall.SYS_FDATASYNC:            "fdatasync",            // { int|sys||fdatasync(int fd); }
	syscall.SYS_MLOCKALL:             "mlockall",             // { int|sys||mlockall(int flags); }
	syscall.SYS_MUNLOCKALL:           "munlockall",           // { int|sys||munlockall(void); }
	syscall.SYS_SIGQUEUEINFO:         "sigqueueinfo",         // { int|sys||sigqueueinfo(pid_t pid, const siginfo_t *info); }
	syscall.SYS_MODCTL:               "modctl",               // { int|sys||modctl(int cmd, void *arg); }
	syscall.SYS___POSIX_RENAME:       "__posix_rename",       // { int|sys||__posix_rename(const char *from, const char *to); }
	syscall.SYS_SWAPCTL:              "swapctl",              // { int|sys||swapctl(int cmd, void *arg, int misc); }
	syscall.SYS_MINHERIT:             "minherit",             // { int|sys||minherit(void *addr, size_t len, int inherit); }
	syscall.SYS_LCHMOD:               "lchmod",               // { int|sys||lchmod(const char *path, mode_t mode); }
	syscall.SYS_LCHOWN:               "lchown",               // { int|sys||lchown(const char *path, uid_t uid, gid_t gid); }
	syscall.SYS_MSYNC:                "msync",                // { int|sys|13|msync(void *addr, size_t len, int flags); }
	syscall.SYS___POSIX_CHOWN:        "__posix_chown",        // { int|sys||__posix_chown(const char *path, uid_t uid, gid_t gid); }
	syscall.SYS___POSIX_FCHOWN:       "__posix_fchown",       // { int|sys||__posix_fchown(int fd, uid_t uid, gid_t gid); }
	syscall.SYS___POSIX_LCHOWN:       "__posix_lchown",       // { int|sys||__posix_lchown(const char *path, uid_t uid, gid_t gid); }
	syscall.SYS_GETSID:               "getsid",               // { pid_t|sys||getsid(pid_t pid); }
	syscall.SYS___CLONE:              "__clone",              // { pid_t|sys||__clone(int flags, void *stack); }
	syscall.SYS_FKTRACE:              "fktrace",              // { int|sys||fktrace(int fd, int ops, int facs, pid_t pid); }
	syscall.SYS_PREADV:               "preadv",               // { ssize_t|sys||preadv(int fd, const struct iovec *iovp, int iovcnt, int PAD, off_t offset); }
	syscall.SYS_PWRITEV:              "pwritev",              // { ssize_t|sys||pwritev(int fd, const struct iovec *iovp, int iovcnt, int PAD, off_t offset); }
	syscall.SYS___GETCWD:             "__getcwd",             // { int|sys||__getcwd(char *bufp, size_t length); }
	syscall.SYS_FCHROOT:              "fchroot",              // { int|sys||fchroot(int fd); }
	syscall.SYS_LCHFLAGS:             "lchflags",             // { int|sys||lchflags(const char *path, u_long flags); }
	syscall.SYS_ISSETUGID:            "issetugid",            // { int|sys||issetugid(void); }
	syscall.SYS_UTRACE:               "utrace",               // { int|sys||utrace(const char *label, void *addr, size_t len); }
	syscall.SYS_GETCONTEXT:           "getcontext",           // { int|sys||getcontext(struct __ucontext *ucp); }
	syscall.SYS_SETCONTEXT:           "setcontext",           // { int|sys||setcontext(const struct __ucontext *ucp); }
	syscall.SYS__LWP_CREATE:          "_lwp_create",          // { int|sys||_lwp_create(const struct __ucontext *ucp, u_long flags, lwpid_t *new_lwp); }
	syscall.SYS__LWP_EXIT:            "_lwp_exit",            // { int|sys||_lwp_exit(void); }
	syscall.SYS__LWP_SELF:            "_lwp_self",            // { lwpid_t|sys||_lwp_self(void); }
	syscall.SYS__LWP_WAIT:            "_lwp_wait",            // { int|sys||_lwp_wait(lwpid_t wait_for, lwpid_t *departed); }
	syscall.SYS__LWP_SUSPEND:         "_lwp_suspend",         // { int|sys||_lwp_suspend(lwpid_t target); }
	syscall.SYS__LWP_CONTINUE:        "_lwp_continue",        // { int|sys||_lwp_continue(lwpid_t target); }
	syscall.SYS__LWP_WAKEUP:          "_lwp_wakeup",          // { int|sys||_lwp_wakeup(lwpid_t target); }
	syscall.SYS__LWP_GETPRIVATE:      "_lwp_getprivate",      // { void *|sys||_lwp_getprivate(void); }
	syscall.SYS__LWP_SETPRIVATE:      "_lwp_setprivate",      // { void|sys||_lwp_setprivate(void *ptr); }
	syscall.SYS__LWP_KILL:            "_lwp_kill",            // { int|sys||_lwp_kill(lwpid_t target, int signo); }
	syscall.SYS__LWP_DETACH:          "_lwp_detach",          // { int|sys||_lwp_detach(lwpid_t target); }
	syscall.SYS__LWP_UNPARK:          "_lwp_unpark",          // { int|sys||_lwp_unpark(lwpid_t target, const void *hint); }
	syscall.SYS__LWP_UNPARK_ALL:      "_lwp_unpark_all",      // { ssize_t|sys||_lwp_unpark_all(const lwpid_t *targets, size_t ntargets, const void *hint); }
	syscall.SYS__LWP_SETNAME:         "_lwp_setname",         // { int|sys||_lwp_setname(lwpid_t target, const char *name); }
	syscall.SYS__LWP_GETNAME:         "_lwp_getname",         // { int|sys||_lwp_getname(lwpid_t target, char *name, size_t len); }
	syscall.SYS__LWP_CTL:             "_lwp_ctl",             // { int|sys||_lwp_ctl(int features, struct lwpctl **address); }
	syscall.SYS___SIGACTION_SIGTRAMP: "__sigaction_sigtramp", // { int|sys||__sigaction_sigtramp(int signum, const struct sigaction *nsa, struct sigaction *osa, const void *tramp, int vers); }
	syscall.SYS_PMC_GET_INFO:         "pmc_get_info",         // { int|sys||pmc_get_info(int ctr, int op, void *args); }
	syscall.SYS_PMC_CONTROL:          "pmc_control",          // { int|sys||pmc_control(int ctr, int op, void *args); }
	syscall.SYS_RASCTL:               "rasctl",               // { int|sys||rasctl(void *addr, size_t len, int op); }
	syscall.SYS_KQUEUE:               "kqueue",               // { int|sys||kqueue(void); }
	syscall.SYS__SCHED_SETPARAM:      "_sched_setparam",      // { int|sys||_sched_setparam(pid_t pid, lwpid_t lid, int policy, const struct sched_param *params); }
	syscall.SYS__SCHED_GETPARAM:      "_sched_getparam",      // { int|sys||_sched_getparam(pid_t pid, lwpid_t lid, int *policy, struct sched_param *params); }
	syscall.SYS__SCHED_SETAFFINITY:   "_sched_setaffinity",   // { int|sys||_sched_setaffinity(pid_t pid, lwpid_t lid, size_t size, const cpuset_t *cpuset); }
	syscall.SYS__SCHED_GETAFFINITY:   "_sched_getaffinity",   // { int|sys||_sched_getaffinity(pid_t pid, lwpid_t lid, size_t size, cpuset_t *cpuset); }
	syscall.SYS_SCHED_YIELD:          "sched_yield",          // { int|sys||sched_yield(void); }
	syscall.SYS_FSYNC_RANGE:          "fsync_range",          // { int|sys||fsync_range(int fd, int flags, off_t start, off_t length); }
	syscall.SYS_UUIDGEN:              "uuidgen",              // { int|sys||uuidgen(struct uuid *store, int count); }
	syscall.SYS_GETVFSSTAT:           "getvfsstat",           // { int|sys||getvfsstat(struct statvfs *buf, size_t bufsize, int flags); }
	syscall.SYS_STATVFS1:             "statvfs1",             // { int|sys||statvfs1(const char *path, struct statvfs *buf, int flags); }
	syscall.SYS_FSTATVFS1:            "fstatvfs1",            // { int|sys||fstatvfs1(int fd, struct statvfs *buf, int flags); }
	syscall.SYS_EXTATTRCTL:           "extattrctl",           // { int|sys||extattrctl(const char *path, int cmd, const char *filename, int attrnamespace, const char *attrname); }
	syscall.SYS_EXTATTR_SET_FILE:     "extattr_set_file",     // { int|sys||extattr_set_file(const char *path, int attrnamespace, const char *attrname, const void *data, size_t nbytes); }
	syscall.SYS_EXTATTR_GET_FILE:     "extattr_get_file",     // { ssize_t|sys||extattr_get_file(const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	syscall.SYS_EXTATTR_DELETE_FILE:  "extattr_delete_file",  // { int|sys||extattr_delete_file(const char *path, int attrnamespace, const char *attrname); }
	syscall.SYS_EXTATTR_SET_FD:       "extattr_set_fd",       // { int|sys||extattr_set_fd(int fd, int attrnamespace, const char *attrname, const void *data, size_t nbytes); }
	syscall.SYS_EXTATTR_GET_FD:       "extattr_get_fd",       // { ssize_t|sys||extattr_get_fd(int fd, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	syscall.SYS_EXTATTR_DELETE_FD:    "extattr_delete_fd",    // { int|sys||extattr_delete_fd(int fd, int attrnamespace, const char *attrname); }
	syscall.SYS_EXTATTR_SET_LINK:     "extattr_set_link",     // { int|sys||extattr_set_link(const char *path, int attrnamespace, const char *attrname, const void *data, size_t nbytes); }
	syscall.SYS_EXTATTR_GET_LINK:     "extattr_get_link",     // { ssize_t|sys||extattr_get_link(const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	syscall.SYS_EXTATTR_DELETE_LINK:  "extattr_delete_link",  // { int|sys||extattr_delete_link(const char *path, int attrnamespace, const char *attrname); }
	syscall.SYS_EXTATTR_LIST_FD:      "extattr_list_fd",      // { ssize_t|sys||extattr_list_fd(int fd, int attrnamespace, void *data, size_t nbytes); }
	syscall.SYS_EXTATTR_LIST_FILE:    "extattr_list_file",    // { ssize_t|sys||extattr_list_file(const char *path, int attrnamespace, void *data, size_t nbytes); }
	syscall.SYS_EXTATTR_LIST_LINK:    "extattr_list_link",    // { ssize_t|sys||extattr_list_link(const char *path, int attrnamespace, void *data, size_t nbytes); }
	syscall.SYS_SETXATTR:             "setxattr",             // { int|sys||setxattr(const char *path, const char *name, const void *value, size_t size, int flags); }
	syscall.SYS_LSETXATTR:            "lsetxattr",            // { int|sys||lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags); }
	syscall.SYS_FSETXATTR:            "fsetxattr",            // { int|sys||fsetxattr(int fd, const char *name, const void *value, size_t size, int flags); }
	syscall.SYS_GETXATTR:             "getxattr",             // { int|sys||getxattr(const char *path, const char *name, void *value, size_t size); }
	syscall.SYS_LGETXATTR:            "lgetxattr",            // { int|sys||lgetxattr(const char *path, const char *name, void *value, size_t size); }
	syscall.SYS_FGETXATTR:            "fgetxattr",            // { int|sys||fgetxattr(int fd, const char *name, void *value, size_t size); }
	syscall.SYS_LISTXATTR:            "listxattr",            // { int|sys||listxattr(const char *path, char *list, size_t size); }
	syscall.SYS_LLISTXATTR:           "llistxattr",           // { int|sys||llistxattr(const char *path, char *list, size_t size); }
	syscall.SYS_FLISTXATTR:           "flistxattr",           // { int|sys||flistxattr(int fd, char *list, size_t size); }
	syscall.SYS_REMOVEXATTR:          "removexattr",          // { int|sys||removexattr(const char *path, const char *name); }
	syscall.SYS_LREMOVEXATTR:         "lremovexattr",         // { int|sys||lremovexattr(const char *path, const char *name); }
	syscall.SYS_FREMOVEXATTR:         "fremovexattr",         // { int|sys||fremovexattr(int fd, const char *name); }
	syscall.SYS_GETDENTS:             "getdents",             // { int|sys|30|getdents(int fd, char *buf, size_t count); }
	syscall.SYS_SOCKET:               "socket",               // { int|sys|30|socket(int domain, int type, int protocol); }
	syscall.SYS_GETFH:                "getfh",                // { int|sys|30|getfh(const char *fname, void *fhp, size_t *fh_size); }
	syscall.SYS_MOUNT:                "mount",                // { int|sys|50|mount(const char *type, const char *path, int flags, void *data, size_t data_len); }
	syscall.SYS_MREMAP:               "mremap",               // { void *|sys||mremap(void *old_address, size_t old_size, void *new_address, size_t new_size, int flags); }
	syscall.SYS_PSET_CREATE:          "pset_create",          // { int|sys||pset_create(psetid_t *psid); }
	syscall.SYS_PSET_DESTROY:         "pset_destroy",         // { int|sys||pset_destroy(psetid_t psid); }
	syscall.SYS_PSET_ASSIGN:          "pset_assign",          // { int|sys||pset_assign(psetid_t psid, cpuid_t cpuid, psetid_t *opsid); }
	syscall.SYS__PSET_BIND:           "_pset_bind",           // { int|sys||_pset_bind(idtype_t idtype, id_t first_id, id_t second_id, psetid_t psid, psetid_t *opsid); }
	syscall.SYS_POSIX_FADVISE:        "posix_fadvise",        // { int|sys|50|posix_fadvise(int fd, int PAD, off_t offset, off_t len, int advice); }
	syscall.SYS_SELECT:               "select",               // { int|sys|50|select(int nd, fd_set *in, fd_set *ou, fd_set *ex, struct timeval *tv); }
	syscall.SYS_GETTIMEOFDAY:         "gettimeofday",         // { int|sys|50|gettimeofday(struct timeval *tp, void *tzp); }
	syscall.SYS_SETTIMEOFDAY:         "settimeofday",         // { int|sys|50|settimeofday(const struct timeval *tv, const void *tzp); }
	syscall.SYS_UTIMES:               "utimes",               // { int|sys|50|utimes(const char *path, const struct timeval *tptr); }
	syscall.SYS_ADJTIME:              "adjtime",              // { int|sys|50|adjtime(const struct timeval *delta, struct timeval *olddelta); }
	syscall.SYS_FUTIMES:              "futimes",              // { int|sys|50|futimes(int fd, const struct timeval *tptr); }
	syscall.SYS_LUTIMES:              "lutimes",              // { int|sys|50|lutimes(const char *path, const struct timeval *tptr); }
	syscall.SYS_SETITIMER:            "setitimer",            // { int|sys|50|setitimer(int which, const struct itimerval *itv, struct itimerval *oitv); }
	syscall.SYS_GETITIMER:            "getitimer",            // { int|sys|50|getitimer(int which, struct itimerval *itv); }
	syscall.SYS_CLOCK_GETTIME:        "clock_gettime",        // { int|sys|50|clock_gettime(clockid_t clock_id, struct timespec *tp); }
	syscall.SYS_CLOCK_SETTIME:        "clock_settime",        // { int|sys|50|clock_settime(clockid_t clock_id, const struct timespec *tp); }
	syscall.SYS_CLOCK_GETRES:         "clock_getres",         // { int|sys|50|clock_getres(clockid_t clock_id, struct timespec *tp); }
	syscall.SYS_NANOSLEEP:            "nanosleep",            // { int|sys|50|nanosleep(const struct timespec *rqtp, struct timespec *rmtp); }
	syscall.SYS___SIGTIMEDWAIT:       "__sigtimedwait",       // { int|sys|50|__sigtimedwait(const sigset_t *set, siginfo_t *info, struct timespec *timeout); }
	syscall.SYS__LWP_PARK:            "_lwp_park",            // { int|sys|50|_lwp_park(const struct timespec *ts, lwpid_t unpark, const void *hint, const void *unparkhint); }
	syscall.SYS_KEVENT:               "kevent",               // { int|sys|50|kevent(int fd, const struct kevent *changelist, size_t nchanges, struct kevent *eventlist, size_t nevents, const struct timespec *timeout); }
	syscall.SYS_PSELECT:              "pselect",              // { int|sys|50|pselect(int nd, fd_set *in, fd_set *ou, fd_set *ex, const struct timespec *ts, const sigset_t *mask); }
	syscall.SYS_POLLTS:               "pollts",               // { int|sys|50|pollts(struct pollfd *fds, u_int nfds, const struct timespec *ts, const sigset_t *mask); }
	syscall.SYS_STAT:                 "stat",                 // { int|sys|50|stat(const char *path, struct stat *ub); }
	syscall.SYS_FSTAT:                "fstat",                // { int|sys|50|fstat(int fd, struct stat *sb); }
	syscall.SYS_LSTAT:                "lstat",                // { int|sys|50|lstat(const char *path, struct stat *ub); }
	syscall.SYS___SEMCTL:             "__semctl",             // { int|sys|50|__semctl(int semid, int semnum, int cmd, ... union __semun *arg); }
	syscall.SYS_SHMCTL:               "shmctl",               // { int|sys|50|shmctl(int shmid, int cmd, struct shmid_ds *buf); }
	syscall.SYS_MSGCTL:               "msgctl",               // { int|sys|50|msgctl(int msqid, int cmd, struct msqid_ds *buf); }
	syscall.SYS_GETRUSAGE:            "getrusage",            // { int|sys|50|getrusage(int who, struct rusage *rusage); }
	syscall.SYS_TIMER_SETTIME:        "timer_settime",        // { int|sys|50|timer_settime(timer_t timerid, int flags, const struct itimerspec *value, struct itimerspec *ovalue); }
	syscall.SYS_TIMER_GETTIME:        "timer_gettime",        // { int|sys|50|timer_gettime(timer_t timerid, struct itimerspec *value); }
	syscall.SYS_NTP_GETTIME:          "ntp_gettime",          // { int|sys|50|ntp_gettime(struct ntptimeval *ntvp); }
	syscall.SYS_WAIT4:                "wait4",                // { int|sys|50|wait4(pid_t pid, int *status, int options, struct rusage *rusage); }
	syscall.SYS_MKNOD:                "mknod",                // { int|sys|50|mknod(const char *path, mode_t mode, dev_t dev); }
	syscall.SYS_FHSTAT:               "fhstat",               // { int|sys|50|fhstat(const void *fhp, size_t fh_size, struct stat *sb); }
	syscall.SYS_PIPE2:                "pipe2",                // { int|sys||pipe2(int *fildes, int flags); }
	syscall.SYS_DUP3:                 "dup3",                 // { int|sys||dup3(int from, int to, int flags); }
	syscall.SYS_KQUEUE1:              "kqueue1",              // { int|sys||kqueue1(int flags); }
	syscall.SYS_PACCEPT:              "paccept",              // { int|sys||paccept(int s, struct sockaddr *name, socklen_t *anamelen, const sigset_t *mask, int flags); }
	syscall.SYS_LINKAT:               "linkat",               // { int|sys||linkat(int fd1, const char *name1, int fd2, const char *name2, int flags); }
	syscall.SYS_RENAMEAT:             "renameat",             // { int|sys||renameat(int fromfd, const char *from, int tofd, const char *to); }
	syscall.SYS_MKFIFOAT:             "mkfifoat",             // { int|sys||mkfifoat(int fd, const char *path, mode_t mode); }
	syscall.SYS_MKNODAT:              "mknodat",              // { int|sys||mknodat(int fd, const char *path, mode_t mode, uint32_t dev); }
	syscall.SYS_MKDIRAT:              "mkdirat",              // { int|sys||mkdirat(int fd, const char *path, mode_t mode); }
	syscall.SYS_FACCESSAT:            "faccessat",            // { int|sys||faccessat(int fd, const char *path, int amode, int flag); }
	syscall.SYS_FCHMODAT:             "fchmodat",             // { int|sys||fchmodat(int fd, const char *path, mode_t mode, int flag); }
	syscall.SYS_FCHOWNAT:             "fchownat",             // { int|sys||fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag); }
	syscall.SYS_FEXECVE:              "fexecve",              // { int|sys||fexecve(int fd, char * const *argp, char * const *envp); }
	syscall.SYS_FSTATAT:              "fstatat",              // { int|sys||fstatat(int fd, const char *path, struct stat *buf, int flag); }
	syscall.SYS_UTIMENSAT:            "utimensat",            // { int|sys||utimensat(int fd, const char *path, const struct timespec *tptr, int flag); }
	syscall.SYS_OPENAT:               "openat",               // { int|sys||openat(int fd, const char *path, int oflags, ... mode_t mode); }
	syscall.SYS_READLINKAT:           "readlinkat",           // { int|sys||readlinkat(int fd, const char *path, char *buf, size_t bufsize); }
	syscall.SYS_SYMLINKAT:            "symlinkat",            // { int|sys||symlinkat(const char *path1, int fd, const char *path2); }
	syscall.SYS_UNLINKAT:             "unlinkat",             // { int|sys||unlinkat(int fd, const char *path, int flag); }
	syscall.SYS_FUTIMENS:             "futimens",             // { int|sys||futimens(int fd, const struct timespec *tptr); }
	syscall.SYS___QUOTACTL:           "__quotactl",           // { int|sys||__quotactl(const char *path, struct quotactl_args *args); }
	syscall.SYS_POSIX_SPAWN:          "posix_spawn",          // { int|sys||posix_spawn(pid_t *pid, const char *path, const struct posix_spawn_file_actions *file_actions, const struct posix_spawnattr *attrp, char *const *argv, char *const *envp); }
	syscall.SYS_RECVMMSG:             "recvmmsg",             // { int|sys||recvmmsg(int s, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags, struct timespec *timeout); }
	syscall.SYS_SENDMMSG:             "sendmmsg",             // { int|sys||sendmmsg(int s, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags); }
}
