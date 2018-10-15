package syscalls

import "golang.org/x/sys/unix"

var _ = unix.Exit

var Name = map[uint64]string{
	unix.SYS_EXIT:                 "exit",                 // { void|sys||exit(int rval); }
	unix.SYS_FORK:                 "fork",                 // { int|sys||fork(void); }
	unix.SYS_READ:                 "read",                 // { ssize_t|sys||read(int fd, void *buf, size_t nbyte); }
	unix.SYS_WRITE:                "write",                // { ssize_t|sys||write(int fd, const void *buf, size_t nbyte); }
	unix.SYS_OPEN:                 "open",                 // { int|sys||open(const char *path, int flags, ... mode_t mode); }
	unix.SYS_CLOSE:                "close",                // { int|sys||close(int fd); }
	unix.SYS_LINK:                 "link",                 // { int|sys||link(const char *path, const char *link); }
	unix.SYS_UNLINK:               "unlink",               // { int|sys||unlink(const char *path); }
	unix.SYS_CHDIR:                "chdir",                // { int|sys||chdir(const char *path); }
	unix.SYS_FCHDIR:               "fchdir",               // { int|sys||fchdir(int fd); }
	unix.SYS_CHMOD:                "chmod",                // { int|sys||chmod(const char *path, mode_t mode); }
	unix.SYS_CHOWN:                "chown",                // { int|sys||chown(const char *path, uid_t uid, gid_t gid); }
	unix.SYS_BREAK:                "break",                // { int|sys||obreak(char *nsize); }
	unix.SYS_GETPID:               "getpid",               // { pid_t|sys||getpid_with_ppid(void); }
	unix.SYS_UNMOUNT:              "unmount",              // { int|sys||unmount(const char *path, int flags); }
	unix.SYS_SETUID:               "setuid",               // { int|sys||setuid(uid_t uid); }
	unix.SYS_GETUID:               "getuid",               // { uid_t|sys||getuid_with_euid(void); }
	unix.SYS_GETEUID:              "geteuid",              // { uid_t|sys||geteuid(void); }
	unix.SYS_PTRACE:               "ptrace",               // { int|sys||ptrace(int req, pid_t pid, void *addr, int data); }
	unix.SYS_RECVMSG:              "recvmsg",              // { ssize_t|sys||recvmsg(int s, struct msghdr *msg, int flags); }
	unix.SYS_SENDMSG:              "sendmsg",              // { ssize_t|sys||sendmsg(int s, const struct msghdr *msg, int flags); }
	unix.SYS_RECVFROM:             "recvfrom",             // { ssize_t|sys||recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlenaddr); }
	unix.SYS_ACCEPT:               "accept",               // { int|sys||accept(int s, struct sockaddr *name, socklen_t *anamelen); }
	unix.SYS_GETPEERNAME:          "getpeername",          // { int|sys||getpeername(int fdes, struct sockaddr *asa, socklen_t *alen); }
	unix.SYS_GETSOCKNAME:          "getsockname",          // { int|sys||getsockname(int fdes, struct sockaddr *asa, socklen_t *alen); }
	unix.SYS_ACCESS:               "access",               // { int|sys||access(const char *path, int flags); }
	unix.SYS_CHFLAGS:              "chflags",              // { int|sys||chflags(const char *path, u_long flags); }
	unix.SYS_FCHFLAGS:             "fchflags",             // { int|sys||fchflags(int fd, u_long flags); }
	unix.SYS_SYNC:                 "sync",                 // { void|sys||sync(void); }
	unix.SYS_KILL:                 "kill",                 // { int|sys||kill(pid_t pid, int signum); }
	unix.SYS_GETPPID:              "getppid",              // { pid_t|sys||getppid(void); }
	unix.SYS_DUP:                  "dup",                  // { int|sys||dup(int fd); }
	unix.SYS_PIPE:                 "pipe",                 // { int|sys||pipe(void); }
	unix.SYS_GETEGID:              "getegid",              // { gid_t|sys||getegid(void); }
	unix.SYS_PROFIL:               "profil",               // { int|sys||profil(char *samples, size_t size, u_long offset, u_int scale); }
	unix.SYS_KTRACE:               "ktrace",               // { int|sys||ktrace(const char *fname, int ops, int facs, pid_t pid); }
	unix.SYS_GETGID:               "getgid",               // { gid_t|sys||getgid_with_egid(void); }
	unix.SYS___GETLOGIN:           "__getlogin",           // { int|sys||__getlogin(char *namebuf, size_t namelen); }
	unix.SYS___SETLOGIN:           "__setlogin",           // { int|sys||__setlogin(const char *namebuf); }
	unix.SYS_ACCT:                 "acct",                 // { int|sys||acct(const char *path); }
	unix.SYS_IOCTL:                "ioctl",                // { int|sys||ioctl(int fd, u_long com, ... void *data); }
	unix.SYS_REVOKE:               "revoke",               // { int|sys||revoke(const char *path); }
	unix.SYS_SYMLINK:              "symlink",              // { int|sys||symlink(const char *path, const char *link); }
	unix.SYS_READLINK:             "readlink",             // { ssize_t|sys||readlink(const char *path, char *buf, size_t count); }
	unix.SYS_EXECVE:               "execve",               // { int|sys||execve(const char *path, char * const *argp, char * const *envp); }
	unix.SYS_UMASK:                "umask",                // { mode_t|sys||umask(mode_t newmask); }
	unix.SYS_CHROOT:               "chroot",               // { int|sys||chroot(const char *path); }
	unix.SYS_VFORK:                "vfork",                // { int|sys||vfork(void); }
	unix.SYS_SBRK:                 "sbrk",                 // { int|sys||sbrk(intptr_t incr); }
	unix.SYS_SSTK:                 "sstk",                 // { int|sys||sstk(int incr); }
	unix.SYS_VADVISE:              "vadvise",              // { int|sys||ovadvise(int anom); }
	unix.SYS_MUNMAP:               "munmap",               // { int|sys||munmap(void *addr, size_t len); }
	unix.SYS_MPROTECT:             "mprotect",             // { int|sys||mprotect(void *addr, size_t len, int prot); }
	unix.SYS_MADVISE:              "madvise",              // { int|sys||madvise(void *addr, size_t len, int behav); }
	unix.SYS_MINCORE:              "mincore",              // { int|sys||mincore(void *addr, size_t len, char *vec); }
	unix.SYS_GETGROUPS:            "getgroups",            // { int|sys||getgroups(int gidsetsize, gid_t *gidset); }
	unix.SYS_SETGROUPS:            "setgroups",            // { int|sys||setgroups(int gidsetsize, const gid_t *gidset); }
	unix.SYS_GETPGRP:              "getpgrp",              // { int|sys||getpgrp(void); }
	unix.SYS_SETPGID:              "setpgid",              // { int|sys||setpgid(pid_t pid, pid_t pgid); }
	unix.SYS_DUP2:                 "dup2",                 // { int|sys||dup2(int from, int to); }
	unix.SYS_FCNTL:                "fcntl",                // { int|sys||fcntl(int fd, int cmd, ... void *arg); }
	unix.SYS_FSYNC:                "fsync",                // { int|sys||fsync(int fd); }
	unix.SYS_SETPRIORITY:          "setpriority",          // { int|sys||setpriority(int which, id_t who, int prio); }
	unix.SYS_CONNECT:              "connect",              // { int|sys||connect(int s, const struct sockaddr *name, socklen_t namelen); }
	unix.SYS_GETPRIORITY:          "getpriority",          // { int|sys||getpriority(int which, id_t who); }
	unix.SYS_BIND:                 "bind",                 // { int|sys||bind(int s, const struct sockaddr *name, socklen_t namelen); }
	unix.SYS_SETSOCKOPT:           "setsockopt",           // { int|sys||setsockopt(int s, int level, int name, const void *val, socklen_t valsize); }
	unix.SYS_LISTEN:               "listen",               // { int|sys||listen(int s, int backlog); }
	unix.SYS_GETSOCKOPT:           "getsockopt",           // { int|sys||getsockopt(int s, int level, int name, void *val, socklen_t *avalsize); }
	unix.SYS_READV:                "readv",                // { ssize_t|sys||readv(int fd, const struct iovec *iovp, int iovcnt); }
	unix.SYS_WRITEV:               "writev",               // { ssize_t|sys||writev(int fd, const struct iovec *iovp, int iovcnt); }
	unix.SYS_FCHOWN:               "fchown",               // { int|sys||fchown(int fd, uid_t uid, gid_t gid); }
	unix.SYS_FCHMOD:               "fchmod",               // { int|sys||fchmod(int fd, mode_t mode); }
	unix.SYS_SETREUID:             "setreuid",             // { int|sys||setreuid(uid_t ruid, uid_t euid); }
	unix.SYS_SETREGID:             "setregid",             // { int|sys||setregid(gid_t rgid, gid_t egid); }
	unix.SYS_RENAME:               "rename",               // { int|sys||rename(const char *from, const char *to); }
	unix.SYS_FLOCK:                "flock",                // { int|sys||flock(int fd, int how); }
	unix.SYS_MKFIFO:               "mkfifo",               // { int|sys||mkfifo(const char *path, mode_t mode); }
	unix.SYS_SENDTO:               "sendto",               // { ssize_t|sys||sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen); }
	unix.SYS_SHUTDOWN:             "shutdown",             // { int|sys||shutdown(int s, int how); }
	unix.SYS_SOCKETPAIR:           "socketpair",           // { int|sys||socketpair(int domain, int type, int protocol, int *rsv); }
	unix.SYS_MKDIR:                "mkdir",                // { int|sys||mkdir(const char *path, mode_t mode); }
	unix.SYS_RMDIR:                "rmdir",                // { int|sys||rmdir(const char *path); }
	unix.SYS_SETSID:               "setsid",               // { int|sys||setsid(void); }
	unix.SYS_SYSARCH:              "sysarch",              // { int|sys||sysarch(int op, void *parms); }
	unix.SYS_PREAD:                "pread",                // { ssize_t|sys||pread(int fd, void *buf, size_t nbyte, int PAD, off_t offset); }
	unix.SYS_PWRITE:               "pwrite",               // { ssize_t|sys||pwrite(int fd, const void *buf, size_t nbyte, int PAD, off_t offset); }
	unix.SYS_NTP_ADJTIME:          "ntp_adjtime",          // { int|sys||ntp_adjtime(struct timex *tp); }
	unix.SYS_SETGID:               "setgid",               // { int|sys||setgid(gid_t gid); }
	unix.SYS_SETEGID:              "setegid",              // { int|sys||setegid(gid_t egid); }
	unix.SYS_SETEUID:              "seteuid",              // { int|sys||seteuid(uid_t euid); }
	unix.SYS_PATHCONF:             "pathconf",             // { long|sys||pathconf(const char *path, int name); }
	unix.SYS_FPATHCONF:            "fpathconf",            // { long|sys||fpathconf(int fd, int name); }
	unix.SYS_GETRLIMIT:            "getrlimit",            // { int|sys||getrlimit(int which, struct rlimit *rlp); }
	unix.SYS_SETRLIMIT:            "setrlimit",            // { int|sys||setrlimit(int which, const struct rlimit *rlp); }
	unix.SYS_MMAP:                 "mmap",                 // { void *|sys||mmap(void *addr, size_t len, int prot, int flags, int fd, long PAD, off_t pos); }
	unix.SYS_LSEEK:                "lseek",                // { off_t|sys||lseek(int fd, int PAD, off_t offset, int whence); }
	unix.SYS_TRUNCATE:             "truncate",             // { int|sys||truncate(const char *path, int PAD, off_t length); }
	unix.SYS_FTRUNCATE:            "ftruncate",            // { int|sys||ftruncate(int fd, int PAD, off_t length); }
	unix.SYS___SYSCTL:             "__sysctl",             // { int|sys||__sysctl(const int *name, u_int namelen, void *old, size_t *oldlenp, const void *new, size_t newlen); }
	unix.SYS_MLOCK:                "mlock",                // { int|sys||mlock(const void *addr, size_t len); }
	unix.SYS_MUNLOCK:              "munlock",              // { int|sys||munlock(const void *addr, size_t len); }
	unix.SYS_UNDELETE:             "undelete",             // { int|sys||undelete(const char *path); }
	unix.SYS_GETPGID:              "getpgid",              // { pid_t|sys||getpgid(pid_t pid); }
	unix.SYS_REBOOT:               "reboot",               // { int|sys||reboot(int opt, char *bootstr); }
	unix.SYS_POLL:                 "poll",                 // { int|sys||poll(struct pollfd *fds, u_int nfds, int timeout); }
	unix.SYS_SEMGET:               "semget",               // { int|sys||semget(key_t key, int nsems, int semflg); }
	unix.SYS_SEMOP:                "semop",                // { int|sys||semop(int semid, struct sembuf *sops, size_t nsops); }
	unix.SYS_SEMCONFIG:            "semconfig",            // { int|sys||semconfig(int flag); }
	unix.SYS_MSGGET:               "msgget",               // { int|sys||msgget(key_t key, int msgflg); }
	unix.SYS_MSGSND:               "msgsnd",               // { int|sys||msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); }
	unix.SYS_MSGRCV:               "msgrcv",               // { ssize_t|sys||msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); }
	unix.SYS_SHMAT:                "shmat",                // { void *|sys||shmat(int shmid, const void *shmaddr, int shmflg); }
	unix.SYS_SHMDT:                "shmdt",                // { int|sys||shmdt(const void *shmaddr); }
	unix.SYS_SHMGET:               "shmget",               // { int|sys||shmget(key_t key, size_t size, int shmflg); }
	unix.SYS_TIMER_CREATE:         "timer_create",         // { int|sys||timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid); }
	unix.SYS_TIMER_DELETE:         "timer_delete",         // { int|sys||timer_delete(timer_t timerid); }
	unix.SYS_TIMER_GETOVERRUN:     "timer_getoverrun",     // { int|sys||timer_getoverrun(timer_t timerid); }
	unix.SYS_FDATASYNC:            "fdatasync",            // { int|sys||fdatasync(int fd); }
	unix.SYS_MLOCKALL:             "mlockall",             // { int|sys||mlockall(int flags); }
	unix.SYS_MUNLOCKALL:           "munlockall",           // { int|sys||munlockall(void); }
	unix.SYS_SIGQUEUEINFO:         "sigqueueinfo",         // { int|sys||sigqueueinfo(pid_t pid, const siginfo_t *info); }
	unix.SYS_MODCTL:               "modctl",               // { int|sys||modctl(int cmd, void *arg); }
	unix.SYS___POSIX_RENAME:       "__posix_rename",       // { int|sys||__posix_rename(const char *from, const char *to); }
	unix.SYS_SWAPCTL:              "swapctl",              // { int|sys||swapctl(int cmd, void *arg, int misc); }
	unix.SYS_MINHERIT:             "minherit",             // { int|sys||minherit(void *addr, size_t len, int inherit); }
	unix.SYS_LCHMOD:               "lchmod",               // { int|sys||lchmod(const char *path, mode_t mode); }
	unix.SYS_LCHOWN:               "lchown",               // { int|sys||lchown(const char *path, uid_t uid, gid_t gid); }
	unix.SYS_MSYNC:                "msync",                // { int|sys|13|msync(void *addr, size_t len, int flags); }
	unix.SYS___POSIX_CHOWN:        "__posix_chown",        // { int|sys||__posix_chown(const char *path, uid_t uid, gid_t gid); }
	unix.SYS___POSIX_FCHOWN:       "__posix_fchown",       // { int|sys||__posix_fchown(int fd, uid_t uid, gid_t gid); }
	unix.SYS___POSIX_LCHOWN:       "__posix_lchown",       // { int|sys||__posix_lchown(const char *path, uid_t uid, gid_t gid); }
	unix.SYS_GETSID:               "getsid",               // { pid_t|sys||getsid(pid_t pid); }
	unix.SYS___CLONE:              "__clone",              // { pid_t|sys||__clone(int flags, void *stack); }
	unix.SYS_FKTRACE:              "fktrace",              // { int|sys||fktrace(int fd, int ops, int facs, pid_t pid); }
	unix.SYS_PREADV:               "preadv",               // { ssize_t|sys||preadv(int fd, const struct iovec *iovp, int iovcnt, int PAD, off_t offset); }
	unix.SYS_PWRITEV:              "pwritev",              // { ssize_t|sys||pwritev(int fd, const struct iovec *iovp, int iovcnt, int PAD, off_t offset); }
	unix.SYS___GETCWD:             "__getcwd",             // { int|sys||__getcwd(char *bufp, size_t length); }
	unix.SYS_FCHROOT:              "fchroot",              // { int|sys||fchroot(int fd); }
	unix.SYS_LCHFLAGS:             "lchflags",             // { int|sys||lchflags(const char *path, u_long flags); }
	unix.SYS_ISSETUGID:            "issetugid",            // { int|sys||issetugid(void); }
	unix.SYS_UTRACE:               "utrace",               // { int|sys||utrace(const char *label, void *addr, size_t len); }
	unix.SYS_GETCONTEXT:           "getcontext",           // { int|sys||getcontext(struct __ucontext *ucp); }
	unix.SYS_SETCONTEXT:           "setcontext",           // { int|sys||setcontext(const struct __ucontext *ucp); }
	unix.SYS__LWP_CREATE:          "_lwp_create",          // { int|sys||_lwp_create(const struct __ucontext *ucp, u_long flags, lwpid_t *new_lwp); }
	unix.SYS__LWP_EXIT:            "_lwp_exit",            // { int|sys||_lwp_exit(void); }
	unix.SYS__LWP_SELF:            "_lwp_self",            // { lwpid_t|sys||_lwp_self(void); }
	unix.SYS__LWP_WAIT:            "_lwp_wait",            // { int|sys||_lwp_wait(lwpid_t wait_for, lwpid_t *departed); }
	unix.SYS__LWP_SUSPEND:         "_lwp_suspend",         // { int|sys||_lwp_suspend(lwpid_t target); }
	unix.SYS__LWP_CONTINUE:        "_lwp_continue",        // { int|sys||_lwp_continue(lwpid_t target); }
	unix.SYS__LWP_WAKEUP:          "_lwp_wakeup",          // { int|sys||_lwp_wakeup(lwpid_t target); }
	unix.SYS__LWP_GETPRIVATE:      "_lwp_getprivate",      // { void *|sys||_lwp_getprivate(void); }
	unix.SYS__LWP_SETPRIVATE:      "_lwp_setprivate",      // { void|sys||_lwp_setprivate(void *ptr); }
	unix.SYS__LWP_KILL:            "_lwp_kill",            // { int|sys||_lwp_kill(lwpid_t target, int signo); }
	unix.SYS__LWP_DETACH:          "_lwp_detach",          // { int|sys||_lwp_detach(lwpid_t target); }
	unix.SYS__LWP_UNPARK:          "_lwp_unpark",          // { int|sys||_lwp_unpark(lwpid_t target, const void *hint); }
	unix.SYS__LWP_UNPARK_ALL:      "_lwp_unpark_all",      // { ssize_t|sys||_lwp_unpark_all(const lwpid_t *targets, size_t ntargets, const void *hint); }
	unix.SYS__LWP_SETNAME:         "_lwp_setname",         // { int|sys||_lwp_setname(lwpid_t target, const char *name); }
	unix.SYS__LWP_GETNAME:         "_lwp_getname",         // { int|sys||_lwp_getname(lwpid_t target, char *name, size_t len); }
	unix.SYS__LWP_CTL:             "_lwp_ctl",             // { int|sys||_lwp_ctl(int features, struct lwpctl **address); }
	unix.SYS___SIGACTION_SIGTRAMP: "__sigaction_sigtramp", // { int|sys||__sigaction_sigtramp(int signum, const struct sigaction *nsa, struct sigaction *osa, const void *tramp, int vers); }
	unix.SYS_PMC_GET_INFO:         "pmc_get_info",         // { int|sys||pmc_get_info(int ctr, int op, void *args); }
	unix.SYS_PMC_CONTROL:          "pmc_control",          // { int|sys||pmc_control(int ctr, int op, void *args); }
	unix.SYS_RASCTL:               "rasctl",               // { int|sys||rasctl(void *addr, size_t len, int op); }
	unix.SYS_KQUEUE:               "kqueue",               // { int|sys||kqueue(void); }
	unix.SYS__SCHED_SETPARAM:      "_sched_setparam",      // { int|sys||_sched_setparam(pid_t pid, lwpid_t lid, int policy, const struct sched_param *params); }
	unix.SYS__SCHED_GETPARAM:      "_sched_getparam",      // { int|sys||_sched_getparam(pid_t pid, lwpid_t lid, int *policy, struct sched_param *params); }
	unix.SYS__SCHED_SETAFFINITY:   "_sched_setaffinity",   // { int|sys||_sched_setaffinity(pid_t pid, lwpid_t lid, size_t size, const cpuset_t *cpuset); }
	unix.SYS__SCHED_GETAFFINITY:   "_sched_getaffinity",   // { int|sys||_sched_getaffinity(pid_t pid, lwpid_t lid, size_t size, cpuset_t *cpuset); }
	unix.SYS_SCHED_YIELD:          "sched_yield",          // { int|sys||sched_yield(void); }
	unix.SYS_FSYNC_RANGE:          "fsync_range",          // { int|sys||fsync_range(int fd, int flags, off_t start, off_t length); }
	unix.SYS_UUIDGEN:              "uuidgen",              // { int|sys||uuidgen(struct uuid *store, int count); }
	unix.SYS_GETVFSSTAT:           "getvfsstat",           // { int|sys||getvfsstat(struct statvfs *buf, size_t bufsize, int flags); }
	unix.SYS_STATVFS1:             "statvfs1",             // { int|sys||statvfs1(const char *path, struct statvfs *buf, int flags); }
	unix.SYS_FSTATVFS1:            "fstatvfs1",            // { int|sys||fstatvfs1(int fd, struct statvfs *buf, int flags); }
	unix.SYS_EXTATTRCTL:           "extattrctl",           // { int|sys||extattrctl(const char *path, int cmd, const char *filename, int attrnamespace, const char *attrname); }
	unix.SYS_EXTATTR_SET_FILE:     "extattr_set_file",     // { int|sys||extattr_set_file(const char *path, int attrnamespace, const char *attrname, const void *data, size_t nbytes); }
	unix.SYS_EXTATTR_GET_FILE:     "extattr_get_file",     // { ssize_t|sys||extattr_get_file(const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	unix.SYS_EXTATTR_DELETE_FILE:  "extattr_delete_file",  // { int|sys||extattr_delete_file(const char *path, int attrnamespace, const char *attrname); }
	unix.SYS_EXTATTR_SET_FD:       "extattr_set_fd",       // { int|sys||extattr_set_fd(int fd, int attrnamespace, const char *attrname, const void *data, size_t nbytes); }
	unix.SYS_EXTATTR_GET_FD:       "extattr_get_fd",       // { ssize_t|sys||extattr_get_fd(int fd, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	unix.SYS_EXTATTR_DELETE_FD:    "extattr_delete_fd",    // { int|sys||extattr_delete_fd(int fd, int attrnamespace, const char *attrname); }
	unix.SYS_EXTATTR_SET_LINK:     "extattr_set_link",     // { int|sys||extattr_set_link(const char *path, int attrnamespace, const char *attrname, const void *data, size_t nbytes); }
	unix.SYS_EXTATTR_GET_LINK:     "extattr_get_link",     // { ssize_t|sys||extattr_get_link(const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	unix.SYS_EXTATTR_DELETE_LINK:  "extattr_delete_link",  // { int|sys||extattr_delete_link(const char *path, int attrnamespace, const char *attrname); }
	unix.SYS_EXTATTR_LIST_FD:      "extattr_list_fd",      // { ssize_t|sys||extattr_list_fd(int fd, int attrnamespace, void *data, size_t nbytes); }
	unix.SYS_EXTATTR_LIST_FILE:    "extattr_list_file",    // { ssize_t|sys||extattr_list_file(const char *path, int attrnamespace, void *data, size_t nbytes); }
	unix.SYS_EXTATTR_LIST_LINK:    "extattr_list_link",    // { ssize_t|sys||extattr_list_link(const char *path, int attrnamespace, void *data, size_t nbytes); }
	unix.SYS_SETXATTR:             "setxattr",             // { int|sys||setxattr(const char *path, const char *name, const void *value, size_t size, int flags); }
	unix.SYS_LSETXATTR:            "lsetxattr",            // { int|sys||lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags); }
	unix.SYS_FSETXATTR:            "fsetxattr",            // { int|sys||fsetxattr(int fd, const char *name, const void *value, size_t size, int flags); }
	unix.SYS_GETXATTR:             "getxattr",             // { int|sys||getxattr(const char *path, const char *name, void *value, size_t size); }
	unix.SYS_LGETXATTR:            "lgetxattr",            // { int|sys||lgetxattr(const char *path, const char *name, void *value, size_t size); }
	unix.SYS_FGETXATTR:            "fgetxattr",            // { int|sys||fgetxattr(int fd, const char *name, void *value, size_t size); }
	unix.SYS_LISTXATTR:            "listxattr",            // { int|sys||listxattr(const char *path, char *list, size_t size); }
	unix.SYS_LLISTXATTR:           "llistxattr",           // { int|sys||llistxattr(const char *path, char *list, size_t size); }
	unix.SYS_FLISTXATTR:           "flistxattr",           // { int|sys||flistxattr(int fd, char *list, size_t size); }
	unix.SYS_REMOVEXATTR:          "removexattr",          // { int|sys||removexattr(const char *path, const char *name); }
	unix.SYS_LREMOVEXATTR:         "lremovexattr",         // { int|sys||lremovexattr(const char *path, const char *name); }
	unix.SYS_FREMOVEXATTR:         "fremovexattr",         // { int|sys||fremovexattr(int fd, const char *name); }
	unix.SYS_GETDENTS:             "getdents",             // { int|sys|30|getdents(int fd, char *buf, size_t count); }
	unix.SYS_SOCKET:               "socket",               // { int|sys|30|socket(int domain, int type, int protocol); }
	unix.SYS_GETFH:                "getfh",                // { int|sys|30|getfh(const char *fname, void *fhp, size_t *fh_size); }
	unix.SYS_MOUNT:                "mount",                // { int|sys|50|mount(const char *type, const char *path, int flags, void *data, size_t data_len); }
	unix.SYS_MREMAP:               "mremap",               // { void *|sys||mremap(void *old_address, size_t old_size, void *new_address, size_t new_size, int flags); }
	unix.SYS_PSET_CREATE:          "pset_create",          // { int|sys||pset_create(psetid_t *psid); }
	unix.SYS_PSET_DESTROY:         "pset_destroy",         // { int|sys||pset_destroy(psetid_t psid); }
	unix.SYS_PSET_ASSIGN:          "pset_assign",          // { int|sys||pset_assign(psetid_t psid, cpuid_t cpuid, psetid_t *opsid); }
	unix.SYS__PSET_BIND:           "_pset_bind",           // { int|sys||_pset_bind(idtype_t idtype, id_t first_id, id_t second_id, psetid_t psid, psetid_t *opsid); }
	unix.SYS_POSIX_FADVISE:        "posix_fadvise",        // { int|sys|50|posix_fadvise(int fd, int PAD, off_t offset, off_t len, int advice); }
	unix.SYS_SELECT:               "select",               // { int|sys|50|select(int nd, fd_set *in, fd_set *ou, fd_set *ex, struct timeval *tv); }
	unix.SYS_GETTIMEOFDAY:         "gettimeofday",         // { int|sys|50|gettimeofday(struct timeval *tp, void *tzp); }
	unix.SYS_SETTIMEOFDAY:         "settimeofday",         // { int|sys|50|settimeofday(const struct timeval *tv, const void *tzp); }
	unix.SYS_UTIMES:               "utimes",               // { int|sys|50|utimes(const char *path, const struct timeval *tptr); }
	unix.SYS_ADJTIME:              "adjtime",              // { int|sys|50|adjtime(const struct timeval *delta, struct timeval *olddelta); }
	unix.SYS_FUTIMES:              "futimes",              // { int|sys|50|futimes(int fd, const struct timeval *tptr); }
	unix.SYS_LUTIMES:              "lutimes",              // { int|sys|50|lutimes(const char *path, const struct timeval *tptr); }
	unix.SYS_SETITIMER:            "setitimer",            // { int|sys|50|setitimer(int which, const struct itimerval *itv, struct itimerval *oitv); }
	unix.SYS_GETITIMER:            "getitimer",            // { int|sys|50|getitimer(int which, struct itimerval *itv); }
	unix.SYS_CLOCK_GETTIME:        "clock_gettime",        // { int|sys|50|clock_gettime(clockid_t clock_id, struct timespec *tp); }
	unix.SYS_CLOCK_SETTIME:        "clock_settime",        // { int|sys|50|clock_settime(clockid_t clock_id, const struct timespec *tp); }
	unix.SYS_CLOCK_GETRES:         "clock_getres",         // { int|sys|50|clock_getres(clockid_t clock_id, struct timespec *tp); }
	unix.SYS_NANOSLEEP:            "nanosleep",            // { int|sys|50|nanosleep(const struct timespec *rqtp, struct timespec *rmtp); }
	unix.SYS___SIGTIMEDWAIT:       "__sigtimedwait",       // { int|sys|50|__sigtimedwait(const sigset_t *set, siginfo_t *info, struct timespec *timeout); }
	unix.SYS__LWP_PARK:            "_lwp_park",            // { int|sys|50|_lwp_park(const struct timespec *ts, lwpid_t unpark, const void *hint, const void *unparkhint); }
	unix.SYS_KEVENT:               "kevent",               // { int|sys|50|kevent(int fd, const struct kevent *changelist, size_t nchanges, struct kevent *eventlist, size_t nevents, const struct timespec *timeout); }
	unix.SYS_PSELECT:              "pselect",              // { int|sys|50|pselect(int nd, fd_set *in, fd_set *ou, fd_set *ex, const struct timespec *ts, const sigset_t *mask); }
	unix.SYS_POLLTS:               "pollts",               // { int|sys|50|pollts(struct pollfd *fds, u_int nfds, const struct timespec *ts, const sigset_t *mask); }
	unix.SYS_STAT:                 "stat",                 // { int|sys|50|stat(const char *path, struct stat *ub); }
	unix.SYS_FSTAT:                "fstat",                // { int|sys|50|fstat(int fd, struct stat *sb); }
	unix.SYS_LSTAT:                "lstat",                // { int|sys|50|lstat(const char *path, struct stat *ub); }
	unix.SYS___SEMCTL:             "__semctl",             // { int|sys|50|__semctl(int semid, int semnum, int cmd, ... union __semun *arg); }
	unix.SYS_SHMCTL:               "shmctl",               // { int|sys|50|shmctl(int shmid, int cmd, struct shmid_ds *buf); }
	unix.SYS_MSGCTL:               "msgctl",               // { int|sys|50|msgctl(int msqid, int cmd, struct msqid_ds *buf); }
	unix.SYS_GETRUSAGE:            "getrusage",            // { int|sys|50|getrusage(int who, struct rusage *rusage); }
	unix.SYS_TIMER_SETTIME:        "timer_settime",        // { int|sys|50|timer_settime(timer_t timerid, int flags, const struct itimerspec *value, struct itimerspec *ovalue); }
	unix.SYS_TIMER_GETTIME:        "timer_gettime",        // { int|sys|50|timer_gettime(timer_t timerid, struct itimerspec *value); }
	unix.SYS_NTP_GETTIME:          "ntp_gettime",          // { int|sys|50|ntp_gettime(struct ntptimeval *ntvp); }
	unix.SYS_WAIT4:                "wait4",                // { int|sys|50|wait4(pid_t pid, int *status, int options, struct rusage *rusage); }
	unix.SYS_MKNOD:                "mknod",                // { int|sys|50|mknod(const char *path, mode_t mode, dev_t dev); }
	unix.SYS_FHSTAT:               "fhstat",               // { int|sys|50|fhstat(const void *fhp, size_t fh_size, struct stat *sb); }
	unix.SYS_PIPE2:                "pipe2",                // { int|sys||pipe2(int *fildes, int flags); }
	unix.SYS_DUP3:                 "dup3",                 // { int|sys||dup3(int from, int to, int flags); }
	unix.SYS_KQUEUE1:              "kqueue1",              // { int|sys||kqueue1(int flags); }
	unix.SYS_PACCEPT:              "paccept",              // { int|sys||paccept(int s, struct sockaddr *name, socklen_t *anamelen, const sigset_t *mask, int flags); }
	unix.SYS_LINKAT:               "linkat",               // { int|sys||linkat(int fd1, const char *name1, int fd2, const char *name2, int flags); }
	unix.SYS_RENAMEAT:             "renameat",             // { int|sys||renameat(int fromfd, const char *from, int tofd, const char *to); }
	unix.SYS_MKFIFOAT:             "mkfifoat",             // { int|sys||mkfifoat(int fd, const char *path, mode_t mode); }
	unix.SYS_MKNODAT:              "mknodat",              // { int|sys||mknodat(int fd, const char *path, mode_t mode, uint32_t dev); }
	unix.SYS_MKDIRAT:              "mkdirat",              // { int|sys||mkdirat(int fd, const char *path, mode_t mode); }
	unix.SYS_FACCESSAT:            "faccessat",            // { int|sys||faccessat(int fd, const char *path, int amode, int flag); }
	unix.SYS_FCHMODAT:             "fchmodat",             // { int|sys||fchmodat(int fd, const char *path, mode_t mode, int flag); }
	unix.SYS_FCHOWNAT:             "fchownat",             // { int|sys||fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag); }
	unix.SYS_FEXECVE:              "fexecve",              // { int|sys||fexecve(int fd, char * const *argp, char * const *envp); }
	unix.SYS_FSTATAT:              "fstatat",              // { int|sys||fstatat(int fd, const char *path, struct stat *buf, int flag); }
	unix.SYS_UTIMENSAT:            "utimensat",            // { int|sys||utimensat(int fd, const char *path, const struct timespec *tptr, int flag); }
	unix.SYS_OPENAT:               "openat",               // { int|sys||openat(int fd, const char *path, int oflags, ... mode_t mode); }
	unix.SYS_READLINKAT:           "readlinkat",           // { int|sys||readlinkat(int fd, const char *path, char *buf, size_t bufsize); }
	unix.SYS_SYMLINKAT:            "symlinkat",            // { int|sys||symlinkat(const char *path1, int fd, const char *path2); }
	unix.SYS_UNLINKAT:             "unlinkat",             // { int|sys||unlinkat(int fd, const char *path, int flag); }
	unix.SYS_FUTIMENS:             "futimens",             // { int|sys||futimens(int fd, const struct timespec *tptr); }
	unix.SYS___QUOTACTL:           "__quotactl",           // { int|sys||__quotactl(const char *path, struct quotactl_args *args); }
	unix.SYS_POSIX_SPAWN:          "posix_spawn",          // { int|sys||posix_spawn(pid_t *pid, const char *path, const struct posix_spawn_file_actions *file_actions, const struct posix_spawnattr *attrp, char *const *argv, char *const *envp); }
	unix.SYS_RECVMMSG:             "recvmmsg",             // { int|sys||recvmmsg(int s, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags, struct timespec *timeout); }
	unix.SYS_SENDMMSG:             "sendmmsg",             // { int|sys||sendmmsg(int s, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags); }
}
