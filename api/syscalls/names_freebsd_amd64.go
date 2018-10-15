package syscalls

import "syscall"

var _ = syscall.Exit

var Name = map[uint64]string{
	syscall.SYS_EXIT:                     "exit",                     // { void sys_exit(int rval); } exit \
	syscall.SYS_FORK:                     "fork",                     // { int fork(void); }
	syscall.SYS_READ:                     "read",                     // { ssize_t read(int fd, void *buf, \
	syscall.SYS_WRITE:                    "write",                    // { ssize_t write(int fd, const void *buf, \
	syscall.SYS_OPEN:                     "open",                     // { int open(char *path, int flags, int mode); }
	syscall.SYS_CLOSE:                    "close",                    // { int close(int fd); }
	syscall.SYS_WAIT4:                    "wait4",                    // { int wait4(int pid, int *status, \
	syscall.SYS_LINK:                     "link",                     // { int link(char *path, char *link); }
	syscall.SYS_UNLINK:                   "unlink",                   // { int unlink(char *path); }
	syscall.SYS_CHDIR:                    "chdir",                    // { int chdir(char *path); }
	syscall.SYS_FCHDIR:                   "fchdir",                   // { int fchdir(int fd); }
	syscall.SYS_MKNOD:                    "mknod",                    // { int mknod(char *path, int mode, int dev); }
	syscall.SYS_CHMOD:                    "chmod",                    // { int chmod(char *path, int mode); }
	syscall.SYS_CHOWN:                    "chown",                    // { int chown(char *path, int uid, int gid); }
	syscall.SYS_OBREAK:                   "obreak",                   // { int obreak(char *nsize); } break \
	syscall.SYS_GETPID:                   "getpid",                   // { pid_t getpid(void); }
	syscall.SYS_MOUNT:                    "mount",                    // { int mount(char *type, char *path, \
	syscall.SYS_UNMOUNT:                  "unmount",                  // { int unmount(char *path, int flags); }
	syscall.SYS_SETUID:                   "setuid",                   // { int setuid(uid_t uid); }
	syscall.SYS_GETUID:                   "getuid",                   // { uid_t getuid(void); }
	syscall.SYS_GETEUID:                  "geteuid",                  // { uid_t geteuid(void); }
	syscall.SYS_PTRACE:                   "ptrace",                   // { int ptrace(int req, pid_t pid, \
	syscall.SYS_RECVMSG:                  "recvmsg",                  // { int recvmsg(int s, struct msghdr *msg, \
	syscall.SYS_SENDMSG:                  "sendmsg",                  // { int sendmsg(int s, struct msghdr *msg, \
	syscall.SYS_RECVFROM:                 "recvfrom",                 // { int recvfrom(int s, caddr_t buf, \
	syscall.SYS_ACCEPT:                   "accept",                   // { int accept(int s, \
	syscall.SYS_GETPEERNAME:              "getpeername",              // { int getpeername(int fdes, \
	syscall.SYS_GETSOCKNAME:              "getsockname",              // { int getsockname(int fdes, \
	syscall.SYS_ACCESS:                   "access",                   // { int access(char *path, int amode); }
	syscall.SYS_CHFLAGS:                  "chflags",                  // { int chflags(const char *path, u_long flags); }
	syscall.SYS_FCHFLAGS:                 "fchflags",                 // { int fchflags(int fd, u_long flags); }
	syscall.SYS_SYNC:                     "sync",                     // { int sync(void); }
	syscall.SYS_KILL:                     "kill",                     // { int kill(int pid, int signum); }
	syscall.SYS_GETPPID:                  "getppid",                  // { pid_t getppid(void); }
	syscall.SYS_DUP:                      "dup",                      // { int dup(u_int fd); }
	syscall.SYS_PIPE:                     "pipe",                     // { int pipe(void); }
	syscall.SYS_GETEGID:                  "getegid",                  // { gid_t getegid(void); }
	syscall.SYS_PROFIL:                   "profil",                   // { int profil(caddr_t samples, size_t size, \
	syscall.SYS_KTRACE:                   "ktrace",                   // { int ktrace(const char *fname, int ops, \
	syscall.SYS_GETGID:                   "getgid",                   // { gid_t getgid(void); }
	syscall.SYS_GETLOGIN:                 "getlogin",                 // { int getlogin(char *namebuf, u_int \
	syscall.SYS_SETLOGIN:                 "setlogin",                 // { int setlogin(char *namebuf); }
	syscall.SYS_ACCT:                     "acct",                     // { int acct(char *path); }
	syscall.SYS_SIGALTSTACK:              "sigaltstack",              // { int sigaltstack(stack_t *ss, \
	syscall.SYS_IOCTL:                    "ioctl",                    // { int ioctl(int fd, u_long com, \
	syscall.SYS_REBOOT:                   "reboot",                   // { int reboot(int opt); }
	syscall.SYS_REVOKE:                   "revoke",                   // { int revoke(char *path); }
	syscall.SYS_SYMLINK:                  "symlink",                  // { int symlink(char *path, char *link); }
	syscall.SYS_READLINK:                 "readlink",                 // { ssize_t readlink(char *path, char *buf, \
	syscall.SYS_EXECVE:                   "execve",                   // { int execve(char *fname, char **argv, \
	syscall.SYS_UMASK:                    "umask",                    // { int umask(int newmask); } umask umask_args \
	syscall.SYS_CHROOT:                   "chroot",                   // { int chroot(char *path); }
	syscall.SYS_MSYNC:                    "msync",                    // { int msync(void *addr, size_t len, \
	syscall.SYS_VFORK:                    "vfork",                    // { int vfork(void); }
	syscall.SYS_SBRK:                     "sbrk",                     // { int sbrk(int incr); }
	syscall.SYS_SSTK:                     "sstk",                     // { int sstk(int incr); }
	syscall.SYS_OVADVISE:                 "ovadvise",                 // { int ovadvise(int anom); } vadvise \
	syscall.SYS_MUNMAP:                   "munmap",                   // { int munmap(void *addr, size_t len); }
	syscall.SYS_MPROTECT:                 "mprotect",                 // { int mprotect(const void *addr, size_t len, \
	syscall.SYS_MADVISE:                  "madvise",                  // { int madvise(void *addr, size_t len, \
	syscall.SYS_MINCORE:                  "mincore",                  // { int mincore(const void *addr, size_t len, \
	syscall.SYS_GETGROUPS:                "getgroups",                // { int getgroups(u_int gidsetsize, \
	syscall.SYS_SETGROUPS:                "setgroups",                // { int setgroups(u_int gidsetsize, \
	syscall.SYS_GETPGRP:                  "getpgrp",                  // { int getpgrp(void); }
	syscall.SYS_SETPGID:                  "setpgid",                  // { int setpgid(int pid, int pgid); }
	syscall.SYS_SETITIMER:                "setitimer",                // { int setitimer(u_int which, struct \
	syscall.SYS_SWAPON:                   "swapon",                   // { int swapon(char *name); }
	syscall.SYS_GETITIMER:                "getitimer",                // { int getitimer(u_int which, \
	syscall.SYS_GETDTABLESIZE:            "getdtablesize",            // { int getdtablesize(void); }
	syscall.SYS_DUP2:                     "dup2",                     // { int dup2(u_int from, u_int to); }
	syscall.SYS_FCNTL:                    "fcntl",                    // { int fcntl(int fd, int cmd, long arg); }
	syscall.SYS_SELECT:                   "select",                   // { int select(int nd, fd_set *in, fd_set *ou, \
	syscall.SYS_FSYNC:                    "fsync",                    // { int fsync(int fd); }
	syscall.SYS_SETPRIORITY:              "setpriority",              // { int setpriority(int which, int who, \
	syscall.SYS_SOCKET:                   "socket",                   // { int socket(int domain, int type, \
	syscall.SYS_CONNECT:                  "connect",                  // { int connect(int s, caddr_t name, \
	syscall.SYS_GETPRIORITY:              "getpriority",              // { int getpriority(int which, int who); }
	syscall.SYS_BIND:                     "bind",                     // { int bind(int s, caddr_t name, \
	syscall.SYS_SETSOCKOPT:               "setsockopt",               // { int setsockopt(int s, int level, int name, \
	syscall.SYS_LISTEN:                   "listen",                   // { int listen(int s, int backlog); }
	syscall.SYS_GETTIMEOFDAY:             "gettimeofday",             // { int gettimeofday(struct timeval *tp, \
	syscall.SYS_GETRUSAGE:                "getrusage",                // { int getrusage(int who, \
	syscall.SYS_GETSOCKOPT:               "getsockopt",               // { int getsockopt(int s, int level, int name, \
	syscall.SYS_READV:                    "readv",                    // { int readv(int fd, struct iovec *iovp, \
	syscall.SYS_WRITEV:                   "writev",                   // { int writev(int fd, struct iovec *iovp, \
	syscall.SYS_SETTIMEOFDAY:             "settimeofday",             // { int settimeofday(struct timeval *tv, \
	syscall.SYS_FCHOWN:                   "fchown",                   // { int fchown(int fd, int uid, int gid); }
	syscall.SYS_FCHMOD:                   "fchmod",                   // { int fchmod(int fd, int mode); }
	syscall.SYS_SETREUID:                 "setreuid",                 // { int setreuid(int ruid, int euid); }
	syscall.SYS_SETREGID:                 "setregid",                 // { int setregid(int rgid, int egid); }
	syscall.SYS_RENAME:                   "rename",                   // { int rename(char *from, char *to); }
	syscall.SYS_FLOCK:                    "flock",                    // { int flock(int fd, int how); }
	syscall.SYS_MKFIFO:                   "mkfifo",                   // { int mkfifo(char *path, int mode); }
	syscall.SYS_SENDTO:                   "sendto",                   // { int sendto(int s, caddr_t buf, size_t len, \
	syscall.SYS_SHUTDOWN:                 "shutdown",                 // { int shutdown(int s, int how); }
	syscall.SYS_SOCKETPAIR:               "socketpair",               // { int socketpair(int domain, int type, \
	syscall.SYS_MKDIR:                    "mkdir",                    // { int mkdir(char *path, int mode); }
	syscall.SYS_RMDIR:                    "rmdir",                    // { int rmdir(char *path); }
	syscall.SYS_UTIMES:                   "utimes",                   // { int utimes(char *path, \
	syscall.SYS_ADJTIME:                  "adjtime",                  // { int adjtime(struct timeval *delta, \
	syscall.SYS_SETSID:                   "setsid",                   // { int setsid(void); }
	syscall.SYS_QUOTACTL:                 "quotactl",                 // { int quotactl(char *path, int cmd, int uid, \
	syscall.SYS_LGETFH:                   "lgetfh",                   // { int lgetfh(char *fname, \
	syscall.SYS_GETFH:                    "getfh",                    // { int getfh(char *fname, \
	syscall.SYS_SYSARCH:                  "sysarch",                  // { int sysarch(int op, char *parms); }
	syscall.SYS_RTPRIO:                   "rtprio",                   // { int rtprio(int function, pid_t pid, \
	syscall.SYS_FREEBSD6_PREAD:           "freebsd6_pread",           // { ssize_t freebsd6_pread(int fd, void *buf, \
	syscall.SYS_FREEBSD6_PWRITE:          "freebsd6_pwrite",          // { ssize_t freebsd6_pwrite(int fd, \
	syscall.SYS_SETFIB:                   "setfib",                   // { int setfib(int fibnum); }
	syscall.SYS_NTP_ADJTIME:              "ntp_adjtime",              // { int ntp_adjtime(struct timex *tp); }
	syscall.SYS_SETGID:                   "setgid",                   // { int setgid(gid_t gid); }
	syscall.SYS_SETEGID:                  "setegid",                  // { int setegid(gid_t egid); }
	syscall.SYS_SETEUID:                  "seteuid",                  // { int seteuid(uid_t euid); }
	syscall.SYS_STAT:                     "stat",                     // { int stat(char *path, struct stat *ub); }
	syscall.SYS_FSTAT:                    "fstat",                    // { int fstat(int fd, struct stat *sb); }
	syscall.SYS_LSTAT:                    "lstat",                    // { int lstat(char *path, struct stat *ub); }
	syscall.SYS_PATHCONF:                 "pathconf",                 // { int pathconf(char *path, int name); }
	syscall.SYS_FPATHCONF:                "fpathconf",                // { int fpathconf(int fd, int name); }
	syscall.SYS_GETRLIMIT:                "getrlimit",                // { int getrlimit(u_int which, \
	syscall.SYS_SETRLIMIT:                "setrlimit",                // { int setrlimit(u_int which, \
	syscall.SYS_GETDIRENTRIES:            "getdirentries",            // { int getdirentries(int fd, char *buf, \
	syscall.SYS_FREEBSD6_MMAP:            "freebsd6_mmap",            // { caddr_t freebsd6_mmap(caddr_t addr, \
	syscall.SYS_FREEBSD6_LSEEK:           "freebsd6_lseek",           // { off_t freebsd6_lseek(int fd, int pad, \
	syscall.SYS_FREEBSD6_TRUNCATE:        "freebsd6_truncate",        // { int freebsd6_truncate(char *path, int pad, \
	syscall.SYS_FREEBSD6_FTRUNCATE:       "freebsd6_ftruncate",       // { int freebsd6_ftruncate(int fd, int pad, \
	syscall.SYS___SYSCTL:                 "__sysctl",                 // { int __sysctl(int *name, u_int namelen, \
	syscall.SYS_MLOCK:                    "mlock",                    // { int mlock(const void *addr, size_t len); }
	syscall.SYS_MUNLOCK:                  "munlock",                  // { int munlock(const void *addr, size_t len); }
	syscall.SYS_UNDELETE:                 "undelete",                 // { int undelete(char *path); }
	syscall.SYS_FUTIMES:                  "futimes",                  // { int futimes(int fd, struct timeval *tptr); }
	syscall.SYS_GETPGID:                  "getpgid",                  // { int getpgid(pid_t pid); }
	syscall.SYS_POLL:                     "poll",                     // { int poll(struct pollfd *fds, u_int nfds, \
	syscall.SYS_CLOCK_GETTIME:            "clock_gettime",            // { int clock_gettime(clockid_t clock_id, \
	syscall.SYS_CLOCK_SETTIME:            "clock_settime",            // { int clock_settime( \
	syscall.SYS_CLOCK_GETRES:             "clock_getres",             // { int clock_getres(clockid_t clock_id, \
	syscall.SYS_KTIMER_CREATE:            "ktimer_create",            // { int ktimer_create(clockid_t clock_id, \
	syscall.SYS_KTIMER_DELETE:            "ktimer_delete",            // { int ktimer_delete(int timerid); }
	syscall.SYS_KTIMER_SETTIME:           "ktimer_settime",           // { int ktimer_settime(int timerid, int flags, \
	syscall.SYS_KTIMER_GETTIME:           "ktimer_gettime",           // { int ktimer_gettime(int timerid, struct \
	syscall.SYS_KTIMER_GETOVERRUN:        "ktimer_getoverrun",        // { int ktimer_getoverrun(int timerid); }
	syscall.SYS_NANOSLEEP:                "nanosleep",                // { int nanosleep(const struct timespec *rqtp, \
	syscall.SYS_FFCLOCK_GETCOUNTER:       "ffclock_getcounter",       // { int ffclock_getcounter(ffcounter *ffcount); }
	syscall.SYS_FFCLOCK_SETESTIMATE:      "ffclock_setestimate",      // { int ffclock_setestimate( \
	syscall.SYS_FFCLOCK_GETESTIMATE:      "ffclock_getestimate",      // { int ffclock_getestimate( \
	syscall.SYS_CLOCK_GETCPUCLOCKID2:     "clock_getcpuclockid2",     // { int clock_getcpuclockid2(id_t id,\
	syscall.SYS_NTP_GETTIME:              "ntp_gettime",              // { int ntp_gettime(struct ntptimeval *ntvp); }
	syscall.SYS_MINHERIT:                 "minherit",                 // { int minherit(void *addr, size_t len, \
	syscall.SYS_RFORK:                    "rfork",                    // { int rfork(int flags); }
	syscall.SYS_OPENBSD_POLL:             "openbsd_poll",             // { int openbsd_poll(struct pollfd *fds, \
	syscall.SYS_ISSETUGID:                "issetugid",                // { int issetugid(void); }
	syscall.SYS_LCHOWN:                   "lchown",                   // { int lchown(char *path, int uid, int gid); }
	syscall.SYS_GETDENTS:                 "getdents",                 // { int getdents(int fd, char *buf, \
	syscall.SYS_LCHMOD:                   "lchmod",                   // { int lchmod(char *path, mode_t mode); }
	syscall.SYS_LUTIMES:                  "lutimes",                  // { int lutimes(char *path, \
	syscall.SYS_NSTAT:                    "nstat",                    // { int nstat(char *path, struct nstat *ub); }
	syscall.SYS_NFSTAT:                   "nfstat",                   // { int nfstat(int fd, struct nstat *sb); }
	syscall.SYS_NLSTAT:                   "nlstat",                   // { int nlstat(char *path, struct nstat *ub); }
	syscall.SYS_PREADV:                   "preadv",                   // { ssize_t preadv(int fd, struct iovec *iovp, \
	syscall.SYS_PWRITEV:                  "pwritev",                  // { ssize_t pwritev(int fd, struct iovec *iovp, \
	syscall.SYS_FHOPEN:                   "fhopen",                   // { int fhopen(const struct fhandle *u_fhp, \
	syscall.SYS_FHSTAT:                   "fhstat",                   // { int fhstat(const struct fhandle *u_fhp, \
	syscall.SYS_MODNEXT:                  "modnext",                  // { int modnext(int modid); }
	syscall.SYS_MODSTAT:                  "modstat",                  // { int modstat(int modid, \
	syscall.SYS_MODFNEXT:                 "modfnext",                 // { int modfnext(int modid); }
	syscall.SYS_MODFIND:                  "modfind",                  // { int modfind(const char *name); }
	syscall.SYS_KLDLOAD:                  "kldload",                  // { int kldload(const char *file); }
	syscall.SYS_KLDUNLOAD:                "kldunload",                // { int kldunload(int fileid); }
	syscall.SYS_KLDFIND:                  "kldfind",                  // { int kldfind(const char *file); }
	syscall.SYS_KLDNEXT:                  "kldnext",                  // { int kldnext(int fileid); }
	syscall.SYS_KLDSTAT:                  "kldstat",                  // { int kldstat(int fileid, struct \
	syscall.SYS_KLDFIRSTMOD:              "kldfirstmod",              // { int kldfirstmod(int fileid); }
	syscall.SYS_GETSID:                   "getsid",                   // { int getsid(pid_t pid); }
	syscall.SYS_SETRESUID:                "setresuid",                // { int setresuid(uid_t ruid, uid_t euid, \
	syscall.SYS_SETRESGID:                "setresgid",                // { int setresgid(gid_t rgid, gid_t egid, \
	syscall.SYS_YIELD:                    "yield",                    // { int yield(void); }
	syscall.SYS_MLOCKALL:                 "mlockall",                 // { int mlockall(int how); }
	syscall.SYS_MUNLOCKALL:               "munlockall",               // { int munlockall(void); }
	syscall.SYS___GETCWD:                 "__getcwd",                 // { int __getcwd(u_char *buf, u_int buflen); }
	syscall.SYS_SCHED_SETPARAM:           "sched_setparam",           // { int sched_setparam (pid_t pid, \
	syscall.SYS_SCHED_GETPARAM:           "sched_getparam",           // { int sched_getparam (pid_t pid, struct \
	syscall.SYS_SCHED_SETSCHEDULER:       "sched_setscheduler",       // { int sched_setscheduler (pid_t pid, int \
	syscall.SYS_SCHED_GETSCHEDULER:       "sched_getscheduler",       // { int sched_getscheduler (pid_t pid); }
	syscall.SYS_SCHED_YIELD:              "sched_yield",              // { int sched_yield (void); }
	syscall.SYS_SCHED_GET_PRIORITY_MAX:   "sched_get_priority_max",   // { int sched_get_priority_max (int policy); }
	syscall.SYS_SCHED_GET_PRIORITY_MIN:   "sched_get_priority_min",   // { int sched_get_priority_min (int policy); }
	syscall.SYS_SCHED_RR_GET_INTERVAL:    "sched_rr_get_interval",    // { int sched_rr_get_interval (pid_t pid, \
	syscall.SYS_UTRACE:                   "utrace",                   // { int utrace(const void *addr, size_t len); }
	syscall.SYS_KLDSYM:                   "kldsym",                   // { int kldsym(int fileid, int cmd, \
	syscall.SYS_JAIL:                     "jail",                     // { int jail(struct jail *jail); }
	syscall.SYS_SIGPROCMASK:              "sigprocmask",              // { int sigprocmask(int how, \
	syscall.SYS_SIGSUSPEND:               "sigsuspend",               // { int sigsuspend(const sigset_t *sigmask); }
	syscall.SYS_SIGPENDING:               "sigpending",               // { int sigpending(sigset_t *set); }
	syscall.SYS_SIGTIMEDWAIT:             "sigtimedwait",             // { int sigtimedwait(const sigset_t *set, \
	syscall.SYS_SIGWAITINFO:              "sigwaitinfo",              // { int sigwaitinfo(const sigset_t *set, \
	syscall.SYS___ACL_GET_FILE:           "__acl_get_file",           // { int __acl_get_file(const char *path, \
	syscall.SYS___ACL_SET_FILE:           "__acl_set_file",           // { int __acl_set_file(const char *path, \
	syscall.SYS___ACL_GET_FD:             "__acl_get_fd",             // { int __acl_get_fd(int filedes, \
	syscall.SYS___ACL_SET_FD:             "__acl_set_fd",             // { int __acl_set_fd(int filedes, \
	syscall.SYS___ACL_DELETE_FILE:        "__acl_delete_file",        // { int __acl_delete_file(const char *path, \
	syscall.SYS___ACL_DELETE_FD:          "__acl_delete_fd",          // { int __acl_delete_fd(int filedes, \
	syscall.SYS___ACL_ACLCHECK_FILE:      "__acl_aclcheck_file",      // { int __acl_aclcheck_file(const char *path, \
	syscall.SYS___ACL_ACLCHECK_FD:        "__acl_aclcheck_fd",        // { int __acl_aclcheck_fd(int filedes, \
	syscall.SYS_EXTATTRCTL:               "extattrctl",               // { int extattrctl(const char *path, int cmd, \
	syscall.SYS_EXTATTR_SET_FILE:         "extattr_set_file",         // { ssize_t extattr_set_file( \
	syscall.SYS_EXTATTR_GET_FILE:         "extattr_get_file",         // { ssize_t extattr_get_file( \
	syscall.SYS_EXTATTR_DELETE_FILE:      "extattr_delete_file",      // { int extattr_delete_file(const char *path, \
	syscall.SYS_GETRESUID:                "getresuid",                // { int getresuid(uid_t *ruid, uid_t *euid, \
	syscall.SYS_GETRESGID:                "getresgid",                // { int getresgid(gid_t *rgid, gid_t *egid, \
	syscall.SYS_KQUEUE:                   "kqueue",                   // { int kqueue(void); }
	syscall.SYS_KEVENT:                   "kevent",                   // { int kevent(int fd, \
	syscall.SYS_EXTATTR_SET_FD:           "extattr_set_fd",           // { ssize_t extattr_set_fd(int fd, \
	syscall.SYS_EXTATTR_GET_FD:           "extattr_get_fd",           // { ssize_t extattr_get_fd(int fd, \
	syscall.SYS_EXTATTR_DELETE_FD:        "extattr_delete_fd",        // { int extattr_delete_fd(int fd, \
	syscall.SYS___SETUGID:                "__setugid",                // { int __setugid(int flag); }
	syscall.SYS_EACCESS:                  "eaccess",                  // { int eaccess(char *path, int amode); }
	syscall.SYS_NMOUNT:                   "nmount",                   // { int nmount(struct iovec *iovp, \
	syscall.SYS___MAC_GET_PROC:           "__mac_get_proc",           // { int __mac_get_proc(struct mac *mac_p); }
	syscall.SYS___MAC_SET_PROC:           "__mac_set_proc",           // { int __mac_set_proc(struct mac *mac_p); }
	syscall.SYS___MAC_GET_FD:             "__mac_get_fd",             // { int __mac_get_fd(int fd, \
	syscall.SYS___MAC_GET_FILE:           "__mac_get_file",           // { int __mac_get_file(const char *path_p, \
	syscall.SYS___MAC_SET_FD:             "__mac_set_fd",             // { int __mac_set_fd(int fd, \
	syscall.SYS___MAC_SET_FILE:           "__mac_set_file",           // { int __mac_set_file(const char *path_p, \
	syscall.SYS_KENV:                     "kenv",                     // { int kenv(int what, const char *name, \
	syscall.SYS_LCHFLAGS:                 "lchflags",                 // { int lchflags(const char *path, \
	syscall.SYS_UUIDGEN:                  "uuidgen",                  // { int uuidgen(struct uuid *store, \
	syscall.SYS_SENDFILE:                 "sendfile",                 // { int sendfile(int fd, int s, off_t offset, \
	syscall.SYS_MAC_SYSCALL:              "mac_syscall",              // { int mac_syscall(const char *policy, \
	syscall.SYS_GETFSSTAT:                "getfsstat",                // { int getfsstat(struct statfs *buf, \
	syscall.SYS_STATFS:                   "statfs",                   // { int statfs(char *path, \
	syscall.SYS_FSTATFS:                  "fstatfs",                  // { int fstatfs(int fd, struct statfs *buf); }
	syscall.SYS_FHSTATFS:                 "fhstatfs",                 // { int fhstatfs(const struct fhandle *u_fhp, \
	syscall.SYS___MAC_GET_PID:            "__mac_get_pid",            // { int __mac_get_pid(pid_t pid, \
	syscall.SYS___MAC_GET_LINK:           "__mac_get_link",           // { int __mac_get_link(const char *path_p, \
	syscall.SYS___MAC_SET_LINK:           "__mac_set_link",           // { int __mac_set_link(const char *path_p, \
	syscall.SYS_EXTATTR_SET_LINK:         "extattr_set_link",         // { ssize_t extattr_set_link( \
	syscall.SYS_EXTATTR_GET_LINK:         "extattr_get_link",         // { ssize_t extattr_get_link( \
	syscall.SYS_EXTATTR_DELETE_LINK:      "extattr_delete_link",      // { int extattr_delete_link( \
	syscall.SYS___MAC_EXECVE:             "__mac_execve",             // { int __mac_execve(char *fname, char **argv, \
	syscall.SYS_SIGACTION:                "sigaction",                // { int sigaction(int sig, \
	syscall.SYS_SIGRETURN:                "sigreturn",                // { int sigreturn( \
	syscall.SYS_GETCONTEXT:               "getcontext",               // { int getcontext(struct __ucontext *ucp); }
	syscall.SYS_SETCONTEXT:               "setcontext",               // { int setcontext( \
	syscall.SYS_SWAPCONTEXT:              "swapcontext",              // { int swapcontext(struct __ucontext *oucp, \
	syscall.SYS_SWAPOFF:                  "swapoff",                  // { int swapoff(const char *name); }
	syscall.SYS___ACL_GET_LINK:           "__acl_get_link",           // { int __acl_get_link(const char *path, \
	syscall.SYS___ACL_SET_LINK:           "__acl_set_link",           // { int __acl_set_link(const char *path, \
	syscall.SYS___ACL_DELETE_LINK:        "__acl_delete_link",        // { int __acl_delete_link(const char *path, \
	syscall.SYS___ACL_ACLCHECK_LINK:      "__acl_aclcheck_link",      // { int __acl_aclcheck_link(const char *path, \
	syscall.SYS_SIGWAIT:                  "sigwait",                  // { int sigwait(const sigset_t *set, \
	syscall.SYS_THR_CREATE:               "thr_create",               // { int thr_create(ucontext_t *ctx, long *id, \
	syscall.SYS_THR_EXIT:                 "thr_exit",                 // { void thr_exit(long *state); }
	syscall.SYS_THR_SELF:                 "thr_self",                 // { int thr_self(long *id); }
	syscall.SYS_THR_KILL:                 "thr_kill",                 // { int thr_kill(long id, int sig); }
	syscall.SYS__UMTX_LOCK:               "_umtx_lock",               // { int _umtx_lock(struct umtx *umtx); }
	syscall.SYS__UMTX_UNLOCK:             "_umtx_unlock",             // { int _umtx_unlock(struct umtx *umtx); }
	syscall.SYS_JAIL_ATTACH:              "jail_attach",              // { int jail_attach(int jid); }
	syscall.SYS_EXTATTR_LIST_FD:          "extattr_list_fd",          // { ssize_t extattr_list_fd(int fd, \
	syscall.SYS_EXTATTR_LIST_FILE:        "extattr_list_file",        // { ssize_t extattr_list_file( \
	syscall.SYS_EXTATTR_LIST_LINK:        "extattr_list_link",        // { ssize_t extattr_list_link( \
	syscall.SYS_THR_SUSPEND:              "thr_suspend",              // { int thr_suspend( \
	syscall.SYS_THR_WAKE:                 "thr_wake",                 // { int thr_wake(long id); }
	syscall.SYS_KLDUNLOADF:               "kldunloadf",               // { int kldunloadf(int fileid, int flags); }
	syscall.SYS_AUDIT:                    "audit",                    // { int audit(const void *record, \
	syscall.SYS_AUDITON:                  "auditon",                  // { int auditon(int cmd, void *data, \
	syscall.SYS_GETAUID:                  "getauid",                  // { int getauid(uid_t *auid); }
	syscall.SYS_SETAUID:                  "setauid",                  // { int setauid(uid_t *auid); }
	syscall.SYS_GETAUDIT:                 "getaudit",                 // { int getaudit(struct auditinfo *auditinfo); }
	syscall.SYS_SETAUDIT:                 "setaudit",                 // { int setaudit(struct auditinfo *auditinfo); }
	syscall.SYS_GETAUDIT_ADDR:            "getaudit_addr",            // { int getaudit_addr( \
	syscall.SYS_SETAUDIT_ADDR:            "setaudit_addr",            // { int setaudit_addr( \
	syscall.SYS_AUDITCTL:                 "auditctl",                 // { int auditctl(char *path); }
	syscall.SYS__UMTX_OP:                 "_umtx_op",                 // { int _umtx_op(void *obj, int op, \
	syscall.SYS_THR_NEW:                  "thr_new",                  // { int thr_new(struct thr_param *param, \
	syscall.SYS_SIGQUEUE:                 "sigqueue",                 // { int sigqueue(pid_t pid, int signum, void *value); }
	syscall.SYS_ABORT2:                   "abort2",                   // { int abort2(const char *why, int nargs, void **args); }
	syscall.SYS_THR_SET_NAME:             "thr_set_name",             // { int thr_set_name(long id, const char *name); }
	syscall.SYS_RTPRIO_THREAD:            "rtprio_thread",            // { int rtprio_thread(int function, \
	syscall.SYS_SCTP_PEELOFF:             "sctp_peeloff",             // { int sctp_peeloff(int sd, uint32_t name); }
	syscall.SYS_SCTP_GENERIC_SENDMSG:     "sctp_generic_sendmsg",     // { int sctp_generic_sendmsg(int sd, caddr_t msg, int mlen, \
	syscall.SYS_SCTP_GENERIC_SENDMSG_IOV: "sctp_generic_sendmsg_iov", // { int sctp_generic_sendmsg_iov(int sd, struct iovec *iov, int iovlen, \
	syscall.SYS_SCTP_GENERIC_RECVMSG:     "sctp_generic_recvmsg",     // { int sctp_generic_recvmsg(int sd, struct iovec *iov, int iovlen, \
	syscall.SYS_PREAD:                    "pread",                    // { ssize_t pread(int fd, void *buf, \
	syscall.SYS_PWRITE:                   "pwrite",                   // { ssize_t pwrite(int fd, const void *buf, \
	syscall.SYS_MMAP:                     "mmap",                     // { caddr_t mmap(caddr_t addr, size_t len, \
	syscall.SYS_LSEEK:                    "lseek",                    // { off_t lseek(int fd, off_t offset, \
	syscall.SYS_TRUNCATE:                 "truncate",                 // { int truncate(char *path, off_t length); }
	syscall.SYS_FTRUNCATE:                "ftruncate",                // { int ftruncate(int fd, off_t length); }
	syscall.SYS_THR_KILL2:                "thr_kill2",                // { int thr_kill2(pid_t pid, long id, int sig); }
	syscall.SYS_SHM_OPEN:                 "shm_open",                 // { int shm_open(const char *path, int flags, \
	syscall.SYS_SHM_UNLINK:               "shm_unlink",               // { int shm_unlink(const char *path); }
	syscall.SYS_CPUSET:                   "cpuset",                   // { int cpuset(cpusetid_t *setid); }
	syscall.SYS_CPUSET_SETID:             "cpuset_setid",             // { int cpuset_setid(cpuwhich_t which, id_t id, \
	syscall.SYS_CPUSET_GETID:             "cpuset_getid",             // { int cpuset_getid(cpulevel_t level, \
	syscall.SYS_CPUSET_GETAFFINITY:       "cpuset_getaffinity",       // { int cpuset_getaffinity(cpulevel_t level, \
	syscall.SYS_CPUSET_SETAFFINITY:       "cpuset_setaffinity",       // { int cpuset_setaffinity(cpulevel_t level, \
	syscall.SYS_FACCESSAT:                "faccessat",                // { int faccessat(int fd, char *path, int amode, \
	syscall.SYS_FCHMODAT:                 "fchmodat",                 // { int fchmodat(int fd, char *path, mode_t mode, \
	syscall.SYS_FCHOWNAT:                 "fchownat",                 // { int fchownat(int fd, char *path, uid_t uid, \
	syscall.SYS_FEXECVE:                  "fexecve",                  // { int fexecve(int fd, char **argv, \
	syscall.SYS_FSTATAT:                  "fstatat",                  // { int fstatat(int fd, char *path, \
	syscall.SYS_FUTIMESAT:                "futimesat",                // { int futimesat(int fd, char *path, \
	syscall.SYS_LINKAT:                   "linkat",                   // { int linkat(int fd1, char *path1, int fd2, \
	syscall.SYS_MKDIRAT:                  "mkdirat",                  // { int mkdirat(int fd, char *path, mode_t mode); }
	syscall.SYS_MKFIFOAT:                 "mkfifoat",                 // { int mkfifoat(int fd, char *path, mode_t mode); }
	syscall.SYS_MKNODAT:                  "mknodat",                  // { int mknodat(int fd, char *path, mode_t mode, \
	syscall.SYS_OPENAT:                   "openat",                   // { int openat(int fd, char *path, int flag, \
	syscall.SYS_READLINKAT:               "readlinkat",               // { int readlinkat(int fd, char *path, char *buf, \
	syscall.SYS_RENAMEAT:                 "renameat",                 // { int renameat(int oldfd, char *old, int newfd, \
	syscall.SYS_SYMLINKAT:                "symlinkat",                // { int symlinkat(char *path1, int fd, \
	syscall.SYS_UNLINKAT:                 "unlinkat",                 // { int unlinkat(int fd, char *path, int flag); }
	syscall.SYS_POSIX_OPENPT:             "posix_openpt",             // { int posix_openpt(int flags); }
	syscall.SYS_JAIL_GET:                 "jail_get",                 // { int jail_get(struct iovec *iovp, \
	syscall.SYS_JAIL_SET:                 "jail_set",                 // { int jail_set(struct iovec *iovp, \
	syscall.SYS_JAIL_REMOVE:              "jail_remove",              // { int jail_remove(int jid); }
	syscall.SYS_CLOSEFROM:                "closefrom",                // { int closefrom(int lowfd); }
	syscall.SYS_LPATHCONF:                "lpathconf",                // { int lpathconf(char *path, int name); }
	syscall.SYS_CAP_NEW:                  "cap_new",                  // { int cap_new(int fd, uint64_t rights); }
	syscall.SYS_CAP_GETRIGHTS:            "cap_getrights",            // { int cap_getrights(int fd, \
	syscall.SYS_CAP_ENTER:                "cap_enter",                // { int cap_enter(void); }
	syscall.SYS_CAP_GETMODE:              "cap_getmode",              // { int cap_getmode(u_int *modep); }
	syscall.SYS_PDFORK:                   "pdfork",                   // { int pdfork(int *fdp, int flags); }
	syscall.SYS_PDKILL:                   "pdkill",                   // { int pdkill(int fd, int signum); }
	syscall.SYS_PDGETPID:                 "pdgetpid",                 // { int pdgetpid(int fd, pid_t *pidp); }
	syscall.SYS_PSELECT:                  "pselect",                  // { int pselect(int nd, fd_set *in, \
	syscall.SYS_GETLOGINCLASS:            "getloginclass",            // { int getloginclass(char *namebuf, \
	syscall.SYS_SETLOGINCLASS:            "setloginclass",            // { int setloginclass(const char *namebuf); }
	syscall.SYS_RCTL_GET_RACCT:           "rctl_get_racct",           // { int rctl_get_racct(const void *inbufp, \
	syscall.SYS_RCTL_GET_RULES:           "rctl_get_rules",           // { int rctl_get_rules(const void *inbufp, \
	syscall.SYS_RCTL_GET_LIMITS:          "rctl_get_limits",          // { int rctl_get_limits(const void *inbufp, \
	syscall.SYS_RCTL_ADD_RULE:            "rctl_add_rule",            // { int rctl_add_rule(const void *inbufp, \
	syscall.SYS_RCTL_REMOVE_RULE:         "rctl_remove_rule",         // { int rctl_remove_rule(const void *inbufp, \
	syscall.SYS_POSIX_FALLOCATE:          "posix_fallocate",          // { int posix_fallocate(int fd, \
	syscall.SYS_POSIX_FADVISE:            "posix_fadvise",            // { int posix_fadvise(int fd, off_t offset, \
	syscall.SYS_WAIT6:                    "wait6",                    // { int wait6(idtype_t idtype, id_t id, \
	syscall.SYS_BINDAT:                   "bindat",                   // { int bindat(int fd, int s, caddr_t name, \
	syscall.SYS_CONNECTAT:                "connectat",                // { int connectat(int fd, int s, caddr_t name, \
	syscall.SYS_CHFLAGSAT:                "chflagsat",                // { int chflagsat(int fd, const char *path, \
	syscall.SYS_ACCEPT4:                  "accept4",                  // { int accept4(int s, \
	syscall.SYS_PIPE2:                    "pipe2",                    // { int pipe2(int *fildes, int flags); }
	syscall.SYS_PROCCTL:                  "procctl",                  // { int procctl(idtype_t idtype, id_t id, \
	syscall.SYS_UTIMENSAT:                "utimensat",                // { int utimensat(int fd, \
}
