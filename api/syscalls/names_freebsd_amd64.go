package syscalls

import "golang.org/x/sys/unix"

var _ = unix.Exit

var Name = map[uint64]string{
	unix.SYS_EXIT:                   "exit",                   // { void sys_exit(int rval); } exit \
	unix.SYS_FORK:                   "fork",                   // { int fork(void); }
	unix.SYS_READ:                   "read",                   // { ssize_t read(int fd, void *buf, \
	unix.SYS_WRITE:                  "write",                  // { ssize_t write(int fd, const void *buf, \
	unix.SYS_OPEN:                   "open",                   // { int open(char *path, int flags, int mode); }
	unix.SYS_CLOSE:                  "close",                  // { int close(int fd); }
	unix.SYS_WAIT4:                  "wait4",                  // { int wait4(int pid, int *status, \
	unix.SYS_LINK:                   "link",                   // { int link(char *path, char *link); }
	unix.SYS_UNLINK:                 "unlink",                 // { int unlink(char *path); }
	unix.SYS_CHDIR:                  "chdir",                  // { int chdir(char *path); }
	unix.SYS_FCHDIR:                 "fchdir",                 // { int fchdir(int fd); }
	unix.SYS_MKNOD:                  "mknod",                  // { int mknod(char *path, int mode, int dev); }
	unix.SYS_CHMOD:                  "chmod",                  // { int chmod(char *path, int mode); }
	unix.SYS_CHOWN:                  "chown",                  // { int chown(char *path, int uid, int gid); }
	unix.SYS_OBREAK:                 "obreak",                 // { int obreak(char *nsize); } break \
	unix.SYS_GETPID:                 "getpid",                 // { pid_t getpid(void); }
	unix.SYS_MOUNT:                  "mount",                  // { int mount(char *type, char *path, \
	unix.SYS_UNMOUNT:                "unmount",                // { int unmount(char *path, int flags); }
	unix.SYS_SETUID:                 "setuid",                 // { int setuid(uid_t uid); }
	unix.SYS_GETUID:                 "getuid",                 // { uid_t getuid(void); }
	unix.SYS_GETEUID:                "geteuid",                // { uid_t geteuid(void); }
	unix.SYS_PTRACE:                 "ptrace",                 // { int ptrace(int req, pid_t pid, \
	unix.SYS_RECVMSG:                "recvmsg",                // { int recvmsg(int s, struct msghdr *msg, \
	unix.SYS_SENDMSG:                "sendmsg",                // { int sendmsg(int s, struct msghdr *msg, \
	unix.SYS_RECVFROM:               "recvfrom",               // { int recvfrom(int s, caddr_t buf, \
	unix.SYS_ACCEPT:                 "accept",                 // { int accept(int s, \
	unix.SYS_GETPEERNAME:            "getpeername",            // { int getpeername(int fdes, \
	unix.SYS_GETSOCKNAME:            "getsockname",            // { int getsockname(int fdes, \
	unix.SYS_ACCESS:                 "access",                 // { int access(char *path, int amode); }
	unix.SYS_CHFLAGS:                "chflags",                // { int chflags(const char *path, u_long flags); }
	unix.SYS_FCHFLAGS:               "fchflags",               // { int fchflags(int fd, u_long flags); }
	unix.SYS_SYNC:                   "sync",                   // { int sync(void); }
	unix.SYS_KILL:                   "kill",                   // { int kill(int pid, int signum); }
	unix.SYS_GETPPID:                "getppid",                // { pid_t getppid(void); }
	unix.SYS_DUP:                    "dup",                    // { int dup(u_int fd); }
	unix.SYS_PIPE:                   "pipe",                   // { int pipe(void); }
	unix.SYS_GETEGID:                "getegid",                // { gid_t getegid(void); }
	unix.SYS_PROFIL:                 "profil",                 // { int profil(caddr_t samples, size_t size, \
	unix.SYS_KTRACE:                 "ktrace",                 // { int ktrace(const char *fname, int ops, \
	unix.SYS_GETGID:                 "getgid",                 // { gid_t getgid(void); }
	unix.SYS_GETLOGIN:               "getlogin",               // { int getlogin(char *namebuf, u_int \
	unix.SYS_SETLOGIN:               "setlogin",               // { int setlogin(char *namebuf); }
	unix.SYS_ACCT:                   "acct",                   // { int acct(char *path); }
	unix.SYS_SIGALTSTACK:            "sigaltstack",            // { int sigaltstack(stack_t *ss, \
	unix.SYS_IOCTL:                  "ioctl",                  // { int ioctl(int fd, u_long com, \
	unix.SYS_REBOOT:                 "reboot",                 // { int reboot(int opt); }
	unix.SYS_REVOKE:                 "revoke",                 // { int revoke(char *path); }
	unix.SYS_SYMLINK:                "symlink",                // { int symlink(char *path, char *link); }
	unix.SYS_READLINK:               "readlink",               // { ssize_t readlink(char *path, char *buf, \
	unix.SYS_EXECVE:                 "execve",                 // { int execve(char *fname, char **argv, \
	unix.SYS_UMASK:                  "umask",                  // { int umask(int newmask); } umask umask_args \
	unix.SYS_CHROOT:                 "chroot",                 // { int chroot(char *path); }
	unix.SYS_MSYNC:                  "msync",                  // { int msync(void *addr, size_t len, \
	unix.SYS_VFORK:                  "vfork",                  // { int vfork(void); }
	unix.SYS_SBRK:                   "sbrk",                   // { int sbrk(int incr); }
	unix.SYS_SSTK:                   "sstk",                   // { int sstk(int incr); }
	unix.SYS_OVADVISE:               "ovadvise",               // { int ovadvise(int anom); } vadvise \
	unix.SYS_MUNMAP:                 "munmap",                 // { int munmap(void *addr, size_t len); }
	unix.SYS_MPROTECT:               "mprotect",               // { int mprotect(const void *addr, size_t len, \
	unix.SYS_MADVISE:                "madvise",                // { int madvise(void *addr, size_t len, \
	unix.SYS_MINCORE:                "mincore",                // { int mincore(const void *addr, size_t len, \
	unix.SYS_GETGROUPS:              "getgroups",              // { int getgroups(u_int gidsetsize, \
	unix.SYS_SETGROUPS:              "setgroups",              // { int setgroups(u_int gidsetsize, \
	unix.SYS_GETPGRP:                "getpgrp",                // { int getpgrp(void); }
	unix.SYS_SETPGID:                "setpgid",                // { int setpgid(int pid, int pgid); }
	unix.SYS_SETITIMER:              "setitimer",              // { int setitimer(u_int which, struct \
	unix.SYS_SWAPON:                 "swapon",                 // { int swapon(char *name); }
	unix.SYS_GETITIMER:              "getitimer",              // { int getitimer(u_int which, \
	unix.SYS_GETDTABLESIZE:          "getdtablesize",          // { int getdtablesize(void); }
	unix.SYS_DUP2:                   "dup2",                   // { int dup2(u_int from, u_int to); }
	unix.SYS_FCNTL:                  "fcntl",                  // { int fcntl(int fd, int cmd, long arg); }
	unix.SYS_SELECT:                 "select",                 // { int select(int nd, fd_set *in, fd_set *ou, \
	unix.SYS_FSYNC:                  "fsync",                  // { int fsync(int fd); }
	unix.SYS_SETPRIORITY:            "setpriority",            // { int setpriority(int which, int who, \
	unix.SYS_SOCKET:                 "socket",                 // { int socket(int domain, int type, \
	unix.SYS_CONNECT:                "connect",                // { int connect(int s, caddr_t name, \
	unix.SYS_GETPRIORITY:            "getpriority",            // { int getpriority(int which, int who); }
	unix.SYS_BIND:                   "bind",                   // { int bind(int s, caddr_t name, \
	unix.SYS_SETSOCKOPT:             "setsockopt",             // { int setsockopt(int s, int level, int name, \
	unix.SYS_LISTEN:                 "listen",                 // { int listen(int s, int backlog); }
	unix.SYS_GETTIMEOFDAY:           "gettimeofday",           // { int gettimeofday(struct timeval *tp, \
	unix.SYS_GETRUSAGE:              "getrusage",              // { int getrusage(int who, \
	unix.SYS_GETSOCKOPT:             "getsockopt",             // { int getsockopt(int s, int level, int name, \
	unix.SYS_READV:                  "readv",                  // { int readv(int fd, struct iovec *iovp, \
	unix.SYS_WRITEV:                 "writev",                 // { int writev(int fd, struct iovec *iovp, \
	unix.SYS_SETTIMEOFDAY:           "settimeofday",           // { int settimeofday(struct timeval *tv, \
	unix.SYS_FCHOWN:                 "fchown",                 // { int fchown(int fd, int uid, int gid); }
	unix.SYS_FCHMOD:                 "fchmod",                 // { int fchmod(int fd, int mode); }
	unix.SYS_SETREUID:               "setreuid",               // { int setreuid(int ruid, int euid); }
	unix.SYS_SETREGID:               "setregid",               // { int setregid(int rgid, int egid); }
	unix.SYS_RENAME:                 "rename",                 // { int rename(char *from, char *to); }
	unix.SYS_FLOCK:                  "flock",                  // { int flock(int fd, int how); }
	unix.SYS_MKFIFO:                 "mkfifo",                 // { int mkfifo(char *path, int mode); }
	unix.SYS_SENDTO:                 "sendto",                 // { int sendto(int s, caddr_t buf, size_t len, \
	unix.SYS_SHUTDOWN:               "shutdown",               // { int shutdown(int s, int how); }
	unix.SYS_SOCKETPAIR:             "socketpair",             // { int socketpair(int domain, int type, \
	unix.SYS_MKDIR:                  "mkdir",                  // { int mkdir(char *path, int mode); }
	unix.SYS_RMDIR:                  "rmdir",                  // { int rmdir(char *path); }
	unix.SYS_UTIMES:                 "utimes",                 // { int utimes(char *path, \
	unix.SYS_ADJTIME:                "adjtime",                // { int adjtime(struct timeval *delta, \
	unix.SYS_SETSID:                 "setsid",                 // { int setsid(void); }
	unix.SYS_QUOTACTL:               "quotactl",               // { int quotactl(char *path, int cmd, int uid, \
	unix.SYS_LGETFH:                 "lgetfh",                 // { int lgetfh(char *fname, \
	unix.SYS_GETFH:                  "getfh",                  // { int getfh(char *fname, \
	unix.SYS_SYSARCH:                "sysarch",                // { int sysarch(int op, char *parms); }
	unix.SYS_RTPRIO:                 "rtprio",                 // { int rtprio(int function, pid_t pid, \
	unix.SYS_FREEBSD6_PREAD:         "freebsd6_pread",         // { ssize_t freebsd6_pread(int fd, void *buf, \
	unix.SYS_FREEBSD6_PWRITE:        "freebsd6_pwrite",        // { ssize_t freebsd6_pwrite(int fd, \
	unix.SYS_SETFIB:                 "setfib",                 // { int setfib(int fibnum); }
	unix.SYS_NTP_ADJTIME:            "ntp_adjtime",            // { int ntp_adjtime(struct timex *tp); }
	unix.SYS_SETGID:                 "setgid",                 // { int setgid(gid_t gid); }
	unix.SYS_SETEGID:                "setegid",                // { int setegid(gid_t egid); }
	unix.SYS_SETEUID:                "seteuid",                // { int seteuid(uid_t euid); }
	unix.SYS_STAT:                   "stat",                   // { int stat(char *path, struct stat *ub); }
	unix.SYS_FSTAT:                  "fstat",                  // { int fstat(int fd, struct stat *sb); }
	unix.SYS_LSTAT:                  "lstat",                  // { int lstat(char *path, struct stat *ub); }
	unix.SYS_PATHCONF:               "pathconf",               // { int pathconf(char *path, int name); }
	unix.SYS_FPATHCONF:              "fpathconf",              // { int fpathconf(int fd, int name); }
	unix.SYS_GETRLIMIT:              "getrlimit",              // { int getrlimit(u_int which, \
	unix.SYS_SETRLIMIT:              "setrlimit",              // { int setrlimit(u_int which, \
	unix.SYS_GETDIRENTRIES:          "getdirentries",          // { int getdirentries(int fd, char *buf, \
	unix.SYS_FREEBSD6_MMAP:          "freebsd6_mmap",          // { caddr_t freebsd6_mmap(caddr_t addr, \
	unix.SYS_FREEBSD6_LSEEK:         "freebsd6_lseek",         // { off_t freebsd6_lseek(int fd, int pad, \
	unix.SYS_FREEBSD6_TRUNCATE:      "freebsd6_truncate",      // { int freebsd6_truncate(char *path, int pad, \
	unix.SYS_FREEBSD6_FTRUNCATE:     "freebsd6_ftruncate",     // { int freebsd6_ftruncate(int fd, int pad, \
	unix.SYS___SYSCTL:               "__sysctl",               // { int __sysctl(int *name, u_int namelen, \
	unix.SYS_MLOCK:                  "mlock",                  // { int mlock(const void *addr, size_t len); }
	unix.SYS_MUNLOCK:                "munlock",                // { int munlock(const void *addr, size_t len); }
	unix.SYS_UNDELETE:               "undelete",               // { int undelete(char *path); }
	unix.SYS_FUTIMES:                "futimes",                // { int futimes(int fd, struct timeval *tptr); }
	unix.SYS_GETPGID:                "getpgid",                // { int getpgid(pid_t pid); }
	unix.SYS_POLL:                   "poll",                   // { int poll(struct pollfd *fds, u_int nfds, \
	unix.SYS_CLOCK_GETTIME:          "clock_gettime",          // { int clock_gettime(clockid_t clock_id, \
	unix.SYS_CLOCK_SETTIME:          "clock_settime",          // { int clock_settime( \
	unix.SYS_CLOCK_GETRES:           "clock_getres",           // { int clock_getres(clockid_t clock_id, \
	unix.SYS_KTIMER_CREATE:          "ktimer_create",          // { int ktimer_create(clockid_t clock_id, \
	unix.SYS_KTIMER_DELETE:          "ktimer_delete",          // { int ktimer_delete(int timerid); }
	unix.SYS_KTIMER_SETTIME:         "ktimer_settime",         // { int ktimer_settime(int timerid, int flags, \
	unix.SYS_KTIMER_GETTIME:         "ktimer_gettime",         // { int ktimer_gettime(int timerid, struct \
	unix.SYS_KTIMER_GETOVERRUN:      "ktimer_getoverrun",      // { int ktimer_getoverrun(int timerid); }
	unix.SYS_NANOSLEEP:              "nanosleep",              // { int nanosleep(const struct timespec *rqtp, \
	unix.SYS_FFCLOCK_GETCOUNTER:     "ffclock_getcounter",     // { int ffclock_getcounter(ffcounter *ffcount); }
	unix.SYS_FFCLOCK_SETESTIMATE:    "ffclock_setestimate",    // { int ffclock_setestimate( \
	unix.SYS_FFCLOCK_GETESTIMATE:    "ffclock_getestimate",    // { int ffclock_getestimate( \
	unix.SYS_CLOCK_GETCPUCLOCKID2:   "clock_getcpuclockid2",   // { int clock_getcpuclockid2(id_t id,\
	unix.SYS_NTP_GETTIME:            "ntp_gettime",            // { int ntp_gettime(struct ntptimeval *ntvp); }
	unix.SYS_MINHERIT:               "minherit",               // { int minherit(void *addr, size_t len, \
	unix.SYS_RFORK:                  "rfork",                  // { int rfork(int flags); }
	unix.SYS_OPENBSD_POLL:           "openbsd_poll",           // { int openbsd_poll(struct pollfd *fds, \
	unix.SYS_ISSETUGID:              "issetugid",              // { int issetugid(void); }
	unix.SYS_LCHOWN:                 "lchown",                 // { int lchown(char *path, int uid, int gid); }
	unix.SYS_GETDENTS:               "getdents",               // { int getdents(int fd, char *buf, \
	unix.SYS_LCHMOD:                 "lchmod",                 // { int lchmod(char *path, mode_t mode); }
	unix.SYS_LUTIMES:                "lutimes",                // { int lutimes(char *path, \
	unix.SYS_NSTAT:                  "nstat",                  // { int nstat(char *path, struct nstat *ub); }
	unix.SYS_NFSTAT:                 "nfstat",                 // { int nfstat(int fd, struct nstat *sb); }
	unix.SYS_NLSTAT:                 "nlstat",                 // { int nlstat(char *path, struct nstat *ub); }
	unix.SYS_PREADV:                 "preadv",                 // { ssize_t preadv(int fd, struct iovec *iovp, \
	unix.SYS_PWRITEV:                "pwritev",                // { ssize_t pwritev(int fd, struct iovec *iovp, \
	unix.SYS_FHOPEN:                 "fhopen",                 // { int fhopen(const struct fhandle *u_fhp, \
	unix.SYS_FHSTAT:                 "fhstat",                 // { int fhstat(const struct fhandle *u_fhp, \
	unix.SYS_MODNEXT:                "modnext",                // { int modnext(int modid); }
	unix.SYS_MODSTAT:                "modstat",                // { int modstat(int modid, \
	unix.SYS_MODFNEXT:               "modfnext",               // { int modfnext(int modid); }
	unix.SYS_MODFIND:                "modfind",                // { int modfind(const char *name); }
	unix.SYS_KLDLOAD:                "kldload",                // { int kldload(const char *file); }
	unix.SYS_KLDUNLOAD:              "kldunload",              // { int kldunload(int fileid); }
	unix.SYS_KLDFIND:                "kldfind",                // { int kldfind(const char *file); }
	unix.SYS_KLDNEXT:                "kldnext",                // { int kldnext(int fileid); }
	unix.SYS_KLDSTAT:                "kldstat",                // { int kldstat(int fileid, struct \
	unix.SYS_KLDFIRSTMOD:            "kldfirstmod",            // { int kldfirstmod(int fileid); }
	unix.SYS_GETSID:                 "getsid",                 // { int getsid(pid_t pid); }
	unix.SYS_SETRESUID:              "setresuid",              // { int setresuid(uid_t ruid, uid_t euid, \
	unix.SYS_SETRESGID:              "setresgid",              // { int setresgid(gid_t rgid, gid_t egid, \
	unix.SYS_YIELD:                  "yield",                  // { int yield(void); }
	unix.SYS_MLOCKALL:               "mlockall",               // { int mlockall(int how); }
	unix.SYS_MUNLOCKALL:             "munlockall",             // { int munlockall(void); }
	unix.SYS___GETCWD:               "__getcwd",               // { int __getcwd(char *buf, u_int buflen); }
	unix.SYS_SCHED_SETPARAM:         "sched_setparam",         // { int sched_setparam (pid_t pid, \
	unix.SYS_SCHED_GETPARAM:         "sched_getparam",         // { int sched_getparam (pid_t pid, struct \
	unix.SYS_SCHED_SETSCHEDULER:     "sched_setscheduler",     // { int sched_setscheduler (pid_t pid, int \
	unix.SYS_SCHED_GETSCHEDULER:     "sched_getscheduler",     // { int sched_getscheduler (pid_t pid); }
	unix.SYS_SCHED_YIELD:            "sched_yield",            // { int sched_yield (void); }
	unix.SYS_SCHED_GET_PRIORITY_MAX: "sched_get_priority_max", // { int sched_get_priority_max (int policy); }
	unix.SYS_SCHED_GET_PRIORITY_MIN: "sched_get_priority_min", // { int sched_get_priority_min (int policy); }
	unix.SYS_SCHED_RR_GET_INTERVAL:  "sched_rr_get_interval",  // { int sched_rr_get_interval (pid_t pid, \
	unix.SYS_UTRACE:                 "utrace",                 // { int utrace(const void *addr, size_t len); }
	unix.SYS_KLDSYM:                 "kldsym",                 // { int kldsym(int fileid, int cmd, \
	unix.SYS_JAIL:                   "jail",                   // { int jail(struct jail *jail); }
	unix.SYS_SIGPROCMASK:            "sigprocmask",            // { int sigprocmask(int how, \
	unix.SYS_SIGSUSPEND:             "sigsuspend",             // { int sigsuspend(const sigset_t *sigmask); }
	unix.SYS_SIGPENDING:             "sigpending",             // { int sigpending(sigset_t *set); }
	unix.SYS_SIGTIMEDWAIT:           "sigtimedwait",           // { int sigtimedwait(const sigset_t *set, \
	unix.SYS_SIGWAITINFO:            "sigwaitinfo",            // { int sigwaitinfo(const sigset_t *set, \
	unix.SYS___ACL_GET_FILE:         "__acl_get_file",         // { int __acl_get_file(const char *path, \
	unix.SYS___ACL_SET_FILE:         "__acl_set_file",         // { int __acl_set_file(const char *path, \
	unix.SYS___ACL_GET_FD:           "__acl_get_fd",           // { int __acl_get_fd(int filedes, \
	unix.SYS___ACL_SET_FD:           "__acl_set_fd",           // { int __acl_set_fd(int filedes, \
	unix.SYS___ACL_DELETE_FILE:      "__acl_delete_file",      // { int __acl_delete_file(const char *path, \
	unix.SYS___ACL_DELETE_FD:        "__acl_delete_fd",        // { int __acl_delete_fd(int filedes, \
	unix.SYS___ACL_ACLCHECK_FILE:    "__acl_aclcheck_file",    // { int __acl_aclcheck_file(const char *path, \
	unix.SYS___ACL_ACLCHECK_FD:      "__acl_aclcheck_fd",      // { int __acl_aclcheck_fd(int filedes, \
	unix.SYS_EXTATTRCTL:             "extattrctl",             // { int extattrctl(const char *path, int cmd, \
	unix.SYS_EXTATTR_SET_FILE:       "extattr_set_file",       // { ssize_t extattr_set_file( \
	unix.SYS_EXTATTR_GET_FILE:       "extattr_get_file",       // { ssize_t extattr_get_file( \
	unix.SYS_EXTATTR_DELETE_FILE:    "extattr_delete_file",    // { int extattr_delete_file(const char *path, \
	unix.SYS_GETRESUID:              "getresuid",              // { int getresuid(uid_t *ruid, uid_t *euid, \
	unix.SYS_GETRESGID:              "getresgid",              // { int getresgid(gid_t *rgid, gid_t *egid, \
	unix.SYS_KQUEUE:                 "kqueue",                 // { int kqueue(void); }
	unix.SYS_KEVENT:                 "kevent",                 // { int kevent(int fd, \
	unix.SYS_EXTATTR_SET_FD:         "extattr_set_fd",         // { ssize_t extattr_set_fd(int fd, \
	unix.SYS_EXTATTR_GET_FD:         "extattr_get_fd",         // { ssize_t extattr_get_fd(int fd, \
	unix.SYS_EXTATTR_DELETE_FD:      "extattr_delete_fd",      // { int extattr_delete_fd(int fd, \
	unix.SYS___SETUGID:              "__setugid",              // { int __setugid(int flag); }
	unix.SYS_EACCESS:                "eaccess",                // { int eaccess(char *path, int amode); }
	unix.SYS_NMOUNT:                 "nmount",                 // { int nmount(struct iovec *iovp, \
	unix.SYS___MAC_GET_PROC:         "__mac_get_proc",         // { int __mac_get_proc(struct mac *mac_p); }
	unix.SYS___MAC_SET_PROC:         "__mac_set_proc",         // { int __mac_set_proc(struct mac *mac_p); }
	unix.SYS___MAC_GET_FD:           "__mac_get_fd",           // { int __mac_get_fd(int fd, \
	unix.SYS___MAC_GET_FILE:         "__mac_get_file",         // { int __mac_get_file(const char *path_p, \
	unix.SYS___MAC_SET_FD:           "__mac_set_fd",           // { int __mac_set_fd(int fd, \
	unix.SYS___MAC_SET_FILE:         "__mac_set_file",         // { int __mac_set_file(const char *path_p, \
	unix.SYS_KENV:                   "kenv",                   // { int kenv(int what, const char *name, \
	unix.SYS_LCHFLAGS:               "lchflags",               // { int lchflags(const char *path, \
	unix.SYS_UUIDGEN:                "uuidgen",                // { int uuidgen(struct uuid *store, \
	unix.SYS_SENDFILE:               "sendfile",               // { int sendfile(int fd, int s, off_t offset, \
	unix.SYS_MAC_SYSCALL:            "mac_syscall",            // { int mac_syscall(const char *policy, \
	unix.SYS_GETFSSTAT:              "getfsstat",              // { int getfsstat(struct statfs *buf, \
	unix.SYS_STATFS:                 "statfs",                 // { int statfs(char *path, \
	unix.SYS_FSTATFS:                "fstatfs",                // { int fstatfs(int fd, struct statfs *buf); }
	unix.SYS_FHSTATFS:               "fhstatfs",               // { int fhstatfs(const struct fhandle *u_fhp, \
	unix.SYS___MAC_GET_PID:          "__mac_get_pid",          // { int __mac_get_pid(pid_t pid, \
	unix.SYS___MAC_GET_LINK:         "__mac_get_link",         // { int __mac_get_link(const char *path_p, \
	unix.SYS___MAC_SET_LINK:         "__mac_set_link",         // { int __mac_set_link(const char *path_p, \
	unix.SYS_EXTATTR_SET_LINK:       "extattr_set_link",       // { ssize_t extattr_set_link( \
	unix.SYS_EXTATTR_GET_LINK:       "extattr_get_link",       // { ssize_t extattr_get_link( \
	unix.SYS_EXTATTR_DELETE_LINK:    "extattr_delete_link",    // { int extattr_delete_link( \
	unix.SYS___MAC_EXECVE:           "__mac_execve",           // { int __mac_execve(char *fname, char **argv, \
	unix.SYS_SIGACTION:              "sigaction",              // { int sigaction(int sig, \
	unix.SYS_SIGRETURN:              "sigreturn",              // { int sigreturn( \
	unix.SYS_GETCONTEXT:             "getcontext",             // { int getcontext(struct __ucontext *ucp); }
	unix.SYS_SETCONTEXT:             "setcontext",             // { int setcontext( \
	unix.SYS_SWAPCONTEXT:            "swapcontext",            // { int swapcontext(struct __ucontext *oucp, \
	unix.SYS_SWAPOFF:                "swapoff",                // { int swapoff(const char *name); }
	unix.SYS___ACL_GET_LINK:         "__acl_get_link",         // { int __acl_get_link(const char *path, \
	unix.SYS___ACL_SET_LINK:         "__acl_set_link",         // { int __acl_set_link(const char *path, \
	unix.SYS___ACL_DELETE_LINK:      "__acl_delete_link",      // { int __acl_delete_link(const char *path, \
	unix.SYS___ACL_ACLCHECK_LINK:    "__acl_aclcheck_link",    // { int __acl_aclcheck_link(const char *path, \
	unix.SYS_SIGWAIT:                "sigwait",                // { int sigwait(const sigset_t *set, \
	unix.SYS_THR_CREATE:             "thr_create",             // { int thr_create(ucontext_t *ctx, long *id, \
	unix.SYS_THR_EXIT:               "thr_exit",               // { void thr_exit(long *state); }
	unix.SYS_THR_SELF:               "thr_self",               // { int thr_self(long *id); }
	unix.SYS_THR_KILL:               "thr_kill",               // { int thr_kill(long id, int sig); }
	unix.SYS__UMTX_LOCK:             "_umtx_lock",             // { int _umtx_lock(struct umtx *umtx); }
	unix.SYS__UMTX_UNLOCK:           "_umtx_unlock",           // { int _umtx_unlock(struct umtx *umtx); }
	unix.SYS_JAIL_ATTACH:            "jail_attach",            // { int jail_attach(int jid); }
	unix.SYS_EXTATTR_LIST_FD:        "extattr_list_fd",        // { ssize_t extattr_list_fd(int fd, \
	unix.SYS_EXTATTR_LIST_FILE:      "extattr_list_file",      // { ssize_t extattr_list_file( \
	unix.SYS_EXTATTR_LIST_LINK:      "extattr_list_link",      // { ssize_t extattr_list_link( \
	unix.SYS_THR_SUSPEND:            "thr_suspend",            // { int thr_suspend( \
	unix.SYS_THR_WAKE:               "thr_wake",               // { int thr_wake(long id); }
	unix.SYS_KLDUNLOADF:             "kldunloadf",             // { int kldunloadf(int fileid, int flags); }
	unix.SYS_AUDIT:                  "audit",                  // { int audit(const void *record, \
	unix.SYS_AUDITON:                "auditon",                // { int auditon(int cmd, void *data, \
	unix.SYS_GETAUID:                "getauid",                // { int getauid(uid_t *auid); }
	unix.SYS_SETAUID:                "setauid",                // { int setauid(uid_t *auid); }
	unix.SYS_GETAUDIT:               "getaudit",               // { int getaudit(struct auditinfo *auditinfo); }
	unix.SYS_SETAUDIT:               "setaudit",               // { int setaudit(struct auditinfo *auditinfo); }
	unix.SYS_GETAUDIT_ADDR:          "getaudit_addr",          // { int getaudit_addr( \
	unix.SYS_SETAUDIT_ADDR:          "setaudit_addr",          // { int setaudit_addr( \
	unix.SYS_AUDITCTL:               "auditctl",               // { int auditctl(char *path); }
	unix.SYS__UMTX_OP:               "_umtx_op",               // { int _umtx_op(void *obj, int op, \
	unix.SYS_THR_NEW:                "thr_new",                // { int thr_new(struct thr_param *param, \
	unix.SYS_SIGQUEUE:               "sigqueue",               // { int sigqueue(pid_t pid, int signum, void *value); }
	unix.SYS_ABORT2:                 "abort2",                 // { int abort2(const char *why, int nargs, void **args); }
	unix.SYS_THR_SET_NAME:           "thr_set_name",           // { int thr_set_name(long id, const char *name); }
	unix.SYS_RTPRIO_THREAD:          "rtprio_thread",          // { int rtprio_thread(int function, \
	unix.SYS_PREAD:                  "pread",                  // { ssize_t pread(int fd, void *buf, \
	unix.SYS_PWRITE:                 "pwrite",                 // { ssize_t pwrite(int fd, const void *buf, \
	unix.SYS_MMAP:                   "mmap",                   // { caddr_t mmap(caddr_t addr, size_t len, \
	unix.SYS_LSEEK:                  "lseek",                  // { off_t lseek(int fd, off_t offset, \
	unix.SYS_TRUNCATE:               "truncate",               // { int truncate(char *path, off_t length); }
	unix.SYS_FTRUNCATE:              "ftruncate",              // { int ftruncate(int fd, off_t length); }
	unix.SYS_THR_KILL2:              "thr_kill2",              // { int thr_kill2(pid_t pid, long id, int sig); }
	unix.SYS_SHM_OPEN:               "shm_open",               // { int shm_open(const char *path, int flags, \
	unix.SYS_SHM_UNLINK:             "shm_unlink",             // { int shm_unlink(const char *path); }
	unix.SYS_CPUSET:                 "cpuset",                 // { int cpuset(cpusetid_t *setid); }
	unix.SYS_CPUSET_SETID:           "cpuset_setid",           // { int cpuset_setid(cpuwhich_t which, id_t id, \
	unix.SYS_CPUSET_GETID:           "cpuset_getid",           // { int cpuset_getid(cpulevel_t level, \
	unix.SYS_CPUSET_GETAFFINITY:     "cpuset_getaffinity",     // { int cpuset_getaffinity(cpulevel_t level, \
	unix.SYS_CPUSET_SETAFFINITY:     "cpuset_setaffinity",     // { int cpuset_setaffinity(cpulevel_t level, \
	unix.SYS_FACCESSAT:              "faccessat",              // { int faccessat(int fd, char *path, int amode, \
	unix.SYS_FCHMODAT:               "fchmodat",               // { int fchmodat(int fd, char *path, mode_t mode, \
	unix.SYS_FCHOWNAT:               "fchownat",               // { int fchownat(int fd, char *path, uid_t uid, \
	unix.SYS_FEXECVE:                "fexecve",                // { int fexecve(int fd, char **argv, \
	unix.SYS_FSTATAT:                "fstatat",                // { int fstatat(int fd, char *path, \
	unix.SYS_FUTIMESAT:              "futimesat",              // { int futimesat(int fd, char *path, \
	unix.SYS_LINKAT:                 "linkat",                 // { int linkat(int fd1, char *path1, int fd2, \
	unix.SYS_MKDIRAT:                "mkdirat",                // { int mkdirat(int fd, char *path, mode_t mode); }
	unix.SYS_MKFIFOAT:               "mkfifoat",               // { int mkfifoat(int fd, char *path, mode_t mode); }
	unix.SYS_MKNODAT:                "mknodat",                // { int mknodat(int fd, char *path, mode_t mode, \
	unix.SYS_OPENAT:                 "openat",                 // { int openat(int fd, char *path, int flag, \
	unix.SYS_READLINKAT:             "readlinkat",             // { int readlinkat(int fd, char *path, char *buf, \
	unix.SYS_RENAMEAT:               "renameat",               // { int renameat(int oldfd, char *old, int newfd, \
	unix.SYS_SYMLINKAT:              "symlinkat",              // { int symlinkat(char *path1, int fd, \
	unix.SYS_UNLINKAT:               "unlinkat",               // { int unlinkat(int fd, char *path, int flag); }
	unix.SYS_POSIX_OPENPT:           "posix_openpt",           // { int posix_openpt(int flags); }
	unix.SYS_JAIL_GET:               "jail_get",               // { int jail_get(struct iovec *iovp, \
	unix.SYS_JAIL_SET:               "jail_set",               // { int jail_set(struct iovec *iovp, \
	unix.SYS_JAIL_REMOVE:            "jail_remove",            // { int jail_remove(int jid); }
	unix.SYS_CLOSEFROM:              "closefrom",              // { int closefrom(int lowfd); }
	unix.SYS_LPATHCONF:              "lpathconf",              // { int lpathconf(char *path, int name); }
	unix.SYS___CAP_RIGHTS_GET:       "__cap_rights_get",       // { int __cap_rights_get(int version, \
	unix.SYS_CAP_ENTER:              "cap_enter",              // { int cap_enter(void); }
	unix.SYS_CAP_GETMODE:            "cap_getmode",            // { int cap_getmode(u_int *modep); }
	unix.SYS_PDFORK:                 "pdfork",                 // { int pdfork(int *fdp, int flags); }
	unix.SYS_PDKILL:                 "pdkill",                 // { int pdkill(int fd, int signum); }
	unix.SYS_PDGETPID:               "pdgetpid",               // { int pdgetpid(int fd, pid_t *pidp); }
	unix.SYS_PSELECT:                "pselect",                // { int pselect(int nd, fd_set *in, \
	unix.SYS_GETLOGINCLASS:          "getloginclass",          // { int getloginclass(char *namebuf, \
	unix.SYS_SETLOGINCLASS:          "setloginclass",          // { int setloginclass(const char *namebuf); }
	unix.SYS_RCTL_GET_RACCT:         "rctl_get_racct",         // { int rctl_get_racct(const void *inbufp, \
	unix.SYS_RCTL_GET_RULES:         "rctl_get_rules",         // { int rctl_get_rules(const void *inbufp, \
	unix.SYS_RCTL_GET_LIMITS:        "rctl_get_limits",        // { int rctl_get_limits(const void *inbufp, \
	unix.SYS_RCTL_ADD_RULE:          "rctl_add_rule",          // { int rctl_add_rule(const void *inbufp, \
	unix.SYS_RCTL_REMOVE_RULE:       "rctl_remove_rule",       // { int rctl_remove_rule(const void *inbufp, \
	unix.SYS_POSIX_FALLOCATE:        "posix_fallocate",        // { int posix_fallocate(int fd, \
	unix.SYS_POSIX_FADVISE:          "posix_fadvise",          // { int posix_fadvise(int fd, off_t offset, \
	unix.SYS_WAIT6:                  "wait6",                  // { int wait6(idtype_t idtype, id_t id, \
	unix.SYS_CAP_RIGHTS_LIMIT:       "cap_rights_limit",       // { int cap_rights_limit(int fd, \
	unix.SYS_CAP_IOCTLS_LIMIT:       "cap_ioctls_limit",       // { int cap_ioctls_limit(int fd, \
	unix.SYS_CAP_IOCTLS_GET:         "cap_ioctls_get",         // { ssize_t cap_ioctls_get(int fd, \
	unix.SYS_CAP_FCNTLS_LIMIT:       "cap_fcntls_limit",       // { int cap_fcntls_limit(int fd, \
	unix.SYS_CAP_FCNTLS_GET:         "cap_fcntls_get",         // { int cap_fcntls_get(int fd, \
	unix.SYS_BINDAT:                 "bindat",                 // { int bindat(int fd, int s, caddr_t name, \
	unix.SYS_CONNECTAT:              "connectat",              // { int connectat(int fd, int s, caddr_t name, \
	unix.SYS_CHFLAGSAT:              "chflagsat",              // { int chflagsat(int fd, const char *path, \
	unix.SYS_ACCEPT4:                "accept4",                // { int accept4(int s, \
	unix.SYS_PIPE2:                  "pipe2",                  // { int pipe2(int *fildes, int flags); }
	unix.SYS_PROCCTL:                "procctl",                // { int procctl(idtype_t idtype, id_t id, \
	unix.SYS_PPOLL:                  "ppoll",                  // { int ppoll(struct pollfd *fds, u_int nfds, \
	unix.SYS_FUTIMENS:               "futimens",               // { int futimens(int fd, \
	unix.SYS_UTIMENSAT:              "utimensat",              // { int utimensat(int fd, \
}
