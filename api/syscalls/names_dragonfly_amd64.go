package syscalls

import "golang.org/x/sys/unix"

var _ = unix.Exit

var Name = map[uint64]string{
	unix.SYS_EXIT:                   "exit",                   // { void exit(int rval); }
	unix.SYS_FORK:                   "fork",                   // { int fork(void); }
	unix.SYS_READ:                   "read",                   // { ssize_t read(int fd, void *buf, size_t nbyte); }
	unix.SYS_WRITE:                  "write",                  // { ssize_t write(int fd, const void *buf, size_t nbyte); }
	unix.SYS_OPEN:                   "open",                   // { int open(char *path, int flags, int mode); }
	unix.SYS_CLOSE:                  "close",                  // { int close(int fd); }
	unix.SYS_WAIT4:                  "wait4",                  // { int wait4(int pid, int *status, int options, \
	unix.SYS_LINK:                   "link",                   // { int link(char *path, char *link); }
	unix.SYS_UNLINK:                 "unlink",                 // { int unlink(char *path); }
	unix.SYS_CHDIR:                  "chdir",                  // { int chdir(char *path); }
	unix.SYS_FCHDIR:                 "fchdir",                 // { int fchdir(int fd); }
	unix.SYS_MKNOD:                  "mknod",                  // { int mknod(char *path, int mode, int dev); }
	unix.SYS_CHMOD:                  "chmod",                  // { int chmod(char *path, int mode); }
	unix.SYS_CHOWN:                  "chown",                  // { int chown(char *path, int uid, int gid); }
	unix.SYS_OBREAK:                 "obreak",                 // { int obreak(char *nsize); } break obreak_args int
	unix.SYS_GETFSSTAT:              "getfsstat",              // { int getfsstat(struct statfs *buf, long bufsize, \
	unix.SYS_GETPID:                 "getpid",                 // { pid_t getpid(void); }
	unix.SYS_MOUNT:                  "mount",                  // { int mount(char *type, char *path, int flags, \
	unix.SYS_UNMOUNT:                "unmount",                // { int unmount(char *path, int flags); }
	unix.SYS_SETUID:                 "setuid",                 // { int setuid(uid_t uid); }
	unix.SYS_GETUID:                 "getuid",                 // { uid_t getuid(void); }
	unix.SYS_GETEUID:                "geteuid",                // { uid_t geteuid(void); }
	unix.SYS_PTRACE:                 "ptrace",                 // { int ptrace(int req, pid_t pid, caddr_t addr, \
	unix.SYS_RECVMSG:                "recvmsg",                // { int recvmsg(int s, struct msghdr *msg, int flags); }
	unix.SYS_SENDMSG:                "sendmsg",                // { int sendmsg(int s, caddr_t msg, int flags); }
	unix.SYS_RECVFROM:               "recvfrom",               // { int recvfrom(int s, caddr_t buf, size_t len, \
	unix.SYS_ACCEPT:                 "accept",                 // { int accept(int s, caddr_t name, int *anamelen); }
	unix.SYS_GETPEERNAME:            "getpeername",            // { int getpeername(int fdes, caddr_t asa, int *alen); }
	unix.SYS_GETSOCKNAME:            "getsockname",            // { int getsockname(int fdes, caddr_t asa, int *alen); }
	unix.SYS_ACCESS:                 "access",                 // { int access(char *path, int flags); }
	unix.SYS_CHFLAGS:                "chflags",                // { int chflags(char *path, int flags); }
	unix.SYS_FCHFLAGS:               "fchflags",               // { int fchflags(int fd, int flags); }
	unix.SYS_SYNC:                   "sync",                   // { int sync(void); }
	unix.SYS_KILL:                   "kill",                   // { int kill(int pid, int signum); }
	unix.SYS_GETPPID:                "getppid",                // { pid_t getppid(void); }
	unix.SYS_DUP:                    "dup",                    // { int dup(int fd); }
	unix.SYS_PIPE:                   "pipe",                   // { int pipe(void); }
	unix.SYS_GETEGID:                "getegid",                // { gid_t getegid(void); }
	unix.SYS_PROFIL:                 "profil",                 // { int profil(caddr_t samples, size_t size, \
	unix.SYS_KTRACE:                 "ktrace",                 // { int ktrace(const char *fname, int ops, int facs, \
	unix.SYS_GETGID:                 "getgid",                 // { gid_t getgid(void); }
	unix.SYS_GETLOGIN:               "getlogin",               // { int getlogin(char *namebuf, u_int namelen); }
	unix.SYS_SETLOGIN:               "setlogin",               // { int setlogin(char *namebuf); }
	unix.SYS_ACCT:                   "acct",                   // { int acct(char *path); }
	unix.SYS_SIGALTSTACK:            "sigaltstack",            // { int sigaltstack(stack_t *ss, stack_t *oss); }
	unix.SYS_IOCTL:                  "ioctl",                  // { int ioctl(int fd, u_long com, caddr_t data); }
	unix.SYS_REBOOT:                 "reboot",                 // { int reboot(int opt); }
	unix.SYS_REVOKE:                 "revoke",                 // { int revoke(char *path); }
	unix.SYS_SYMLINK:                "symlink",                // { int symlink(char *path, char *link); }
	unix.SYS_READLINK:               "readlink",               // { int readlink(char *path, char *buf, int count); }
	unix.SYS_EXECVE:                 "execve",                 // { int execve(char *fname, char **argv, char **envv); }
	unix.SYS_UMASK:                  "umask",                  // { int umask(int newmask); } umask umask_args int
	unix.SYS_CHROOT:                 "chroot",                 // { int chroot(char *path); }
	unix.SYS_MSYNC:                  "msync",                  // { int msync(void *addr, size_t len, int flags); }
	unix.SYS_VFORK:                  "vfork",                  // { pid_t vfork(void); }
	unix.SYS_SBRK:                   "sbrk",                   // { int sbrk(int incr); }
	unix.SYS_SSTK:                   "sstk",                   // { int sstk(int incr); }
	unix.SYS_MUNMAP:                 "munmap",                 // { int munmap(void *addr, size_t len); }
	unix.SYS_MPROTECT:               "mprotect",               // { int mprotect(void *addr, size_t len, int prot); }
	unix.SYS_MADVISE:                "madvise",                // { int madvise(void *addr, size_t len, int behav); }
	unix.SYS_MINCORE:                "mincore",                // { int mincore(const void *addr, size_t len, \
	unix.SYS_GETGROUPS:              "getgroups",              // { int getgroups(u_int gidsetsize, gid_t *gidset); }
	unix.SYS_SETGROUPS:              "setgroups",              // { int setgroups(u_int gidsetsize, gid_t *gidset); }
	unix.SYS_GETPGRP:                "getpgrp",                // { int getpgrp(void); }
	unix.SYS_SETPGID:                "setpgid",                // { int setpgid(int pid, int pgid); }
	unix.SYS_SETITIMER:              "setitimer",              // { int setitimer(u_int which, struct itimerval *itv, \
	unix.SYS_SWAPON:                 "swapon",                 // { int swapon(char *name); }
	unix.SYS_GETITIMER:              "getitimer",              // { int getitimer(u_int which, struct itimerval *itv); }
	unix.SYS_GETDTABLESIZE:          "getdtablesize",          // { int getdtablesize(void); }
	unix.SYS_DUP2:                   "dup2",                   // { int dup2(int from, int to); }
	unix.SYS_FCNTL:                  "fcntl",                  // { int fcntl(int fd, int cmd, long arg); }
	unix.SYS_SELECT:                 "select",                 // { int select(int nd, fd_set *in, fd_set *ou, \
	unix.SYS_FSYNC:                  "fsync",                  // { int fsync(int fd); }
	unix.SYS_SETPRIORITY:            "setpriority",            // { int setpriority(int which, int who, int prio); }
	unix.SYS_SOCKET:                 "socket",                 // { int socket(int domain, int type, int protocol); }
	unix.SYS_CONNECT:                "connect",                // { int connect(int s, caddr_t name, int namelen); }
	unix.SYS_GETPRIORITY:            "getpriority",            // { int getpriority(int which, int who); }
	unix.SYS_BIND:                   "bind",                   // { int bind(int s, caddr_t name, int namelen); }
	unix.SYS_SETSOCKOPT:             "setsockopt",             // { int setsockopt(int s, int level, int name, \
	unix.SYS_LISTEN:                 "listen",                 // { int listen(int s, int backlog); }
	unix.SYS_GETTIMEOFDAY:           "gettimeofday",           // { int gettimeofday(struct timeval *tp, \
	unix.SYS_GETRUSAGE:              "getrusage",              // { int getrusage(int who, struct rusage *rusage); }
	unix.SYS_GETSOCKOPT:             "getsockopt",             // { int getsockopt(int s, int level, int name, \
	unix.SYS_READV:                  "readv",                  // { int readv(int fd, struct iovec *iovp, u_int iovcnt); }
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
	unix.SYS_SOCKETPAIR:             "socketpair",             // { int socketpair(int domain, int type, int protocol, \
	unix.SYS_MKDIR:                  "mkdir",                  // { int mkdir(char *path, int mode); }
	unix.SYS_RMDIR:                  "rmdir",                  // { int rmdir(char *path); }
	unix.SYS_UTIMES:                 "utimes",                 // { int utimes(char *path, struct timeval *tptr); }
	unix.SYS_ADJTIME:                "adjtime",                // { int adjtime(struct timeval *delta, \
	unix.SYS_SETSID:                 "setsid",                 // { int setsid(void); }
	unix.SYS_QUOTACTL:               "quotactl",               // { int quotactl(char *path, int cmd, int uid, \
	unix.SYS_STATFS:                 "statfs",                 // { int statfs(char *path, struct statfs *buf); }
	unix.SYS_FSTATFS:                "fstatfs",                // { int fstatfs(int fd, struct statfs *buf); }
	unix.SYS_GETFH:                  "getfh",                  // { int getfh(char *fname, struct fhandle *fhp); }
	unix.SYS_GETDOMAINNAME:          "getdomainname",          // { int getdomainname(char *domainname, int len); }
	unix.SYS_SETDOMAINNAME:          "setdomainname",          // { int setdomainname(char *domainname, int len); }
	unix.SYS_UNAME:                  "uname",                  // { int uname(struct utsname *name); }
	unix.SYS_SYSARCH:                "sysarch",                // { int sysarch(int op, char *parms); }
	unix.SYS_RTPRIO:                 "rtprio",                 // { int rtprio(int function, pid_t pid, \
	unix.SYS_EXTPREAD:               "extpread",               // { ssize_t extpread(int fd, void *buf, \
	unix.SYS_EXTPWRITE:              "extpwrite",              // { ssize_t extpwrite(int fd, const void *buf, \
	unix.SYS_NTP_ADJTIME:            "ntp_adjtime",            // { int ntp_adjtime(struct timex *tp); }
	unix.SYS_SETGID:                 "setgid",                 // { int setgid(gid_t gid); }
	unix.SYS_SETEGID:                "setegid",                // { int setegid(gid_t egid); }
	unix.SYS_SETEUID:                "seteuid",                // { int seteuid(uid_t euid); }
	unix.SYS_PATHCONF:               "pathconf",               // { int pathconf(char *path, int name); }
	unix.SYS_FPATHCONF:              "fpathconf",              // { int fpathconf(int fd, int name); }
	unix.SYS_GETRLIMIT:              "getrlimit",              // { int getrlimit(u_int which, \
	unix.SYS_SETRLIMIT:              "setrlimit",              // { int setrlimit(u_int which, \
	unix.SYS_MMAP:                   "mmap",                   // { caddr_t mmap(caddr_t addr, size_t len, int prot, \
	unix.SYS_LSEEK:                  "lseek",                  // { off_t lseek(int fd, int pad, off_t offset, \
	unix.SYS_TRUNCATE:               "truncate",               // { int truncate(char *path, int pad, off_t length); }
	unix.SYS_FTRUNCATE:              "ftruncate",              // { int ftruncate(int fd, int pad, off_t length); }
	unix.SYS___SYSCTL:               "__sysctl",               // { int __sysctl(int *name, u_int namelen, void *old, \
	unix.SYS_MLOCK:                  "mlock",                  // { int mlock(const void *addr, size_t len); }
	unix.SYS_MUNLOCK:                "munlock",                // { int munlock(const void *addr, size_t len); }
	unix.SYS_UNDELETE:               "undelete",               // { int undelete(char *path); }
	unix.SYS_FUTIMES:                "futimes",                // { int futimes(int fd, struct timeval *tptr); }
	unix.SYS_GETPGID:                "getpgid",                // { int getpgid(pid_t pid); }
	unix.SYS_POLL:                   "poll",                   // { int poll(struct pollfd *fds, u_int nfds, \
	unix.SYS___SEMCTL:               "__semctl",               // { int __semctl(int semid, int semnum, int cmd, \
	unix.SYS_SEMGET:                 "semget",                 // { int semget(key_t key, int nsems, int semflg); }
	unix.SYS_SEMOP:                  "semop",                  // { int semop(int semid, struct sembuf *sops, \
	unix.SYS_MSGCTL:                 "msgctl",                 // { int msgctl(int msqid, int cmd, \
	unix.SYS_MSGGET:                 "msgget",                 // { int msgget(key_t key, int msgflg); }
	unix.SYS_MSGSND:                 "msgsnd",                 // { int msgsnd(int msqid, const void *msgp, size_t msgsz, \
	unix.SYS_MSGRCV:                 "msgrcv",                 // { int msgrcv(int msqid, void *msgp, size_t msgsz, \
	unix.SYS_SHMAT:                  "shmat",                  // { caddr_t shmat(int shmid, const void *shmaddr, \
	unix.SYS_SHMCTL:                 "shmctl",                 // { int shmctl(int shmid, int cmd, \
	unix.SYS_SHMDT:                  "shmdt",                  // { int shmdt(const void *shmaddr); }
	unix.SYS_SHMGET:                 "shmget",                 // { int shmget(key_t key, size_t size, int shmflg); }
	unix.SYS_CLOCK_GETTIME:          "clock_gettime",          // { int clock_gettime(clockid_t clock_id, \
	unix.SYS_CLOCK_SETTIME:          "clock_settime",          // { int clock_settime(clockid_t clock_id, \
	unix.SYS_CLOCK_GETRES:           "clock_getres",           // { int clock_getres(clockid_t clock_id, \
	unix.SYS_NANOSLEEP:              "nanosleep",              // { int nanosleep(const struct timespec *rqtp, \
	unix.SYS_MINHERIT:               "minherit",               // { int minherit(void *addr, size_t len, int inherit); }
	unix.SYS_RFORK:                  "rfork",                  // { int rfork(int flags); }
	unix.SYS_OPENBSD_POLL:           "openbsd_poll",           // { int openbsd_poll(struct pollfd *fds, u_int nfds, \
	unix.SYS_ISSETUGID:              "issetugid",              // { int issetugid(void); }
	unix.SYS_LCHOWN:                 "lchown",                 // { int lchown(char *path, int uid, int gid); }
	unix.SYS_LCHMOD:                 "lchmod",                 // { int lchmod(char *path, mode_t mode); }
	unix.SYS_LUTIMES:                "lutimes",                // { int lutimes(char *path, struct timeval *tptr); }
	unix.SYS_EXTPREADV:              "extpreadv",              // { ssize_t extpreadv(int fd, struct iovec *iovp, \
	unix.SYS_EXTPWRITEV:             "extpwritev",             // { ssize_t extpwritev(int fd, struct iovec *iovp,\
	unix.SYS_FHSTATFS:               "fhstatfs",               // { int fhstatfs(const struct fhandle *u_fhp, struct statfs *buf); }
	unix.SYS_FHOPEN:                 "fhopen",                 // { int fhopen(const struct fhandle *u_fhp, int flags); }
	unix.SYS_MODNEXT:                "modnext",                // { int modnext(int modid); }
	unix.SYS_MODSTAT:                "modstat",                // { int modstat(int modid, struct module_stat* stat); }
	unix.SYS_MODFNEXT:               "modfnext",               // { int modfnext(int modid); }
	unix.SYS_MODFIND:                "modfind",                // { int modfind(const char *name); }
	unix.SYS_KLDLOAD:                "kldload",                // { int kldload(const char *file); }
	unix.SYS_KLDUNLOAD:              "kldunload",              // { int kldunload(int fileid); }
	unix.SYS_KLDFIND:                "kldfind",                // { int kldfind(const char *file); }
	unix.SYS_KLDNEXT:                "kldnext",                // { int kldnext(int fileid); }
	unix.SYS_KLDSTAT:                "kldstat",                // { int kldstat(int fileid, struct kld_file_stat* stat); }
	unix.SYS_KLDFIRSTMOD:            "kldfirstmod",            // { int kldfirstmod(int fileid); }
	unix.SYS_GETSID:                 "getsid",                 // { int getsid(pid_t pid); }
	unix.SYS_SETRESUID:              "setresuid",              // { int setresuid(uid_t ruid, uid_t euid, uid_t suid); }
	unix.SYS_SETRESGID:              "setresgid",              // { int setresgid(gid_t rgid, gid_t egid, gid_t sgid); }
	unix.SYS_AIO_RETURN:             "aio_return",             // { int aio_return(struct aiocb *aiocbp); }
	unix.SYS_AIO_SUSPEND:            "aio_suspend",            // { int aio_suspend(struct aiocb * const * aiocbp, int nent, const struct timespec *timeout); }
	unix.SYS_AIO_CANCEL:             "aio_cancel",             // { int aio_cancel(int fd, struct aiocb *aiocbp); }
	unix.SYS_AIO_ERROR:              "aio_error",              // { int aio_error(struct aiocb *aiocbp); }
	unix.SYS_AIO_READ:               "aio_read",               // { int aio_read(struct aiocb *aiocbp); }
	unix.SYS_AIO_WRITE:              "aio_write",              // { int aio_write(struct aiocb *aiocbp); }
	unix.SYS_LIO_LISTIO:             "lio_listio",             // { int lio_listio(int mode, struct aiocb * const *acb_list, int nent, struct sigevent *sig); }
	unix.SYS_YIELD:                  "yield",                  // { int yield(void); }
	unix.SYS_MLOCKALL:               "mlockall",               // { int mlockall(int how); }
	unix.SYS_MUNLOCKALL:             "munlockall",             // { int munlockall(void); }
	unix.SYS___GETCWD:               "__getcwd",               // { int __getcwd(u_char *buf, u_int buflen); }
	unix.SYS_SCHED_SETPARAM:         "sched_setparam",         // { int sched_setparam (pid_t pid, const struct sched_param *param); }
	unix.SYS_SCHED_GETPARAM:         "sched_getparam",         // { int sched_getparam (pid_t pid, struct sched_param *param); }
	unix.SYS_SCHED_SETSCHEDULER:     "sched_setscheduler",     // { int sched_setscheduler (pid_t pid, int policy, const struct sched_param *param); }
	unix.SYS_SCHED_GETSCHEDULER:     "sched_getscheduler",     // { int sched_getscheduler (pid_t pid); }
	unix.SYS_SCHED_YIELD:            "sched_yield",            // { int sched_yield (void); }
	unix.SYS_SCHED_GET_PRIORITY_MAX: "sched_get_priority_max", // { int sched_get_priority_max (int policy); }
	unix.SYS_SCHED_GET_PRIORITY_MIN: "sched_get_priority_min", // { int sched_get_priority_min (int policy); }
	unix.SYS_SCHED_RR_GET_INTERVAL:  "sched_rr_get_interval",  // { int sched_rr_get_interval (pid_t pid, struct timespec *interval); }
	unix.SYS_UTRACE:                 "utrace",                 // { int utrace(const void *addr, size_t len); }
	unix.SYS_KLDSYM:                 "kldsym",                 // { int kldsym(int fileid, int cmd, void *data); }
	unix.SYS_JAIL:                   "jail",                   // { int jail(struct jail *jail); }
	unix.SYS_SIGPROCMASK:            "sigprocmask",            // { int sigprocmask(int how, const sigset_t *set, \
	unix.SYS_SIGSUSPEND:             "sigsuspend",             // { int sigsuspend(const sigset_t *sigmask); }
	unix.SYS_SIGACTION:              "sigaction",              // { int sigaction(int sig, const struct sigaction *act, \
	unix.SYS_SIGPENDING:             "sigpending",             // { int sigpending(sigset_t *set); }
	unix.SYS_SIGRETURN:              "sigreturn",              // { int sigreturn(ucontext_t *sigcntxp); }
	unix.SYS_SIGTIMEDWAIT:           "sigtimedwait",           // { int sigtimedwait(const sigset_t *set,\
	unix.SYS_SIGWAITINFO:            "sigwaitinfo",            // { int sigwaitinfo(const sigset_t *set,\
	unix.SYS___ACL_GET_FILE:         "__acl_get_file",         // { int __acl_get_file(const char *path, \
	unix.SYS___ACL_SET_FILE:         "__acl_set_file",         // { int __acl_set_file(const char *path, \
	unix.SYS___ACL_GET_FD:           "__acl_get_fd",           // { int __acl_get_fd(int filedes, acl_type_t type, \
	unix.SYS___ACL_SET_FD:           "__acl_set_fd",           // { int __acl_set_fd(int filedes, acl_type_t type, \
	unix.SYS___ACL_DELETE_FILE:      "__acl_delete_file",      // { int __acl_delete_file(const char *path, \
	unix.SYS___ACL_DELETE_FD:        "__acl_delete_fd",        // { int __acl_delete_fd(int filedes, acl_type_t type); }
	unix.SYS___ACL_ACLCHECK_FILE:    "__acl_aclcheck_file",    // { int __acl_aclcheck_file(const char *path, \
	unix.SYS___ACL_ACLCHECK_FD:      "__acl_aclcheck_fd",      // { int __acl_aclcheck_fd(int filedes, acl_type_t type, \
	unix.SYS_EXTATTRCTL:             "extattrctl",             // { int extattrctl(const char *path, int cmd, \
	unix.SYS_EXTATTR_SET_FILE:       "extattr_set_file",       // { int extattr_set_file(const char *path, \
	unix.SYS_EXTATTR_GET_FILE:       "extattr_get_file",       // { int extattr_get_file(const char *path, \
	unix.SYS_EXTATTR_DELETE_FILE:    "extattr_delete_file",    // { int extattr_delete_file(const char *path, \
	unix.SYS_AIO_WAITCOMPLETE:       "aio_waitcomplete",       // { int aio_waitcomplete(struct aiocb **aiocbp, struct timespec *timeout); }
	unix.SYS_GETRESUID:              "getresuid",              // { int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); }
	unix.SYS_GETRESGID:              "getresgid",              // { int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); }
	unix.SYS_KQUEUE:                 "kqueue",                 // { int kqueue(void); }
	unix.SYS_KEVENT:                 "kevent",                 // { int kevent(int fd, \
	unix.SYS_KENV:                   "kenv",                   // { int kenv(int what, const char *name, char *value, int len); }
	unix.SYS_LCHFLAGS:               "lchflags",               // { int lchflags(char *path, int flags); }
	unix.SYS_UUIDGEN:                "uuidgen",                // { int uuidgen(struct uuid *store, int count); }
	unix.SYS_SENDFILE:               "sendfile",               // { int sendfile(int fd, int s, off_t offset, size_t nbytes, \
	unix.SYS_VARSYM_SET:             "varsym_set",             // { int varsym_set(int level, const char *name, const char *data); }
	unix.SYS_VARSYM_GET:             "varsym_get",             // { int varsym_get(int mask, const char *wild, char *buf, int bufsize); }
	unix.SYS_VARSYM_LIST:            "varsym_list",            // { int varsym_list(int level, char *buf, int maxsize, int *marker); }
	unix.SYS_EXEC_SYS_REGISTER:      "exec_sys_register",      // { int exec_sys_register(void *entry); }
	unix.SYS_EXEC_SYS_UNREGISTER:    "exec_sys_unregister",    // { int exec_sys_unregister(int id); }
	unix.SYS_SYS_CHECKPOINT:         "sys_checkpoint",         // { int sys_checkpoint(int type, int fd, pid_t pid, int retval); }
	unix.SYS_MOUNTCTL:               "mountctl",               // { int mountctl(const char *path, int op, int fd, const void *ctl, int ctllen, void *buf, int buflen); }
	unix.SYS_UMTX_SLEEP:             "umtx_sleep",             // { int umtx_sleep(volatile const int *ptr, int value, int timeout); }
	unix.SYS_UMTX_WAKEUP:            "umtx_wakeup",            // { int umtx_wakeup(volatile const int *ptr, int count); }
	unix.SYS_JAIL_ATTACH:            "jail_attach",            // { int jail_attach(int jid); }
	unix.SYS_SET_TLS_AREA:           "set_tls_area",           // { int set_tls_area(int which, struct tls_info *info, size_t infosize); }
	unix.SYS_GET_TLS_AREA:           "get_tls_area",           // { int get_tls_area(int which, struct tls_info *info, size_t infosize); }
	unix.SYS_CLOSEFROM:              "closefrom",              // { int closefrom(int fd); }
	unix.SYS_STAT:                   "stat",                   // { int stat(const char *path, struct stat *ub); }
	unix.SYS_FSTAT:                  "fstat",                  // { int fstat(int fd, struct stat *sb); }
	unix.SYS_LSTAT:                  "lstat",                  // { int lstat(const char *path, struct stat *ub); }
	unix.SYS_FHSTAT:                 "fhstat",                 // { int fhstat(const struct fhandle *u_fhp, struct stat *sb); }
	unix.SYS_GETDIRENTRIES:          "getdirentries",          // { int getdirentries(int fd, char *buf, u_int count, \
	unix.SYS_GETDENTS:               "getdents",               // { int getdents(int fd, char *buf, size_t count); }
	unix.SYS_USCHED_SET:             "usched_set",             // { int usched_set(pid_t pid, int cmd, void *data, \
	unix.SYS_EXTACCEPT:              "extaccept",              // { int extaccept(int s, int flags, caddr_t name, int *anamelen); }
	unix.SYS_EXTCONNECT:             "extconnect",             // { int extconnect(int s, int flags, caddr_t name, int namelen); }
	unix.SYS_MCONTROL:               "mcontrol",               // { int mcontrol(void *addr, size_t len, int behav, off_t value); }
	unix.SYS_VMSPACE_CREATE:         "vmspace_create",         // { int vmspace_create(void *id, int type, void *data); }
	unix.SYS_VMSPACE_DESTROY:        "vmspace_destroy",        // { int vmspace_destroy(void *id); }
	unix.SYS_VMSPACE_CTL:            "vmspace_ctl",            // { int vmspace_ctl(void *id, int cmd, 		\
	unix.SYS_VMSPACE_MMAP:           "vmspace_mmap",           // { int vmspace_mmap(void *id, void *addr, size_t len, \
	unix.SYS_VMSPACE_MUNMAP:         "vmspace_munmap",         // { int vmspace_munmap(void *id, void *addr,	\
	unix.SYS_VMSPACE_MCONTROL:       "vmspace_mcontrol",       // { int vmspace_mcontrol(void *id, void *addr, 	\
	unix.SYS_VMSPACE_PREAD:          "vmspace_pread",          // { ssize_t vmspace_pread(void *id, void *buf, \
	unix.SYS_VMSPACE_PWRITE:         "vmspace_pwrite",         // { ssize_t vmspace_pwrite(void *id, const void *buf, \
	unix.SYS_EXTEXIT:                "extexit",                // { void extexit(int how, int status, void *addr); }
	unix.SYS_LWP_CREATE:             "lwp_create",             // { int lwp_create(struct lwp_params *params); }
	unix.SYS_LWP_GETTID:             "lwp_gettid",             // { lwpid_t lwp_gettid(void); }
	unix.SYS_LWP_KILL:               "lwp_kill",               // { int lwp_kill(pid_t pid, lwpid_t tid, int signum); }
	unix.SYS_LWP_RTPRIO:             "lwp_rtprio",             // { int lwp_rtprio(int function, pid_t pid, lwpid_t tid, struct rtprio *rtp); }
	unix.SYS_PSELECT:                "pselect",                // { int pselect(int nd, fd_set *in, fd_set *ou, \
	unix.SYS_STATVFS:                "statvfs",                // { int statvfs(const char *path, struct statvfs *buf); }
	unix.SYS_FSTATVFS:               "fstatvfs",               // { int fstatvfs(int fd, struct statvfs *buf); }
	unix.SYS_FHSTATVFS:              "fhstatvfs",              // { int fhstatvfs(const struct fhandle *u_fhp, struct statvfs *buf); }
	unix.SYS_GETVFSSTAT:             "getvfsstat",             // { int getvfsstat(struct statfs *buf,          \
	unix.SYS_OPENAT:                 "openat",                 // { int openat(int fd, char *path, int flags, int mode); }
	unix.SYS_FSTATAT:                "fstatat",                // { int fstatat(int fd, char *path, 	\
	unix.SYS_FCHMODAT:               "fchmodat",               // { int fchmodat(int fd, char *path, int mode, \
	unix.SYS_FCHOWNAT:               "fchownat",               // { int fchownat(int fd, char *path, int uid, int gid, \
	unix.SYS_UNLINKAT:               "unlinkat",               // { int unlinkat(int fd, char *path, int flags); }
	unix.SYS_FACCESSAT:              "faccessat",              // { int faccessat(int fd, char *path, int amode, \
	unix.SYS_MQ_OPEN:                "mq_open",                // { mqd_t mq_open(const char * name, int oflag, \
	unix.SYS_MQ_CLOSE:               "mq_close",               // { int mq_close(mqd_t mqdes); }
	unix.SYS_MQ_UNLINK:              "mq_unlink",              // { int mq_unlink(const char *name); }
	unix.SYS_MQ_GETATTR:             "mq_getattr",             // { int mq_getattr(mqd_t mqdes, \
	unix.SYS_MQ_SETATTR:             "mq_setattr",             // { int mq_setattr(mqd_t mqdes, \
	unix.SYS_MQ_NOTIFY:              "mq_notify",              // { int mq_notify(mqd_t mqdes, \
	unix.SYS_MQ_SEND:                "mq_send",                // { int mq_send(mqd_t mqdes, const char *msg_ptr, \
	unix.SYS_MQ_RECEIVE:             "mq_receive",             // { ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, \
	unix.SYS_MQ_TIMEDSEND:           "mq_timedsend",           // { int mq_timedsend(mqd_t mqdes, \
	unix.SYS_MQ_TIMEDRECEIVE:        "mq_timedreceive",        // { ssize_t mq_timedreceive(mqd_t mqdes, \
	unix.SYS_IOPRIO_SET:             "ioprio_set",             // { int ioprio_set(int which, int who, int prio); }
	unix.SYS_IOPRIO_GET:             "ioprio_get",             // { int ioprio_get(int which, int who); }
	unix.SYS_CHROOT_KERNEL:          "chroot_kernel",          // { int chroot_kernel(char *path); }
	unix.SYS_RENAMEAT:               "renameat",               // { int renameat(int oldfd, char *old, int newfd, \
	unix.SYS_MKDIRAT:                "mkdirat",                // { int mkdirat(int fd, char *path, mode_t mode); }
	unix.SYS_MKFIFOAT:               "mkfifoat",               // { int mkfifoat(int fd, char *path, mode_t mode); }
	unix.SYS_MKNODAT:                "mknodat",                // { int mknodat(int fd, char *path, mode_t mode, \
	unix.SYS_READLINKAT:             "readlinkat",             // { int readlinkat(int fd, char *path, char *buf, \
	unix.SYS_SYMLINKAT:              "symlinkat",              // { int symlinkat(char *path1, int fd, char *path2); }
	unix.SYS_SWAPOFF:                "swapoff",                // { int swapoff(char *name); }
	unix.SYS_VQUOTACTL:              "vquotactl",              // { int vquotactl(const char *path, \
	unix.SYS_LINKAT:                 "linkat",                 // { int linkat(int fd1, char *path1, int fd2, \
	unix.SYS_EACCESS:                "eaccess",                // { int eaccess(char *path, int flags); }
	unix.SYS_LPATHCONF:              "lpathconf",              // { int lpathconf(char *path, int name); }
	unix.SYS_VMM_GUEST_CTL:          "vmm_guest_ctl",          // { int vmm_guest_ctl(int op, struct vmm_guest_options *options); }
	unix.SYS_VMM_GUEST_SYNC_ADDR:    "vmm_guest_sync_addr",    // { int vmm_guest_sync_addr(long *dstaddr, long *srcaddr); }
	unix.SYS_PROCCTL:                "procctl",                // { int procctl(idtype_t idtype, id_t id, int cmd, void *data); }
	unix.SYS_CHFLAGSAT:              "chflagsat",              // { int chflagsat(int fd, const char *path, int flags, int atflags);}
	unix.SYS_PIPE2:                  "pipe2",                  // { int pipe2(int *fildes, int flags); }
	unix.SYS_UTIMENSAT:              "utimensat",              // { int utimensat(int fd, const char *path, const struct timespec *ts, int flags); }
	unix.SYS_FUTIMENS:               "futimens",               // { int futimens(int fd, const struct timespec *ts); }
	unix.SYS_ACCEPT4:                "accept4",                // { int accept4(int s, caddr_t name, int *anamelen, int flags); }
	unix.SYS_LWP_SETNAME:            "lwp_setname",            // { int lwp_setname(lwpid_t tid, const char *name); }
	unix.SYS_PPOLL:                  "ppoll",                  // { int ppoll(struct pollfd *fds, u_int nfds, \
	unix.SYS_LWP_SETAFFINITY:        "lwp_setaffinity",        // { int lwp_setaffinity(pid_t pid, lwpid_t tid, const cpumask_t *mask); }
	unix.SYS_LWP_GETAFFINITY:        "lwp_getaffinity",        // { int lwp_getaffinity(pid_t pid, lwpid_t tid, cpumask_t *mask); }
	unix.SYS_LWP_CREATE2:            "lwp_create2",            // { int lwp_create2(struct lwp_params *params, const cpumask_t *mask); }
}
