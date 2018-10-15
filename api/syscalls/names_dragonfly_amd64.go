package syscalls

import "syscall"

var _ = syscall.Exit

var Name = map[uint64]string{
	syscall.SYS_EXIT:                   "exit",                   // { void exit(int rval); }
	syscall.SYS_FORK:                   "fork",                   // { int fork(void); }
	syscall.SYS_READ:                   "read",                   // { ssize_t read(int fd, void *buf, size_t nbyte); }
	syscall.SYS_WRITE:                  "write",                  // { ssize_t write(int fd, const void *buf, size_t nbyte); }
	syscall.SYS_OPEN:                   "open",                   // { int open(char *path, int flags, int mode); }
	syscall.SYS_CLOSE:                  "close",                  // { int close(int fd); }
	syscall.SYS_WAIT4:                  "wait4",                  // { int wait4(int pid, int *status, int options, \
	syscall.SYS_LINK:                   "link",                   // { int link(char *path, char *link); }
	syscall.SYS_UNLINK:                 "unlink",                 // { int unlink(char *path); }
	syscall.SYS_CHDIR:                  "chdir",                  // { int chdir(char *path); }
	syscall.SYS_FCHDIR:                 "fchdir",                 // { int fchdir(int fd); }
	syscall.SYS_MKNOD:                  "mknod",                  // { int mknod(char *path, int mode, int dev); }
	syscall.SYS_CHMOD:                  "chmod",                  // { int chmod(char *path, int mode); }
	syscall.SYS_CHOWN:                  "chown",                  // { int chown(char *path, int uid, int gid); }
	syscall.SYS_OBREAK:                 "obreak",                 // { int obreak(char *nsize); } break obreak_args int
	syscall.SYS_GETFSSTAT:              "getfsstat",              // { int getfsstat(struct statfs *buf, long bufsize, \
	syscall.SYS_GETPID:                 "getpid",                 // { pid_t getpid(void); }
	syscall.SYS_MOUNT:                  "mount",                  // { int mount(char *type, char *path, int flags, \
	syscall.SYS_UNMOUNT:                "unmount",                // { int unmount(char *path, int flags); }
	syscall.SYS_SETUID:                 "setuid",                 // { int setuid(uid_t uid); }
	syscall.SYS_GETUID:                 "getuid",                 // { uid_t getuid(void); }
	syscall.SYS_GETEUID:                "geteuid",                // { uid_t geteuid(void); }
	syscall.SYS_PTRACE:                 "ptrace",                 // { int ptrace(int req, pid_t pid, caddr_t addr, \
	syscall.SYS_RECVMSG:                "recvmsg",                // { int recvmsg(int s, struct msghdr *msg, int flags); }
	syscall.SYS_SENDMSG:                "sendmsg",                // { int sendmsg(int s, caddr_t msg, int flags); }
	syscall.SYS_RECVFROM:               "recvfrom",               // { int recvfrom(int s, caddr_t buf, size_t len, \
	syscall.SYS_ACCEPT:                 "accept",                 // { int accept(int s, caddr_t name, int *anamelen); }
	syscall.SYS_GETPEERNAME:            "getpeername",            // { int getpeername(int fdes, caddr_t asa, int *alen); }
	syscall.SYS_GETSOCKNAME:            "getsockname",            // { int getsockname(int fdes, caddr_t asa, int *alen); }
	syscall.SYS_ACCESS:                 "access",                 // { int access(char *path, int flags); }
	syscall.SYS_CHFLAGS:                "chflags",                // { int chflags(char *path, int flags); }
	syscall.SYS_FCHFLAGS:               "fchflags",               // { int fchflags(int fd, int flags); }
	syscall.SYS_SYNC:                   "sync",                   // { int sync(void); }
	syscall.SYS_KILL:                   "kill",                   // { int kill(int pid, int signum); }
	syscall.SYS_GETPPID:                "getppid",                // { pid_t getppid(void); }
	syscall.SYS_DUP:                    "dup",                    // { int dup(u_int fd); }
	syscall.SYS_PIPE:                   "pipe",                   // { int pipe(void); }
	syscall.SYS_GETEGID:                "getegid",                // { gid_t getegid(void); }
	syscall.SYS_PROFIL:                 "profil",                 // { int profil(caddr_t samples, size_t size, \
	syscall.SYS_KTRACE:                 "ktrace",                 // { int ktrace(const char *fname, int ops, int facs, \
	syscall.SYS_GETGID:                 "getgid",                 // { gid_t getgid(void); }
	syscall.SYS_GETLOGIN:               "getlogin",               // { int getlogin(char *namebuf, u_int namelen); }
	syscall.SYS_SETLOGIN:               "setlogin",               // { int setlogin(char *namebuf); }
	syscall.SYS_ACCT:                   "acct",                   // { int acct(char *path); }
	syscall.SYS_SIGALTSTACK:            "sigaltstack",            // { int sigaltstack(stack_t *ss, stack_t *oss); }
	syscall.SYS_IOCTL:                  "ioctl",                  // { int ioctl(int fd, u_long com, caddr_t data); }
	syscall.SYS_REBOOT:                 "reboot",                 // { int reboot(int opt); }
	syscall.SYS_REVOKE:                 "revoke",                 // { int revoke(char *path); }
	syscall.SYS_SYMLINK:                "symlink",                // { int symlink(char *path, char *link); }
	syscall.SYS_READLINK:               "readlink",               // { int readlink(char *path, char *buf, int count); }
	syscall.SYS_EXECVE:                 "execve",                 // { int execve(char *fname, char **argv, char **envv); }
	syscall.SYS_UMASK:                  "umask",                  // { int umask(int newmask); } umask umask_args int
	syscall.SYS_CHROOT:                 "chroot",                 // { int chroot(char *path); }
	syscall.SYS_MSYNC:                  "msync",                  // { int msync(void *addr, size_t len, int flags); }
	syscall.SYS_VFORK:                  "vfork",                  // { pid_t vfork(void); }
	syscall.SYS_SBRK:                   "sbrk",                   // { int sbrk(int incr); }
	syscall.SYS_SSTK:                   "sstk",                   // { int sstk(int incr); }
	syscall.SYS_MUNMAP:                 "munmap",                 // { int munmap(void *addr, size_t len); }
	syscall.SYS_MPROTECT:               "mprotect",               // { int mprotect(void *addr, size_t len, int prot); }
	syscall.SYS_MADVISE:                "madvise",                // { int madvise(void *addr, size_t len, int behav); }
	syscall.SYS_MINCORE:                "mincore",                // { int mincore(const void *addr, size_t len, \
	syscall.SYS_GETGROUPS:              "getgroups",              // { int getgroups(u_int gidsetsize, gid_t *gidset); }
	syscall.SYS_SETGROUPS:              "setgroups",              // { int setgroups(u_int gidsetsize, gid_t *gidset); }
	syscall.SYS_GETPGRP:                "getpgrp",                // { int getpgrp(void); }
	syscall.SYS_SETPGID:                "setpgid",                // { int setpgid(int pid, int pgid); }
	syscall.SYS_SETITIMER:              "setitimer",              // { int setitimer(u_int which, struct itimerval *itv, \
	syscall.SYS_SWAPON:                 "swapon",                 // { int swapon(char *name); }
	syscall.SYS_GETITIMER:              "getitimer",              // { int getitimer(u_int which, struct itimerval *itv); }
	syscall.SYS_GETDTABLESIZE:          "getdtablesize",          // { int getdtablesize(void); }
	syscall.SYS_DUP2:                   "dup2",                   // { int dup2(u_int from, u_int to); }
	syscall.SYS_FCNTL:                  "fcntl",                  // { int fcntl(int fd, int cmd, long arg); }
	syscall.SYS_SELECT:                 "select",                 // { int select(int nd, fd_set *in, fd_set *ou, \
	syscall.SYS_FSYNC:                  "fsync",                  // { int fsync(int fd); }
	syscall.SYS_SETPRIORITY:            "setpriority",            // { int setpriority(int which, int who, int prio); }
	syscall.SYS_SOCKET:                 "socket",                 // { int socket(int domain, int type, int protocol); }
	syscall.SYS_CONNECT:                "connect",                // { int connect(int s, caddr_t name, int namelen); }
	syscall.SYS_GETPRIORITY:            "getpriority",            // { int getpriority(int which, int who); }
	syscall.SYS_BIND:                   "bind",                   // { int bind(int s, caddr_t name, int namelen); }
	syscall.SYS_SETSOCKOPT:             "setsockopt",             // { int setsockopt(int s, int level, int name, \
	syscall.SYS_LISTEN:                 "listen",                 // { int listen(int s, int backlog); }
	syscall.SYS_GETTIMEOFDAY:           "gettimeofday",           // { int gettimeofday(struct timeval *tp, \
	syscall.SYS_GETRUSAGE:              "getrusage",              // { int getrusage(int who, struct rusage *rusage); }
	syscall.SYS_GETSOCKOPT:             "getsockopt",             // { int getsockopt(int s, int level, int name, \
	syscall.SYS_READV:                  "readv",                  // { int readv(int fd, struct iovec *iovp, u_int iovcnt); }
	syscall.SYS_WRITEV:                 "writev",                 // { int writev(int fd, struct iovec *iovp, \
	syscall.SYS_SETTIMEOFDAY:           "settimeofday",           // { int settimeofday(struct timeval *tv, \
	syscall.SYS_FCHOWN:                 "fchown",                 // { int fchown(int fd, int uid, int gid); }
	syscall.SYS_FCHMOD:                 "fchmod",                 // { int fchmod(int fd, int mode); }
	syscall.SYS_SETREUID:               "setreuid",               // { int setreuid(int ruid, int euid); }
	syscall.SYS_SETREGID:               "setregid",               // { int setregid(int rgid, int egid); }
	syscall.SYS_RENAME:                 "rename",                 // { int rename(char *from, char *to); }
	syscall.SYS_FLOCK:                  "flock",                  // { int flock(int fd, int how); }
	syscall.SYS_MKFIFO:                 "mkfifo",                 // { int mkfifo(char *path, int mode); }
	syscall.SYS_SENDTO:                 "sendto",                 // { int sendto(int s, caddr_t buf, size_t len, \
	syscall.SYS_SHUTDOWN:               "shutdown",               // { int shutdown(int s, int how); }
	syscall.SYS_SOCKETPAIR:             "socketpair",             // { int socketpair(int domain, int type, int protocol, \
	syscall.SYS_MKDIR:                  "mkdir",                  // { int mkdir(char *path, int mode); }
	syscall.SYS_RMDIR:                  "rmdir",                  // { int rmdir(char *path); }
	syscall.SYS_UTIMES:                 "utimes",                 // { int utimes(char *path, struct timeval *tptr); }
	syscall.SYS_ADJTIME:                "adjtime",                // { int adjtime(struct timeval *delta, \
	syscall.SYS_SETSID:                 "setsid",                 // { int setsid(void); }
	syscall.SYS_QUOTACTL:               "quotactl",               // { int quotactl(char *path, int cmd, int uid, \
	syscall.SYS_STATFS:                 "statfs",                 // { int statfs(char *path, struct statfs *buf); }
	syscall.SYS_FSTATFS:                "fstatfs",                // { int fstatfs(int fd, struct statfs *buf); }
	syscall.SYS_GETFH:                  "getfh",                  // { int getfh(char *fname, struct fhandle *fhp); }
	syscall.SYS_GETDOMAINNAME:          "getdomainname",          // { int getdomainname(char *domainname, int len); }
	syscall.SYS_SETDOMAINNAME:          "setdomainname",          // { int setdomainname(char *domainname, int len); }
	syscall.SYS_UNAME:                  "uname",                  // { int uname(struct utsname *name); }
	syscall.SYS_SYSARCH:                "sysarch",                // { int sysarch(int op, char *parms); }
	syscall.SYS_RTPRIO:                 "rtprio",                 // { int rtprio(int function, pid_t pid, \
	syscall.SYS_EXTPREAD:               "extpread",               // { ssize_t extpread(int fd, void *buf, \
	syscall.SYS_EXTPWRITE:              "extpwrite",              // { ssize_t extpwrite(int fd, const void *buf, \
	syscall.SYS_NTP_ADJTIME:            "ntp_adjtime",            // { int ntp_adjtime(struct timex *tp); }
	syscall.SYS_SETGID:                 "setgid",                 // { int setgid(gid_t gid); }
	syscall.SYS_SETEGID:                "setegid",                // { int setegid(gid_t egid); }
	syscall.SYS_SETEUID:                "seteuid",                // { int seteuid(uid_t euid); }
	syscall.SYS_PATHCONF:               "pathconf",               // { int pathconf(char *path, int name); }
	syscall.SYS_FPATHCONF:              "fpathconf",              // { int fpathconf(int fd, int name); }
	syscall.SYS_GETRLIMIT:              "getrlimit",              // { int getrlimit(u_int which, \
	syscall.SYS_SETRLIMIT:              "setrlimit",              // { int setrlimit(u_int which, \
	syscall.SYS_MMAP:                   "mmap",                   // { caddr_t mmap(caddr_t addr, size_t len, int prot, \
	syscall.SYS_LSEEK:                  "lseek",                  // { off_t lseek(int fd, int pad, off_t offset, \
	syscall.SYS_TRUNCATE:               "truncate",               // { int truncate(char *path, int pad, off_t length); }
	syscall.SYS_FTRUNCATE:              "ftruncate",              // { int ftruncate(int fd, int pad, off_t length); }
	syscall.SYS___SYSCTL:               "__sysctl",               // { int __sysctl(int *name, u_int namelen, void *old, \
	syscall.SYS_MLOCK:                  "mlock",                  // { int mlock(const void *addr, size_t len); }
	syscall.SYS_MUNLOCK:                "munlock",                // { int munlock(const void *addr, size_t len); }
	syscall.SYS_UNDELETE:               "undelete",               // { int undelete(char *path); }
	syscall.SYS_FUTIMES:                "futimes",                // { int futimes(int fd, struct timeval *tptr); }
	syscall.SYS_GETPGID:                "getpgid",                // { int getpgid(pid_t pid); }
	syscall.SYS_POLL:                   "poll",                   // { int poll(struct pollfd *fds, u_int nfds, \
	syscall.SYS___SEMCTL:               "__semctl",               // { int __semctl(int semid, int semnum, int cmd, \
	syscall.SYS_SEMGET:                 "semget",                 // { int semget(key_t key, int nsems, int semflg); }
	syscall.SYS_SEMOP:                  "semop",                  // { int semop(int semid, struct sembuf *sops, \
	syscall.SYS_MSGCTL:                 "msgctl",                 // { int msgctl(int msqid, int cmd, \
	syscall.SYS_MSGGET:                 "msgget",                 // { int msgget(key_t key, int msgflg); }
	syscall.SYS_MSGSND:                 "msgsnd",                 // { int msgsnd(int msqid, void *msgp, size_t msgsz, \
	syscall.SYS_MSGRCV:                 "msgrcv",                 // { int msgrcv(int msqid, void *msgp, size_t msgsz, \
	syscall.SYS_SHMAT:                  "shmat",                  // { caddr_t shmat(int shmid, const void *shmaddr, \
	syscall.SYS_SHMCTL:                 "shmctl",                 // { int shmctl(int shmid, int cmd, \
	syscall.SYS_SHMDT:                  "shmdt",                  // { int shmdt(const void *shmaddr); }
	syscall.SYS_SHMGET:                 "shmget",                 // { int shmget(key_t key, size_t size, int shmflg); }
	syscall.SYS_CLOCK_GETTIME:          "clock_gettime",          // { int clock_gettime(clockid_t clock_id, \
	syscall.SYS_CLOCK_SETTIME:          "clock_settime",          // { int clock_settime(clockid_t clock_id, \
	syscall.SYS_CLOCK_GETRES:           "clock_getres",           // { int clock_getres(clockid_t clock_id, \
	syscall.SYS_NANOSLEEP:              "nanosleep",              // { int nanosleep(const struct timespec *rqtp, \
	syscall.SYS_MINHERIT:               "minherit",               // { int minherit(void *addr, size_t len, int inherit); }
	syscall.SYS_RFORK:                  "rfork",                  // { int rfork(int flags); }
	syscall.SYS_OPENBSD_POLL:           "openbsd_poll",           // { int openbsd_poll(struct pollfd *fds, u_int nfds, \
	syscall.SYS_ISSETUGID:              "issetugid",              // { int issetugid(void); }
	syscall.SYS_LCHOWN:                 "lchown",                 // { int lchown(char *path, int uid, int gid); }
	syscall.SYS_LCHMOD:                 "lchmod",                 // { int lchmod(char *path, mode_t mode); }
	syscall.SYS_LUTIMES:                "lutimes",                // { int lutimes(char *path, struct timeval *tptr); }
	syscall.SYS_EXTPREADV:              "extpreadv",              // { ssize_t extpreadv(int fd, struct iovec *iovp, \
	syscall.SYS_EXTPWRITEV:             "extpwritev",             // { ssize_t extpwritev(int fd, struct iovec *iovp,\
	syscall.SYS_FHSTATFS:               "fhstatfs",               // { int fhstatfs(const struct fhandle *u_fhp, struct statfs *buf); }
	syscall.SYS_FHOPEN:                 "fhopen",                 // { int fhopen(const struct fhandle *u_fhp, int flags); }
	syscall.SYS_MODNEXT:                "modnext",                // { int modnext(int modid); }
	syscall.SYS_MODSTAT:                "modstat",                // { int modstat(int modid, struct module_stat* stat); }
	syscall.SYS_MODFNEXT:               "modfnext",               // { int modfnext(int modid); }
	syscall.SYS_MODFIND:                "modfind",                // { int modfind(const char *name); }
	syscall.SYS_KLDLOAD:                "kldload",                // { int kldload(const char *file); }
	syscall.SYS_KLDUNLOAD:              "kldunload",              // { int kldunload(int fileid); }
	syscall.SYS_KLDFIND:                "kldfind",                // { int kldfind(const char *file); }
	syscall.SYS_KLDNEXT:                "kldnext",                // { int kldnext(int fileid); }
	syscall.SYS_KLDSTAT:                "kldstat",                // { int kldstat(int fileid, struct kld_file_stat* stat); }
	syscall.SYS_KLDFIRSTMOD:            "kldfirstmod",            // { int kldfirstmod(int fileid); }
	syscall.SYS_GETSID:                 "getsid",                 // { int getsid(pid_t pid); }
	syscall.SYS_SETRESUID:              "setresuid",              // { int setresuid(uid_t ruid, uid_t euid, uid_t suid); }
	syscall.SYS_SETRESGID:              "setresgid",              // { int setresgid(gid_t rgid, gid_t egid, gid_t sgid); }
	syscall.SYS_AIO_RETURN:             "aio_return",             // { int aio_return(struct aiocb *aiocbp); }
	syscall.SYS_AIO_SUSPEND:            "aio_suspend",            // { int aio_suspend(struct aiocb * const * aiocbp, int nent, const struct timespec *timeout); }
	syscall.SYS_AIO_CANCEL:             "aio_cancel",             // { int aio_cancel(int fd, struct aiocb *aiocbp); }
	syscall.SYS_AIO_ERROR:              "aio_error",              // { int aio_error(struct aiocb *aiocbp); }
	syscall.SYS_AIO_READ:               "aio_read",               // { int aio_read(struct aiocb *aiocbp); }
	syscall.SYS_AIO_WRITE:              "aio_write",              // { int aio_write(struct aiocb *aiocbp); }
	syscall.SYS_LIO_LISTIO:             "lio_listio",             // { int lio_listio(int mode, struct aiocb * const *acb_list, int nent, struct sigevent *sig); }
	syscall.SYS_YIELD:                  "yield",                  // { int yield(void); }
	syscall.SYS_MLOCKALL:               "mlockall",               // { int mlockall(int how); }
	syscall.SYS_MUNLOCKALL:             "munlockall",             // { int munlockall(void); }
	syscall.SYS___GETCWD:               "__getcwd",               // { int __getcwd(u_char *buf, u_int buflen); }
	syscall.SYS_SCHED_SETPARAM:         "sched_setparam",         // { int sched_setparam (pid_t pid, const struct sched_param *param); }
	syscall.SYS_SCHED_GETPARAM:         "sched_getparam",         // { int sched_getparam (pid_t pid, struct sched_param *param); }
	syscall.SYS_SCHED_SETSCHEDULER:     "sched_setscheduler",     // { int sched_setscheduler (pid_t pid, int policy, const struct sched_param *param); }
	syscall.SYS_SCHED_GETSCHEDULER:     "sched_getscheduler",     // { int sched_getscheduler (pid_t pid); }
	syscall.SYS_SCHED_YIELD:            "sched_yield",            // { int sched_yield (void); }
	syscall.SYS_SCHED_GET_PRIORITY_MAX: "sched_get_priority_max", // { int sched_get_priority_max (int policy); }
	syscall.SYS_SCHED_GET_PRIORITY_MIN: "sched_get_priority_min", // { int sched_get_priority_min (int policy); }
	syscall.SYS_SCHED_RR_GET_INTERVAL:  "sched_rr_get_interval",  // { int sched_rr_get_interval (pid_t pid, struct timespec *interval); }
	syscall.SYS_UTRACE:                 "utrace",                 // { int utrace(const void *addr, size_t len); }
	syscall.SYS_KLDSYM:                 "kldsym",                 // { int kldsym(int fileid, int cmd, void *data); }
	syscall.SYS_JAIL:                   "jail",                   // { int jail(struct jail *jail); }
	syscall.SYS_SIGPROCMASK:            "sigprocmask",            // { int sigprocmask(int how, const sigset_t *set, \
	syscall.SYS_SIGSUSPEND:             "sigsuspend",             // { int sigsuspend(const sigset_t *sigmask); }
	syscall.SYS_SIGACTION:              "sigaction",              // { int sigaction(int sig, const struct sigaction *act, \
	syscall.SYS_SIGPENDING:             "sigpending",             // { int sigpending(sigset_t *set); }
	syscall.SYS_SIGRETURN:              "sigreturn",              // { int sigreturn(ucontext_t *sigcntxp); }
	syscall.SYS_SIGTIMEDWAIT:           "sigtimedwait",           // { int sigtimedwait(const sigset_t *set,\
	syscall.SYS_SIGWAITINFO:            "sigwaitinfo",            // { int sigwaitinfo(const sigset_t *set,\
	syscall.SYS___ACL_GET_FILE:         "__acl_get_file",         // { int __acl_get_file(const char *path, \
	syscall.SYS___ACL_SET_FILE:         "__acl_set_file",         // { int __acl_set_file(const char *path, \
	syscall.SYS___ACL_GET_FD:           "__acl_get_fd",           // { int __acl_get_fd(int filedes, acl_type_t type, \
	syscall.SYS___ACL_SET_FD:           "__acl_set_fd",           // { int __acl_set_fd(int filedes, acl_type_t type, \
	syscall.SYS___ACL_DELETE_FILE:      "__acl_delete_file",      // { int __acl_delete_file(const char *path, \
	syscall.SYS___ACL_DELETE_FD:        "__acl_delete_fd",        // { int __acl_delete_fd(int filedes, acl_type_t type); }
	syscall.SYS___ACL_ACLCHECK_FILE:    "__acl_aclcheck_file",    // { int __acl_aclcheck_file(const char *path, \
	syscall.SYS___ACL_ACLCHECK_FD:      "__acl_aclcheck_fd",      // { int __acl_aclcheck_fd(int filedes, acl_type_t type, \
	syscall.SYS_EXTATTRCTL:             "extattrctl",             // { int extattrctl(const char *path, int cmd, \
	syscall.SYS_EXTATTR_SET_FILE:       "extattr_set_file",       // { int extattr_set_file(const char *path, \
	syscall.SYS_EXTATTR_GET_FILE:       "extattr_get_file",       // { int extattr_get_file(const char *path, \
	syscall.SYS_EXTATTR_DELETE_FILE:    "extattr_delete_file",    // { int extattr_delete_file(const char *path, \
	syscall.SYS_AIO_WAITCOMPLETE:       "aio_waitcomplete",       // { int aio_waitcomplete(struct aiocb **aiocbp, struct timespec *timeout); }
	syscall.SYS_GETRESUID:              "getresuid",              // { int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); }
	syscall.SYS_GETRESGID:              "getresgid",              // { int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); }
	syscall.SYS_KQUEUE:                 "kqueue",                 // { int kqueue(void); }
	syscall.SYS_KEVENT:                 "kevent",                 // { int kevent(int fd, \
	syscall.SYS_SCTP_PEELOFF:           "sctp_peeloff",           // { int sctp_peeloff(int sd, caddr_t name ); }
	syscall.SYS_LCHFLAGS:               "lchflags",               // { int lchflags(char *path, int flags); }
	syscall.SYS_UUIDGEN:                "uuidgen",                // { int uuidgen(struct uuid *store, int count); }
	syscall.SYS_SENDFILE:               "sendfile",               // { int sendfile(int fd, int s, off_t offset, size_t nbytes, \
	syscall.SYS_VARSYM_SET:             "varsym_set",             // { int varsym_set(int level, const char *name, const char *data); }
	syscall.SYS_VARSYM_GET:             "varsym_get",             // { int varsym_get(int mask, const char *wild, char *buf, int bufsize); }
	syscall.SYS_VARSYM_LIST:            "varsym_list",            // { int varsym_list(int level, char *buf, int maxsize, int *marker); }
	syscall.SYS_EXEC_SYS_REGISTER:      "exec_sys_register",      // { int exec_sys_register(void *entry); }
	syscall.SYS_EXEC_SYS_UNREGISTER:    "exec_sys_unregister",    // { int exec_sys_unregister(int id); }
	syscall.SYS_SYS_CHECKPOINT:         "sys_checkpoint",         // { int sys_checkpoint(int type, int fd, pid_t pid, int retval); }
	syscall.SYS_MOUNTCTL:               "mountctl",               // { int mountctl(const char *path, int op, int fd, const void *ctl, int ctllen, void *buf, int buflen); }
	syscall.SYS_UMTX_SLEEP:             "umtx_sleep",             // { int umtx_sleep(volatile const int *ptr, int value, int timeout); }
	syscall.SYS_UMTX_WAKEUP:            "umtx_wakeup",            // { int umtx_wakeup(volatile const int *ptr, int count); }
	syscall.SYS_JAIL_ATTACH:            "jail_attach",            // { int jail_attach(int jid); }
	syscall.SYS_SET_TLS_AREA:           "set_tls_area",           // { int set_tls_area(int which, struct tls_info *info, size_t infosize); }
	syscall.SYS_GET_TLS_AREA:           "get_tls_area",           // { int get_tls_area(int which, struct tls_info *info, size_t infosize); }
	syscall.SYS_CLOSEFROM:              "closefrom",              // { int closefrom(int fd); }
	syscall.SYS_STAT:                   "stat",                   // { int stat(const char *path, struct stat *ub); }
	syscall.SYS_FSTAT:                  "fstat",                  // { int fstat(int fd, struct stat *sb); }
	syscall.SYS_LSTAT:                  "lstat",                  // { int lstat(const char *path, struct stat *ub); }
	syscall.SYS_FHSTAT:                 "fhstat",                 // { int fhstat(const struct fhandle *u_fhp, struct stat *sb); }
	syscall.SYS_GETDIRENTRIES:          "getdirentries",          // { int getdirentries(int fd, char *buf, u_int count, \
	syscall.SYS_GETDENTS:               "getdents",               // { int getdents(int fd, char *buf, size_t count); }
	syscall.SYS_USCHED_SET:             "usched_set",             // { int usched_set(pid_t pid, int cmd, void *data, \
	syscall.SYS_EXTACCEPT:              "extaccept",              // { int extaccept(int s, int flags, caddr_t name, int *anamelen); }
	syscall.SYS_EXTCONNECT:             "extconnect",             // { int extconnect(int s, int flags, caddr_t name, int namelen); }
	syscall.SYS_MCONTROL:               "mcontrol",               // { int mcontrol(void *addr, size_t len, int behav, off_t value); }
	syscall.SYS_VMSPACE_CREATE:         "vmspace_create",         // { int vmspace_create(void *id, int type, void *data); }
	syscall.SYS_VMSPACE_DESTROY:        "vmspace_destroy",        // { int vmspace_destroy(void *id); }
	syscall.SYS_VMSPACE_CTL:            "vmspace_ctl",            // { int vmspace_ctl(void *id, int cmd, 		\
	syscall.SYS_VMSPACE_MMAP:           "vmspace_mmap",           // { int vmspace_mmap(void *id, void *addr, size_t len, \
	syscall.SYS_VMSPACE_MUNMAP:         "vmspace_munmap",         // { int vmspace_munmap(void *id, void *addr,	\
	syscall.SYS_VMSPACE_MCONTROL:       "vmspace_mcontrol",       // { int vmspace_mcontrol(void *id, void *addr, 	\
	syscall.SYS_VMSPACE_PREAD:          "vmspace_pread",          // { ssize_t vmspace_pread(void *id, void *buf, \
	syscall.SYS_VMSPACE_PWRITE:         "vmspace_pwrite",         // { ssize_t vmspace_pwrite(void *id, const void *buf, \
	syscall.SYS_EXTEXIT:                "extexit",                // { void extexit(int how, int status, void *addr); }
	syscall.SYS_LWP_CREATE:             "lwp_create",             // { int lwp_create(struct lwp_params *params); }
	syscall.SYS_LWP_GETTID:             "lwp_gettid",             // { lwpid_t lwp_gettid(void); }
	syscall.SYS_LWP_KILL:               "lwp_kill",               // { int lwp_kill(pid_t pid, lwpid_t tid, int signum); }
	syscall.SYS_LWP_RTPRIO:             "lwp_rtprio",             // { int lwp_rtprio(int function, pid_t pid, lwpid_t tid, struct rtprio *rtp); }
	syscall.SYS_PSELECT:                "pselect",                // { int pselect(int nd, fd_set *in, fd_set *ou, \
	syscall.SYS_STATVFS:                "statvfs",                // { int statvfs(const char *path, struct statvfs *buf); }
	syscall.SYS_FSTATVFS:               "fstatvfs",               // { int fstatvfs(int fd, struct statvfs *buf); }
	syscall.SYS_FHSTATVFS:              "fhstatvfs",              // { int fhstatvfs(const struct fhandle *u_fhp, struct statvfs *buf); }
	syscall.SYS_GETVFSSTAT:             "getvfsstat",             // { int getvfsstat(struct statfs *buf,          \
	syscall.SYS_OPENAT:                 "openat",                 // { int openat(int fd, char *path, int flags, int mode); }
	syscall.SYS_FSTATAT:                "fstatat",                // { int fstatat(int fd, char *path, 	\
	syscall.SYS_FCHMODAT:               "fchmodat",               // { int fchmodat(int fd, char *path, int mode, \
	syscall.SYS_FCHOWNAT:               "fchownat",               // { int fchownat(int fd, char *path, int uid, int gid, \
	syscall.SYS_UNLINKAT:               "unlinkat",               // { int unlinkat(int fd, char *path, int flags); }
	syscall.SYS_FACCESSAT:              "faccessat",              // { int faccessat(int fd, char *path, int amode, \
	syscall.SYS_MQ_OPEN:                "mq_open",                // { mqd_t mq_open(const char * name, int oflag, \
	syscall.SYS_MQ_CLOSE:               "mq_close",               // { int mq_close(mqd_t mqdes); }
	syscall.SYS_MQ_UNLINK:              "mq_unlink",              // { int mq_unlink(const char *name); }
	syscall.SYS_MQ_GETATTR:             "mq_getattr",             // { int mq_getattr(mqd_t mqdes, \
	syscall.SYS_MQ_SETATTR:             "mq_setattr",             // { int mq_setattr(mqd_t mqdes, \
	syscall.SYS_MQ_NOTIFY:              "mq_notify",              // { int mq_notify(mqd_t mqdes, \
	syscall.SYS_MQ_SEND:                "mq_send",                // { int mq_send(mqd_t mqdes, const char *msg_ptr, \
	syscall.SYS_MQ_RECEIVE:             "mq_receive",             // { ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, \
	syscall.SYS_MQ_TIMEDSEND:           "mq_timedsend",           // { int mq_timedsend(mqd_t mqdes, \
	syscall.SYS_MQ_TIMEDRECEIVE:        "mq_timedreceive",        // { ssize_t mq_timedreceive(mqd_t mqdes, \
	syscall.SYS_IOPRIO_SET:             "ioprio_set",             // { int ioprio_set(int which, int who, int prio); }
	syscall.SYS_IOPRIO_GET:             "ioprio_get",             // { int ioprio_get(int which, int who); }
	syscall.SYS_CHROOT_KERNEL:          "chroot_kernel",          // { int chroot_kernel(char *path); }
	syscall.SYS_RENAMEAT:               "renameat",               // { int renameat(int oldfd, char *old, int newfd, \
	syscall.SYS_MKDIRAT:                "mkdirat",                // { int mkdirat(int fd, char *path, mode_t mode); }
	syscall.SYS_MKFIFOAT:               "mkfifoat",               // { int mkfifoat(int fd, char *path, mode_t mode); }
	syscall.SYS_MKNODAT:                "mknodat",                // { int mknodat(int fd, char *path, mode_t mode, \
	syscall.SYS_READLINKAT:             "readlinkat",             // { int readlinkat(int fd, char *path, char *buf, \
	syscall.SYS_SYMLINKAT:              "symlinkat",              // { int symlinkat(char *path1, int fd, char *path2); }
	syscall.SYS_SWAPOFF:                "swapoff",                // { int swapoff(char *name); }
	syscall.SYS_VQUOTACTL:              "vquotactl",              // { int vquotactl(const char *path, \
	syscall.SYS_LINKAT:                 "linkat",                 // { int linkat(int fd1, char *path1, int fd2, \
	syscall.SYS_EACCESS:                "eaccess",                // { int eaccess(char *path, int flags); }
	syscall.SYS_LPATHCONF:              "lpathconf",              // { int lpathconf(char *path, int name); }
	syscall.SYS_VMM_GUEST_CTL:          "vmm_guest_ctl",          // { int vmm_guest_ctl(int op, struct vmm_guest_options *options); }
	syscall.SYS_VMM_GUEST_SYNC_ADDR:    "vmm_guest_sync_addr",    // { int vmm_guest_sync_addr(long *dstaddr, long *srcaddr); }
	syscall.SYS_UTIMENSAT:              "utimensat",              // { int utimensat(int fd, const char *path, const struct timespec *ts, int flags); }
	syscall.SYS_ACCEPT4:                "accept4",                // { int accept4(int s, caddr_t name, int *anamelen, int flags); }
}
