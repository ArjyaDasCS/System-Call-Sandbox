#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdbool.h>
#include<sys/user.h>
#include<sys/syscall.h>
#include<signal.h>
#include<sys/ptrace.h>
#include<sys/wait.h>
#include<sys/reg.h>
#include<sys/types.h>
#include "automataSimulation.h"
#include "nodeStructure.h"
#include "graphStructure.h"
#include "systemcallhandler.h"

// macro to avoid writing redundant lines
// depending upon the system call number it simulates the automata
#define SystemCallNumber(x) case x: isValid = SystemCallProcessing(#x, currentState, nextState, data, totalNodes); break;

// This function tracks the system calls further
int waitForSystemCall(pid_t child)
{
	int childStatus;   // to observe the information returned from child
	ptrace(PTRACE_SYSCALL,child,0,0);  
    /* inspect the arguments to the system call at the first stop, then do another PTRACE_SYSCALL 
       and inspect the return value of the system call at the second stop.
    */
	waitpid(child,&childStatus,0);
    /* It suspends the parent until the system gets status information on the child */
	if(WIFSTOPPED(childStatus) && (WSTOPSIG(childStatus) & 0x80)) 
    /* using WIFSTOPPED() parent waits for the child to stop. 
       WIFSTOPPED evaluates to true (1) when the process (child) for which the wait() call was made is stopped.
    */
    /* WSTOPSIG(status) returns the stop signal. logical AND with 0x80 will tell us if 7th bit of
       signal is set or not (i.e. it is system call or not)  
    */
	{
        int SystemCall = ptrace(PTRACE_PEEKUSER,child,sizeof(long)*ORIG_RAX,0);
        /* PTRACE_PEEKUSER reads a word at offset ORIG_RAX in the tracee's (child) USER area. This offset varies
           across different architectures.
        */
        return SystemCall;
    }
    if(WIFEXITED(childStatus)) 
        /* check if tracee (child) has ended its life (exit) */
    {
        return -1;
    }
}
void signalProcessing(pid_t child, char ***data, int entrylocation,int totalNodes)
{
	int* currentState = (int*)malloc(totalNodes * sizeof(int)); // stores the current state of automata
	int* nextState = (int*)malloc(totalNodes * sizeof(int));    // stores the next state of automata
	bool isValid;                                               // checks if system call made is valid or not
	currentState[entrylocation]=1;                              // denotes that the automata is in start state
	while(true)
	{
		int SystemCall;
		SystemCall = waitForSystemCall(child);                  // tracks the system call
		if(SystemCall < 0)                                      
		{                                                       // exit point
			break;
		}
		switch(SystemCall)                                      // handle specific system calls
		{
			SystemCallNumber(SYS_restart_syscall);
            SystemCallNumber(SYS_exit);
            SystemCallNumber(SYS_fork);
            SystemCallNumber(SYS_read);
            SystemCallNumber(SYS_write);
            SystemCallNumber(SYS_open);
            SystemCallNumber(SYS_close);
            //SystemCallNumber(SYS_waitpid);
            SystemCallNumber(SYS_creat);
            SystemCallNumber(SYS_link);
            SystemCallNumber(SYS_unlink);
            SystemCallNumber(SYS_execve);
            SystemCallNumber(SYS_chdir);
            SystemCallNumber(SYS_time);
            SystemCallNumber(SYS_mknod);
            SystemCallNumber(SYS_chmod);
            //SystemCallNumber(SYS_lchown16);
            SystemCallNumber(SYS_stat);
            SystemCallNumber(SYS_lseek);
            SystemCallNumber(SYS_getpid);
            SystemCallNumber(SYS_mount);
            //SystemCallNumber(SYS_oldumount);
            //SystemCallNumber(SYS_setuid16);
            //SystemCallNumber(SYS_getuid16);
            //SystemCallNumber(SYS_stime);
            SystemCallNumber(SYS_ptrace);
            SystemCallNumber(SYS_alarm);
            SystemCallNumber(SYS_fstat);
            SystemCallNumber(SYS_pause);
            SystemCallNumber(SYS_utime);
            SystemCallNumber(SYS_access);
            //SystemCallNumber(SYS_nice);
            SystemCallNumber(SYS_sync);
            SystemCallNumber(SYS_kill);
            SystemCallNumber(SYS_rename);
            SystemCallNumber(SYS_mkdir);
            SystemCallNumber(SYS_rmdir);
            SystemCallNumber(SYS_dup);
            SystemCallNumber(SYS_pipe);
            SystemCallNumber(SYS_times);
            SystemCallNumber(SYS_brk);
            //SystemCallNumber(SYS_setgid16);
            //SystemCallNumber(SYS_getgid16);
            //SystemCallNumber(SYS_signal);
            //SystemCallNumber(SYS_geteuid16);
            //SystemCallNumber(SYS_getegid16);
            SystemCallNumber(SYS_acct);
            //SystemCallNumber(SYS_umount);
            SystemCallNumber(SYS_ioctl);
            SystemCallNumber(SYS_fcntl);
            SystemCallNumber(SYS_setpgid);
            //SystemCallNumber(SYS_olduname);
            SystemCallNumber(SYS_umask);
            SystemCallNumber(SYS_chroot);
            SystemCallNumber(SYS_ustat);
            SystemCallNumber(SYS_dup2);
            SystemCallNumber(SYS_getppid);
            SystemCallNumber(SYS_getpgrp);
            SystemCallNumber(SYS_setsid);
            //SystemCallNumber(SYS_sigaction);
            //SystemCallNumber(SYS_sgetmask);
            //SystemCallNumber(SYS_ssetmask);
            //SystemCallNumber(SYS_setreuid16);
            //SystemCallNumber(SYS_setregid16);
            //SystemCallNumber(SYS_sigsuspend);
            //SystemCallNumber(SYS_sigpending);
            SystemCallNumber(SYS_sethostname);
            //SystemCallNumber(SYS_setrlimit);
            //SystemCallNumber(SYS_old_getrlimit);
            SystemCallNumber(SYS_getrusage);
            SystemCallNumber(SYS_gettimeofday);
            SystemCallNumber(SYS_settimeofday);
            //SystemCallNumber(SYS_getgroups16);
            //SystemCallNumber(SYS_setgroups16);
            //SystemCallNumber(SYS_old_select);
            SystemCallNumber(SYS_symlink);
            SystemCallNumber(SYS_lstat);
            SystemCallNumber(SYS_readlink);
            SystemCallNumber(SYS_uselib);
            SystemCallNumber(SYS_swapon);
            SystemCallNumber(SYS_reboot);
            //SystemCallNumber(SYS_old_readdir);
            //SystemCallNumber(SYS_old_mmap);
            SystemCallNumber(SYS_munmap);
            SystemCallNumber(SYS_truncate);
            SystemCallNumber(SYS_ftruncate);
            SystemCallNumber(SYS_fchmod);
            //SystemCallNumber(SYS_fchown16);
            SystemCallNumber(SYS_getpriority);
            SystemCallNumber(SYS_setpriority);
            SystemCallNumber(SYS_statfs);
            SystemCallNumber(SYS_fstatfs);
            SystemCallNumber(SYS_ioperm);
            //SystemCallNumber(SYS_socketcall);
            SystemCallNumber(SYS_syslog);
            SystemCallNumber(SYS_setitimer);
            SystemCallNumber(SYS_getitimer);
            // SystemCallNumber(SYS_newstat);
            // SystemCallNumber(SYS_newlstat);
            // SystemCallNumber(SYS_newfstat);
            SystemCallNumber(SYS_uname);
            SystemCallNumber(SYS_iopl);
            SystemCallNumber(SYS_vhangup);
            // SystemCallNumber(SYS_vm86old);
            SystemCallNumber(SYS_wait4);
            SystemCallNumber(SYS_swapoff);
            SystemCallNumber(SYS_sysinfo);
            SystemCallNumber(SYS_arch_prctl);
            SystemCallNumber(SYS_fsync);
            // SystemCallNumber(SYS_sigreturn);
            SystemCallNumber(SYS_clone);
            SystemCallNumber(SYS_setdomainname);
            // SystemCallNumber(SYS_newuname);
            SystemCallNumber(SYS_modify_ldt);
            SystemCallNumber(SYS_adjtimex);
            SystemCallNumber(SYS_mprotect);
            // SystemCallNumber(SYS_sigprocmask);
            SystemCallNumber(SYS_init_module);
            SystemCallNumber(SYS_delete_module);
            SystemCallNumber(SYS_quotactl);
            SystemCallNumber(SYS_getpgid);
            SystemCallNumber(SYS_fchdir);
             //SystemCallNumber(SYS_bdflush);
            SystemCallNumber(SYS_sysfs);
            SystemCallNumber(SYS_personality);
             //SystemCallNumber(SYS_setfsuid16);
             //SystemCallNumber(SYS_setfsgid16);
             //SystemCallNumber(SYS_llseek);
            SystemCallNumber(SYS_getdents);
            SystemCallNumber(SYS_select);
            SystemCallNumber(SYS_flock);
            SystemCallNumber(SYS_msync);
            SystemCallNumber(SYS_readv);
            SystemCallNumber(SYS_writev);
            SystemCallNumber(SYS_getsid);
            SystemCallNumber(SYS_fdatasync);
             //SystemCallNumber(SYS_sysctl);
            SystemCallNumber(SYS_mlock);
            SystemCallNumber(SYS_munlock);
            SystemCallNumber(SYS_mlockall);
            SystemCallNumber(SYS_munlockall);
            SystemCallNumber(SYS_sched_setparam);
            SystemCallNumber(SYS_sched_getparam);
            SystemCallNumber(SYS_sched_setscheduler);
            SystemCallNumber(SYS_sched_getscheduler);
            SystemCallNumber(SYS_sched_yield);
            SystemCallNumber(SYS_sched_get_priority_max);
            SystemCallNumber(SYS_sched_get_priority_min);
            SystemCallNumber(SYS_nanosleep);
            SystemCallNumber(SYS_mremap);
             //SystemCallNumber(SYS_setresuid16);
             //SystemCallNumber(SYS_getresuid16);
             //SystemCallNumber(SYS_vm86);
            SystemCallNumber(SYS_poll);
             //SystemCallNumber(SYS_setresgid16);
             //SystemCallNumber(SYS_getresgid16);
            SystemCallNumber(SYS_prctl);
            SystemCallNumber(SYS_rt_sigreturn);
            SystemCallNumber(SYS_rt_sigaction);
            SystemCallNumber(SYS_rt_sigprocmask);
            SystemCallNumber(SYS_rt_sigpending);
            SystemCallNumber(SYS_rt_sigtimedwait);
            SystemCallNumber(SYS_rt_sigqueueinfo);
            SystemCallNumber(SYS_rt_sigsuspend);
            SystemCallNumber(SYS_pread64);
            SystemCallNumber(SYS_pwrite64);
            // SystemCallNumber(SYS_chown16);
            SystemCallNumber(SYS_getcwd);
            SystemCallNumber(SYS_capget);
            SystemCallNumber(SYS_capset);
            SystemCallNumber(SYS_sigaltstack);
            SystemCallNumber(SYS_sendfile);
            SystemCallNumber(SYS_vfork);
            SystemCallNumber(SYS_getrlimit);
             //SystemCallNumber(SYS_mmap_pgoff);
             //SystemCallNumber(SYS_truncate64);
             //SystemCallNumber(SYS_ftruncate64);
             //SystemCallNumber(SYS_stat64);
             //SystemCallNumber(SYS_lstat64);
             //SystemCallNumber(SYS_fstat64);
            SystemCallNumber(SYS_lchown);
            SystemCallNumber(SYS_getuid);
            SystemCallNumber(SYS_getgid);
            SystemCallNumber(SYS_geteuid);
            SystemCallNumber(SYS_getegid);
            SystemCallNumber(SYS_setreuid);
            SystemCallNumber(SYS_setregid);
            SystemCallNumber(SYS_getgroups);
            SystemCallNumber(SYS_setgroups);
            SystemCallNumber(SYS_fchown);
            SystemCallNumber(SYS_setresuid);
            SystemCallNumber(SYS_getresuid);
            SystemCallNumber(SYS_setresgid);
            SystemCallNumber(SYS_getresgid);
            SystemCallNumber(SYS_chown);
            SystemCallNumber(SYS_setuid);
            SystemCallNumber(SYS_setgid);
            SystemCallNumber(SYS_setfsuid);
            SystemCallNumber(SYS_setfsgid);
            SystemCallNumber(SYS_pivot_root);
            SystemCallNumber(SYS_mincore);
            SystemCallNumber(SYS_madvise);
            SystemCallNumber(SYS_getdents64);
             //SystemCallNumber(SYS_fcntl64);
            SystemCallNumber(SYS_gettid);
            SystemCallNumber(SYS_readahead);
            SystemCallNumber(SYS_setxattr);
            SystemCallNumber(SYS_lsetxattr);
            SystemCallNumber(SYS_fsetxattr);
            SystemCallNumber(SYS_getxattr);
            SystemCallNumber(SYS_lgetxattr);
            SystemCallNumber(SYS_fgetxattr);
            SystemCallNumber(SYS_listxattr);
            SystemCallNumber(SYS_llistxattr);
            SystemCallNumber(SYS_flistxattr);
            SystemCallNumber(SYS_removexattr);
            SystemCallNumber(SYS_lremovexattr);
            SystemCallNumber(SYS_fremovexattr);
            SystemCallNumber(SYS_tkill);
            // SystemCallNumber(SYS_sendfile64);
            SystemCallNumber(SYS_futex);
            SystemCallNumber(SYS_sched_setaffinity);
            SystemCallNumber(SYS_sched_getaffinity);
            SystemCallNumber(SYS_set_thread_area);
            SystemCallNumber(SYS_get_thread_area);
            SystemCallNumber(SYS_io_setup);
            SystemCallNumber(SYS_io_destroy);
            SystemCallNumber(SYS_io_getevents);
            SystemCallNumber(SYS_io_submit);
            SystemCallNumber(SYS_io_cancel);
            SystemCallNumber(SYS_fadvise64);
            SystemCallNumber(SYS_exit_group);
            SystemCallNumber(SYS_lookup_dcookie);
            SystemCallNumber(SYS_epoll_create);
            SystemCallNumber(SYS_epoll_ctl);
            SystemCallNumber(SYS_epoll_wait);
            SystemCallNumber(SYS_remap_file_pages);
            SystemCallNumber(SYS_set_tid_address);
            SystemCallNumber(SYS_timer_create);
            SystemCallNumber(SYS_timer_settime);
            SystemCallNumber(SYS_timer_gettime);
            SystemCallNumber(SYS_timer_getoverrun);
            SystemCallNumber(SYS_timer_delete);
            SystemCallNumber(SYS_clock_settime);
            SystemCallNumber(SYS_clock_gettime);
            SystemCallNumber(SYS_clock_getres);
            SystemCallNumber(SYS_clock_nanosleep);
             //SystemCallNumber(SYS_statfs64);
             //SystemCallNumber(SYS_fstatfs64);
            SystemCallNumber(SYS_tgkill);
            SystemCallNumber(SYS_utimes);
             //SystemCallNumber(SYS_fadvise64_64);
            SystemCallNumber(SYS_mbind);
            SystemCallNumber(SYS_get_mempolicy);
            SystemCallNumber(SYS_set_mempolicy);
            SystemCallNumber(SYS_mq_open);
            SystemCallNumber(SYS_mq_unlink);
            SystemCallNumber(SYS_mq_timedsend);
            SystemCallNumber(SYS_mq_timedreceive);
            SystemCallNumber(SYS_mq_notify);
            SystemCallNumber(SYS_mq_getsetattr);
            SystemCallNumber(SYS_kexec_load);
            SystemCallNumber(SYS_waitid);
            SystemCallNumber(SYS_add_key);
            SystemCallNumber(SYS_request_key);
            SystemCallNumber(SYS_keyctl);
            SystemCallNumber(SYS_ioprio_set);
            SystemCallNumber(SYS_ioprio_get);
            SystemCallNumber(SYS_inotify_init);
            SystemCallNumber(SYS_inotify_add_watch);
            SystemCallNumber(SYS_inotify_rm_watch);
            SystemCallNumber(SYS_migrate_pages);
            SystemCallNumber(SYS_openat);
            SystemCallNumber(SYS_mkdirat);
            SystemCallNumber(SYS_mknodat);
            SystemCallNumber(SYS_fchownat);
            SystemCallNumber(SYS_futimesat);
             //SystemCallNumber(SYS_fstatat64);
            SystemCallNumber(SYS_unlinkat);
            SystemCallNumber(SYS_renameat);
            SystemCallNumber(SYS_linkat);
            SystemCallNumber(SYS_symlinkat);
            SystemCallNumber(SYS_readlinkat);
            SystemCallNumber(SYS_fchmodat);
            SystemCallNumber(SYS_faccessat);
            SystemCallNumber(SYS_pselect6);
            SystemCallNumber(SYS_ppoll);
            SystemCallNumber(SYS_unshare);
            SystemCallNumber(SYS_set_robust_list);
            SystemCallNumber(SYS_get_robust_list);
            SystemCallNumber(SYS_splice);
            SystemCallNumber(SYS_sync_file_range);
            SystemCallNumber(SYS_tee);
            SystemCallNumber(SYS_vmsplice);
            SystemCallNumber(SYS_move_pages);
            SystemCallNumber(SYS_getcpu);
            SystemCallNumber(SYS_epoll_pwait);
            SystemCallNumber(SYS_utimensat);
            SystemCallNumber(SYS_signalfd);
            SystemCallNumber(SYS_timerfd_create);
            SystemCallNumber(SYS_eventfd);
            SystemCallNumber(SYS_fallocate);
            SystemCallNumber(SYS_timerfd_settime);
            SystemCallNumber(SYS_timerfd_gettime);
            SystemCallNumber(SYS_signalfd4);
            SystemCallNumber(SYS_eventfd2);
            SystemCallNumber(SYS_epoll_create1);
            SystemCallNumber(SYS_dup3);
            SystemCallNumber(SYS_pipe2);
            SystemCallNumber(SYS_inotify_init1);
            SystemCallNumber(SYS_preadv);
            SystemCallNumber(SYS_pwritev);
            SystemCallNumber(SYS_rt_tgsigqueueinfo);
            SystemCallNumber(SYS_perf_event_open);
            SystemCallNumber(SYS_recvmmsg);
            SystemCallNumber(SYS_fanotify_init);
            SystemCallNumber(SYS_fanotify_mark);
            SystemCallNumber(SYS_prlimit64);
            SystemCallNumber(SYS_name_to_handle_at);
            SystemCallNumber(SYS_open_by_handle_at);
            SystemCallNumber(SYS_clock_adjtime);
            SystemCallNumber(SYS_syncfs);
            SystemCallNumber(SYS_sendmmsg);
            SystemCallNumber(SYS_setns);
            SystemCallNumber(SYS_process_vm_readv);
            SystemCallNumber(SYS_process_vm_writev);
            SystemCallNumber(SYS_kcmp);
            SystemCallNumber(SYS_finit_module);
            default:
                isValid == true;              // when hook is not present keep the automata in same state and move on.
                break;
		}
		if(isValid == false)                  // terminate the process if illegal system call is received
                                              // also kill the child
		{
			puts("\nAttack detected. Terminating the process ...\n");
            kill(child, SIGKILL);
            break;
		}
		SystemCall = waitForSystemCall(child); // after encountering a valid system call wait for next one
		if(SystemCall < 0)                     // exit point
		{
			break;
		}
	}
}