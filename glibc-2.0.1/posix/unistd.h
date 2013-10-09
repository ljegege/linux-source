/* Copyright (C) 1991, 92, 93, 94, 95, 96, 97 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/*
 *	POSIX Standard: 2.10 Symbolic Constants		<unistd.h>
 */

#ifndef	_UNISTD_H

#define	_UNISTD_H	1
#include <features.h>

__BEGIN_DECLS

/* These may be used to determine what facilities are present at compile time.
   Their values can be obtained at run time from `sysconf'.  */

/* POSIX Standard approved as IEEE Std 1003.1 as of August, 1988 and
   extended by P1003.1b (aka POSIX.4).  */
#define	_POSIX_VERSION	199309L

/* These are not #ifdef __USE_POSIX2 because they are
   in the theoretically application-owned namespace.  */

#define	_POSIX2_C_VERSION	199912L	/* Invalid until 1003.2 is done.  */

/* If defined, the implementation supports the
   C Language Bindings Option.  */
#define	_POSIX2_C_BIND	1

/* If defined, the implementation supports the
   C Language Development Utilities Option.  */
#define	_POSIX2_C_DEV	1

/* If defined, the implementation supports the
   Software Development Utilities Option.  */
#define	_POSIX2_SW_DEV	1

/* If defined, the implementation supports the
   creation of locales with the localedef utility.  */
#define _POSIX2_LOCALEDEF       1

/* Library conforms to X/Open version 4.  */
#define _XOPEN_VERSION	4

/* Commands and utilities from XPG4 are available.  */
#define _XOPEN_XCU_VERSION	4

/* We are compatible with the old published standards as well.  */
#define _XOPEN_XPG2	1
#define _XOPEN_XPG3	1
#define _XOPEN_XPG4	1

/* The X/Open Unix extensions are available.  */
#define _XOPEN_UNIX	1

/* Encryption is present.  */
#define	_XOPEN_CRYPT	1

/* The enhanced internationalization capabilities according to XPG4.2
   are present.  */
#define	_XOPEN_ENH_I18N	1


/* Get values of POSIX options:

   If these symbols are defined, the corresponding features are
   always available.  If not, they may be available sometimes.
   The current values can be obtained with `sysconf'.

   _POSIX_JOB_CONTROL		Job control is supported.
   _POSIX_SAVED_IDS		Processes have a saved set-user-ID
   				and a saved set-group-ID.
   _POSIX_REALTIME_SIGNALS	Real-time, queued signals are supported.
   _POSIX_PRIORITY_SCHEDULING	Priority scheduling is supported.
   _POSIX_TIMERS		POSIX.4 clocks and timers are supported.
   _POSIX_ASYNCHRONOUS_IO	Asynchronous I/O is supported.
   _POSIX_PRIORITIZED_IO	Prioritized asynchronous I/O is supported.
   _POSIX_SYNCHRONIZED_IO	Synchronizing file data is supported.
   _POSIX_FSYNC			The fsync function is present.
   _POSIX_MAPPED_FILES		Mapping of files to memory is supported.
   _POSIX_MEMLOCK		Locking of all memory is supported.
   _POSIX_MEMLOCK_RANGE		Locking of ranges of memory is supported.
   _POSIX_MEMORY_PROTECTION	Setting of memory protections is supported.
   _POSIX_MESSAGE_PASSING	POSIX.4 message queues are supported.
   _POSIX_SEMAPHORES		POSIX.4 counting semaphores are supported.
   _POSIX_SHARED_MEMORY_OBJECTS	POSIX.4 shared memory objects are supported.
   _POSIX_PII			Protocol-independent interfaces are supported.
   _POSIX_PII_XTI		XTI protocol-indep. interfaces are supported.
   _POSIX_PII_SOCKET		Socket protocol-indep. interfaces are supported.
   _POSIX_PII_INTERNET		Internet family of protocols supported.
   _POSIX_PII_INTERNET_STREAM	Connection-mode Internet protocol supported.
   _POSIX_PII_INTERNET_DGRAM	Connectionless Internet protocol supported.
   _POSIX_PII_OSI		ISO/OSI family of protocols supported.
   _POSIX_PII_OSI_COTS		Connection-mode ISO/OSI service supported.
   _POSIX_PII_OSI_CLTS		Connectionless ISO/OSI service supported.
   _POSIX_POLL			Implementation supports `poll' function.
   _POSIX_SELECT		Implementation supports `select' and `pselect'.

   _XOPEN_SHM			Shared memory interface according to XPG4.2.

   If any of these symbols is defined as -1, the corresponding option is not
   true for any file.  If any is defined as other than -1, the corresponding
   option is true for all files.  If a symbol is not defined at all, the value
   for a specific file can be obtained from `pathconf' and `fpathconf'.

   _POSIX_CHOWN_RESTRICTED	Only the super user can use `chown' to change
   				the owner of a file.  `chown' can only be used
				to change the group ID of a file to a group of
				which the calling process is a member.
   _POSIX_NO_TRUNC		Pathname components longer than
   				NAME_MAX generate an error.
   _POSIX_VDISABLE		If defined, if the value of an element of the
				`c_cc' member of `struct termios' is
				_POSIX_VDISABLE, no character will have the
				effect associated with that element.
   _POSIX_SYNC_IO		Synchronous I/O may be performed.
   _POSIX_ASYNC_IO		Asynchronous I/O may be performed.
   _POSIX_PRIO_IO		Prioritized Asynchronous I/O may be performed.
   */

#include <posix_opt.h>


/* Standard file descriptors.  */
#define	STDIN_FILENO	0	/* Standard input.  */
#define	STDOUT_FILENO	1	/* Standard output.  */
#define	STDERR_FILENO	2	/* Standard error output.  */


/* All functions that are not declared anywhere else.  */

#include <gnu/types.h>

#ifndef	ssize_t
typedef __ssize_t ssize_t;
#define	ssize_t	ssize_t
#endif

#define	__need_size_t
#define __need_NULL
#include <stddef.h>


/* Values for the second argument to access.
   These may be OR'd together.  */
#define	R_OK	4		/* Test for read permission.  */
#define	W_OK	2		/* Test for write permission.  */
#define	X_OK	1		/* Test for execute permission.  */
#define	F_OK	0		/* Test for existence.  */

/* Test for access to NAME using the real UID and real GID.  */
extern int __access __P ((__const char *__name, int __type));
extern int access __P ((__const char *__name, int __type));

#ifdef __USE_GNU
/* Test for access to NAME using the effective UID and GID
   (as normal file operations use).  */
extern int euidaccess __P ((__const char *__name, int __type));
#endif


/* Values for the WHENCE argument to lseek.  */
#ifndef	_STDIO_H		/* <stdio.h> has the same definitions.  */
#define	SEEK_SET	0	/* Seek from beginning of file.  */
#define	SEEK_CUR	1	/* Seek from current position.  */
#define	SEEK_END	2	/* Seek from end of file.  */
#endif

#if defined (__USE_BSD) && !defined (L_SET)
/* Old BSD names for the same constants; just for compatibility.  */
#define	L_SET		SEEK_SET
#define	L_INCR		SEEK_CUR
#define	L_XTND		SEEK_END
#endif


/* Move FD's file position to OFFSET bytes from the
   beginning of the file (if WHENCE is SEEK_SET),
   the current position (if WHENCE is SEEK_CUR),
   or the end of the file (if WHENCE is SEEK_END).
   Return the new file position.  */
extern __off_t __lseek __P ((int __fd, __off_t __offset, int __whence));
extern __off_t lseek __P ((int __fd, __off_t __offset, int __whence));

/* Close the file descriptor FD.  */
extern int __close __P ((int __fd));
extern int close __P ((int __fd));

/* Read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF.  */
extern ssize_t __read __P ((int __fd, __ptr_t __buf, size_t __nbytes));
extern ssize_t read __P ((int __fd, __ptr_t __buf, size_t __nbytes));

/* Write N bytes of BUF to FD.  Return the number written, or -1.  */
extern ssize_t __write __P ((int __fd, __const __ptr_t __buf, size_t __n));
extern ssize_t write __P ((int __fd, __const __ptr_t __buf, size_t __n));


/* Create a one-way communication channel (pipe).
   If successful, two file descriptors are stored in PIPEDES;
   bytes written on PIPEDES[1] can be read from PIPEDES[0].
   Returns 0 if successful, -1 if not.  */
extern int __pipe __P ((int __pipedes[2]));
extern int pipe __P ((int __pipedes[2]));

/* Schedule an alarm.  In SECONDS seconds, the process will get a SIGALRM.
   If SECONDS is zero, any currently scheduled alarm will be cancelled.
   The function returns the number of seconds remaining until the last
   alarm scheduled would have signaled, or zero if there wasn't one.
   There is no return value to indicate an error, but you can set `errno'
   to 0 and check its value after calling `alarm', and this might tell you.
   The signal may come late due to processor scheduling.  */
extern unsigned int alarm __P ((unsigned int __seconds));

/* Make the process sleep for SECONDS seconds, or until a signal arrives
   and is not ignored.  The function returns the number of seconds less
   than SECONDS which it actually slept (thus zero if it slept the full time).
   If a signal handler does a `longjmp' or modifies the handling of the
   SIGALRM signal while inside `sleep' call, the handling of the SIGALRM
   signal afterwards is undefined.  There is no return value to indicate
   error, but if `sleep' returns SECONDS, it probably didn't work.  */
extern unsigned int sleep __P ((unsigned int __seconds));

#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Set an alarm to go off (generating a SIGALRM signal) in VALUE
   microseconds.  If INTERVAL is nonzero, when the alarm goes off, the
   timer is reset to go off every INTERVAL microseconds thereafter.
   Returns the number of microseconds remaining before the alarm.  */
extern unsigned int ualarm __P ((unsigned int __value,
				 unsigned int __interval));

/* Sleep USECONDS microseconds, or until a signal arrives that is not blocked
   or ignored.  */
extern void usleep __P ((unsigned int __useconds));
#endif


/* Suspend the process until a signal arrives.
   This always returns -1 and sets `errno' to EINTR.  */
extern int pause __P ((void));


/* Change the owner and group of FILE.  */
extern int __chown __P ((__const char *__file,
			 __uid_t __owner, __gid_t __group));
extern int chown __P ((__const char *__file,
		       __uid_t __owner, __gid_t __group));

#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Change the owner and group of the file that FD is open on.  */
extern int __fchown __P ((int __fd,
			  __uid_t __owner, __gid_t __group));
extern int fchown __P ((int __fd,
			__uid_t __owner, __gid_t __group));


/* Change owner and group of FILE, if it is a symbolic
   link the ownership of the symbolic link is changed.  */
extern int __lchown __P ((__const char *__file, __uid_t __owner,
			  __gid_t __group));
extern int lchown __P ((__const char *__file, __uid_t __owner,
			__gid_t __group));

#endif /* Use BSD || X/Open Unix.  */

/* Change the process's working directory to PATH.  */
extern int __chdir __P ((__const char *__path));
extern int chdir __P ((__const char *__path));

#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Change the process's working directory to the one FD is open on.  */
extern int fchdir __P ((int __fd));
#endif

/* Get the pathname of the current working directory,
   and put it in SIZE bytes of BUF.  Returns NULL if the
   directory couldn't be determined or SIZE was too small.
   If successful, returns BUF.  In GNU, if BUF is NULL,
   an array is allocated with `malloc'; the array is SIZE
   bytes long, unless SIZE <= 0, in which case it is as
   big as necessary.  */
extern char *__getcwd __P ((char *__buf, size_t __size));
extern char *getcwd __P ((char *__buf, size_t __size));

#ifdef	__USE_GNU
/* Return a malloc'd string containing the current directory name.
   If the environment variable `PWD' is set, and its value is correct,
   that value is used.  */
extern char *get_current_dir_name __P ((void));

/* Get the canonical absolute name of the named directory, and put it in SIZE
   bytes of BUF.  Returns NULL if the directory couldn't be determined or
   SIZE was too small.  If successful, returns BUF.  In GNU, if BUF is
   NULL, an array is allocated with `malloc'; the array is SIZE bytes long,
   unless SIZE <= 0, in which case it is as big as necessary.  */

char *__canonicalize_directory_name_internal __P ((__const char *__thisdir,
						   char *__buf,
						   size_t __size));
#endif

#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Put the absolute pathname of the current working directory in BUF.
   If successful, return BUF.  If not, put an error message in
   BUF and return NULL.  BUF should be at least PATH_MAX bytes long.  */
extern char *getwd __P ((char *__buf));
#endif


/* Duplicate FD, returning a new file descriptor on the same file.  */
extern int __dup __P ((int __fd));
extern int dup __P ((int __fd));

/* Duplicate FD to FD2, closing FD2 and making it open on the same file.  */
extern int __dup2 __P ((int __fd, int __fd2));
extern int dup2 __P ((int __fd, int __fd2));

/* NULL-terminated array of "NAME=VALUE" environment variables.  */
extern char **__environ;
#ifdef __USE_GNU
extern char **environ;
#endif


/* Replace the current process, executing PATH with arguments ARGV and
   environment ENVP.  ARGV and ENVP are terminated by NULL pointers.  */
extern int __execve __P ((__const char *__path, char *__const __argv[],
			  char *__const __envp[]));
extern int execve __P ((__const char *__path, char *__const __argv[],
			char *__const __envp[]));

#ifdef __USE_GNU
/* Execute the file FD refers to, overlaying the running program image.
   ARGV and ENVP are passed to the new program, as for `execve'.  */
extern int fexecve __P ((int __fd,
			 char *__const __argv[], char *__const __envp[]));

#endif


/* Execute PATH with arguments ARGV and environment from `environ'.  */
extern int execv __P ((__const char *__path, char *__const __argv[]));

/* Execute PATH with all arguments after PATH until a NULL pointer,
   and the argument after that for environment.  */
extern int execle __P ((__const char *__path, __const char *__arg, ...));

/* Execute PATH with all arguments after PATH until
   a NULL pointer and environment from `environ'.  */
extern int execl __P ((__const char *__path, __const char *__arg, ...));

/* Execute FILE, searching in the `PATH' environment variable if it contains
   no slashes, with arguments ARGV and environment from `environ'.  */
extern int execvp __P ((__const char *__file, char *__const __argv[]));

/* Execute FILE, searching in the `PATH' environment variable if
   it contains no slashes, with all arguments after FILE until a
   NULL pointer and environment from `environ'.  */
extern int execlp __P ((__const char *__file, __const char *__arg, ...));


#if defined(__USE_MISC) || defined(__USE_XOPEN)
/* Add INC to priority of the current process.  */
extern int nice __P ((int __inc));
#endif


/* Terminate program execution with the low-order 8 bits of STATUS.  */
extern void _exit __P ((int __status)) __attribute__ ((__noreturn__));


/* Get the `_PC_*' symbols for the NAME argument to `pathconf' and `fpathconf';
   the `_SC_*' symbols for the NAME argument to `sysconf';
   and the `_CS_*' symbols for the NAME argument to `confstr'.  */
#include <confname.h>

/* Get file-specific configuration information about PATH.  */
extern long int __pathconf __P ((__const char *__path, int __name));
extern long int pathconf __P ((__const char *__path, int __name));

/* Get file-specific configuration about descriptor FD.  */
extern long int __fpathconf __P ((int __fd, int __name));
extern long int fpathconf __P ((int __fd, int __name));

/* Get the value of the system variable NAME.  */
extern long int __sysconf __P ((int __name));
extern long int sysconf __P ((int __name));

#ifdef	__USE_POSIX2
/* Get the value of the string-valued system variable NAME.  */
extern size_t confstr __P ((int __name, char *__buf, size_t __len));
#endif


/* Get the process ID of the calling process.  */
extern __pid_t __getpid __P ((void));
extern __pid_t getpid __P ((void));

/* Get the process ID of the calling process's parent.  */
extern __pid_t __getppid __P ((void));
extern __pid_t getppid __P ((void));

/* Get the process group ID of the calling process.  */
extern __pid_t getpgrp __P ((void));

/* Set the process group ID of the process matching PID to PGID.
   If PID is zero, the current process's process group ID is set.
   If PGID is zero, the process ID of the process is used.  */
extern int setpgid __P ((__pid_t __pid, __pid_t __pgid));

/* Get the process group ID of process PID.  */
extern __pid_t __getpgid __P ((__pid_t __pid));
#ifdef __USE_XOPEN_EXTENDED
extern __pid_t getpgid __P ((__pid_t __pid));
#endif

#if defined(__USE_SVID) || defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Both System V and BSD have `setpgrp' functions, but with different
   calling conventions.  The BSD function is the same as POSIX.1 `setpgid'
   (above).  The System V function takes no arguments and puts the calling
   process in its on group like `setpgid (0, 0)'.

   New programs should always use `setpgid' instead.

   The default in GNU is to provide the System V function.  The BSD
   function is available under -D_BSD_SOURCE with -lbsd-compat.  */

#ifndef	__FAVOR_BSD

/* Set the process group ID of the calling process to its own PID.
   This is exactly the same as `setpgid (0, 0)'.  */
extern int setpgrp __P ((void));

#else

/* Another name for `setpgid' (above).  */
extern int setpgrp __P ((__pid_t __pid, __pid_t __pgrp));

#endif	/* Favor BSD.  */
#endif	/* Use SVID or BSD.  */

/* Create a new session with the calling process as its leader.
   The process group IDs of the session and the calling process
   are set to the process ID of the calling process, which is returned.  */
extern __pid_t __setsid __P ((void));
extern __pid_t setsid __P ((void));

#ifdef __USE_XOPEN_EXTENDED
/* Return the session ID of the given process.  */
extern __pid_t getsid __P ((__pid_t __pid));
#endif

/* Get the real user ID of the calling process.  */
extern __uid_t __getuid __P ((void));
extern __uid_t getuid __P ((void));

/* Get the effective user ID of the calling process.  */
extern __uid_t __geteuid __P ((void));
extern __uid_t geteuid __P ((void));

/* Get the real group ID of the calling process.  */
extern __gid_t __getgid __P ((void));
extern __gid_t getgid __P ((void));

/* Get the effective group ID of the calling process.  */
extern __gid_t __getegid __P ((void));
extern __gid_t getegid __P ((void));

/* If SIZE is zero, return the number of supplementary groups
   the calling process is in.  Otherwise, fill in the group IDs
   of its supplementary groups in LIST and return the number written.  */
extern int __getgroups __P ((int __size, __gid_t __list[]));
extern int getgroups __P ((int __size, __gid_t __list[]));

#ifdef	__USE_GNU
/* Return nonzero iff the calling process is in group GID.  */
extern int __group_member __P ((__gid_t __gid));
extern int group_member __P ((__gid_t __gid));
#endif

/* Set the user ID of the calling process to UID.
   If the calling process is the super-user, set the real
   and effective user IDs, and the saved set-user-ID to UID;
   if not, the effective user ID is set to UID.  */
extern int __setuid __P ((__uid_t __uid));
extern int setuid __P ((__uid_t __uid));

#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Set the real user ID of the calling process to RUID,
   and the effective user ID of the calling process to EUID.  */
extern int __setreuid __P ((__uid_t __ruid, __uid_t __euid));
extern int setreuid __P ((__uid_t __ruid, __uid_t __euid));
#endif

#ifdef	__USE_BSD
/* Set the effective user ID of the calling process to UID.  */
extern int seteuid __P ((__uid_t __uid));
#endif /* Use BSD.  */

/* Set the group ID of the calling process to GID.
   If the calling process is the super-user, set the real
   and effective group IDs, and the saved set-group-ID to GID;
   if not, the effective group ID is set to GID.  */
extern int __setgid __P ((__gid_t __gid));
extern int setgid __P ((__gid_t __gid));

#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Set the real group ID of the calling process to RGID,
   and the effective group ID of the calling process to EGID.  */
extern int __setregid __P ((__gid_t __rgid, __gid_t __egid));
extern int setregid __P ((__gid_t __rgid, __gid_t __egid));
#endif

#ifdef __USE_BSD
/* Set the effective group ID of the calling process to GID.  */
extern int setegid __P ((__gid_t __gid));
#endif /* Use BSD.  */


/* Clone the calling process, creating an exact copy.
   Return -1 for errors, 0 to the new process,
   and the process ID of the new process to the old process.  */
extern __pid_t __fork __P ((void));
extern __pid_t fork __P ((void));

#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Clone the calling process, but without copying the whole address space.
   The the calling process is suspended until the the new process exits or is
   replaced by a call to `execve'.  Return -1 for errors, 0 to the new process,
   and the process ID of the new process to the old process.  */
extern __pid_t __vfork __P ((void));
extern __pid_t vfork __P ((void));
#endif /* Use BSD. */


/* Return the pathname of the terminal FD is open on, or NULL on errors.
   The returned storage is good only until the next call to this function.  */
extern char *ttyname __P ((int __fd));

/* Store at most BUFLEN characters of the pathname of the terminal FD is
   open on in BUF.  Return 0 on success, -1 otherwise.  */
extern int __ttyname_r __P ((int __fd, char *__buf, size_t __buflen));
extern int ttyname_r __P ((int __fd, char *__buf, size_t __buflen));

/* Return 1 if FD is a valid descriptor associated
   with a terminal, zero if not.  */
extern int __isatty __P ((int __fd));
extern int isatty __P ((int __fd));

#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Return the index into the active-logins file (utmp) for
   the controlling terminal.  */
extern int ttyslot __P ((void));
#endif


/* Make a link to FROM named TO.  */
extern int __link __P ((__const char *__from, __const char *__to));
extern int link __P ((__const char *__from, __const char *__to));

#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)
/* Make a symbolic link to FROM named TO.  */
extern int __symlink __P ((__const char *__from, __const char *__to));
extern int symlink __P ((__const char *__from, __const char *__to));

/* Read the contents of the symbolic link PATH into no more than
   LEN bytes of BUF.  The contents are not null-terminated.
   Returns the number of characters read, or -1 for errors.  */
extern int __readlink __P ((__const char *__path, char *__buf, size_t __len));
extern int readlink __P ((__const char *__path, char *__buf, size_t __len));
#endif /* Use BSD.  */

/* Remove the link NAME.  */
extern int __unlink __P ((__const char *__name));
extern int unlink __P ((__const char *__name));

/* Remove the directory PATH.  */
extern int __rmdir __P ((__const char *__path));
extern int rmdir __P ((__const char *__path));


/* Return the foreground process group ID of FD.  */
extern __pid_t tcgetpgrp __P ((int __fd));

/* Set the foreground process group ID of FD set PGRP_ID.  */
extern int tcsetpgrp __P ((int __fd, __pid_t __pgrp_id));


/* Return the login name of the user.  */
extern char *getlogin __P ((void));
#ifdef __USE_REENTRANT
/* Return at most NAME_LEN characters of the login name of the user in NAME.
   If it cannot be determined or some other error occurred, return the error
   code.  Otherwise return 0.  */
extern int getlogin_r __P ((char *__name, size_t __name_len));
#endif

#ifdef	__USE_BSD
/* Set the login name returned by `getlogin'.  */
extern int setlogin __P ((__const char *__name));
#endif


#ifdef	__USE_POSIX2
/* Process the arguments in ARGV (ARGC of them, minus
   the program name) for options given in OPTS.

   If `opterr' is zero, no messages are generated
   for invalid options; it defaults to 1.
   `optind' is the current index into ARGV.
   `optarg' is the argument corresponding to the current option.
   Return the option character from OPTS just read.
   Return -1 when there are no more options.
   For unrecognized options, or options missing arguments,
   `optopt' is set to the option letter, and '?' is returned.

   The OPTS string is a list of characters which are recognized option
   letters, optionally followed by colons, specifying that that letter
   takes an argument, to be placed in `optarg'.

   If a letter in OPTS is followed by two colons, its argument is optional.
   This behavior is specific to the GNU `getopt'.

   The argument `--' causes premature termination of argument scanning,
   explicitly telling `getopt' that there are no more options.

   If OPTS begins with `--', then non-option arguments
   are treated as arguments to the option '\0'.
   This behavior is specific to the GNU `getopt'.  */
extern int getopt __P ((int __argc, char *__const * __argv,
			__const char *__opts));
extern int opterr;
extern int optind;
extern int optopt;
extern char *optarg;
#endif


#if defined(__USE_BSD) || defined (__USE_XOPEN)

/* Put the name of the current host in no more than LEN bytes of NAME.
   The result is null-terminated if LEN is large enough for the full
   name and the terminator.  */
extern int __gethostname __P ((char *__name, size_t __len));
extern int gethostname __P ((char *__name, size_t __len));

/* Set the name of the current host to NAME, which is LEN bytes long.
   This call is restricted to the super-user.  */
extern int sethostname __P ((__const char *__name, size_t __len));

/* Set the current machine's Internet number to ID.
   This call is restricted to the super-user.  */
extern int sethostid __P ((long int __id));


/* Get and set the NIS (aka YP) domain name, if any.
   Called just like `gethostname' and `sethostname'.
   The NIS domain name is usually the empty string when not using NIS.  */
extern int getdomainname __P ((char *__name, size_t __len));
extern int setdomainname __P ((__const char *__name, size_t __len));


/* Make all changes done to FD actually appear on disk.  */
extern int fsync __P ((int __fd));


/* Revoke access permissions to all processes currently communicating
   with the control terminal, and then send a SIGHUP signal to the process
   group of the control terminal.  */
extern int vhangup __P ((void));

/* Revoke the access of all descriptors currently open on FILE.  */
extern int revoke __P ((__const char *__file));


/* Enable statistical profiling, writing samples of the PC into at most
   SIZE bytes of SAMPLE_BUFFER; every processor clock tick while profiling
   is enabled, the system examines the user PC and increments
   SAMPLE_BUFFER[((PC - OFFSET) / 2) * SCALE / 65536].  If SCALE is zero,
   disable profiling.  Returns zero on success, -1 on error.  */
extern int profil __P ((unsigned short int *__sample_buffer, size_t __size,
			size_t __offset, unsigned int __scale));


/* Turn accounting on if NAME is an existing file.  The system will then write
   a record for each process as it terminates, to this file.  If NAME is NULL,
   turn accounting off.  This call is restricted to the super-user.  */
extern int acct __P ((__const char *__name));

/* Make PATH be the root directory (the starting point for absolute paths).
   This call is restricted to the super-user.  */
extern int chroot __P ((__const char *__path));


/* Successive calls return the shells listed in `/etc/shells'.  */
extern char *getusershell __P ((void));
extern void endusershell __P ((void)); /* Discard cached info.  */
extern void setusershell __P ((void)); /* Rewind and re-read the file.  */


/* Prompt with PROMPT and read a string from the terminal without echoing.
   Uses /dev/tty if possible; otherwise stderr and stdin.  */
extern char *getpass __P ((__const char *__prompt));

/* Put the program in the background, and dissociate from the controlling
   terminal.  If NOCHDIR is zero, do `chdir ("/")'.  If NOCLOSE is zero,
   redirects stdin, stdout, and stderr to /dev/null.  */
extern int daemon __P ((int __nochdir, int __noclose));

#endif /* Use BSD || X/Open.  */


#if defined(__USE_BSD) || defined(__USE_XOPEN_EXTENDED)

/* Return the current machine's Internet number.  */
extern long int gethostid __P ((void));

/* Make all changes done to all files actually appear on disk.  */
extern int sync __P ((void));


/* Return the number of bytes in a page.  This is the system's page size,
   which is not necessarily the same as the hardware page size.  */
extern int __getpagesize __P ((void));
extern int getpagesize __P ((void));


/* Truncate FILE to LENGTH bytes.  */
extern int truncate __P ((__const char *__file, __off_t __length));

/* Truncate the file FD is open on to LENGTH bytes.  */
extern int ftruncate __P ((int __fd, __off_t __length));


/* Return the maximum number of file descriptors
   the current process could possibly have.  */
extern int __getdtablesize __P ((void));
extern int getdtablesize __P ((void));

#endif /* Use BSD || X/Open Unix.  */


#if defined(__USE_MISC) || defined(__USE_XOPEN_EXTENDED)

/* Set the end of accessible data space (aka "the break") to ADDR.
   Returns zero on success and -1 for errors (with errno set).  */
extern int __brk __P ((__ptr_t __addr));
extern int brk __P ((__ptr_t __addr));

#define __need_ptrdiff_t
#include <stddef.h>

/* Increase or decrease the end of accessible data space by DELTA bytes.
   If successful, returns the address the previous end of data space
   (i.e. the beginning of the new space, if DELTA > 0);
   returns (void *) -1 for errors (with errno set).  */
extern __ptr_t __sbrk __P ((ptrdiff_t __delta));
extern __ptr_t sbrk __P ((ptrdiff_t __delta));
#endif


#ifdef __USE_MISC
/* Invoke `system call' number SYSNO, passing it the remaining arguments.
   This is completely system-dependent, and not often useful.

   In Unix, `syscall' sets `errno' for all errors and most calls return -1
   for errors; in many systems you cannot pass arguments or get return
   values for all system calls (`pipe', `fork', and `getppid' typically
   among them).

   In Mach, all system calls take normal arguments and always return an
   error code (zero for success).  */
extern long int syscall __P ((long int __sysno, ...));

#endif	/* Use misc.  */


#if (defined (__USE_MISC) || defined (__USE_XOPEN_EXTENDED)) \
    && !defined (F_LOCK)
/* NOTE: These declarations also appear in <fcntl.h>; be sure to keep both
   files consistent.  Some systems have them there and some here, and some
   software depends on the macros being defined without including both.  */

/* `lockf' is a simpler interface to the locking facilities of `fcntl'.
   LEN is always relative to the current file position.
   The CMD argument is one of the following.  */

#define F_ULOCK 0       /* Unlock a previously locked region.  */
#define F_LOCK  1       /* Lock a region for exclusive use.  */
#define F_TLOCK 2       /* Test and lock a region for exclusive use.  */
#define F_TEST  3       /* Test a region for other processes locks.  */

extern int lockf __P ((int __fd, int __cmd, __off_t __len));
#endif /* Use misc and F_LOCK not already defined.  */


#ifdef __USE_GNU

/* Evaluate EXPRESSION, and repeat as long as it returns -1 with `errno'
   set to EINTR.  */

#define TEMP_FAILURE_RETRY(expression) \
  (__extension__							      \
    ({ long int __result;						      \
       do __result = (long int) (expression);				      \
       while (__result == -1L && errno == EINTR);			      \
       __result; }))							      \


/* This variable is set nonzero at startup if the process's effective IDs
   differ from its real IDs, or it is otherwise indicated that extra
   security should be used.  When this is set the dynamic linker ignores
   the various environment variables that normally affect it.  */
extern int __libc_enable_secure;

#endif

#ifdef __USE_POSIX199309
/* Synchronize at least the data part of a file with the underlying
   media.  */
extern int fdatasync __P ((int __fildes));
#endif /* Use POSIX199309 */


/* XPG4.2 specifies that prototypes for the encryption functions must
   be defined here.  */
#ifdef	__USE_XOPEN
/* Encrypt at most 8 characters from KEY using salt to perturb DES.  */
extern char *crypt __P ((__const char *__key, __const char *__salt));

/* Setup DES tables according KEY.  */
extern void setkey __P ((__const char *__key));

/* Encrypt data in BLOCK in place if EDFLAG is zero; otherwise decrypt
   block in place.  */
extern void encrypt __P ((char *__block, int __edflag));


/* Swab pairs bytes in the first N bytes of the area pointed to by
   FROM and copy the result to TO.  The value of TO must not be in the
   range [FROM - N + 1, FROM - 1].  If N is odd the first byte in FROM
   is without partner.  */
extern void swab __P ((__const char *__from, char *__to, ssize_t __n));
#endif

__END_DECLS

#endif /* unistd.h  */
