/* Copyright (C) 1995, 1996, 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, August 1995.

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

#ifndef _SYS_MSQ_BUF_H

#define _SYS_MSQ_BUF_H	1
#include <features.h>

#include <sys/types.h>

/* Define options for message queue functions.  */
#define MSG_NOERROR	010000	/* no error if message is too big */
#define MSG_EXCEPT	020000	/* recv any msg except of specified type */


__BEGIN_DECLS

/* Structure of record for one message inside the kernel.
   The type `struct __msg' is opaque.  */
struct msqid_ds
{
  struct ipc_perm msg_perm;	/* structure describing operation permission */
  struct msg *__msg_first;	/* pointer to first message on queue */
  struct msg *__msg_last;	/* pointer to last message on queue */
  __time_t msg_stime;		/* time of last msgsnd command */
  __time_t msg_rtime;		/* time of last msgrcv command */
  __time_t msg_ctime;		/* time of last change */
  struct wait_queue *__wwait;	/* ??? */
  struct wait_queue *__rwait;	/* ??? */
  unsigned short int __msg_cbytes;/* current number of bytes on queue */
  unsigned short int msg_qnum;	/* number of messages currently on queue */
  unsigned short int msg_qbytes;/* max number of bytes allowed on queue */
  int msg_lspid;		/* pid of last msgsnd() */
  int msg_lrpid;		/* pid of last msgrcv() */
};

#ifdef __USE_MISC

#define msg_cbytes	__msg_cbytes

/* ipcs ctl commands */
#define MSG_STAT 11
#define MSG_INFO 12

/* buffer for msgctl calls IPC_INFO, MSG_INFO */
struct msginfo
{
  int msgpool;
  int msgmap;
  int msgmax;
  int msgmnb;
  int msgmni;
  int msgssz;
  int msgtql;
  ushort  msgseg;
};

#endif /* __USE_MISC */

__END_DECLS

#endif /* _SYS_MSQ_BUF_H */
