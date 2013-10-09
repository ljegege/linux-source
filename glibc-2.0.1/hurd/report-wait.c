/* Report on what a thread in our task is waiting for.
Copyright (C) 1996 Free Software Foundation, Inc.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <hurd.h>
#include <hurd/signal.h>
#include <hurd/fd.h>
#include <string.h>
#include <assert.h>
#include <hurd/msg_server.h>
#include "thread_state.h"
#include "intr-msg.h"

static void
describe_number (string_t description, const char *flavor, unsigned long int i)
{
  unsigned long int j;
  char *p = __stpcpy (description, flavor);

  /* Allocate space for the number at the end of DESCRIPTION.  */
  for (j = i; j >= 10; j /= 10)
    p++;
  p[1] = '\0';

  do
    {
      *p-- = '0' + i % 10;
      i /= 10;
    } while (i != 0);
  assert (*p == '#');
}

static void
describe_port (string_t description, mach_port_t port)
{
  int i;

  if (port == __mach_task_self ())
    {
      strcpy (description, "task-self");
      return;
    }

  for (i = 0; i < _hurd_nports; ++i)
    if (port == _hurd_ports[i].port)
      {
	describe_number (description, "init#", i);
	return;
      }

  if (_hurd_init_dtable)
    {
      for (i = 0; i < _hurd_init_dtablesize; ++i)
	if (port == _hurd_init_dtable[i])
	  {
	    describe_number (description, "fd#", i);
	    return;
	  }
    }
  else if (_hurd_dtable)
    {
      for (i = 0; i < _hurd_dtablesize; ++i)
	if (_hurd_dtable[i] == NULL)
	  continue;
	else if (port == _hurd_dtable[i]->port.port)
	  {
	    describe_number (description, "fd#", i);
	    return;
	  }
	else if (port == _hurd_dtable[i]->ctty.port)
	  {
	    describe_number (description, "bgfd#", i);
	    return;
	  }
    }

  describe_number (description, "port#", port);
}


/* Common defn so we don't link in the itimer code unnecessarily.  */
thread_t _hurd_itimer_thread; /* XXX */

kern_return_t
_S_msg_report_wait (mach_port_t msgport, thread_t thread,
		    string_t description, int *msgid)
{
  *msgid = 0;

  if (thread == _hurd_msgport_thread)
    /* Cute.  */
    strcpy (description, "msgport");
  else if (thread == _hurd_itimer_thread)
    strcpy (description, "itimer");
  else
    {
      /* Make sure this is really one of our threads.  */

      struct hurd_sigstate *ss;

      __mutex_lock (&_hurd_siglock);
      for (ss = _hurd_sigstates; ss != NULL; ss = ss->next)
	if (ss->thread == thread)
	  break;
      __mutex_unlock (&_hurd_siglock);
      if (ss == NULL)
	/* To hell with you.  */
	return EINVAL;

      if (ss->suspended != MACH_PORT_NULL)
	strcpy (description, "sigsuspend");
      else
	{
	  /* Examine the thread's state to see if it is blocked in an RPC.  */

	  struct machine_thread_state state;
	  mach_msg_type_number_t count = MACHINE_THREAD_STATE_COUNT;
	  error_t err;

	  err = __thread_get_state (thread, MACHINE_THREAD_STATE_FLAVOR,
				    (integer_t *) &state, &count);
	  if (err)
	    return err;
	  assert (count == MACHINE_THREAD_STATE_COUNT);
	  if (SYSCALL_EXAMINE (&state, msgid))
	    {
	      /* Blocked in a system call.  */
	      if (*msgid == -25)
		/* mach_msg system call.  Examine its parameters.  */
		describe_port (description, MSG_EXAMINE (&state, msgid));
	      else
		strcpy (description, "kernel");
	    }
	  else
	    description[0] = '\0';
	}
    }

  __mach_port_deallocate (__mach_task_self (), thread);
  return 0;
}

kern_return_t
_S_msg_describe_ports (mach_port_t msgport, mach_port_t refport,
		       mach_port_t *ports, mach_msg_type_number_t nports,
		       char **desc, mach_msg_type_number_t *desclen)
{
  char *p, *end;

  if (__USEPORT (AUTH, msgport != port))
    return EPERM;

  end = *desc + *desclen;
  p = *desc;
  while (nports-- > 0)
    {
      char this[200];
      describe_port (this, *ports++);
      p = __stpncpy (p, this, end - p);
      if (p == end && p[-1] != '\0')
	return ENOMEM;
    }

  *desclen = p - *desc;
  return 0;
}
