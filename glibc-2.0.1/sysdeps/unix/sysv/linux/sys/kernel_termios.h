#ifndef _SYS_KERNEL_TERMIOS_H
#define _SYS_KERNEL_TERMIOS_H 1
/* The following corresponds to the values from the Linux 2.1.20 kernel.  */

/* We need the definition of tcflag_t, cc_t, and speed_t.  */
#include <termbits.h>

#define __KERNEL_NCCS 19

struct __kernel_termios
  {
    tcflag_t c_iflag;		/* input mode flags */
    tcflag_t c_oflag;		/* output mode flags */
    tcflag_t c_cflag;		/* control mode flags */
    tcflag_t c_lflag;		/* local mode flags */
    cc_t c_line;		/* line discipline */
    cc_t c_cc[__KERNEL_NCCS];	/* control characters */
  };

#endif /* sys/kernel_termios.h */
