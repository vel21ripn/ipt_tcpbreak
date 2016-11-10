#ifndef _XT_IFTAG_H
#define _XT_IFTAG_H

#include <linux/types.h>

struct xt_tcpbreak_tgt {
	char mode,location[1023];
};

#endif /*_XT_IFTAG_H*/
