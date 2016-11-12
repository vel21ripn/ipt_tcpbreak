/*
 *	"TCPBREAK" target extension for iptables
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <xtables.h>
#include "ipt_TCPBREAK.h"

enum {
	O_SET_LOC = 0,
	O_SET_RAW,
};

#define s struct xt_tcpbreak_tgt
static const struct xt_option_entry tcpbreak_tg_opts[] = {
        {.name = "http302", .id = O_SET_LOC, .type = XTTYPE_STRING,
		.flags = XTOPT_PUT, XTOPT_POINTER(s, location), .min = 1},
        {.name = "raw",      .id = O_SET_RAW, .type = XTTYPE_STRING,
		.flags = XTOPT_PUT, XTOPT_POINTER(s, location), .min = 1},
	XTOPT_TABLEEND,
};
#undef s

static char _print_buf[sizeof(struct xt_tcpbreak_tgt)*2];
static char *cvt_hex = "0123456789abcdef";

static char *printable(const char *src) {
char c,*o = _print_buf;
int len = sizeof(_print_buf)-1;
while(len && !!(c = *src++)) {
	if (c >= ' ' && c != '\\' && (unsigned char)c < 127 ) {
		*o++ = c, len--;
		continue;
	}
	/* skip utf-8 code */
	if((c & 0xe0) == 0xc0 && (*src & 0xc0) == 0x80) {
		*o++ = c, len--;
		if(!len) break;
		*o++ = *src++, len--;
		continue;
	}
	*o++ = '\\', len--;
	if(!len) break;
	if (c == '\\') {
		*o++ = c, len--;
	} else
	if (c == '\r') {
		*o++ = 'r', len--;
	} else
	if (c == '\n') {
		*o++ = 'n', len--;
	} else
	if (c == '\t') {
		*o++ = 't', len--;
	} else {
		if(len >= 2) {
    		*o++ = cvt_hex[(c >> 4) & 0xf];
    		*o++ = cvt_hex[c & 0xf];
		len -= 2;
		} else break;
	}
}
*o = '\0';
return _print_buf;
}

static char *parse_opt_string(const char *src,char *buf, size_t len) {
char c;
int r;

while(len > 0 && !!(c = *src++)) {
    if(c == '\\') {
	c = *src++;
	switch(c) {
	  case '\\':
		  break;
	  case 'r':
		  c = '\r';
		  break;
	  case 'n':
		  c = '\n';
		  break;
	  case 't':
		  c = '\t';
		  break;
	  default:
		  if (strchr(cvt_hex, c) && strchr(cvt_hex, *src)) {
			r = (strchr(cvt_hex, c) - &cvt_hex[0]) << 4;
			c = *src++;
			r |= strchr(cvt_hex, c) - &cvt_hex[0];
			c = r;
		  } else {
		  	*buf++ = '\\'; len--;
		  }
		  break;
	}
    }
    if(!c) break;
    if(len) {
	*buf++ = c;
	len--;
    }
}
*buf = '\0';
return buf;
}

static void tcpbreak_tg_help(void)
{
	printf("tcpbreak [--http302 url | --raw string]\n\n");
}

static void tcpbreak_tg_save(const void *ip, const struct xt_entry_target *target)
{
	struct xt_tcpbreak_tgt *tginfo = (void *)target->data;
	if(tginfo->mode)
		printf(" --%s %s",tginfo->mode == 'L' ? "http302":"raw",
				  printable(tginfo->location));
}
static void tcpbreak_tg_print(const void *ip, const struct xt_entry_target *target,
		                          int numeric)
{
	struct xt_tcpbreak_tgt *tginfo = (void *)target->data;
	if(tginfo->mode)
		printf(" %s '%s'", tginfo->mode == 'L' ? "http302":"raw", printable(tginfo->location));
}

static void tcpbreak_tg_parse(struct xt_option_call *cb)
{
	struct xt_tcpbreak_tgt *tginfo = cb->data;
	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_SET_LOC:
		if(tginfo->mode == 'R')
	                xtables_error(PARAMETER_PROBLEM,
        	                   "TCPBREAK target: can't mix http302 and raw");
		parse_opt_string(cb->arg,tginfo->location,sizeof(tginfo->location)-1);
		tginfo->mode = 'L';
		break;
	case O_SET_RAW:
		if(tginfo->mode == 'L')
	                xtables_error(PARAMETER_PROBLEM,
        	                   "TCPBREAK target: can't mix http302 and raw");
		parse_opt_string(cb->arg,tginfo->location,sizeof(tginfo->location)-1);
		tginfo->mode = 'R';
		break;
	default:
                xtables_error(PARAMETER_PROBLEM,
                           "TCPBREAK target: unknown --%s",
                           cb->entry->name);
	}
}

static void tcpbreak_tg_check(struct xt_fcheck_call *cb)
{
	struct xt_tcpbreak_tgt *tginfo = cb->data;

	if(tginfo->mode == 'R' || tginfo->mode == 'L') {
		if(tginfo->location[0]) return;
		xtables_error(PARAMETER_PROBLEM, "Missing argument for '%s'\n",tginfo->mode == 'L' ? "http302":"raw");
	}
}

static struct xtables_target tcpbreak_tg_reg = {
	.version	= XTABLES_VERSION,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct xt_tcpbreak_tgt)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_tcpbreak_tgt)),
	.name		= "TCPBREAK",
	.family		= NFPROTO_IPV4,
	.help		= tcpbreak_tg_help,
	.print		= tcpbreak_tg_print,
	.save		= tcpbreak_tg_save,
	.x6_parse	= tcpbreak_tg_parse,
	.x6_fcheck	= tcpbreak_tg_check,
	.x6_options	= tcpbreak_tg_opts,
};


static __attribute__((constructor)) void tcpbreak_tg_ldr(void)
{
	xtables_register_target(&tcpbreak_tg_reg);
}
