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

static void tcpbreak_tg_help(void)
{
	printf("tcpbreak [--http302 url | --raw string]\n\n");
}

static void tcpbreak_tg_save(const void *ip, const struct xt_entry_target *target)
{
	struct xt_tcpbreak_tgt *tginfo = (void *)target->data;
	if(tginfo->mode)
		printf(" --%s %s",tginfo->mode == 'L' ? "http302":"raw",
				  tginfo->location);
}
static void tcpbreak_tg_print(const void *ip, const struct xt_entry_target *target,
		                          int numeric)
{
	struct xt_tcpbreak_tgt *tginfo = (void *)target->data;
	if(tginfo->mode)
		printf(" %s %s", tginfo->mode == 'L' ? "http302":"raw", tginfo->location);
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
		strncpy(tginfo->location,cb->arg,sizeof(tginfo->location)-1);
		tginfo->mode = 'L';
		break;
	case O_SET_RAW:
		if(tginfo->mode == 'L')
	                xtables_error(PARAMETER_PROBLEM,
        	                   "TCPBREAK target: can't mix http302 and raw");
		strncpy(tginfo->location,cb->arg,sizeof(tginfo->location)-1);
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
