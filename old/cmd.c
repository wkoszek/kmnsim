/*
 * Copyright (c) 2009 Wojciech Koszek <wkoszek@FreeBSD.czest.pl>
 *                       Piotr Matyja <piotr-matyja@o2.pl>
 *
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "queue.h"
#include "kmnsim.h"

void
cmdlist_show_fp(struct cmdlist *cmdlist, FILE *output)
{
	struct cmd *cmdp;

	TAILQ_FOREACH(cmdp, cmdlist, next)
		fprintf(output, "'%s'\n", cmdp->name);
}

void
cmdlist_show(struct cmdlist *cmdlist)
{

	cmdlist_show_fp(cmdlist, stdout);
}

int
cmd_parse(struct cmdlist **cmdlist, int *cmd_num, const char *cmdstring)
{
	struct cmdlist *l = NULL;
	struct cmd *cmdp = NULL;
	char *tmps = NULL;
	char *cmds = NULL;
	int howmany = 0;

	assert(cmdlist != NULL);
	assert(*cmdlist == NULL);
	assert(cmd_num != NULL);
	assert(cmdstring != NULL);

	l = calloc(sizeof(*l), 1);
	assert(l != NULL);
	TAILQ_INIT(l);

	tmps = strdup(cmdstring);
	assert(tmps != NULL);

	while ((cmds = strsep(&tmps, " ")) != NULL) {
		cmdp = calloc(1, sizeof(*cmdp));
		assert(cmdp != NULL);
		snprintf(cmdp->name, sizeof(cmdp->name), "%s", cmds);
		TAILQ_INSERT_TAIL(l, cmdp, next);
		howmany++;
	}

	if (howmany <= 0)
		return (-1);

	*cmdlist = l;
	*cmd_num = howmany;

	if (cmd_verbose)
		cmdlist_show(l);

	return (0);
}

int
cmd_remove_if_match(struct cmdlist *l, const char *match)
{
	struct cmd *cmd_thing = NULL;
	
	assert(l != NULL && "l nie mo¿e byæ tutaj NULL");

	cmd_thing = TAILQ_FIRST(l);
	assert(cmd_thing != NULL && "lista musi mieæ choæby 1 element");
	if (strcmp(cmd_thing->name, match) == 0) {
		TAILQ_REMOVE(l, cmd_thing, next);
		/* free mem */
		return (1);
	}

	return (0);
}

struct cmd *
cmdlist_first(struct cmdlist *l)
{
	struct cmd *ret;

	assert(l != NULL);
	if (TAILQ_EMPTY(l))
		return (NULL);
	ret = TAILQ_FIRST(l);
	TAILQ_REMOVE(l, ret, next);
	return (ret);
}

char *
cmd_val(struct cmd *c)
{

	assert(c != NULL);
	assert(c->name != NULL);
	return (c->name);
}

int
cmd_dispatch(struct network *n, struct cmdlist *l)
{
	int error = 0;

	assert(TAILQ_EMPTY(l) != 1);

	if (cmd_remove_if_match(l, "version")) {
		error = cmd_dispatch_version(n, l);
	} else if (cmd_remove_if_match(l, "host")) {
		error = cmd_dispatch_host(n, l);
	} else if (cmd_remove_if_match(l, "hub")) {
		error = cmd_dispatch_hub(n, l);
	} else if (cmd_remove_if_match(l, "router")) {
		error = cmd_dispatch_router(n, l);
	} else if (cmd_remove_if_match(l, "connect")) {
		error = cmd_dispatch_connect(n, l);
	} else if (cmd_remove_if_match(l, "iface")) {
		error = cmd_dispatch_iface(n, l);
	} else if (cmd_remove_if_match(l, "graph")) {
		/*
		 * Wykorzystywane przez graficzny interfejs u¿ytkownika.
		 * Po dodaniu logicznego opisu sieci, GUI mo¿e
		 * potrzebowaæ informacji, gdzie fizycznie (na ekranie)
		 * znajduje siê hostA. Mo¿e wykorzystaæ do tego celu
		 * linie zaczynaj±ce siê od "graph", które przez sam
		 * symulator s± pomijane. Umo¿liwi to równie¿
		 * wspó³pracê wielu graficznych nak³adek.
		 */
	} else {
		/* change the "first" to some macro */
		return (network_err(n, "Problem in specification file, line:"
		    " %d\nNieznane s³owo kluczowe '%s'.\n", n->lineno,
		    (TAILQ_FIRST(l))->name));
	}

	return (error);
}
