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

int
cmd_dispatch_host_ip(struct network *n, const char *host_name, struct cmdlist *l)
{
	struct cmd *ip = NULL;
	struct cmd *nm = NULL;

	NETWORK_ASSERT(n);
	assert(l);

	ip = cmdlist_first(l);
	if (ip == NULL)
		return (network_err(n, "IP address expected"));
	CMD_ASSERT(ip);

	nm = cmdlist_first(l);
	if (nm == NULL)
		return (network_err(n, "Netmask address expected"));
	CMD_ASSERT(nm);

	if (!ipv4_addr_valid(cmd_val(ip)))
		return (network_err(n, "IP address '%s' isn't valid", cmd_val(ip)));
	if (!ipv4_netmask_valid(cmd_val(nm)))
		return (network_err(n, "Network mask '%s' isn't valid", cmd_val(ip)));

	/* XXx: Wstawiæ IP do hosta */


	return (0);
}

int
cmd_dispatch_host_mac(struct network *n, const char *host_name, struct cmdlist *l)
{
	struct cmd *mac;

	NETWORK_ASSERT(n);
	assert(l != NULL);

	mac = cmdlist_first(l);
	if (mac == NULL)
		return (network_err(n, "MAC address is expected"));
	CMD_ASSERT(mac);

	/* XXx: Ustawiæ MAC dla interfejsu */

	return (0);
}

int
cmd_dispatch_host(struct network *n, struct cmdlist *l)
{
	struct cmd *host_name = NULL;
	struct cmd *action = NULL;
	char *acts = NULL;
	char *host_name_str = NULL;
	int error = 0;

	DEBUG(" ");

	host_name = cmdlist_first(l);
	if (host_name == NULL)
		return (network_err(n, "No host name given!"));
	host_name_str = cmd_val(host_name);

	action = cmdlist_first(l);
	if (action == NULL)
		return (network_err(n, "No action given!"));
	acts = cmd_val(action);

	if (streq(acts, "create")) {
		error = network_host_create(n, host_name_str);
	} else if (streq(acts, "remove")) {
		error = network_host_remove(n, host_name_str);
	} else {
		error = network_err(n, "Subcommand '%s' unsupported", acts);
	}
#if 0
	else if (streq(acts, "ip") || streq(acts, "ip4")) {
		error = cmd_dispatch_host_ip(n, hname, l);
	} else if (streq(acts, "mac")) {
		error = cmd_dispatch_host_mac(n, hname, l);
#endif
	return (error);
}


int
cmd_dispatch_hub(struct network *n, struct cmdlist *l)
{
	struct cmd *hb;
	struct cmd *action;
	char *hname;
	char *acts;
	int error = 0;

	(void)n;
	(void)l;

	hb = cmdlist_first(l);
	if (hb == NULL)
		return (network_err(n, "Hub name must be given"));
	hname = cmd_val(hb);

	action = cmdlist_first(l);
	if (action == NULL)
		return (network_err(n, "Action is required in 'hub' command"));
	acts = cmd_val(action);

	if (streq(acts, "create")) {
		error = network_hub_create(n, hname);
	} else if (streq(acts, "remove")) {
		error = network_hub_remove(n, hname);
	}

	return (0);
}

int
cmd_dispatch_router(struct network *n, struct cmdlist *l)
{
	struct cmd *rt;
	struct cmd *action;
	char *rname;
	char *acts;
	int error = 0;

	(void)n;
	(void)l;

	rt = cmdlist_first(l);
	if (rt == NULL)
		return (network_err(n, "Router name must be given"));
	rname = cmd_val(rt);

	action = cmdlist_first(l);
	if (action == NULL)
		return (network_err(n, "Action is required in 'router' command"));
	acts = cmd_val(action);

	if (streq(acts, "create")) {
		error = network_router_create(n, rname);
	} else if (streq(acts, "remove")) {
		error = network_router_remove(n, rname);
	} else if (streq(acts, "route")) {
		error =  cmd_dispatch_router_route(n, rname, l);
	} else {
		return (network_err(n,
		    "Unknown subcommand '%s' to the 'router' command", cmd_val(action)));
	}
#if 0
	network_router_add()
	network_router_remove();
#endif

	return (0);
}

int
cmd_dispatch_router_route(struct network *n, const char *rname, struct cmdlist *l)
{

	NETWORK_ASSERT(n);
	TBD();
	return (0);
}


/*
 * Connect command handling:
 *
 * "connect <name0> <interface0> <name1> <interface1>"
 *
 */
int
cmd_dispatch_connect(struct network *n, struct cmdlist *l)
{
	struct cmd *name0 = NULL;
	struct cmd *name1 = NULL;
	struct cmd *iface0 = NULL;
	struct cmd *iface1 = NULL;
	char part0[1024];
	char part1[1024];

	DEBUG(" ");
	/* First connection part */
	name0 = cmdlist_first(l);
	if (name0 == NULL)
		return (network_err(n, "No network object name given!"));
	iface0 = cmdlist_first(l);
	if (iface0 == NULL)
		return (network_err(n, "No interface name given!"));

	/* Second connection part */
	name1 = cmdlist_first(l);
	if (name1 == NULL)
		return (network_err(n, "No network object name given!"));
	iface1 = cmdlist_first(l);
	if (iface1 == NULL)
		return (network_err(n, "No interface name given!"));

	/* Concatenate two strings */
	memset(part0, 0, sizeof(part0));
	memset(part1, 0, sizeof(part1));
	(void)snprintf(part0, sizeof(part0), "%s:%s", cmd_val(name0), cmd_val(iface0));
	(void)snprintf(part1, sizeof(part1), "%s:%s", cmd_val(name1), cmd_val(iface1));

	DEBUG("-- would connect interface '%s' <> '%s'", part0, part1);

	return (0);
}

int
cmd_dispatch_version(struct network *n, struct cmdlist *l)
{
	struct cmd *version = NULL;
	int versid = 1;

	version = cmdlist_first(l);
	ASSERT(version != NULL);
	versid = atoi(cmd_val(version));
	if (versid > kmnsim_version)
		return (network_err(n,
		    "Old program (version: %d) can't read new files (version: %d)",
		        kmnsim_version, versid));
	else
		n->version = versid;
	return (0);
}

int
cmd_dispatch_iface(struct network *n, struct cmdlist *l)
{

	NETWORK_ASSERT(n);
	assert(l != NULL);

	return (0);
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
