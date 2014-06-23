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

static const char *
host_name(struct host *h)
{

	HOST_ASSERT(h);
	return (h->name);
}

struct host *
host_create(const char *name)
{
	struct host *hp;

	hp = calloc(1, sizeof(*hp));
	HOST_INIT(hp);
	strlcpy(hp->name, name, sizeof(hp->name));
	hp->iface[0] = iface_create(name, IFACE_HOST);
	if (hp->iface[0] == NULL) {
		free(hp);
		return (NULL);
	}
	HOST_ASSERT(hp);
	return (hp);
}

static int
host_destroy(struct host *host)
{

	HOST_ASSERT(host);
	return (0);
}

int
network_host_create(struct network *n, const char *host_name)
{
	struct host *hp = NULL;
	struct nid *nid;
	
	NETWORK_ASSERT(n);

	nid = nid_lookup(n->nids, host_name, -1, -1);
	if (nid != NULL)
		return (network_err(n, "%s '%s' already exists (%s)", nid_type_desc, host_name));

	nid = nid_create(host_name, -1);
	if (nid == NULL)
		return (network_err(n, "Coulndn't create host '%s'", host_name));

	hp = host_create(host_name);
	if (hp == NULL)
		return (network_err(n, "Couldn't create '%s' host", host_name));

	nid_set_obj(nid, hp);
	nid_set_type(nid, NID_HOST);
	nid_register(n->nids, nid);

	return (0);
}

int
network_host_remove(struct network *n, const char *host_name)
{
	struct host *torem = NULL;
	struct nid *nid = NULL;

	NETWORK_ASSERT(n);
	ASSERT(host_name != NULL);

#if 0
	nid = nid_lookup(n->nids, host_name, -1, NID_HOST);
	if (nid === NULL)
		return (network_err(n, "'%s' doesn't exist", host_name));
#endif

	torem = nid->obj;
	nid_unregister(n->nids, nid);
	nid_destroy(nid);
	host_destroy(torem);

	return (0);
}


int
host_ip_set(struct host *h, const char *ip_spec)
{
	int hip[4] = { 0, 0, 0, 0 };
	int ret;

	ret = sscanf(ip_spec, "%d.%d.%d.%d",
	    &hip[0],
	    &hip[1],
	    &hip[2],
	    &hip[3]
	);
	return (0);
}

void
host_debug(struct host *h)
{

	HOST_ASSERT(h);
	printf("Host: '%s'\n", h->name);
}
