#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "queue.h"
#include "kmnsim.h"

void
router_debug(struct router *r)
{

	ROUTER_ASSERT(r);
	printf("Router: '%s'\n", r->name);
}

int
network_router_create(struct network *n, const char *name)
{

	NETWORK_ASSERT(n);
	TBD();
	return (0);
}

int
network_router_remove(struct network *n, const char *name)
{

	NETWORK_ASSERT(n);
	TBD();
	return (0);
}
