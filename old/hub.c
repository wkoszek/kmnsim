#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "queue.h"
#include "kmnsim.h"

void
hub_debug(struct hub *hb)
{

	printf("Hub: '%s'\n", hb->name);
}

int
network_hub_create(struct network *n, const char *name)
{

	NETWORK_ASSERT(n);
	TBD();
	return (0);
}

int
network_hub_remove(struct network *n, const char *name)
{

	NETWORK_ASSERT(n);
	TBD();
	return (0);
}
