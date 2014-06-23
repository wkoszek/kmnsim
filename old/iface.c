#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "kmnsim.h"

int iface_destroy(struct iface *iface);

struct iface *
iface_create(struct network *n, const char *name, int id)
{
	struct iface *ifp = NULL;
	struct nid *nid = NULL;

	nid = nid_lookup(n->nids, name, id, -1);
	if (nid != NULL)
		return (NULL);

	nid = nid_create(name, id);
	NID_ASSERT(nid);

	ifp = calloc(1, sizeof(*ifp));
	IFACE_INIT(ifp);
	ifp->nid = nid;
	nid->obj = ifp;
	nid->type = NID_TYPE_IFACE;
	NID_ASSERT(nid);

	return (ifp);
}

int
iface_destroy(struct iface *iface)
{

	IFACE_ASSERT(iface);
	return (0);
}
