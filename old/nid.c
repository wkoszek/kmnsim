#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "queue.h"

#include "kmnsim.h"

static struct nids nids;

/*
 * Inicjalizacja bazy danych dot. przestrzeni nazw.
 */
void
nids_init(void)
{

	memset(&nids, 0, sizeof(nids));
	TAILQ_INIT(&nids);
}

/*
 * Usuniêcie przestrzeni nazw.
 */
void
nids_destroy(void)
{

	/* unlink everything */
	memset(&nids, 0, sizeof(nids));
}

static struct nid*
nid_alloc(void)
{
	struct nid *ret = NULL;

	ret = calloc(sizeof(*ret), 1);
	ASSERT(ret != NULL && "ret == NULL");
	NID_INIT(ret);
	ret->id = -1;
	ret->type = -1;
	return (ret);
}

void
nid_register(struct nids *nids, struct nid *n)
{

	TAILQ_INSERT_TAIL(nids, n, next);
}

void
nid_unregister(struct nids *nids, struct nid *n)
{

	TAILQ_REMOVE(nids, n, next);
}

struct nid *
nid_create(const char *nid, int id)
{
	struct nid *n;
	
	n = nid_alloc();
	if (n == NULL)
		return (NULL);
	NID_ASSERT(n);
	strlcpy(n->name, nid, sizeof(n->name));
	n->id = id;
	NID_ASSERT(n);
	return (nid);
}

void
nid_set_type(struct nid *n, int type)
{

	NID_ASSERT(n);
	n->type = type;
}

void
nid_set_obj(struct nid *n, void *obj)
{

	NID_ASSERT(n);
	n->obj = obj;


struct nid *
nid_lookup(struct nids *nids, const char *name, int id, int type)
{
	struct nid *nid = NULL;

	assert(name != NULL);

	TAILQ_FOREACH(nid, nids, next) {
		if (!streq(nid->name, name))
			continue;
		if (id != -1 && nid->id != id)
			continue;
		if (type != -1 && nid->type != type)
			continue;
		return (nid);
	}
	return (NULL);
}

const char *
nid_type_desc(struct nid *n)
{

	NID_ASSERT(n);

	switch (n->type) {
	case NID_HOST:
		return ("host");
	case NID_HUB:
		return ("hub");
	case NID_ROUTER:
		return ("router");
	case NID_IFACE:
		return ("interface");
	}
	return ("unknown");
}

int
nid_destroy(struct nid *n)
{

	NID_ASSERT(n);
	return (0);
}
