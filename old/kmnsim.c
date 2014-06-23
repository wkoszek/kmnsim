/*
 * KMnsim: Koszek-Matyja Network Simulator
 * (c) 2009 by Dead Beaf Software Group
 * 
 * Authors: Wojciech Koszek <wkoszek@FreeBSD.czest.pl>
 *          Piotr Matyja <piotr_matyja@o2.pl>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "queue.h"

#include "kmnsim.h"

struct network nw;

/*
 * Generalna inicjalizacja siatki, z której bêdziemy budowaæ sieæ.
 */
static int
network_init(struct network *n, const char *fname)
{

	assert(n != NULL);
	NETWORK_INIT(n);

	if (fname == NULL)
		n->stream = stdin;
	else {
		n->stream = fopen(fname, "r");
		if (n->stream == NULL)
			return (network_err(n, "Couldn't open file"
				" %s", fname));
	}
	n->stream_err = stderr;

	n->lineno = 0;
	n->version = -1;
	n->errcode = 0;

	/* Network elements. */
	memset(&n->hosts, 0, sizeof(n->hosts));
	memset(&n->routers, 0, sizeof(n->routers));
	TAILQ_INIT(&n->routers);
	TAILQ_INIT(&n->hosts);

	return (0);
}

/*
 * Zniszczenie wszystkich, wcze¶niej zaalokowanych struktur.
 */
static int
network_destroy(struct network *n)
{
	struct router *rp;
	struct host *hp;
	int error = 0;

	(void)rp;
	(void)hp;
	NETWORK_ASSERT(n);

	if (n->stream != stdin) {
		error = fclose(n->stream);
		if (error != 0)
			return (network_err(n, "Couldn't close "
				"specification file"));
	}
	if (n->stream_err != stderr) {
		error = fclose(n->stream_err);
		if (error != 0)
			return (network_err(n, "Couldn't close "
				"error stream"));
	}

	return (error);
}

/*
 *
 */
static int
network_parse(struct network *n)
{
	char buffer[INPUT_BUF_LEN];
	struct cmdlist *cmdlist = NULL;
	int cmd_num = 0;
	char *cmdline = NULL;
	int has_line = 0;
	int cmd_ok = 0;
	int error = 0;

	(void)cmd_num;
	NETWORK_ASSERT(n);

	has_line = (fgets(buffer, sizeof(buffer), n->stream) != NULL);
	if (has_line == 0)
		return (-1);
	n->lineno++;
	cmdline = trim(buffer);
	if (cmdline == NULL)
		return (-1);
	cmd_parse(&cmdlist, &cmd_num, cmdline);
	cmd_ok = (cmdlist != NULL && cmd_num != 0);
	if (!cmd_ok)
		return (-1);
	error = cmd_dispatch(n, cmdlist);
	if (error != 0)
		return (-1);
	return (0);
}

static int
network_go(struct network *n)
{
	struct host *hostp = NULL;
	struct hub *hubp = NULL;
	struct router *rrp = NULL;

	NETWORK_ASSERT(n);
	puts("---------------------------------");
	printf("Version ID: %d\n", n->version);
	puts("---------------------------------");

	TAILQ_FOREACH(hostp, &n->hosts, next)
		host_debug(hostp);
	TAILQ_FOREACH(hubp, &n->hubs, next)
		hub_debug(hubp);
	TAILQ_FOREACH(rrp, &n->routers, next)
		router_debug(rrp);

	printf("<--- End of network specification --\n");

	return (0);
}

struct opts {
	int need_help;
};

static void
usage(void)
{

	fprintf(stderr, "Usage: kmnsim [-f specfile]\n");
	return;
}

int
main(int argc, char **argv)
{
	int has_more = 0;
	int o = 0;
	struct opts opts;
	char *spec_file = NULL;

	while ((o = getopt(argc, argv, "")) != -1)
		switch (o) {
		case 'f':
			spec_file = optarg;
			break;
		case 'h':
			opts.need_help = 1;
			break;
		}

	argc -= optind;
	argv += optind;

	if (opts.need_help)
		usage();

	nids_init();
	network_init(&nw, spec_file);
	for (;;) {
		has_more = (network_parse(&nw) != -1);
		if (!has_more)
			break;
	}
	if (network_err_has(&nw))
		return (network_err_msg(&nw));
	network_go(&nw);
	network_destroy(&nw);
	nids_destroy();
	exit(EXIT_SUCCESS);
}
