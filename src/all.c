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
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>

#include "queue.h"
#include "kmnsim.h"

#include "subr/subr.h"

#ifndef EX_USAGE
#define EX_USAGE	64
#endif


/* API dla komend - generalnie */
int cmd_parse(struct cmdlist **cmdlist, int *cmd_num, const char *cmdstring);
int cmd_remove_if_match(struct cmdlist *l, const char *match);
void cmdlist_show_fp(struct cmdlist *cmdlist, FILE *output);
void cmdlist_show(struct cmdlist *cmdlist);
struct cmd *cmdlist_first(struct cmdlist *l);
char *cmd_val(struct cmd *c);

/* API dla poszczególnych komend symulatora */
int cmd_dispatch(struct network *n, struct cmdlist *l);
int cmd_dispatch_set(struct network *n, struct cmdlist *l);
int cmd_dispatch_connect(struct network *n, struct cmdlist *l);
int cmd_dispatch_host(struct network *n, struct cmdlist *l);
int cmd_dispatch_hub(struct network *n, struct cmdlist *l, hub_mode_t mode);
int cmd_dispatch_iface(struct network *n, struct cmdlist *l);
int cmd_dispatch_router(struct network *n, struct cmdlist *l);
int cmd_dispatch_router_route(struct network *n, const char *rname, struct cmdlist *l);
int cmd_dispatch_version(struct network *n, struct cmdlist *l);

/* API iface */
int iface_flag_has(struct iface *iface, int flag);
void iface_flag_clear(struct iface *iface, int flag);
struct iface *iface_create(struct network *n, const char *name, int id);
void iface_debug(struct iface *ifp, FILE *fp);
void iface_flag_set(struct iface *iface, int flag);
static void iface_dot_dump(struct iface *iface, FILE *fp);
int iface_destroy(struct network *n, struct iface *iface);
void iface_owner_set(struct iface *ifp, struct nid *nid);
int iface_flag_has(struct iface *iface, int flag);
int network_iface_ipv4_set(struct network *n, struct iface *ifp, const char *addrv4_spec);
int network_iface_mac_set(struct network *n, struct iface *ifp, const char *macspec);
int network_iface_nmv4_set(struct network *n, struct iface *ifp, const char *addrv4_spec);


/* API nid */
char *nid_name_get(struct nid *nid);
const char *nid_type_desc(struct nid *n);
int nid_destroy(struct nid *n);
int nid_id_get(struct nid *nid);
int nid_match(const char *name, int id);
int nid_type_get(struct nid *nid);
struct nid *nid_create(const char *nid, int id);
struct nid *nid_lookup(struct nids *nids, const char *name, int id, int type);
void *nid_obj_get(struct nid *nid);
void nid_debug(struct nid *nid, FILE *fp);
void nid_obj_set(struct nid *nid, void *obj);
void nid_register(struct nids *nids, struct nid *n);
void nid_set_obj(struct nid *n, void *obj);
void nid_set_type(struct nid *n, int type);
void nid_type_set(struct nid *nid, int type);
void nid_unregister(struct nids *nids, struct nid *n);
void nids_destroy(struct nids *);
void nids_init(struct nids *);

/* API host */
int host_create(struct network *n, const char *host_name);
int host_remove(struct network *n, const char *host_name);

/* API hub */
int hub_create(struct network *n, const char *hub_name, hub_mode_t mode);
int hub_remove(struct network *n, const char *hub_name);
int hub_rx_process(struct hub *hub);

/* API router */
int router_remove(struct network *n, const char *router_name);
int router_create(struct network *n, const char *router_name);

/* API Network */
const char *network_errmsg_get(struct network *n);
int network_err(struct network *n, const char *fmt, ...);
int network_err_has(struct network *n);
int network_err_msg(struct network *n);
static int network_dump_txt(struct network *n, FILE *fp);
static int network_dump_dot(struct network *n, FILE *fp);

/* API PKTQ -- kolejka pakietów */
int pktq_empty(struct pktq *pktq);
void pktq_destroy(struct pktq *pktq);
void pktq_enqueue(struct pktq *pktq, struct pkt *pkt);
void pktq_init(struct pktq *pktq);
void pktq_remove(struct pktq *pktq, struct pkt *pkt);
void pktq_debug(struct pktq *pktq, FILE *fp);
struct pkt *pktq_dequeue(struct pktq *pktq);
struct pkt *pktq_dequeue_candidate(struct pktq *pktq);

/* API PKT -- pakiety */
struct pkt *pkt_create(int len);
void pkt_destroy(struct pkt *pkt);
void pkt_init(struct pkt *pkt, int type, struct iface *srci, struct iface *dsti);
struct pkt *pkt_dup(struct pkt *pkt);
static int pkt_ids = 0;

/* API pomocnicze */
int string_to_addrv4(const char *s, unsigned int ip[ADDRV4_LEN]);
int addrv4_eq(unsigned int a0[ADDRV4_LEN], unsigned int a1[ADDRV4_LEN]);
int host_rx_process(struct host *host);
char *strdupf(const char *fmt, ...);

/* API ARP: nieu¿ywane na razie */
void arptable_init(struct arptable *at);
void arptable_destroy(struct arptable *at);

/*
 * Struktura msg trzyma jedn± liniê komunikatu w przebiegu czasowym
 * symulatora. W przypadku wyprowadzania w formacie txt/DOT, te dane nie
 * s± wykorzystywane.
 */
struct msg {
	char buf[512];
};
static int msg_num = 0;
#define MSG_LOG_SIZE	(1024*1024*4)
#define MSG_LOG_NUM	(MSG_LOG_SIZE / sizeof(struct msg))
struct msg nw_log[MSG_LOG_NUM];

/*
 * Inicjalizacja tablicy komunikatów..
 */
void
msg_init(void)
{

	memset(nw_log, 0, sizeof(nw_log));
}

void
msg_destroy(void)
{

	msg_init();
}

/*
 * Zalogowanie jednego komunikatu na pierwszym wolnym miejscu.
 */
void
msg_log(const char *fmt, ...)
{
	va_list va;
	struct msg *msg;

	/*
	 * Sprawd¼, czy aby nie jeste¶my w z³ym miejscu w kolejce
	 * komunikatów.
	 */
	ASSERT(msg_num >= 0 && "msg_num jest za ma³e");
	ASSERT(msg_num <= MSG_LOG_NUM &&
	    "zwiêksz ilo¶æ slotów do logowania");
	msg = &nw_log[msg_num];
	msg_num++;

	va_start(va, fmt);
	vsnprintf(msg->buf, sizeof(msg->buf) - 1, fmt, va);
	va_end(va);
	strlcat(msg->buf, "\n", sizeof(msg->buf));
}

/*
 * Wypisz podsumowanie.
 */
void
network_dump_summary(struct network *n, FILE *fp)
{
	int i;

	(void)n;
	NETWORK_ASSERT(n);
	for (i = 0; i < msg_num; i++)
		fprintf(fp, "%s", nw_log[i].buf);
}

/* Limit this to the minimum */
int cmd_verbose = 0;
int flag_debug = 0;
int kmnsim_version = VERSION;
int verbose = 0;

/*
 * Rozdzielacz metod w zale¿no¶ci od typu elemenentu aktywnego sieci.
 */
struct conn_dispatcher {
	int (*allow)(struct iface *iface, struct pkt *pkt);
	struct pkt *(*tx)(struct iface *iface);
	int (*rx)(struct iface *iface, struct pkt *pkt);
};

/*
 * Akceptor huba. Zawsze dopuszcza odebranie pakietu, bo to hub. Ta
 * czê¶æ powinna w zasadzie ulec zmianie, gdy¿ w przypadku switcha to
 * zachowanie mo¿e byæ odmienne.
 */
int
hub_allow(struct iface *iface, struct pkt *pkt)
{
	struct hub *hub = iface->nid_owner->obj;

	HUB_ASSERT(hub);
	PKT_ASSERT(pkt);

	return (1);
}

/*
 * Odbiera dane w kontek¶cie huba
 */
int
hub_rx(struct iface *iface, struct pkt *pkt)
{
	struct hub *hub = NULL;
	struct pkt *tmppkt = NULL;
	int pos = 0;
	int i = 0;

	/* Sprawd¼, czy interfejs jest ok */
	IFACE_ASSERT(iface);
	hub = iface->nid_owner->obj;
	HUB_ASSERT(hub);
	PKT_ASSERT(pkt);

	/*
	 * Zaloguj nasze postêpowanie.
	 */
	msg_log("%s %s:", nid_type_desc(hub->nid), nid_name_get(hub->nid));
	msg_log("\tOdbiera jeden pakiet z ID = %d", pkt->id);
	TAILQ_FOREACH(tmppkt, &iface->inq, next)
		pos++;
	msg_log("\tPakiet zostaje odebrany i wstawiony na miejsce %d"
	    " w kolejce odbiorczej interfejsu %d",
	    pos,
	    nid_id_get(iface->nid)
	);

	/*
	 * Skolejkuj odebrany pakiet na interfejsie.
	 */
	pktq_enqueue(&iface->inq, pkt);

	/* 
	 * Przetwórz wszystkie kolejki wyj¶ciowe huba.
	 */
	do {
		i = hub_rx_process(hub);
	} while (i == 0);

	return (0);
}

/*
 * Odbierz dane w kontek¶cie huba.
 */
struct pkt *
hub_tx(struct iface *iface)
{
	struct hub *hub;
	struct pkt *pkt = NULL;

	IFACE_ASSERT(iface);
	hub = iface->nid_owner->obj;
	HUB_ASSERT(hub);

	pkt = pktq_dequeue(&iface->outq);
	ASSERT(pkt != NULL && ("pkt nie mo¿e byæ NULL tutaj"));

	msg_log("%s %s:", nid_type_desc(hub->nid), nid_name_get(hub->nid));
	msg_log("\tTransmituje jeden pakiet z ID = %d z interfejsu %d",
	    pkt->id,
	    nid_id_get(iface->nid)
	);

	return (pkt);
}

/*
 * Przetwórz pierwszy dostêpny pakiet z kolejki wej¶ciowej.
 */
int
hub_rx_process(struct hub *hub)
{
	struct pkt *pkt, *pkt2;
	struct iface *iface;
	struct pkt_icmp *icmp;
	struct iface *tgtif = NULL;
	int i;
	int match_ether;
	struct iface *outifs[HUB_IFACES];
	int outif_idx = 0;

	/*
	 * Pobierz pierwszy interfejs, w którym znajduj± siê
	 * jakiekolwiek dane.
	 */
	iface = NULL;
	for (i = 0; i < HUB_IFACES; i++) {
		if (!pktq_empty(&hub->iface[i]->inq)) {
			iface = hub->iface[i];
			break;
		}
	}
	if (iface == NULL)
		/*
		 * ¯aden interfejs huba nie ma danych w swoich kolejkach
		 * nadawczych.
		 */
		return (-1);

	pkt = pktq_dequeue(&iface->inq);
	PKT_ASSERT(pkt);
	icmp = pkt->data;

	/*
	 * Teraz dokonujemy wyboru, na który interfejs/interfejsy
	 * wys³aæ w³a¶nie co odebrane dane.
	 */
	tgtif = NULL;
	for (i = 0; i < HUB_IFACES; i++) {
		if (hub->iface[i] == iface)
			/*
			 * Pomijamy interfejs, z którego przysz³y dane.
			 */
			continue;
		tgtif = hub->iface[i];
		if (!iface_flag_has(tgtif, IFACE_FLAG_HASCONN))
			/*
			 * Interfejs musi mieæ istniej±ce po³±czenie,
			 * tak, by po zduplikowaniu pakietów i próbie
			 * wypchniêcia ich innym portem, istnia³o co¶,
			 * co je potem odbierze.
			 */
			continue;

		if (hub->mode == HUB_MODE_NORMAL) {
			/* 
			 * Hub po prostu gromadzi interfejsy do
			 * pó¼niejszego rozg³oszenia.
			 */
			outifs[outif_idx] = tgtif;
			outif_idx++;
		} else if (hub->mode == HUB_MODE_SWITCH) {
			/*
			 * Sprawd¼, czy zdalny interfejs jest tym, do którego
			 * adresowana jest ramka. Je¿eli tak, to od³ó¿
			 * nasz interfejs jako ten do pó¼niejszej
			 * obs³ugi.
			 */
			match_ether =
			    (memcmp(icmp->e.dst_mac,
				    tgtif->conn_ifp->mac,
				    sizeof(icmp->e.dst_mac)) == 0);
			if (match_ether) {
				outifs[outif_idx] = tgtif;
				outif_idx++;
			}
		}
	}

	/*
	 * Sprawd¼, czy aby nasza infrastruktura dzia³a poprawnie.
	 * Niemo¿liwe powinno byæ posiadanie wiêcej ni¿ jednego
	 * potencjalnego interfejsu w switchu, do którego mo¿naby wys³aæ
	 * dane. Switch powinien mieæ conajwy¿ej jeden taki interfejs.
	 */
	if (hub->mode == HUB_MODE_SWITCH)
		ASSERT(outif_idx <= 1);

	/*
	 * Mo¿e siê okazaæ, ¿e istnieje tylko po³±czenie host->hub (bez
	 * drugiego hosta). Wtedy nie dojdzie do niepotrzebnej
	 * duplikacji pakietów (bo za³ó¿my outif_idx = 0), jednak te¿ nic nie
	 * zostanie wys³ane.
	 */
	if (outif_idx <= 0)
		return (-1);

	for (i = 0; i < outif_idx; i++) {
		/*
		 * Hm. interesuj±ce.
		 * Jak zdejmê pakiet z jednego interfejsu przy
		 * po³±czeniu i wepchnê.. Nie mogê zrobiæ tutaj destroy
		 * w kazdym razie.
		 */
		tgtif = outifs[i];
		IFACE_ASSERT(tgtif);

		PKT_ASSERT(pkt);
		pkt2 = pkt_dup(pkt);
		PKT_ASSERT(pkt2);
		pktq_enqueue(&tgtif->outq, pkt2);
		msg_log("\t\tDane z portu '%d' zostaj± zduplikowane (ID=%d) i przekazane na port '%d'",
		    nid_id_get(iface->nid),
		    pkt2->id,
		    nid_id_get(tgtif->nid)
		);
		//pkt_destroy(pkt);
	}
	return (0);
}

/*
 * Akceptor hosta. Tutaj dokonujemy testu, czy MAC/IP pasuje do tego,
 * które jest w interfejsie sieciowym hosta.
 */
int
host_allow(struct iface *iface, struct pkt *pkt)
{
	struct host *host;
	struct pkt_icmp *icmp;
	int permit_eth;
	int permit_ip;

	/* Sprawd¼, czy interfejs jest ok */
	IFACE_ASSERT(iface);
	host = iface->nid_owner->obj;
	HOST_ASSERT(host);
	PKT_ASSERT(pkt);
	icmp = pkt->data;

	/*
	 * Test zgodno¶ci warstwy drugiej. Tego dokonywa³a by karta
	 * sieciowa wpiêta w komputer po odpowiedniej konfiguracji.
	 */
	permit_eth = (memcmp(icmp->e.dst_mac, iface->mac,
		sizeof(icmp->e.dst_mac)) == 0);

	/*
	 * Test zgodno¶ci warstwy transportowej.
	 */
	permit_ip = (memcmp(icmp->ip.dst_ipv4, iface->ipv4,
		sizeof(icmp->ip.dst_ipv4)) == 0);

	/*
	 * Zaloguj, to co nast±pi³o.
	 */
	if (!permit_eth || !permit_ip)
		msg_log("Host: %s", nid_name_get(host->nid));
	if (!permit_eth) {
		msg_log("\tPakiet ID = %d nie bêdzie zaakceptowany "
		    "przez host %s z powodu braku zgodno¶ci adresów "
		    "MAC", pkt->id, nid_name_get(host->nid));
	}
	if (!permit_ip) {
		msg_log("\tPakiet ID = %d nie bêdzie zaakceptowany "
		    "przez host %s z powodu braku zgodno¶ci adresów "
		    "IP", pkt->id, nid_name_get(host->nid));
	}

	return (permit_ip && permit_eth);
}

/*
 * Odbierz pakiet w kontek¶cie hosta.
 */
int
host_rx(struct iface *iface, struct pkt *pkt)
{
	struct host *host;
	struct pkt *tmppkt;
	int pos = 0;

	IFACE_ASSERT(iface);
	host = iface->nid_owner->obj;
	HOST_ASSERT(host);
	PKT_ASSERT(pkt);

	msg_log("Host %s:", nid_name_get(host->nid));
	msg_log("\tOdbiera jeden pakiet z ID = %d;", pkt->id);
	TAILQ_FOREACH(tmppkt, &iface->inq, next)
		pos++;
	msg_log("\tPakiet zostaje odebrany i wstawiony na miejsce %d"
	    " w kolejce odbiorczej", pos);
	pktq_enqueue(&iface->inq, pkt);
	host_rx_process(host);
	return (0);
}

/*
 * Transmisja pakietu z hosta.
 */
struct pkt *
host_tx(struct iface *iface)
{
	struct host *host;
	struct pkt *pkt = NULL;

	IFACE_ASSERT(iface);
	host = iface->nid_owner->obj;
	HOST_ASSERT(host);

	pkt = pktq_dequeue(&iface->outq);
	ASSERT(pkt != NULL && ("Pakiet nie mo¿e byæ pusty w tym miejscu"));
	msg_log("Host %s:", nid_name_get(host->nid));
	msg_log("\tTransmituje jeden pakiet z ID = %d do ``%s'' o nazwie ``%s''", pkt->id,
	    nid_type_desc(iface->conn_ifp->nid_owner),
	    nid_name_get(iface->conn_ifp->nid)
	);

	return (pkt);
}

/*
 * Przetwarzanie danych odebranych przez host. Ta funkcja jest swojego
 * rodzaju emulacj± stosu TCP/IP hosta; dlatego te¿ powinna ulec ona
 * znacznemu rozbudowaniu w celu symulacji rzeczy o wiele bardziej
 * z³o¿onych ni¿ ICMP.
 *
 * WKPM: host_rx_process powinien staæ siê raczej generaln± funkcj± do
 * obs³ugi jednostek, które maj± stos TCP/IP (routery);
 */
int
host_rx_process(struct host *host)
{
	struct pkt *pkt;
	struct pkt_icmp *icmp;
	struct iface *si, *di;
	struct pktq *inq, *outq;

	/* Kolejki interfejsu hosta */
	inq = &host->iface[0]->inq;
	outq = &host->iface[0]->outq;

	/*
	 * Pobierz dane, je¿eli jakie¶ s± i spraw, ¿e patrzymy na nie
	 * ju¿ jako ruch ``ping''opodobny.
	 *
	 * WKPM: Je¿eli bêdziemy chcieli dodaæ co¶ prócz PING'a, ta
	 * czê¶æ ulegnie zmianie.
	 */
	if (pktq_empty(inq))
		return (0);
	pkt = pktq_dequeue(inq);
	PKT_ASSERT(pkt);
	icmp = pkt->data;

	msg_log("\t\tOdebrane dane ulegaj± przetwarzaniu.");

	/*
	 * Przygotuj siê do odpowiedzi na pro¶bê o ``ping''.
	 */
	if (icmp->ic.type == ICMP_PING_REQUEST) {
		/*
		 * ¬ród³o i cel pakietu, który do nas dotar³ zostaj±
		 * zapamiêtane, dziêki czemu nie musimy wyszukiwaæ w
		 * globalnej bazie danych parametrów interfejsów hostów.
		 */
		si = pkt->src_ifp;
		di = pkt->dst_ifp;

		/*
		 * Tworzê nowy pakiet i poniewa¿ to odpowied¼, to
		 * odwracam kolejno¶æ argumentów ¼ród³o/cel do
		 * pkt_init() tak, by nag³ówek ramki zosta³ poprawnie
		 * zaadresowany.
		 */
		pkt_destroy(pkt);
		pkt = pkt_create(1000);
		PKT_ASSERT(pkt);
		pkt_init(pkt, ICMP_PING_ANSWER, di, si);
		PKT_ASSERT(pkt);

		/*
		 * I w koñcu ustaw w kolejce wyj¶ciowej
		 */
		pktq_enqueue(outq, pkt);
		msg_log("\t\tOdebrano pakiet PING_REQUEST;");
		msg_log("\t\tWygenerowano odpowied¼ PING_ANSWER.");
	} else if (icmp->ic.type == ICMP_PING_ANSWER) {
		/*
		 * Otrzyma³em odpowied¼ na ``ping''. Po prostu usuwam
		 * pakiet z kolejki.
		 */
		pkt_destroy(pkt);
		msg_log("\t\tOdebrano pakiet PING_ANSWER;");
		msg_log("\t\tTest dostêpno¶ci hosta zakoñczony.");
	} else {
		/*
		 * Otrzymali¶my jaki¶ ruch, który nie jest jeszcze
		 * sklasyfikowany przez nas. To definitywny b³±d.
		 */
		fprintf(stderr, "something is very wrong; we don't seem\n"
		    " to handle such a type of traffic.");
		exit(EXIT_FAILURE);
	}
	return (0);
}

/*
 * Dostêpne rozdzielacze.
 * WKPM: wska¼niki na allow/rx/tx powinny byæ w struct iface.
 * Wtedy nie trzeba by³oby mieæ rozdzielacza, ale ju¿...
 */
struct conn_dispatcher dispatchers[] = {
	[NID_HOST] = {
		.allow = host_allow,
		.rx = host_rx,
		.tx = host_tx,
	},
	[NID_HUB] = {
		.allow = hub_allow,
		.rx = hub_rx,
		.tx = hub_tx,
	},
#if 0
	[NID_ROUTER] = {
		.allow = NULL,
		.rx = NULL,
		.tx = NULL,
	},
#endif
};

/*
 * Poka¿ listê komend (debugging)
 */
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

/*
 * Obs³u¿ liniê wej¶ciow± i zwróæ listê komend.
 */
int
cmd_parse(struct cmdlist **cmdlist, int *cmd_num, const char *cmdstring)
{
	struct cmdlist *l = NULL;
	struct cmd *cmdp = NULL;
	char *tmps = NULL;
	char *cmds = NULL;
	int howmany = 0;

	ASSERT(cmdlist != NULL);
	ASSERT(*cmdlist == NULL);
	ASSERT(cmd_num != NULL);
	ASSERT(cmdstring != NULL);

	l = calloc(sizeof(*l), 1);
	ASSERT(l != NULL);
	TAILQ_INIT(l);

	tmps = strdup(cmdstring);
	ASSERT(tmps != NULL);

	while ((cmds = strsep(&tmps, " \t")) != NULL) {
		cmdp = calloc(1, sizeof(*cmdp));
		ASSERT(cmdp != NULL);
		snprintf(cmdp->name, sizeof(cmdp->name) - 1, "%s", cmds);
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

/*
 * We¼ pierwsz± komendê je¿eli to ta, o któr± nam chodzi.
 */
int
cmd_remove_if_match(struct cmdlist *l, const char *match)
{
	struct cmd *cmd_thing = NULL;
	
	ASSERT(l != NULL && "l nie mo¿e byæ tutaj NULL");

	cmd_thing = TAILQ_FIRST(l);
	ASSERT(cmd_thing != NULL && "lista musi mieæ choæby 1 element");
	if (strcmp(cmd_thing->name, match) == 0) {
		TAILQ_REMOVE(l, cmd_thing, next);
		/* free mem */
		return (1);
	}

	return (0);
}

/*
 * We¼ pierwsz± komendê.
 */
struct cmd *
cmdlist_first(struct cmdlist *l)
{
	struct cmd *ret;

	ASSERT(l != NULL);
	if (TAILQ_EMPTY(l))
		return (NULL);
	ret = TAILQ_FIRST(l);
	TAILQ_REMOVE(l, ret, next);
	return (ret);
}

/*
 * Zwróæ warto¶æ komendy.
 */
char *
cmd_val(struct cmd *c)
{

	ASSERT(c != NULL);
	ASSERT(c->name != NULL);
	return (c->name);
}

/*
 * Rozdziel komendy symulatora bazuj±c na ich nazwach.
 */
int
cmd_dispatch(struct network *n, struct cmdlist *l)
{
	int error = 0;

	ASSERT(TAILQ_EMPTY(l) != 1);

	if (cmd_remove_if_match(l, "version")) {
		error = cmd_dispatch_version(n, l);
	} else if (cmd_remove_if_match(l, "host")) {
		error = cmd_dispatch_host(n, l);
	} else if (cmd_remove_if_match(l, "hub")) {
		error = cmd_dispatch_hub(n, l, HUB_MODE_NORMAL);
	} else if (cmd_remove_if_match(l, "switch")) {
		error = cmd_dispatch_hub(n, l, HUB_MODE_SWITCH);
	} else if (cmd_remove_if_match(l, "router")) {
		error = cmd_dispatch_router(n, l);
	} else if (cmd_remove_if_match(l, "connect")) {
		error = cmd_dispatch_connect(n, l);
	} else if (cmd_remove_if_match(l, "iface")) {
		error = cmd_dispatch_iface(n, l);
	}
	else if (cmd_remove_if_match(l, "set")) {
		error = cmd_dispatch_set(n, l);
	}
	else if (cmd_remove_if_match(l, "graph")) {
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

/*
 * Znajd¼ interfejs na bazie jego IP.
 */
struct iface *
iface_find_by_ip(struct network *n, char *ipspec)
{
	struct iface *ifp = NULL;
	struct nid *nid = NULL;
	unsigned int ipv4[ADDRV4_LEN];
	int error = 0;

	error = string_to_addrv4(ipspec, ipv4);
	if (error != 0)
		return (NULL);

	TAILQ_FOREACH(nid, &n->nids, next) {
		if (nid_type_get(nid) == NID_IFACE) {
			ifp = nid->obj;
			if (addrv4_eq(ifp->ipv4, ipv4))
				return (ifp);
		}
	}

	return (NULL);
}

/*
 * Obs³uga komendy: host <nazwa> ping <adresip>
 */
int
cmd_dispatch_host_ping(struct network *n, const char *host_name, struct cmdlist *l)
{
	struct cmd *tgt = NULL;
	char *tgts = NULL;
	struct iface *dst_ifp = NULL;
	struct iface *src_ifp = NULL;
	struct pkt *pkt = NULL;
	struct nid *nid = NULL;

	NETWORK_ASSERT(n);
	ASSERT(l != NULL);
	ASSERT(host_name != NULL);

	/*
	 * Pobierz argument komendy ``ping''. Na razie zak³adamy, ¿e to
	 * jest adres IP.
	 */
	tgt = cmdlist_first(l);
	if (tgt == NULL)
		return (network_err(n, "Ping takes ``target'' argument"));
	tgts = cmd_val(tgt);

	/* 
	 * Zdalny interfejs, do którego docelowo maj± trafiæ pakiety
	 * Nie wrzucamy do niego od razu danych, a tylko pobieramy adres
	 * MAC/IP.
	 */
	dst_ifp = iface_find_by_ip(n, tgts);
	if (dst_ifp == NULL)
		return (network_err(n, "Interface with IP ``%s'' doesn't"
		    " exist", tgts));
	IFACE_ASSERT(dst_ifp);

	/* 
	 * XXX: dsp_ifp tutaj CHYBA mog³oby wskazywaæ na pusty
	 * interfejs, tak ¿eby host móg³ próbowaæ wys³aæ PINGa na
	 * nieistniej±cy interfejs.
	 */

	/*
	 * Lokalny interfejs hosta, z którego wysy³amy
	 */
	nid = nid_lookup(&n->nids, host_name, 0, NID_IFACE);
	if (nid == NULL)
		return (network_err(n, "Host ``%s'' doesn't exist", nid_name_get(nid)));
	src_ifp = nid->obj;
	IFACE_ASSERT(src_ifp);

	/*
	 * Pakujemy dane w pakiet bêd±cy w stanie pomie¶ciæ zarówno
	 * nag³ówek Ethernet jak i IP oraz ICMP.
	 */
	pkt = pkt_create(1000 /*ETH_LEN + IP_LEN + ICMP_LEN */);
	pkt_init(pkt, ICMP_PING_REQUEST, src_ifp, dst_ifp);

	/*
	 * Maj±c pakiet wype³niony ¼ród³owym+docelowym adresem IP oraz 
	 * ¼ród³owym+docelowym adresem MAC, pakiet umieszczamy w kolejce
	 * hosta ¼ród³owego -- czyli staje siê gotowy do wys³ania.
	 */
	PKT_ASSERT(pkt);
	pktq_enqueue(&src_ifp->outq, pkt);

	return (0);
}

/*
 * Obs³uga:
 *	host <nazwa> create
 *	host <nazwa> remove
 *	host <nazwa> ping ...
 */
int
cmd_dispatch_host(struct network *n, struct cmdlist *l)
{
	struct cmd *host_name = NULL;
	struct cmd *action = NULL;
	char *acts = NULL;
	char *host_name_str = NULL;
	int error = 0;

	NETWORK_ASSERT(n);

	host_name = cmdlist_first(l);
	if (host_name == NULL)
		return (network_err(n, "No host name given!"));
	host_name_str = cmd_val(host_name);

	action = cmdlist_first(l);
	if (action == NULL)
		return (network_err(n, "No action given!"));
	acts = cmd_val(action);

	if (streq(acts, "create")) {
		error = host_create(n, host_name_str);
	} else if (streq(acts, "remove")) {
		error = host_remove(n, host_name_str);
	} else if (streq(acts, "ping")) {
		error = cmd_dispatch_host_ping(n, host_name_str, l);
	} else {
		error = network_err(n, "Subcommand '%s' unsupported", acts);
	}
	return (error);
}

/*
 * Obs³uga:
 * 	hub <nazwa> create
 * 	hub <nazwa> remove
 *
 * oraz
 * 	switch <nazwa> create
 * 	switch <nazwa> remove
 */
int
cmd_dispatch_hub(struct network *n, struct cmdlist *l, hub_mode_t mode)
{
	struct cmd *hb = NULL;
	struct cmd *action = NULL;
	char *hname = NULL;
	char *acts = NULL;
	int error = 0;

	NETWORK_ASSERT(n);
	ASSERT(l != NULL);

	hb = cmdlist_first(l);
	if (hb == NULL)
		return (network_err(n, "Hub/switch name must be given"));
	hname = cmd_val(hb);

	action = cmdlist_first(l);
	if (action == NULL)
		return (network_err(n, "Action is required in 'hub' command"));
	acts = cmd_val(action);

	if (streq(acts, "create")) {
		error = hub_create(n, hname, mode);
	} else if (streq(acts, "remove")) {
		error = hub_remove(n, hname);
	}

	return (0);
}

/*
 * Obs³uga:
 * 	router <nazwa> create
 * 	router <nazwa> remove
 * 	router <nazwa> route ...
 */
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
		error = router_create(n, rname);
	} else if (streq(acts, "remove")) {
		error = router_remove(n, rname);
	} else if (streq(acts, "route")) {
		error =  cmd_dispatch_router_route(n, rname, l);
	} else {
		return (network_err(n,
		    "Unknown subcommand '%s' to the 'router' command", cmd_val(action)));
	}

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
 * Alokacja po³aczenia.
 */
struct conn *
conn_alloc(void)
{
	struct conn *c;

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return (NULL);

	CONN_INIT(c);
	CONN_ASSERT(c);

	return (c);
}

/*
 * Zniszczenie po³±czenia.
 */
void
conn_destroy(struct conn *conn)
{
	struct iface *i0, *i1;

	i0 = conn->nid0->obj;
	i1 = conn->nid1->obj;
	IFACE_ASSERT(i0);
	IFACE_ASSERT(i1);
	iface_flag_clear(i0, IFACE_FLAG_HASCONN);
	iface_flag_clear(i1, IFACE_FLAG_HASCONN);
	memset(conn, 0, sizeof(conn));
	free(conn);
}

/*
 * Rejestracja po³±czenia w sieci.
 */
void
conn_register(struct connlist *connlist, struct conn *conn)
{

	ASSERT(connlist != NULL);
	CONN_ASSERT(conn);
	TAILQ_INSERT_TAIL(connlist, conn, next);
}

/*
 * Czy interfejs nale¿y do huba?
 */
int
iface_of_hub(struct iface *ifp)
{

	return (nid_type_get(ifp->nid_owner) == NID_HUB);
}

/*
 * Czy interfejs nale¿y do hosta?
 */
int
iface_of_host(struct iface *ifp)
{

	return (nid_type_get(ifp->nid_owner) == NID_HOST);
}

/*
 * Czy interfejs jest aktywny?
 */
int
iface_is_active(struct iface *ifp)
{
	int i = 0;

	/* 
	 * 3 elements need to be specified in order to make
	 * the interface appear as active:
	 * - netmask
	 * - ip address
	 * - mac address
	 */
	i += iface_flag_has(ifp, IFACE_FLAG_HASIP);
	i += iface_flag_has(ifp, IFACE_FLAG_HASMAC);
	i += iface_flag_has(ifp, IFACE_FLAG_HASNM);
	return (i == 3);
}

/*
 * Stwórz po³±czenie miêdzy dwoma interfejsami -- ka¿dy z 2 przekazanych 
 * tutaj "network identifiers" (identyfikatorów) musi nie¶æ za sob±
 * interfejs.
 */
struct conn *
conn_create(struct nid *nid0, struct nid *nid1)
{
	struct conn *conn = NULL;
	struct iface *i0, *i1;
	int inactive = 0;
	
	/* Activate interfaces */
	i0 = nid0->obj;
	i1 = nid1->obj;
	IFACE_ASSERT(i0);
	IFACE_ASSERT(i1);

	if (iface_of_hub(i0) && iface_of_hub(i1))
		//"Connection between two hub's interfaces isn't possible"
		return (NULL);

	inactive += (iface_is_active(i0) != 1);
	inactive += (iface_is_active(i1) != 1);
	if (inactive == 2) {
		//"Can't create connection between 2 inactive interfaces"
		return (NULL);
	}

	/* Zaznacza, ¿e odt±d mamy po³±czenie. */
	iface_flag_set(i0, IFACE_FLAG_HASCONN);
	i0->conn_ifp = i1;
	iface_flag_set(i1, IFACE_FLAG_HASCONN);
	i1->conn_ifp = i0;

	conn = conn_alloc();
	CONN_ASSERT(conn);
	conn->nid0 = nid0;
	conn->nid1 = nid1;
	CONN_ASSERT(conn);

	return (conn);
}

/*
 * Zwróc opis po³±czenia.
 * WKPM: Uzupe³niæ...
 */
void
conn_debug(struct conn *conn, FILE *fp)
{

	CONN_ASSERT(conn);
	fprintf(fp, "Connection between '%s' and '%s'\n",
	    nid_type_desc(conn->nid0),
	    nid_type_desc(conn->nid0)
	);
}

/*
 * Obs³uga:
 * 	connect <NAZWA> <NUMER> <NAZWA2> <NUMER2>
 *
 */
int
cmd_dispatch_connect(struct network *n, struct cmdlist *l)
{
	struct cmd *name0 = NULL;
	struct cmd *name1 = NULL;
	struct cmd *num0 = NULL;
	struct cmd *num1 = NULL;
	struct nid *nid0 = NULL;
	struct nid *nid1 = NULL;
	char *name0_str = NULL;
	char *name1_str = NULL;
	struct conn *conn = NULL;
	int inum0 = 0;
	int inum1 = 0;

	/* First connection part */
	name0 = cmdlist_first(l);
	if (name0 == NULL)
		return (network_err(n, "No network object name given!"));
	name0_str = cmd_val(name0);

	num0 = cmdlist_first(l);
	if (num0 == NULL)
		return (network_err(n, "No interface name given!"));
	inum0 = atoi(cmd_val(num0));

	/* Second connection part */
	name1 = cmdlist_first(l);
	if (name1 == NULL)
		return (network_err(n, "No network object name given!"));
	name1_str = cmd_val(name1);

	num1 = cmdlist_first(l);
	if (num1 == NULL)
		return (network_err(n, "No interface name given!"));
	inum1 = atoi(cmd_val(num1));

	nid0 = nid_lookup(&n->nids, name0_str, inum0, NID_IFACE);
	if (nid0 == NULL)
		return (network_err(n, "There's not interface %s:%d\n", name0_str, inum0));
	nid1 = nid_lookup(&n->nids, name1_str, inum1, NID_IFACE);
	if (nid1 == NULL)
		return (network_err(n, "There's not interface %s:%d\n", name1_str, inum1));

	conn = conn_create(nid0, nid1);
	if (conn == NULL)
		return (network_err(n, "%s", network_errmsg_get(n)));

	conn_register(&n->connlist, conn);

	return (0);
}

/*
 * Obs³uga:
 * 	version <WERSJA>
 */
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

/*
 * Obs³uga:
 * 	set <param> <val>
 */
int
cmd_dispatch_set(struct network *n, struct cmdlist *l)
{
	struct cmd *param = NULL;
	char *param_str = NULL;
	struct cmd *val = NULL;
	char *val_str = NULL;
	int i;

	param = cmdlist_first(l);
	if (param == NULL)
		return (network_err(n, "Command ``param'' must have a subcommand"));
	param_str = cmd_val(param);
	
	val = cmdlist_first(l);
	if (val == NULL)
		return (network_err(n, "Command ``val'' must have a subcommand"));
	val_str = cmd_val(val);

	if (streq(param_str, "simtime")) {
		i = atoi(val_str);
		if (i < 0 || i > 10000)
			return (network_err(n, "Simtime value '%s' seems wrong", val_str));
		n->simtime = i;
	}
	return (0);
}

/*
 * Czy MAC jest poprawny?
 */
int
ethernet_mac_valid(unsigned int mac[ETHER_MAC_LEN])
{

	return (1);
}

/*
 * Konwersja z "%x:%x:%x:%x:%x:%x" do postaci 6 bajtów.
 */
int
string_to_ethernet(const char *s, unsigned int mac[ETHER_MAC_LEN])
{

	ASSERT(s != NULL);

	sscanf(s, "%x:%x:%x:%x:%x:%x",
	    &mac[0],
	    &mac[1],
	    &mac[2],
	    &mac[3],
	    &mac[4],
	    &mac[5]
	);
	if (!ethernet_mac_valid(mac))
		return (-1);
	return (0);
}

/*
 * Konwersja adresu wersji 4 (maski/IP) do postaci 4 bajtów.
 */
int
string_to_addrv4(const char *s, unsigned int ip[ADDRV4_LEN])
{
	int ret = 0;

	ASSERT(s != NULL);

	ret = sscanf(s, "%u.%u.%u.%u",
	    &ip[0],
	    &ip[1],
	    &ip[2],
	    &ip[3]
	);
	if (ret != 4)
		return (-1);
	return (0);
}

/*
 * Czy 2 adresy s± sobie równe?
 */
int
addrv4_eq(unsigned int a0[ADDRV4_LEN], unsigned int a1[ADDRV4_LEN])
{
	int i = 0;
	int e = 0;

	for (i = 0; i < ADDRV4_LEN; i++)
		if (a0[i] == a1[i])
			e++;

	return (e == ADDRV4_LEN);
}

/*
 * Czy adres IP jest poprawny?
 */
int
ipv4_valid(unsigned int addr[ADDRV4_LEN])
{

	return (1);
}

/*
 * Konwesja adresu IP do postaci 4 bajtów i sprawdzenie poprawno¶ci.
 */
int
string_to_ipv4(const char *s, unsigned int ip[ADDRV4_LEN])
{
	int error;

	error = string_to_addrv4(s, ip); /* shoudl leave ip without a touch */
	if (error != 0 || !ipv4_valid(ip))
		return (-1);
	return (0);
}

/*
 * Czy maska jest poprawna.
 * WKPM: Uzupe³niæ z funkcjami dostêpnymi na dole.
 */
int
nmv4_valid(unsigned int addr[ADDRV4_LEN])
{

	return (1);
}

/*
 * Skonwertuj maskê do postaci 4 bajtów i sprawd¼ jej poprawno¶æ.
 */
int
string_to_nmv4(const char *s, unsigned int nm[ADDRV4_LEN])
{
	int error = 0;

	error = string_to_addrv4(s, nm);
	if (error != 0 || !nmv4_valid(nm))
		return (-1);
	return (0);
}

/*
 * Obs³uga:
 * 	iface <NAZWA> <NUMER> ip <ADRES_IP>
 * 	iface <NAZWA> <NUMER> netmask <ADRES_IP>
 * 	iface <NAZWA> <NUMER> mac <ADRES_MAC>
 * 	iface <NAZWA> <NUMER> ping ...
 */
int
cmd_dispatch_iface(struct network *n, struct cmdlist *l)
{
	struct nid *nid = NULL;
	struct nid *nid_owner = NULL;
	struct cmd *name = NULL;
	struct cmd *ifnum = NULL;
	struct cmd *action = NULL;
	struct cmd *arg = NULL;
	struct iface *ifp = NULL;
	char *arg_str = NULL;
	int inum = -2;
	int error = 0;

	NETWORK_ASSERT(n);
	ASSERT(l != NULL);

	name = cmdlist_first(l);
	if (name == NULL)
		return (network_err(n, "Command 'iface' requires ``name'' argument"));
	ifnum = cmdlist_first(l);
	if (ifnum == NULL)
		return (network_err(n, "Command 'iface' requires ``number'' argument"));
	action = cmdlist_first(l);
	if (action == NULL)
		return (network_err(n, "Command 'iface' requires ``action'' argument"));
	arg = cmdlist_first(l);
	if (arg == NULL)
		return (network_err(n, "Command 'iface' requires ``action argument'' parameter"));
	arg_str = cmd_val(arg);

	inum = atoi(cmd_val(ifnum));
	nid = nid_lookup(&n->nids, cmd_val(name), inum, NID_IFACE);
	if (nid == NULL)
		return (network_err(n, "Interface '%s:%d' doesn't exist", cmd_val(name), inum));
	ifp = nid->obj;
	IFACE_ASSERT(ifp);

	nid_owner = ifp->nid_owner;
	if (nid_type_get(nid_owner) == NID_HUB)
		return (network_err(n, "You can't modify hub's ports -- these are autoconfigured"));

	if (streq(cmd_val(action), "mac")) {
		error = network_iface_mac_set(n, ifp, cmd_val(arg));
	} else if (streq(cmd_val(action), "ip")) {
		error = network_iface_ipv4_set(n, ifp, cmd_val(arg));
	} else if (streq(cmd_val(action), "netmask")) {
		error = network_iface_nmv4_set(n, ifp, cmd_val(arg));
	} else {
		return (network_err(n, "Subcommand '%s' of command 'iface' unknown", cmd_val(action)));
	}

	return (error);
}

/*
 * Ustaw flagê flag.
 */
void
iface_flag_set(struct iface *iface, int flag)
{

	IFACE_ASSERT(iface);
	iface->flags |= flag;
}

/*
 * Wyczy¶æ flagê flag.
 */
void
iface_flag_clear(struct iface *iface, int flag)
{

	IFACE_ASSERT(iface);
	iface->flags &= ~flag;
}

/*
 * Czy interfejs ma flagê flag
 */
int
iface_flag_has(struct iface *iface, int flag)
{

	IFACE_ASSERT(iface);
	return ((iface->flags & flag) != 0);
}

/*
 * Ustaw MAC dla interfejsu.
 */
int
network_iface_mac_set(struct network *n, struct iface *ifp, const char *macspec)
{
	unsigned int mac[ETHER_MAC_LEN];
	int error = 0;

	NETWORK_ASSERT(n);
	IFACE_ASSERT(ifp);

	error = string_to_ethernet(macspec, mac);
	if (error != 0)
		return (network_err(n, "Couldn't convert '%s' to valid Ethernet MAC address",
			macspec));

	iface_flag_set(ifp, IFACE_FLAG_HASMAC);
	memcpy(ifp->mac, mac, sizeof(ifp->mac));

	return (0);
}

/*
 * Ustaw IP dla interfejsu.
 */
int
network_iface_ipv4_set(struct network *n, struct iface *ifp, const char *addrv4_spec)
{
	unsigned int addrv4[ADDRV4_LEN];
	int error = 0;

	NETWORK_ASSERT(n);
	IFACE_ASSERT(ifp);

	error = string_to_ipv4(addrv4_spec, addrv4);
	if (error != 0)
		return (network_err(n, "Couldn't convert '%s' to valid IPv4 address",
		    addrv4_spec));

	iface_flag_set(ifp, IFACE_FLAG_HASIP);
	memcpy(ifp->ipv4, addrv4, sizeof(ifp->ipv4));

	return (0);
}

/*
 * Ustaw maskê sieciow± dla interfejsu.
 */
int
network_iface_nmv4_set(struct network *n, struct iface *ifp, const char *addrv4_spec)
{
	unsigned int addrv4[ADDRV4_LEN];
	int error = 0;

	NETWORK_ASSERT(n);
	IFACE_ASSERT(ifp);

	error = string_to_nmv4(addrv4_spec, addrv4);
	if (error != 0)
		return (network_err(n, "Couldn't convert '%s' to valid IPv4 netmask",
		    addrv4_spec));

	iface_flag_set(ifp, IFACE_FLAG_HASNM);
	memcpy(ifp->nmv4, addrv4, sizeof(ifp->nmv4));

	return (0);
}

/*
 * Alokacja struktury hosta.
 */
struct host *
host_alloc(void)
{
	struct host *h = NULL;

	h = calloc(1, sizeof(*h));
	if (h == NULL)
		return (NULL);

	HOST_INIT(h);
	HOST_ASSERT(h);

	return (h);
}

/*
 * Stwórz host i pod³±cz go do sieci.
 */
int
host_create(struct network *n, const char *host_name)
{
	struct host *hp = NULL;
	struct nid *nid = NULL;
	struct iface *ifp = NULL;

	NETWORK_ASSERT(n);

	nid = nid_lookup(&n->nids, host_name, -1, -1);
	if (nid != NULL)
		return (network_err(n, "%s '%s' already exists (%s)", nid_type_desc(nid), host_name));
	nid = nid_create(host_name, -1);
	if (nid == NULL)
		return (network_err(n, "Coulndn't create host '%s'", host_name));

	hp = host_alloc();
	if (hp == NULL)
		return (network_err(n, "Couldn't create '%s' host", host_name));

	hp->nid = nid;
	nid_obj_set(nid, hp);
	nid_type_set(nid, NID_HOST);

	ifp = iface_create(n, host_name, 0);
	if (ifp == NULL)
		return (network_err(n, "Couldn't create interface"));
	IFACE_ASSERT(ifp);
	iface_owner_set(ifp, nid);
	hp->iface[0] = ifp;

	nid_register(&n->nids, nid);

	return (0);
}

/*
 * Zniszcz host
 */
int
host_destroy(struct network *n, struct host *host)
{
	struct nid *nid = NULL;

	NETWORK_ASSERT(n);
	HOST_ASSERT(host);

	nid = host->nid;
	nid_unregister(&n->nids, nid);
	nid_destroy(nid);

	memset(host, 0, sizeof(*host));
	free(host);

	return (0);
}

/*
 * Usuñ host z sieci.
 */
int
host_remove(struct network *n, const char *host_name)
{
	struct host *host= NULL;
	struct iface *ifp = NULL;
	struct nid *nid = NULL;

	NETWORK_ASSERT(n);
	ASSERT(host_name != NULL);

	/* ID of the interface */
	nid = nid_lookup(&n->nids, host_name, 0, NID_IFACE);
	if (nid == NULL)
		return (network_err(n, "Host '%s' doesn't exist", host_name));

	/* We recover an owner-host of the interface */
	ifp = nid->obj;
	host = ifp->nid_owner->obj;

	iface_destroy(n, ifp);
	host_destroy(n, host);

	return (0);
}

/*
 * Wypisz informacje dot. hosta do strumienia fp
 */
void
host_debug(struct host *h, FILE *fp)
{
	struct nid *nid;

	HOST_ASSERT(h);
	nid = h->nid;
	NID_ASSERT(nid);
	fprintf(fp, "      Host:\n");
	fprintf(fp, "      -----\n");
	fprintf(fp, "      Name: '%s'\n", nid_name_get(nid));
	fprintf(fp, "        ID: %d'\n\n", nid_id_get(nid));
	iface_debug(h->iface[0], fp);
}

/*
 * Wypisz informacje dot. huba do strumienia fp/
 */
void
hub_debug(struct hub *h, FILE *fp)
{
	struct nid *nid;
	int i;

	HUB_ASSERT(h);
	nid = h->nid;
	NID_ASSERT(nid);
	fprintf(fp, "# --| %s: ---------------------------------------------------\n", nid_type_desc(nid));
	fprintf(fp, "       %s: '%s'\n", nid_type_desc(nid), nid_name_get(nid));
	fprintf(fp, "       ID: %d\n", nid_id_get(nid));
	for (i = 0; i < HUB_IFACES; i++)
		iface_debug(h->iface[i], fp);
}

/*
 * Wypisz informacje dot. routera do strumienia fp.
 */
void
router_debug(struct router *h, FILE *fp)
{
	struct nid *nid;

	ROUTER_ASSERT(h);
	nid = h->nid;
	NID_ASSERT(nid);
	fprintf(fp, "\tRouter:\n");
	fprintf(fp, "\t       \tName: '%s'\n", nid_name_get(nid));
	fprintf(fp, "\t       \tInternal NID ID: %d\n", nid_id_get(nid));
}

/*
 * Alokacja struktury huba.
 */
struct hub *
hub_alloc(void)
{
	struct hub *h;

	h = calloc(sizeof(*h), 1);
	if (h == NULL)
		return (NULL);
	HUB_INIT(h);
	HUB_ASSERT(h);
	return (h);
}

/*
 * Zniszczenie struktury huba
 */
void
hub_destroy(struct network *n, struct hub *h)
{
	struct nid *nid = NULL;

	NETWORK_ASSERT(n);
	HUB_ASSERT(h);

	nid = h->nid;
	nid_unregister(&n->nids, nid);
	nid_destroy(nid);

	memset(h, 0, sizeof(*h));
	free(h);
}

/*
 * Stworzenie huba i pod³±czenie go do sieci.
 */
int
hub_create(struct network *n, const char *hub_name, hub_mode_t mode)
{
	struct nid *nid = NULL;
	struct hub *hub = NULL;
	struct iface *ifp = NULL;
	int i = 0;

	NETWORK_ASSERT(n);
	ASSERT(hub_name != NULL);

	nid = nid_lookup(&n->nids, hub_name, -1, -1);
	if (nid != NULL)
		return (network_err(n, "'%s' already exists '%s'", hub_name,
			nid_type_desc(nid)));

	nid = nid_create(hub_name, -1);
	NID_ASSERT(nid);

	hub = hub_alloc();
	hub->nid = nid;

	nid_type_set(nid, NID_HUB);
	nid_obj_set(nid, hub);

	nid_register(&n->nids, nid);

	for (i = 0; i < HUB_IFACES; i++) {
		ifp = iface_create(n, hub_name, i);
		if (ifp == NULL)
			return (network_err(n, "Couldn't create interface"));
		iface_owner_set(ifp, nid);
		hub->iface[i] = ifp;
	}
	hub->mode = mode;

	return (0);
}

/*
 * Usuniêcie huba z sieci i jego zniszczenie.
 */
int
hub_remove(struct network *n, const char *hub_name)
{
	struct nid *nid = NULL;
	struct hub *hub = NULL;
	struct iface *ifp = NULL;
	int i = 0;

	NETWORK_ASSERT(n);
	ASSERT(hub_name != NULL);

	nid = nid_lookup(&n->nids, hub_name, -1, NID_HUB);
	if (nid == NULL)
		return (network_err(n, "Hub/switch '%s' doesn't exist", hub_name));

	NID_ASSERT(nid);
	hub = nid->obj;
	HUB_ASSERT(hub);
	hub_destroy(n, hub);

	for (i = 0; i < HUB_IFACES; i++) {
		nid = nid_lookup(&n->nids, hub_name, i, NID_IFACE);
		if (nid == NULL)
			return (network_err(n, "Interface '%s':%d doesn't exists", hub_name, i));
		NID_ASSERT(nid);
		ifp = nid->obj;
		IFACE_ASSERT(ifp);
		iface_destroy(n, ifp);
	}

	return (0);
}

/*
 * Stwórz pakiet.
 */
struct pkt *
pkt_create(int len)
{
	struct pkt *pkt;

	pkt = calloc(1, sizeof(*pkt));
	PKT_INIT(pkt);
	pkt->data = calloc(1, len);
	ASSERT(pkt->data != NULL);
	pkt->len = len;
	pkt->id = pkt_ids;
	pkt->src_ifp = NULL;
	pkt->dst_ifp = NULL;
	pkt_ids++;
	PKT_ASSERT(pkt);
	return (pkt);
}

/*
 * Zniszcz pakiet.
 */
void
pkt_destroy(struct pkt *pkt)
{

	PKT_ASSERT(pkt);

	memset(pkt->data, 0, pkt->len);
	free(pkt->data);
	memset(pkt, 0, sizeof(pkt));
	free(pkt);
}

/*
 * Ta funkcja replikuje równie¿ wska¼niki na interfejsy, które znajduj±
 * siê w strukturze pakietu.
 */
struct pkt *
pkt_dup(struct pkt *pkt)
{
	struct pkt *pkt2 = NULL;

	PKT_ASSERT(pkt);
	pkt2 = calloc(1, sizeof(*pkt));
	memcpy(pkt2, pkt, sizeof(*pkt2));
	pkt2->data = calloc(1, pkt->len);
	ASSERT(pkt2->data != NULL);
	memcpy(pkt2->data, pkt->data, pkt->len);
	pkt2->id = pkt_ids++;

	return (pkt2);
}

/* ARP -- nieuzywane */
void
arptable_init(struct arptable *at)
{

	TAILQ_INIT(at);
}

void
arptable_destroy(struct arptable *at)
{

	memset(at, 0, sizeof(at));
	at = NULL;
}

/*
 * Pobierz miejsca w pakiecie, w których mamy interesuj±ce nas dane.
 * WKPM: ICMP!
 */
void
pkt_proto_getptrs(struct pkt *pkt, struct eth_hdr **ehp, struct ip_hdr **iphp, struct icmp_hdr **icmphp)
{
	char *begin;

	PKT_ASSERT(pkt);
	ASSERT(pkt->len >=
	    sizeof(*ehp) + sizeof(*iphp) + sizeof(*icmphp)
	);

	begin = (char *)pkt->data;

	*ehp = 
		(struct eth_hdr *)(begin + 0);
	*iphp =
		(struct ip_hdr *)(begin + sizeof(struct eth_hdr));
	*icmphp =
		(struct icmp_hdr *)(begin + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
}

/*
 * Inicjalizuj pakiet
 *
 * ...jak na razie - ICMP
 */
void
pkt_init(struct pkt *pkt, int type, struct iface *srci, struct iface *dsti)
{
	struct eth_hdr *eh = NULL;
	struct ip_hdr *iph = NULL;
	struct icmp_hdr *icmph = NULL;

	PKT_ASSERT(pkt);
	pkt_proto_getptrs(pkt, &eh, &iph, &icmph);
	ASSERT(eh != NULL);
	ASSERT(iph != NULL);
	ASSERT(icmph != NULL);
	ASSERT(
	    type == ICMP_PING_REQUEST ||
	    type == ICMP_PING_ANSWER
	);
	IFACE_ASSERT(srci);
	IFACE_ASSERT(dsti);

	pkt->src_ifp = srci;
	pkt->dst_ifp = dsti;

	/* Ethernet init */
	memcpy(eh->src_mac, srci->mac, sizeof(eh->src_mac));
	memcpy(eh->dst_mac, dsti->mac, sizeof(eh->dst_mac));

	/* IP init */
	memcpy(iph->src_ipv4, srci->ipv4, sizeof(iph->src_ipv4));
	memcpy(iph->dst_ipv4, dsti->ipv4, sizeof(iph->dst_ipv4));

	/* ICMP init */
	icmph->type = type;
}

/*
 * Wypisz informacje dot. pakietu do strumienia fp.
 */
void
pkt_debug(struct pkt *pkt, FILE *fp)
{
	struct eth_hdr *eh = NULL;
	struct ip_hdr *iph = NULL;
	struct icmp_hdr *icmph = NULL;

	PKT_ASSERT(pkt);
	pkt_proto_getptrs(pkt, &eh, &iph, &icmph);
	ASSERT(eh != NULL);
	ASSERT(iph != NULL);
	ASSERT(icmph != NULL);

	PKT_ASSERT(pkt);
	fprintf(fp, 
	    "SrcIP: %d.%d.%d.%d, "
	    "DstIP: %d.%d.%d.%d; "
	    "SrcMAC: %x:%x:%x:%x:%x:%x "
	    "DstMAC: %x:%x:%x:%x:%x:%x "
	    "Type: %d",
	    iph->src_ipv4[0],
	    iph->src_ipv4[1],
	    iph->src_ipv4[2],
	    iph->src_ipv4[3],

	    iph->dst_ipv4[0],
	    iph->dst_ipv4[1],
	    iph->dst_ipv4[2],
	    iph->dst_ipv4[3],

	    eh->src_mac[0],
	    eh->src_mac[1],
	    eh->src_mac[2],
	    eh->src_mac[3],
	    eh->src_mac[4],
	    eh->src_mac[5],

	    eh->dst_mac[0],
	    eh->dst_mac[1],
	    eh->dst_mac[2],
	    eh->dst_mac[3],
	    eh->dst_mac[4],
	    eh->dst_mac[5],

	    icmph->type
	);
}

/*
 * Inicjalizuj kolejkê pktq.
 */
void
pktq_init(struct pktq *pktq)
{

	TAILQ_INIT(pktq);
}

/*
 * Zniszcz kolejkê pktq.
 */
void
pktq_destroy(struct pktq *pktq)
{

	memset(pktq, 0, sizeof(*pktq));
}

/*
 * Wypisz informacje o kolejce do strumienia fp.
 */
void
pktq_debug(struct pktq *pktq, FILE *fp)
{
	struct pkt *pkt = NULL;
	int i = 0;

	TAILQ_FOREACH(pkt, pktq, next) {
		fprintf(fp, "                             ");
		fprintf(fp, "PKT%d = (", i);
		pkt_debug(pkt, fp);
		fprintf(fp, ")\n");
		i++;
	}
}

/*
 * Skolejkuj pakiet pkt w kolejce pktq.
 */
void
pktq_enqueue(struct pktq *pktq, struct pkt *pkt)
{

	ASSERT(pktq != NULL);
	PKT_ASSERT(pkt);

	TAILQ_INSERT_TAIL(pktq, pkt, next);
}

/*
 * Kandydat do usuniêcia.
 */
struct pkt *
pktq_dequeue_candidate(struct pktq *pktq)
{

	return (TAILQ_FIRST(pktq));
}

/*
 * Usuniêcie pakietu z kolejki.
 */
void
pktq_remove(struct pktq *pktq, struct pkt *pkt)
{

	TAILQ_REMOVE(pktq, pkt, next);
}

/*
 * Pobranie pakietu z kolejki.
 */
struct pkt *
pktq_dequeue(struct pktq *pktq)
{
	struct pkt *pkt;

	pkt = pktq_dequeue_candidate(pktq);
	pktq_remove(pktq, pkt);

	return (pkt);
}

/*
 * Czy kolejka pusta?
 */
int
pktq_empty(struct pktq *pktq)
{

	return (TAILQ_EMPTY(pktq));
}

/*
 * Stworzenie interfejsu sieciowego.
 */
struct iface *
iface_create(struct network *n, const char *name, int id)
{
	struct iface *ifp = NULL;
	struct nid *nid = NULL;

	NETWORK_ASSERT(n);
	ASSERT(name != NULL);

	nid = nid_lookup(&n->nids, name, id, -1);
	if (nid != NULL)
		return (NULL);
	nid = nid_create(name, id);
	NID_ASSERT(nid);

	ifp = calloc(1, sizeof(*ifp));
	if (ifp == NULL)
		return (NULL);
	IFACE_INIT(ifp);
	ifp->nid = nid;

	pktq_init(&ifp->inq);
	pktq_init(&ifp->outq);

	ifp->flags = 0;
	ifp->conn_ifp = NULL;

	IFACE_ASSERT(ifp);

	nid_obj_set(nid, ifp);
	nid_type_set(nid, NID_IFACE);
	nid_register(&n->nids, nid);

	return (ifp);
}

/*
 * Zniszczenie interfejsu sieciowego.
 */
int
iface_destroy(struct network *n, struct iface *iface)
{
	struct nid *nid = NULL;

	NETWORK_ASSERT(n);
	IFACE_ASSERT(iface);

	nid = iface->nid;
	NID_ASSERT(nid);

	nid_unregister(&n->nids, nid);
	nid_destroy(nid);

	memset(iface, 0, sizeof(*iface));
	free(iface);

	return (0);
}

/*
 * Ustawienie w³a¶ciciela interfejsu.
 */
void
iface_owner_set(struct iface *ifp, struct nid *nid)
{

	IFACE_ASSERT(ifp);
	NID_ASSERT(nid);

	ifp->nid_owner = nid;
}

/*
 * Wpisanie informacji o interfejsie ifp do strumienia fp.
 */
void
iface_debug(struct iface *ifp, FILE *fp)
{
	char *name = NULL;
	struct nid *nid = NULL;
	int id = -1;

	IFACE_ASSERT(ifp);

	nid = ifp->nid;

	name = nid_name_get(nid);
	id = nid_id_get(nid);

	fprintf(fp, "      Interface:\n");
	fprintf(fp, "      ----------\n");
	fprintf(fp, "\t   Name: '%s'\n", name);
	fprintf(fp, "\t Number: '%d'\n", id);
	fprintf(fp, "\t Active:  %d\n", iface_is_active(ifp));
	fprintf(fp, "\t  Flags: ");
	if (iface_flag_has(ifp, IFACE_FLAG_HASIP))
		fprintf(fp, " HASIP ");
	if (iface_flag_has(ifp, IFACE_FLAG_HASMAC))
		fprintf(fp, " HASMAC ");
	if (iface_flag_has(ifp, IFACE_FLAG_HASNM))
		fprintf(fp, " HASNM ");
	fprintf(fp, "\n");

	fprintf(fp, "\t     IP:  %d.%d.%d.%d;\n", ifp->ipv4[0], ifp->ipv4[1],
	    ifp->ipv4[2], ifp->ipv4[3]);
	fprintf(fp, "\tNetmask:  %d.%d.%d.%d;\n", ifp->nmv4[0], ifp->nmv4[1],
	    ifp->nmv4[2], ifp->nmv4[3]);
	fprintf(fp, "\t    MAC:  %x:%x:%x:%x:%x:%x\n", ifp->mac[0], ifp->mac[1],
	    ifp->mac[2], ifp->mac[3], ifp->mac[4], ifp->mac[5]);
	
	fprintf(fp, "\n");

	fprintf(fp, "      Output packet queue:\n");
	fprintf(fp, "      --------------------\n");
	fprintf(fp, "                  Address: %p\n", (void *)&ifp->outq);
	fprintf(fp, "                  Content:\n");
	pktq_debug(&ifp->outq, fp);
	fprintf(fp, "\n");

	fprintf(fp, "      Input packet queue:\n");
	fprintf(fp, "      ------------------ \n");
	fprintf(fp, "                 Address: %p\n", (void *)&ifp->inq);
	fprintf(fp, "                 Content:\n");
	pktq_debug(&ifp->inq, fp);
	fprintf(fp, "\n");
}

/*
 * Inicjalizacja listy po³±czeñ.
 */
static int
connlist_init(struct connlist *cl)
{

	TAILQ_INIT(cl);
	return (0);
}

/*
 * Zniszczenie listy po³±czeñ.
 */
static int
connlist_destroy(struct connlist *cl)
{

	return (0);
}

/*
 * Generalna inicjalizacja siatki, z której bêdziemy budowaæ sieæ.
 */
static int
network_init(struct network *n, const char *fname)
{

	ASSERT(n != NULL);
	NETWORK_INIT(n);

	if (fname == NULL)
		n->stream = stdin;
	else {
		n->stream = fopen(fname, "r");
		if (n->stream == NULL) {
			return (network_err(n, "Couldn't open file"
				" %s", fname));
		}
	}
	n->stream_err = stderr;

	n->simtime = 10;
	n->lineno = 0;
	n->version = -1;
	n->errcode = 0;

	msg_init();
	arptable_init(&n->arptable);
	nids_init(&n->nids);
	connlist_init(&n->connlist);

	return (0);
}

/*
 * Zniszczenie wszystkich, wcze¶niej zaalokowanych struktur.
 */
static int
network_destroy(struct network *n)
{
	int error = 0;

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

	msg_destroy();
	arptable_destroy(&n->arptable);
	nids_destroy(&n->nids);
	connlist_destroy(&n->connlist);

	return (error);
}

/*
 * Przetwarzenie komend.
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
	if (buffer[0] == '#' || buffer[0] == '%')
		return (0);
	cmdline = trim(buffer);
	if (cmdline == NULL)
		return (0);
	cmd_parse(&cmdlist, &cmd_num, cmdline);
	cmd_ok = (cmdlist != NULL && cmd_num != 0);
	if (!cmd_ok)
		return (-1);
	error = cmd_dispatch(n, cmdlist);
	if (error != 0)
		return (-1);
	return (0);
}

/*
 * Wykonanie jednej czê¶ci po³±czenie -- przes³anie danych w jedn±
 * stronê.
 */
int
tx_perform(struct iface *si, struct iface *ti)
{
	struct conn_dispatcher *sdisp = NULL;
	struct conn_dispatcher *tdisp = NULL;
	struct pkt *pkt = NULL;
	int nid_type = 0;
	int ret = 0;

	/* 
	 * WKPM:
	 * Gdyby interfejs mia³ od razu wpisane w siebie metody do
	 * obs³ugi, to mo¿naby sobie daæ spokój z dispatcherem.
	 */

	/*
	 * Sprawd¼ ¼ród³owy i docelowy interfejs.
	 */
	IFACE_ASSERT(si);
	IFACE_ASSERT(ti);

	/*
	 * Odnajd¼ poprawny dispatcher dla ka¿dego obiektu,
	 * dla którego obs³ugujemy interfejsy.
	 */
	nid_type = nid_type_get(ti->nid_owner);
	ASSERT(nid_type == NID_HUB || nid_type == NID_HOST);
	tdisp = &dispatchers[nid_type];

	nid_type = nid_type_get(si->nid_owner);
	ASSERT(nid_type == NID_HUB || nid_type == NID_HOST);
	sdisp = &dispatchers[nid_type];

	/*
	 * Sprawd¼, czy aby w interfejsie ¼ród³owym s± jakie¶ dane do
	 * wys³ania.
	 */
	if (pktq_empty(&si->outq)) {
		/*
		 * Brak danych. Wychodzimy.
		 */
		VERBOSE(2) {
			DEBUG("PKTQ empty");
		}
		return (0);
	}

	/*
	 * Sprawd¼, czy ewentualny pakiet do wys³ania ze ¼ród³a ma
	 * szansê zostaæ zaakceptowanym przez drug± stronê po³±czenia.
	 */
	pkt = pktq_dequeue_candidate(&si->outq);
	ret = tdisp->allow(ti, pkt);
	if (!ret) {
		/*
		 * Niestety, pakiet nie zosta³ zaakceptowany.
		 * XXx: Nale¿a³oby zwiêkszyæ ilo¶æ prób transmisji pakietu.
		 */
		VERBOSE(2) {
			DEBUG("TX disallowed");
		}
		return (0);
	}
	/*
	 * Pakiet zosta³by zaakceptowany przez drug± stronê. Dokonajmy
	 * wiêc tej transmisji.
	 */
	pkt = sdisp->tx(si);
	PKT_ASSERT(pkt);
	tdisp->rx(ti, pkt);
#if 0
	if (iface_flag_has(ti, IFACE_FLAG_HASNEWRXDATA)) {
		tdisp->rx_handle(ti);
		if (iface_flag_has(ti, IFACE_FLAG_HASNEWRXDATA))
			fprintf(stderr, "method rx_handle() didn't clear"
			    " IFACE_FLAG_HASNEWRXDATA flag");
	}
#endif
	return (0);
}

/*
 * Wykonanie kroku symulacji -- najpierw wykonujemy "pó³" po³±czenia --
 * transmisja w jedn± stronê; i potem drugie 'pó³' w drug±.
 */
int
conn_start(struct conn *conn)
{
	struct iface *i0, *i1;

	i0 = conn->nid0->obj;
	i1 = conn->nid1->obj;
	IFACE_ASSERT(i0);
	IFACE_ASSERT(i1);

	tx_perform(i0, i1);
	tx_perform(i1, i0);

	return (0);
}

/*
 * Rozpoczynamy symulacjê.
 */
static int
network_go(struct network *n)
{
	struct conn *conn = NULL;
	int error = 0;
	int i;

	msg_log("#-------- NETWORK SIMULATION STARTED --------------\n");
	for (i = 0; i < n->simtime; i++) {
		TAILQ_FOREACH(conn, &n->connlist, next) {
			error = conn_start(conn);
			if (error != 0)
				return (network_err(n, "Problems with network connection"));
		}
	}
	return (0);
}

/*
 * Generacja podsumowania -- w zale¿no¶ci od przekazanych argumentów.
 */
static int
network_summarize(struct network *n, const char *spec_file,
    const char *ofile_summary, const char *ofile_txt, const char *ofile_dot)
{
	FILE *summary, *txt, *dot;

	summary = NULL;
	if (ofile_summary != NULL) {
		DEBUG_STR(ofile_summary);
		summary = fopen(ofile_summary, "a+");
		if (summary == NULL) {
			fprintf(stderr, "Couldn't open '%s' file for writing", ofile_summary);
			return (-1);
		}
	}

	txt = NULL;
	if (ofile_txt != NULL) {
		DEBUG_STR(ofile_txt);
		txt = fopen(ofile_txt, "a+");
		if (txt == NULL) {
			fprintf(stderr, "Couldn't open '%s' file for writing", ofile_txt);
			return (-1);
		}
	}

	dot = NULL;
	if (ofile_dot != NULL) {
		DEBUG_STR(ofile_dot);
		dot = fopen(ofile_dot, "a+");
		if (dot == NULL) {
			fprintf(stderr, "Couldn't open '%s' file for writing", ofile_dot);
			return (-1);
		}
	}

	if (summary != NULL)
		network_dump_summary(n, summary);
	if (txt != NULL)
		network_dump_txt(n, txt);
	if (dot != NULL)
		network_dump_dot(n, dot);
	return (0);
}

/*
 * Wypisz dane dot. hosta w formacie DOT do strumienia fp.
 */
static void
host_dot_dump(struct host *host, FILE *fp)
{
	struct nid *nid = NULL;

	nid = host->nid;
	NID_ASSERT(nid);
	fprintf(fp, "\t\"%p\" [shape=box", (void *)host);
	fprintf(fp, ",label=\"Host: %s\"", nid_name_get(nid));
	fprintf(fp, ",style=filled");
	fprintf(fp, ",fillcolor=lightblue");
	fprintf(fp, "];\n");
	fprintf(fp, "\t\"%p\" -> \"%p\";\n", (void *)host, (void *)host->iface[0]);
}

/*
 * Wypisz dane dot. huba w formacie DOT do strumienia fp.
 */
static void
hub_dot_dump(struct hub *hub, FILE *fp)
{
	struct nid *nid = NULL;
	struct iface *ifp = NULL;
	int i = -1;

	nid = hub->nid;
	NID_ASSERT(nid);

	fprintf(fp, "\"%p\" [shape=record", (void *)hub);
	fprintf(fp, ",label=\"{ Hub: %s | { ", nid_name_get(nid));

	for (i = 0; i < HUB_IFACES; i++) {
		fprintf(fp, "<i%d> %d ", i, i);
		if (i != HUB_IFACES - 1)
			fprintf(fp, " | ");
	}
	fprintf(fp, "}}\",style=filled");
	fprintf(fp, ",fillcolor=green");
	fprintf(fp, "];\n");
	for (i = 0; i < HUB_IFACES; i++) {
		ifp = hub->iface[i];
		if (!iface_flag_has(ifp, IFACE_FLAG_HASCONN))
			continue;
		fprintf(fp, "\t\"%p\":<i%d> -> \"%p\";\n", (void *)hub, i, (void *)hub->iface[i]);
	}
}

/*
 * Wypisz dane dot. interfejsu w formacie DOT. do strumienia fp.
 */
static void
iface_dot_dump(struct iface *iface, FILE *fp)
{

	if (iface_of_hub(iface) && !iface_flag_has(iface, IFACE_FLAG_HASCONN))
		return;

	fprintf(fp, "\t\"%p\" [\n", (void *)iface);
	fprintf(fp, "\t\tlabel=\"{");
	fprintf(fp, "Interfejs: %s:%d |", nid_name_get(iface->nid), nid_id_get(iface->nid));
	fprintf(fp, "IP: %d.%d.%d.%d |", iface->ipv4[0], iface->ipv4[1], iface->ipv4[2], iface->ipv4[3]);
	fprintf(fp, "NM: %d.%d.%d.%d ", iface->nmv4[0], iface->nmv4[1], iface->nmv4[2], iface->nmv4[3]);
	fprintf(fp, "}\"\n");
	fprintf(fp, "\t\tshape=record\n");
	fprintf(fp, "\t]\n");
}

/*
 * Wypisz dane dot. sieci w formacie DOT do strumienia fp.
 */
static int
network_dump_dot(struct network *n, FILE *fp)
{
	struct nid *nid = NULL;
	struct conn *conn = NULL;
	int type = -1;

	fprintf(fp, "digraph network {\n");
	fprintf(fp, "\tsize=\"9,8\";\n");

	TAILQ_FOREACH(nid, &n->nids, next) {
		type = nid_type_get(nid);
		if (type == NID_HOST) {
			host_dot_dump(nid->obj, fp);
		} else if (type == NID_HUB) {
			hub_dot_dump(nid->obj, fp);
		} else if (type == NID_IFACE) {
			iface_dot_dump(nid->obj, fp);
		}
	}
	TAILQ_FOREACH(conn, &n->connlist, next)
		fprintf(fp, "\t\"%p\" -> \"%p\";\n",
		    conn->nid0->obj,
		    conn->nid1->obj
		);

	fprintf(fp, "};\n");
	return (0);
}

/*
 * Wypisz podsumowanie w formacie tekstowym.
 */
static int
network_dump_txt(struct network *n, FILE *fp)
{
	struct host *hostp = NULL;
	struct hub *hubp = NULL;
	struct router *rrp = NULL;
	struct nid *nid = NULL;
	struct conn *conn = NULL;
	int nidtype;

	NETWORK_ASSERT(n);
	fprintf(fp, "# --------------------------------------------------------\n");
	fprintf(fp, "# Network dump started\n");
	fprintf(fp, "#\n");

	fprintf(fp, "  Version ID: %d\n\n", n->version);
	
	TAILQ_FOREACH(nid, &n->nids, next) {
		nidtype = nid_type_get(nid);
		if (nidtype == NID_HOST) {
			hostp = (struct host *)nid_obj_get(nid);
			host_debug(hostp, fp);
		} else if (nidtype == NID_HUB) {
			hubp = (struct hub *)nid_obj_get(nid);
			hub_debug(hubp, fp);
		} else if (nidtype == NID_ROUTER) {
			rrp = (struct router *)nid_obj_get(nid);
			router_debug(rrp, fp);
		}
	}

	fprintf(fp, "# -- Raw network identifiers ----------------------------\n");
	TAILQ_FOREACH(nid, &n->nids, next)
		nid_debug(nid, fp);

	fprintf(fp, "# -- Connections between interfaces ---------------------\n");
	TAILQ_FOREACH(conn, &n->connlist, next)
		conn_debug(conn, fp);
	fprintf(fp, "# -- The end of the network specification ---------------\n");

	return (0);
}

/*
 * Jak u¿ywaæ tego programu.
 */
static void
usage(void)
{
	FILE *fp = stderr;

	fprintf(fp, "Usage: kmnsim [-a] [-d] [-D <file] [-h] [-S <file>] "
	    "[-T <file>] [-v] spec_file\n");
	fprintf(fp, "-a\t\tdirect summary (.out), .dot and .txt files to spec_file.EXT;\n");
	fprintf(fp, "-d\t\tturn on debug mode;\n");
	fprintf(fp, "-D <file>\tput Graphviz file to <file>\n");
	fprintf(fp, "-h\t\tprint this help\n");
	fprintf(fp, "-S <file>\tput summary file to <file>\n");
	fprintf(fp, "-T <file>\tput text (debug) file to <file>\n");
	fprintf(fp, "-v\t\tturn verbose mode\n");
	exit(EX_USAGE);
}

/*
 * kmnsim
 */
int
main(int argc, char **argv)
{
	struct network nw;
	char *ofile_summary, *ofile_txt, *ofile_dot, *spec_file;
	int has_more = 0;
	int flag_help = 0;
	int flag_a = 0;
	int o = 0;

	spec_file = ofile_summary = ofile_txt = ofile_dot = NULL;

	while ((o = getopt(argc, argv, "adD:h:S:T:v")) != -1)
		switch (o) {
		case 'a':
			flag_a = 1;
			break;
		case 'd':
			flag_debug++;
			break;
		case 'D':
			ofile_dot = optarg;
			break;
		case 'h':
			flag_help++;
			break;
		case 'S':
			ofile_summary = optarg;
			break;
		case 'T':
			ofile_txt = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			fprintf(stderr, "Unknown option %d", o);
			exit(EXIT_FAILURE);
		}

	argc -= optind;
	argv += optind;

	if (flag_help)
		usage();

	if (argc == 0)
		usage();

	spec_file = argv[0];
	DEBUG_STR(spec_file);

	if (flag_a) {
		ASSERT(spec_file != NULL);
		ofile_summary = strdupf("%s.out", spec_file);
		ofile_dot = strdupf("%s.dot", spec_file);
		ofile_txt = strdupf("%s.txt", spec_file);
	}

	network_init(&nw, spec_file);
	if (network_err_has(&nw)) {
		fprintf(stderr, "%s", network_errmsg_get(&nw));
		exit(EXIT_FAILURE);
	}
	for (;;) {
		has_more = (network_parse(&nw) != -1);
		if (!has_more)
			break;
	}
	if (network_err_has(&nw))
		return (network_err_msg(&nw));
	network_go(&nw);
	network_summarize(&nw, spec_file, ofile_summary, ofile_txt, ofile_dot);
	network_destroy(&nw);
	exit(EXIT_SUCCESS);
}

/*
 * Inicjalizacja bazy danych dot. przestrzeni nazw.
 */
void
nids_init(struct nids *nids)
{


	memset(nids, 0, sizeof(*nids));
	TAILQ_INIT(nids);
}

/*
 * Usuniêcie przestrzeni nazw.
 */
void
nids_destroy(struct nids *nids)
{

	/* unlink everything */
	memset(nids, 0, sizeof(*nids));
}

/*
 * Alokacja NID.
 */
static struct nid *
nid_alloc(void)
{
	struct nid *nid = NULL;

	nid = calloc(sizeof(*nid), 1);
	ASSERT(nid != NULL && "nid == NULL");
	NID_INIT(nid);
	nid->id = -1;
	nid->type = -1;
	nid->obj = NULL;
	NID_ASSERT(nid);
	return (nid);
}

/*
 * Rejestracja NID.
 */
void
nid_register(struct nids *nids, struct nid *n)
{

	TAILQ_INSERT_TAIL(nids, n, next);
}

/*
 * Wyrejestrowanie NID.
 */
void
nid_unregister(struct nids *nids, struct nid *n)
{

	TAILQ_REMOVE(nids, n, next);
}

/*
 * Stworzenie NID.
 */
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
	return (n);
}

/*
 * Wyszukanie na podstawie podanych kryteriów.
 */
struct nid *
nid_lookup(struct nids *nids, const char *name, int id, int type)
{
	struct nid *nid = NULL;

	ASSERT(name != NULL);

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

/*
 * Zwraca typ NID.
 */
const char *
nid_type_desc(struct nid *n)
{
	struct hub *hub = NULL;

	NID_ASSERT(n);

	switch (n->type) {
	case NID_HOST:
		return ("Host");
	case NID_HUB:
		hub = n->obj;
		HUB_ASSERT(hub);
		if (hub->mode == HUB_MODE_NORMAL)
			return ("Hub");
		else
			return ("Switch");
	case NID_IFACE:
		return ("Interface");
#if 0
	case NID_ROUTER:
		return ("router");
#endif
	default:
		fprintf(stderr, "NID UNKNOWN!\n");
		abort();
	}
	return ("unknown");
}

int
nid_type_get(struct nid *nid)
{

	return (nid->type);
}

void
nid_type_set(struct nid *nid, int type)
{

	nid->type = type;
}


void *
nid_obj_get(struct nid *nid)
{

	return (nid->obj);
}

void
nid_obj_set(struct nid *n, void *obj)
{

	NID_ASSERT(n);
	n->obj = obj;
}

int
nid_destroy(struct nid *n)
{

	NID_ASSERT(n);
	memset(n, 0, sizeof(*n));
	free(n);
	return (0);
}

char *
nid_name_get(struct nid *nid)
{

	return (nid->name);
}

int
nid_id_get(struct nid *nid)
{

	return (nid->id);
}

void
nid_debug(struct nid *nid, FILE *fp)
{

	NID_ASSERT(nid);
	fprintf(fp, "# NID: name='%s', id=%d, type=%s, obj=%p\n",
	    nid->name,
	    nid->id,
	    nid_type_desc(nid),
	    nid->obj
	);
}

struct router *
router_alloc(void)
{
	struct router *r;

	r = calloc(sizeof(*r), 1);
	if (r == NULL)
		return (NULL);

	ROUTER_INIT(r);
	ROUTER_ASSERT(r);

	return (r);
}

void
router_destroy(struct network *n, struct router *r)
{
	struct nid *nid = NULL;

	NETWORK_ASSERT(n);
	ROUTER_ASSERT(r);

	nid = r->nid;
	NID_ASSERT(nid);
	nid_unregister(&n->nids, nid);
	nid_destroy(nid);
	memset(r, 0, sizeof(*r));
	free(r);
}

int
router_create(struct network *n, const char *router_name)
{
	struct nid *nid = NULL;
	struct router *router = NULL;
	struct iface *ifp = NULL;
	int i = 0;

	NETWORK_ASSERT(n);
	ASSERT(router_name != NULL);

	nid = nid_lookup(&n->nids, router_name, -1, -1);
	if (nid != NULL)
		return (network_err(n, "'%s' already exists ('%s')",
			router_name, nid_type_desc(nid)));

	nid = nid_create(router_name, -1);
	NID_ASSERT(nid);

	router = router_alloc();
	router->nid = nid;

	nid_type_set(nid, NID_ROUTER);
	nid_obj_set(nid, router);

	nid_register(&n->nids, nid);

	for (i = 0; i < ROUTER_IFACES; i++) {
		ifp = iface_create(n, router_name, i);
		if (ifp == NULL)
			return (network_err(n, "Couldn't create router's interface %d", i));
		iface_owner_set(ifp, nid);
		router->iface[i] = ifp;
	}

	return (0);
}

int
router_remove(struct network *n, const char *router_name)
{
	struct nid *nid = NULL;
	struct router *router = NULL;
	struct iface *ifp = NULL;
	int i = 0;

	NETWORK_ASSERT(n);
	ASSERT(router_name != NULL);

	nid = nid_lookup(&n->nids, router_name, -1, NID_ROUTER);
	if (nid == NULL)
		return (network_err(n, "Router '%s' doesn't exist", router_name));

	NID_ASSERT(nid);
	router = nid->obj;
	ROUTER_ASSERT(router);
	router_destroy(n, router);

	for (i = 0; i < ROUTER_IFACES; i++) {
		nid = nid_lookup(&n->nids, router_name, i, NID_IFACE);
		if (nid == NULL)
			return (network_err(n, "Interface '%s':%d doesn't exists", router_name, i));
		NID_ASSERT(nid);
		ifp = nid->obj;
		IFACE_ASSERT(ifp);
		iface_destroy(n, ifp);
	}

	return (0);
}

#ifdef _TEST

#include <stdlib.h>

static int regression_test = 0;
#define REGRESSION	if (regression_test == 1)
#else
#define REGRESSION
#endif

/*
 * Remove last white-spaces, and return first non-blank character in a
 * passed string.
 */
char *
trim(char *s)
{
	char *sbeg, *send;

	/* Find the end */
	send = strchr(s, '\0');
	ASSERT(send != NULL);
	send--;
	while (isspace(*send)) {
		/* Remove until we find something non-white.. */
		*send = '\0';
		send--;
	}
	/* Return first non-blank, non-white character. */
	sbeg = s;
	while (isspace(*sbeg))
		sbeg++;
	if (sbeg[0] == '\0')
		return (NULL);
	return (sbeg);
}

/*
 * Sensible semantics of checking, whether two NULL-terminated strings
 * are equal.
 */
int
streq(const char *a, const char *b)
{

	return (strcmp(a, b) == 0);
}

char *
strdupf(const char *fmt, ...)
{
	va_list va;
	char buf[1024];
	char *ret;

	memset(buf, 0, sizeof(buf));
	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, va);
	va_end(va);
	ret = strdup(buf);
	ASSERT(ret != NULL);
	return (ret);
}

/*
 * Construct error string, put it in the network structure and return
 * with an error code.
 */
int
network_err(struct network *n, const char *fmt, ...)
{
	va_list va;

	n->errcode = -1;
	va_start(va, fmt);
	vsnprintf(n->errmsg, sizeof(n->errmsg) - 1, fmt, va);
	va_end(va);
	strlcat(n->errmsg, "\n", sizeof(n->errmsg));
	return (-1);
}

int
network_err_has(struct network *n)
{

	NETWORK_ASSERT(n);
	return (n->errcode != 0);
}

int
network_err_msg(struct network *n)
{

	NETWORK_ASSERT(n);
	(void)fprintf(n->stream_err, "Koszek-Matyja Network Simulator:\n");
	(void)fprintf(n->stream_err, "--------------------------------\n");
	(void)fprintf(n->stream_err, "Error: %s", n->errmsg);
	(void)fprintf(n->stream_err, " Line: %d\n", n->lineno);
	fflush(n->stream_err);
	return (n->errcode);
}

const char *
network_errmsg_get(struct network *n)
{

	NETWORK_ASSERT(n);
	return (n->errmsg);
}

/*
 * Uwzglêdniamy, ¿e jedynie ci±g³e maski s± wspierane -- czyli takie, w
 * których ci±g jedynek przykrywaj±cych czê¶æ "sieci" adresu IP nie jest
 * przerwany w pewnym miejscu.
 */
int
netmask_valid(ipv4_t nm)
{
	int i;
	uint32_t bitnm = 0;
	uint32_t fullnm = ~0;
	uint32_t curnm = 0;

	/* Pakujemy maskê sieci w liczbê typu int */
	bitnm |= nm[0]; bitnm <<= 8;
	bitnm |= nm[1]; bitnm <<= 8;
	bitnm |= nm[2]; bitnm <<= 8;
	bitnm |= nm[3];

	REGRESSION {
		printf("%x\n", bitnm);
	}

	/* 
	 * Sprawdzamy, czy która¶ z "normalnych masek pasuje do naszej
	 * maski
	 */
	for (i = 0; i < sizeof(fullnm) * 8; i++) {
		/* Najpierw usuwamy jedynki, zostaj± nam zero z lewej */
		curnm = fullnm >> i;

		/* 
		 * Potem przesuwamy ca³o¶æ jedynek i zostaj± nam zera z
		 * prawej
		 */
		curnm <<= i;

		if (bitnm == curnm)
			return (1);
	}
	return (0);
}

#ifdef _TEST
#include <stdio.h>

/*
 * Test jednostkowy stworzony w celu sprawdzenia, czy netmask_valid()
 * dzia³a tak, jak siê tego spodziewam. Najpierw wrzucamy maski
 * poprawne:
 */
ipv4_t valid_masks[] = {
	{ 255, 255, 255, 0 },
	{ 255, 255,   0, 0 },
	{ 255, 255, 240, 0 }
};

/*
 * ..te z kolei z za³o¿enia s± niepoprawne.
 */
ipv4_t invalid_masks[] = {
	{ 255, 205,   0, 0 },
	{ 255, 255, 204, 0 },
	{ 0xf0, 255, 255, 0 },
};
#define TAB_SIZE(x)	((sizeof((x)))/(sizeof((x)[0])))
#define MAIN(x) x
int
MAIN(main)(int argc, char **argv)
{
	int i;
	int valid = 0;
	ipv4_t nm;

	/*
	 * Dokonujemy sprawdzeñ dla ka¿dej z maski umieszczonej w dwóch,
	 * w.w tablicach.
	 */
	puts("# ---------------------");
	puts("# Checking those valid.");
	puts("# ---------------------");
	for (i = 0; i < TAB_SIZE(valid_masks); i++) {
		printf("# Checking mask %x.%x.%x.%x (should be valid)!\n",
		    valid_masks[i][0],
		    valid_masks[i][1],
		    valid_masks[i][2],
		    valid_masks[i][3]
		);
		valid = netmask_valid(valid_masks[i]);
		if (!valid)
			printf("%d error!\n", i);
		else
			printf("%d ok\n", i);
	}

	puts("# -----------------------");
	puts("# Checking those INvalid.");
	puts("# -----------------------");
	for (i = 0; i < TAB_SIZE(invalid_masks); i++) {
		printf("# Checking mask %x.%x.%x.%x (should be invalid)!\n",
		    invalid_masks[i][0],
		    invalid_masks[i][1],
		    invalid_masks[i][2],
		    invalid_masks[i][3]
		);
		valid = netmask_valid(invalid_masks[i]);
		if (!valid)
			printf("%d ok\n", i);
		else
			printf("%d error!\n", i);
	}

	return (0);
}
#endif
