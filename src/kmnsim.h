#ifndef _KMNSIM_H_
#define _KMNSIM_H_

/* NOT YET CLASSIFIED */
extern int cmd_verbose;
extern int flag_debug;
extern int kmnsim_version;
extern int verbose;

#define ASSERT assert
#define VERBOSE(x)		\
	if ((x) >= verbose && (verbose >= 1))
#define DEBUG(...)					\
	if (flag_debug > 0) {					\
	    	printf("%s(%d)\n", __func__, __LINE__);	\
		printf(__VA_ARGS__);			\
		printf("\n");				\
	}
#define	TBD()	DEBUG("_to_be_done_")
#define DEBUG_STR(x)			\
	printf("%s(%d): '%s' = '%s'\n",	\
	    __func__, __LINE__,		\
	    #x,				\
	    (x)				\
	)

#define VERSION 1

struct network;
struct hub;
struct host;
struct router;
struct iface;
struct conn;
struct connlist;
struct arptable;
struct pktq;

/*
 * NetworkID
 */
struct nid {
	unsigned long	_nid_magic;
#define NID_MAGIC	0x6ba531f0
#define	NID_INIT(h)	do { (h)->_nid_magic = NID_MAGIC; } while (0)
#define NID_ASSERT(h)					\
	do {						\
		assert((h) != NULL);			\
		assert((h)->_nid_magic == NID_MAGIC);	\
	} while (0)

#define NID_LEN	64
	char name[NID_LEN];
	int id;
#define NID_HOST 1
#define NID_IFACE 2
#define NID_HUB 3
#define NID_ROUTER 4
	int type;

	void *obj;

	TAILQ_ENTRY(nid)	next;
};
TAILQ_HEAD(nids, nid);

/*------------------------------------------------------------------------*/

typedef enum {
	IFACE_HOST,
	IFACE_HUB,
	IFACE_ROUTER
} iface_type_t;

typedef int ipv4_t[4];
	
#define ETH_LEN 	20
#define IP_LEN		20
#define ICMP_LEN	20
#define ICMP_PING_REQUEST	0
#define ICMP_PING_ANSWER	1

#define	ETHER_MAC_LEN	6
#define	ADDRV4_LEN	4

/*------------------------------------------------------------------------*/

struct pkt {
	unsigned long	_pkt_magic;
#define PKT_MAGIC 0xaabbccdd
#define	PKT_INIT(h)	do { (h)->_pkt_magic = PKT_MAGIC; } while (0)
#define PKT_ASSERT(h)					\
	do {						\
		assert((h) != NULL);			\
		assert((h)->_pkt_magic == PKT_MAGIC);	\
	} while (0)

	void *data;
	int len;
	int id;

	struct iface *src_ifp;
	struct iface *dst_ifp;

	TAILQ_ENTRY(pkt) next;
};
TAILQ_HEAD(pktq, pkt);


/*------------------------------------------------------------------------*/

struct arp {
	unsigned int	mac[6];
	unsigned int	ip[4];
	TAILQ_ENTRY(arp) next;
};
TAILQ_HEAD(arptable, arp);

/*------------------------------------------------------------------------*/

struct eth_hdr {
	int src_mac[ETHER_MAC_LEN];
	int dst_mac[ETHER_MAC_LEN];
};

struct ip_hdr {
	unsigned int src_ipv4[ADDRV4_LEN];
	unsigned int dst_ipv4[ADDRV4_LEN];
};

struct icmp_hdr {
	int type;
};

struct pkt_icmp {
	struct eth_hdr e;
	struct ip_hdr ip;
	struct icmp_hdr ic;
};

/*------------------------------------------------------------------------*/

/*
 * Interface.
 */
struct iface {
	unsigned long	_iface_magic;
#define IFACE_MAGIC 0x76b297df
#define	IFACE_INIT(h)	do { (h)->_iface_magic = IFACE_MAGIC; } while (0)
#define IFACE_ASSERT(h)					\
	do {						\
		assert((h) != NULL);			\
		assert((h)->_iface_magic == IFACE_MAGIC);	\
	} while (0)

	struct nid *nid;
	struct nid *nid_owner;

	struct pktq inq;
	struct pktq outq;

	int flags;
#define	IFACE_FLAG_HASIP	(1 << 0)
#define	IFACE_FLAG_HASNM	(1 << 1)
#define	IFACE_FLAG_HASMAC	(1 << 2)
#define	IFACE_FLAG_HASCONN	(1 << 3)

	struct iface *conn_ifp;

	unsigned int	ipv4[ADDRV4_LEN];
	unsigned int	nmv4[ADDRV4_LEN];
	unsigned int	mac[ETHER_MAC_LEN];

	TAILQ_ENTRY(iface)	next;
};

/*-------------------------------------------------------------------------
 * This is how we represent the host.
 */
struct host {
	unsigned long	_host_magic;
#define HOST_MAGIC 0x9b23ce4f
#define	HOST_INIT(h)	do { (h)->_host_magic = HOST_MAGIC; } while (0)
#define HOST_ASSERT(h)					\
	do {						\
		assert((h) != NULL);			\
		assert((h)->_host_magic == HOST_MAGIC);	\
	} while (0)

	struct iface *iface[1];
	struct nid *nid;

	TAILQ_ENTRY(host) next;
};

/*-------------------------------------------------------------------------
 * This is our router representation.
 */
struct router {
	unsigned long	_router_magic;
#define ROUTER_MAGIC	0x5fbe58cd
#define	ROUTER_INIT(r)	do { (r)->_router_magic = ROUTER_MAGIC; } while (0)
#define	ROUTER_ASSERT(r)	ASSERT((r)->_router_magic == ROUTER_MAGIC)

	struct nid *nid;
#define ROUTER_IFACES	4
	struct iface *iface[ROUTER_IFACES];
	int iface_num;

	TAILQ_ENTRY(router) next;
};

/*-------------------------------------------------------------------------
 * This is hub structure.
 */
typedef enum {
	HUB_MODE_NORMAL,
	HUB_MODE_SWITCH
} hub_mode_t;

struct hub {
	unsigned long	_hub_magic;
#define	HUB_MAGIC	0x3529565f
#define	HUB_INIT(h)	do { (h)->_hub_magic = HUB_MAGIC; } while (0)
#define	HUB_ASSERT(h)	ASSERT((h)->_hub_magic == HUB_MAGIC)

	struct nid *nid;
#define HUB_IFACES	8
	struct iface *iface[HUB_IFACES];
	int iface_num;
	hub_mode_t mode;

	TAILQ_ENTRY(hub) next;
};


/*-------------------------------------------------------------------------
 * Connection.
 */
struct conn {
	unsigned long	_conn_magic;
#define CONN_MAGIC	0x17797ef4
#define	CONN_INIT(c)	do { (c)->_conn_magic = CONN_MAGIC; } while (0)
#define	CONN_ASSERT(c)	ASSERT((c)->_conn_magic == CONN_MAGIC)

	struct nid *nid0;
	struct nid *nid1;

	TAILQ_ENTRY(conn) next;
};
TAILQ_HEAD(connlist, conn);

/*-------------------------------------------------------------------------
 * The general mesh in kept in network structure.
 */
struct network {
	unsigned long	_network_magic;
#define	NETWORK_MAGIC	0x1c3a556a
#define	NETWORK_INIT(n)	do { (n)->_network_magic = NETWORK_MAGIC; } while (0)
#define	NETWORK_ASSERT(n)	ASSERT((n)->_network_magic == NETWORK_MAGIC)

	struct nids nids;
	struct connlist connlist;
	struct arptable arptable;

	int version;
	int lineno;
	int errcode;
	int simtime;

	FILE *stream_err;
	FILE *stream;
	char errmsg[1024];
};

/*-------------------------------------------------------------------------
 * Command -- as when parsed from the NULL-terminated buffer.
 */
struct cmd {
	unsigned long	_cmd_magic;
#define CMD_MAGIC	0x98326190
#define	CMD_INIT(c)	do { (c)->_cmd_magic = CMD_MAGIC; } while (0)
#define	CMD_ASSERT(c)	ASSERT((c)->_cmd_magic == CMD_MAGIC)

#define CMD_LEN	64
	char	name[CMD_LEN];
	TAILQ_ENTRY(cmd) next;
};
TAILQ_HEAD(cmdlist, cmd);

/*-------------------------------------------------------------------------
 * Input buffer lenght.
 * Used when KMnsim reads text file with network specification.
 */
#define	INPUT_BUF_LEN	1024


/* the rest for subr.c */

/*
 * Returns a pointer to the first, non-white character in a string;
 * additionally, removes white-spaces from the end of a string [it must
 * by 0-terminated.
 */
char *trim(char *s);

/*
 * Checks whether two passed strings are the same.
 */
int streq(const char *a, const char *b);

#endif /* _KMNSIM_H_ */
