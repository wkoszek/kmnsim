/*
 * Koszek-Matyja Network Simulator
 *
 * Copyright (c) 2009 Wojciech Koszek <wkoszek@FreeBSD.czest.pl>
 *                       Piotr Matyja <piotr-matyja@o2.pl>
 *
 * All rights reserved.
 */
#include <sys/types.h>
#include <stdio.h>

#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>

#include "queue.h"

#include "kmnsim.h"

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
	assert(send != NULL);
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
	vsnprintf(n->errmsg, sizeof(n->errmsg), fmt, va);
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
	(void)fprintf(n->stream_err, "%s", n->errmsg);
	(void)fprintf(n->stream_err, "Line: %d\n", n->lineno);
	fflush(n->stream_err);
	return (n->errcode);
}

typedef	int netmask_t[4];

/*
 * Uwzglêdniamy, ¿e jedynie ci±g³e maski s± wspierane -- czyli takie, w
 * których ci±g jedynek przykrywaj±cych czê¶æ "sieci" adresu IP nie jest
 * przerwany w pewnym miejscu.
 */
int
netmask_valid(netmask_t nm)
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

int
ipv4_addr_valid(const char *aspec)
{

	return (0);
}

int
ipv4_netmask_valid(const char *nmspec)
{

	return (0);
}

#ifdef _TEST
#include <stdio.h>

/*
 * Test jednostkowy stworzony w celu sprawdzenia, czy netmask_valid()
 * dzia³a tak, jak siê tego spodziewam. Najpierw wrzucamy maski
 * poprawne:
 */
netmask_t valid_masks[] = {
	{ 255, 255, 255, 0 },
	{ 255, 255,   0, 0 },
	{ 255, 255, 240, 0 }
};

/*
 * ..te z kolei z za³o¿enia s± niepoprawne.
 */
netmask_t invalid_masks[] = {
	{ 255, 205,   0, 0 },
	{ 255, 255, 204, 0 },
	{ 0xf0, 255, 255, 0 },
};
#define TAB_SIZE(x)	((sizeof((x)))/(sizeof((x)[0])))

int
main(int argc, char **argv)
{
	int i;
	int valid = 0;
	netmask_t nm;

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
