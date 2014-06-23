/*
 * Test maj±cy na celu pokazaæ, czy mo¿na przy pomocy makr z queue.h
 * dodaæ jeden element do wielu list bez niszczenia oryginalnych
 * powi±zañ.
 *
 * Okazuje siê, nawet logicznie, ¿e nie mo¿na tego zrobiæ.
 */
#include <stdio.h>
#include "../src/queue.h"

struct l {
	int x;
	TAILQ_ENTRY(l) next;
};
TAILQ_HEAD(lhead, l);

int
main(int argc, char **argv)
{
	struct lhead lh;
	struct lhead lh2;
	int i;
	struct l l[10];
	struct l *lp;

	TAILQ_INIT(&lh);
	TAILQ_INIT(&lh2);
	for (i = 0; i < 10; i++) {
		l[i].x = i;
		TAILQ_INSERT_TAIL(&lh, &l[i], next);
	}

	for (i = 9; i >= 0; i--)
		TAILQ_INSERT_TAIL(&lh2, &l[i], next);

	puts("---------- Lista 2 -----------");
	TAILQ_FOREACH(lp, &lh2, next) {
		printf("l: %d\n", lp->x);
	}

	puts("---------- Lista 1 -----------");
	TAILQ_FOREACH(lp, &lh, next) {
		printf("l: %d\n", lp->x);
	}
	return (0);
}
