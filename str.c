/******************************************************************************

	Filename:	str.c
	Author:		Marcus Watts
	Date:		24 Aug 92
	
	Description:
	Some custom string handling routines.

 ******************************************************************************/

#include <ctype.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#    include <stdlib.h>
#endif
#include "str.h"

char *
getword(char *cp, char *word)
{
    char *wp;

    wp = word;
    while (*cp && isspace(*cp))
	++cp;
    while (*cp && !isspace(*cp))
	*wp++ = *cp++;
    *wp = 0;
    while (*cp && isspace(*cp))
	++cp;
    return cp;
}

int
kwscan(char *wp, char **wtbl)
{
    int i;
    register char *tp, *cp;
    int f;

    i = 0;
    while (++i, tp = *wtbl++) {
	f = 0;
	cp = wp;
	for (;;) {
	    if (*tp == '_') {
		++f;
		++tp;
		continue;
	    }
	    if (!*cp && (f || !*tp))
		return i;
	    if (*cp++ != *tp++)
		break;
	}
    }
    return 0;
}

void
stripnl(char *cp)
{
    if ((cp = strchr(cp, '\n')))
	*cp = 0;
}

#if 0
char *
strdup(char *s)
{
    char *r;
    if ((r = malloc(strlen(s) + 1)))
	strcpy(r, s);
    return r;
}
#endif

char *
skipspace(char *cp)
{
    while (*cp && isspace(*cp))
	++cp;
    return cp;
}
