char *getword(char *, char *);
int kwscan(char *, char **);
void stripnl(char *);
#ifdef ultrix
char *strdup(char *);
#endif
char *skipspace(char *);
#ifdef HAVE_STRLCPY
#define un_strlcpy	strlcpy
#else
extern int un_strlcpy(char *, const char *, int);
#endif
