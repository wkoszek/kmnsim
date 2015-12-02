#ifndef _SUBR_H_
#define _SUBR_H_

#if defined(_WIN32) || defined(__linux__)
char *strdup(const char *str);
size_t strlcat(char * __restrict dst, const char * __restrict src, size_t siz);
size_t strlcpy(char * __restrict dst, const char * __restrict src, size_t siz);
char *strsep(char **stringp, const char *delim);
#endif

#endif /* _SUBR_H_ */
