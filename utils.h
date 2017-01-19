#ifndef TOX_UTILS
#define TOX_UTILS

#define UPDATE_EXPIRE_DAYS 14

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

FILE* LOG_FILE;
#define LOG_TO_FILE(...) (LOG_FILE ? fprintf(LOG_FILE, __VA_ARGS__) & fflush(LOG_FILE) : -1)

/* in main.c */
void set_download_progress(int progress);

void *download_from_host( bool compressed,
                          const char *host,
                          const char *filename,
                          size_t filename_len,
                          uint32_t *downloaded_len,
                          const uint8_t *self_public_key);

#endif
