#include "utils.h"

#include "xz/xz.h"

#define SODIUM_STATIC
#include <sodium.h>

#include <ws2tcpip.h>
#include <time.h>

#include <winsock2.h>
#define close(x) closesocket(x)

static uint32_t inflate(void *dest, void *src, uint32_t dest_size, uint32_t src_len) {
    xz_crc32_init();

    struct xz_dec *dec = xz_dec_init(XZ_SINGLE, 0);
    if (!dec) {
        return 0;
    }

    struct xz_buf buf = {
        .in = src,
        .in_pos = 0,
        .in_size = src_len,

        .out = dest,
        .out_pos = 0,
        .out_size = dest_size,
    };

    int r = xz_dec_run(dec, &buf);
    xz_dec_end(dec);

    LOG_TO_FILE("%i\n", r);

    /* out_pos is only set on success*/
    return buf.out_pos;
}

static void* checksignature(void *data, uint32_t dlen, const uint8_t *self_public_key, size_t *downloaded_len) {
    void *mdata;
    int r;

    mdata = malloc(dlen);
    if (!mdata) {
        LOG_TO_FILE("malloc failed\n");
        free(data);
        return NULL;
    }

    r = crypto_sign_ed25519_open(mdata, (unsigned long long*)downloaded_len, data, dlen, self_public_key);
    free(data);

    if (r == -1) {
        LOG_TO_FILE("invalid signature\n");
        free(mdata);
        return NULL;
    }

    LOG_TO_FILE("Signature cleared\n");
    return mdata;
}


static void* download( struct sockaddr_storage *sock_addr,
                       size_t addr_len,
                       char *request,
                       uint16_t request_len,
                       uint32_t *downloaded_length)
{
    uint32_t sock, len, rlen, dlen;
    char *data = 0;
    bool header = 0;

    sock = socket(sock_addr->ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        LOG_TO_FILE("socket failed\n");
        return NULL;
    }

    if (connect(sock, (struct sockaddr *)sock_addr, addr_len) != 0) {
        LOG_TO_FILE("connect failed\n");
        close(sock);
        return NULL;
    }

    if (send(sock, request, request_len, 0) != request_len) {
        LOG_TO_FILE("send failed\n");
        close(sock);
        return NULL;
    }

    uint8_t recvbuf[0x10000];

    while ((len = recv(sock, (char*)recvbuf, 0xFFFF, 0)) > 0) {
        if (!header) {
            /* work with a null-terminated buffer */
            recvbuf[len] = 0;
            /* check for "Not Found" response (todo: only check first line of response)*/
            if (strstr((char*)recvbuf, "404 Not Found\r\n")) {
                LOG_TO_FILE("Not Found\n");
                break;
            }

            /* find the length field */
            char *str = strstr((char*)recvbuf, "Content-Length: ");
            if (!str) {
                LOG_TO_FILE("invalid HTTP response (1)\n");
                break;
            }

            /* parse the length field */
            str += sizeof("Content-Length: ") - 1;
            dlen = strtol(str, NULL, 10);

            /* find the end of the http response header */
            str = strstr(str, "\r\n\r\n");
            if (!str) {
                LOG_TO_FILE("invalid HTTP response (2)\n");
                break;
            }

            str += sizeof("\r\n\r\n") - 1;

            /* allocate buffer to read into) */
            data = malloc(dlen);
            if (!data) {
                LOG_TO_FILE("malloc failed (1) (%u)\n", dlen);
                break;
            }

            LOG_TO_FILE("Download size: %u\n", dlen);

            /* read the first piece */
            rlen = len - (str - (char*)recvbuf);
            memcpy(data, str, rlen);

            header = 1;
            continue;
        }

        /* check if received too much */
        if (rlen + len > dlen) {
            LOG_TO_FILE("bad download\n");
            break;
        }

        memcpy(data + rlen, recvbuf, len);
        rlen += len;
        set_download_progress((rlen * 100) / dlen);
    }

    close(sock);

    if (!header) {
        /* read nothing or invalid header */
        LOG_TO_FILE("download() failed\n");
        return NULL;
    } else if (rlen != dlen) {
        LOG_TO_FILE("number of bytes read does not match (%u)\n", rlen);
        free(data);
        return NULL;
    }

    *downloaded_length = dlen;
    return data;
}

static int generate_request(char *out,
                            size_t out_len,
                            const char *host,
                            size_t host_len,
                            const char *filename,
                            size_t filename_len)
{
    char host_terminated[host_len + 1];
    memcpy(host_terminated, host, host_len);
    host_terminated[host_len] = 0;

    char filename_terminated[filename_len + 1];
    memcpy(filename_terminated, filename, filename_len);
    filename_terminated[filename_len] = 0;

    int len = snprintf(out, out_len, "GET /%s HTTP/1.0\r\n""Host: %s\r\n\r\n", filename_terminated, host_terminated);

    if (len > out_len + 1 || len <= 0) {
        return -1;
    }

    return len;
}

void* download_signed( void *sock_addr,
                       size_t addr_len,
                       const char *host,
                       size_t host_len,
                       const char *filename,
                       size_t filename_len,
                       uint32_t *downloaded_len,
                       const uint8_t *self_public_key)
{
    void *data, *mdata;
    uint32_t len, t;
    time_t now;
    size_t mlen;

    char request[512];
    int request_len = generate_request(request, sizeof(request), host, host_len, filename, filename_len);

    if (request_len == -1)
        return NULL;

    data = download(sock_addr, addr_len, request, request_len, &len);
    if (!data) {
        return NULL;
    }

    mdata = checksignature(data, len, self_public_key, &mlen);
    if (!mdata) {
        return NULL;
    }

    time(&now);
    memcpy(&t, mdata, 4);

    LOG_TO_FILE("signed %u, now %u\n", (uint32_t)t, (uint32_t)now);

    if (t < now && now - t >= 60 * 60 * 24 * UPDATE_EXPIRE_DAYS) {
        /* build is more than 14 days old: expired */
        LOG_TO_FILE("expired signature (%u)\n", (uint32_t)(now - t));
        free(mdata);
        return NULL;
    }

    *downloaded_len = mlen;
    return mdata;
}

void* download_signed_compressed( void *sock_addr,
                                  size_t addr_len,
                                  const char *host,
                                  size_t host_len,
                                  const char *filename,
                                  size_t filename_len,
                                  uint32_t *downloaded_len,
                                  uint32_t downloaded_len_max,
                                  const uint8_t *self_public_key)
{
    char *data, *mdata;
    uint32_t len, mlen;

    mdata = download_signed(sock_addr, addr_len, host, host_len, filename, filename_len,
                            &mlen, self_public_key);
    if (!mdata) {
        LOG_TO_FILE("file download failed\n");
        return NULL;
    }

    /* inflate */
    data = malloc(downloaded_len_max);
    if (!data) {
        LOG_TO_FILE("malloc failed (2) (%u)\n", downloaded_len_max);
        free(mdata);
        return NULL;
    }

    len = inflate(data, mdata + 4, downloaded_len_max, mlen - 4);
    free(mdata);
    if (len == 0) {
        LOG_TO_FILE("inflate failed\n");
        free(data);
        return NULL;
    }

    *downloaded_len = len;
    return data;
}

#define TRY_TIMES 2

void *download_from_host( bool compressed,
                          const char *host,
                          const char *filename,
                          size_t filename_len,
                          uint32_t *downloaded_len,
                          const uint8_t *self_public_key,
                          const char *cmp_end_file,
                          size_t cmp_end_file_len)
{
    struct addrinfo *root;

    if (getaddrinfo(host, "80", NULL, &root) != 0) {
        LOG_TO_FILE("getaddrinfo failed for host [%s]\n", host);
        return NULL;
    }

    for (struct addrinfo *info = root; info; info = info->ai_next) {
        LOG_TO_FILE("addrinfo %i %i %i %i %i\n", info->ai_flags,    info->ai_family,
                                                 info->ai_socktype, info->ai_protocol,
                                                 info->ai_addrlen);
        if (info->ai_socktype && info->ai_socktype != SOCK_STREAM) {
            continue;
        }

        LOG_TO_FILE("Trying host %s\n", host);
        void *data = 0;
        uint32_t dled_len = 0;
        if (compressed) {
            data = download_signed_compressed(info->ai_addr,
                                              info->ai_addrlen,
                                              host,
                                              strlen(host),
                                              filename, filename_len,
                                              &dled_len,
                                              UINT32_MAX,
                                              self_public_key);
        } else {
            data = download_signed(info->ai_addr,
                                   info->ai_addrlen,
                                   host,
                                   strlen(host),
                                   filename,
                                   filename_len,
                                   &dled_len,
                                   self_public_key);
        }

        if (!data) {
            LOG_TO_FILE("data is NULL\n");
            continue;
        }

        if (cmp_end_file && cmp_end_file_len) {
            if (dled_len < cmp_end_file_len) {
                LOG_TO_FILE("Too Small %u < %u\n", dled_len, cmp_end_file_len);
                continue;
            }

            if (memcmp(cmp_end_file, data + (dled_len - cmp_end_file_len), cmp_end_file_len) != 0) {
                LOG_TO_FILE("cmp_end_file cmp error length %u\n", cmp_end_file_len);
                unsigned int j;
                for (j = 0; j < cmp_end_file_len; ++j) {
                    LOG_TO_FILE("%c", cmp_end_file[j]);
                }

                LOG_TO_FILE("\n");

                uint8_t *tmpdt = data + (dled_len - cmp_end_file_len);
                for (j = 0; j < cmp_end_file_len; ++j) {
                    LOG_TO_FILE("%c", tmpdt[j]);
                }

                LOG_TO_FILE("\n");
                continue;
            }

            dled_len -= cmp_end_file_len;
        }

        *downloaded_len = dled_len;
        freeaddrinfo(root);
        return data;
    }

    freeaddrinfo(root);

    return NULL;
}
