/*
 * Copyright DataVaccinator
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef DV_LIB_H
#define DV_LIB_H

#define DV_BUILDING 1
#include <vaccinator.h>
#include <stdarg.h>
#include <string.h>
#include <yajl/yajl_parse.h>
#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>
#define CURL_DISABLE_TYPECHECK
#include "curl/curl.h"

#ifndef uint
typedef unsigned int uint;
#endif

// vault protocol version for the requests
#define PROTO_VERSION 2

/* service provider stati */
#define STATUS "status"
#define STATUS_OK       "OK"
#define STATUS_INVALID  "INVALID"
#define STATUS_ERROR    "ERROR"
#define STATUS_NOT_FOUND  "NOTFOUND"
// vault json post field
#define JSON_FIELD "json"

#define MIN_APPID_LEN 14
#define BLOCKSIZE 16
// must be multiple of BLOCKSIZE
#define MACSIZE 32
#define KEYBITS 256

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define STORE(ctx, key, val) ctx->store->set(ctx->store, key, val, strlen(val))
#define LOAD(ctx, key, val, len) ctx->store->get(ctx->store, key, val, len)

extern const char *myName;
extern const char *myVersion;
// The current dvPwReplacement of a secret when calling dvSetProp with DV_SECRET.
extern char *dvPwReplacement;

typedef struct dv_ctx *dvctx;
typedef struct dv_get_result *dvGetRes;
typedef struct dv_hdr_ctx *dvHdrCtx;
typedef struct dv_kvList *dvKvList;

/**
 * Holds the current context
 */
#define dvctxType 0x21ff11ff
struct dv_ctx {
    u_int32_t type;     /* magic identification number (ptr type check)*/
    char *serviceUrl;
    char *appId;        /* the app-id */
    char *appIdEnd;     /* the last 2 chars of the appId, the checksum part. */
    uchar key[32];      /* the encryption key derived from appId */

    // storage
    KvStore *store;     /* Where cached data will be stored. */
    bool ownStore;      /* Whether store must be freed with this context */

    // proxy
    char *proxy;        /* proxy URL */
    char *proxyUser;
    char *proxyPass;
    char *certPath;     /* path to certificate file or directory */

    // callbacks
    dvHeaderCb hdrCb;
    void *hdrCtx;
    dvPostCb postCb;
    void *postCtx;

    //.device
    char *appName;
    char *appVersion;

    // utility
    uint curlTimeout;       /* timeout for curl calls. */
    bool curlDebug;         /* whether curl debugging is done */
    bool skipCertCheck;           /* development mode, doesn't verify SSL certs */
};

/**
 * Holds a get result with status code
 */
struct dv_get_result {
    char* data;         // the data or checksum on DVE_INVALID_CREDENTIALS
    int32_t status;     // the associated status usually RUE_OK
};

/**
 * Holds curl slist pointers
 */
struct dv_hdr_ctx {
    // curl headers
    struct curl_slist *chunk;
    // collection of allocs to free
    ruList headers;
};

/**
 * Holds a key value pair
 */
#define dvKvListType 0x21ff44ff
struct dv_kvList {
    u_int32_t type;           /* magic identification number (ptr type check)*/
    char *key;
    char *val;
    rusize len;
    dvKvList next;
};

// curl.c
int32_t newKvList(dvKvList *kvl, const char *key, const char *value, rusize len);
int32_t freeKvList(dvKvList kvl);
int32_t doRequest(dvctx ctx, const char *url, dvKvList postData, char **result,
                  rusize *resultLen);

// misc.c
dvctx getDvCtx(dvCtx pCtx);
dvGetRes newGetRes(char* data, int32_t status);
void freeGetRes(void* in);
void dvClearError();
void dvSetError(const char *format, ...);
void dvCleanerAdd(const char *secret);

// json.c
yajl_val getJson(const char *json);
int32_t jsonEncodeString(const char *input, char **output);
int32_t parseString(yajl_val node, const char *key, char **value);
int32_t parseStatus(yajl_val node, bool *invalidRequest);
int32_t parseVidData(uchar* key, yajl_val node, ruList vids, bool recode,
                     ruMap *data);
int32_t parseSearchData(yajl_val node, ruList *vids);

// crypto.c
int32_t dvSearchHash(const char* term, const char* key, char** hash, bool indexing);
int32_t getCs(const char* appId, rusize idLen, char** csStart);
int32_t mkKey(const char* appId, uchar* key, char** csStart);
int32_t dvAes256Enc(const uchar* key, const char* cs, const char* str,
                    char** cipherText);
int32_t dvAes256Dec(const uchar* key, const char* cipherRecipe, char** data, char* cs);

#ifdef __cplusplus
}   /* extern "C" */
#endif /* __cplusplus */

#endif //DV_LIB_H
