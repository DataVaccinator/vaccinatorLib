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
#include "lib.h"

#ifdef BUILD_NAME
#define DV_BUILD_NAME BUILD_NAME
#else
#define DV_BUILD_NAME "vaccinatorLib"
#endif
#ifdef BUILD_VERSION
#define DV_BUILD_VERSION BUILD_VERSION
#else
#define DV_BUILD_VERSION "0.0.0-dev"
#endif

const char* myName = DV_BUILD_NAME;
const char* myVersion = DV_BUILD_VERSION;

static int32_t setServiceUrl(dvctx ctx, const char* providerUrl) {
    ruFree(ctx->serviceUrl);
    if (providerUrl && strlen(providerUrl) > 0) {
        ctx->serviceUrl = ruStrDup(providerUrl);
        if (ruStrEndsWith(ctx->serviceUrl, "/", NULL)) {
            // snip the trailing /
            *(ctx->serviceUrl + strlen(ctx->serviceUrl)-1) = '\0';
        }
    }
    return RUE_OK;
}

static int32_t setIntOrDefault(const char* value, int64_t defaultNum,
                               int64_t* store) {
    if (value) {
        int64_t to = strtoll(value, NULL, 10);
        if (to > 0) {
            *store = to;
        } else {
            return RUE_INVALID_PARAMETER;
        }
    } else {
        *store = defaultNum;
    }
    return RUE_OK;
}

static int32_t encodeWordList(ruList wordLst, ruString json, const char* key) {
    bool started = false;
    char *jword = NULL;
    int32_t ret;
    ruIterator li = ruListHead(wordLst, &ret);
    if (ret != RUE_OK) {
        dvSetError("Failed getting indexWords iterator ec:%d", ret);
        return ret;
    }
    for (char* word = ruIterNext(li, char*); word;
         word = ruIterNext(li, char*)) {
        ruFree(jword);
        jsonEncodeString(word, &jword);
        if (started) {
            ret = ruStringAppendf(json, ",%s", jword);
            if (ret != RUE_OK) {
                dvSetError("Failed appending to json string ec:%d", ret);
                return ret;
            }
        } else {
            ret = ruStringAppendf(json, ",\"%s\":[%s", key, jword);
            if (ret != RUE_OK) {
                dvSetError("Failed appending to json string ec:%d", ret);
                return ret;
            }
            started = true;
        }
    }
    ret = ruStringAppend(json, "]");
    return ret;
}

static int32_t dvPost(dvCtx dc, const char* data, char** vid, ruList indexWords,
                      const char* passwd, int durationDays) {

    if (!dc || !data || !vid) return RUE_PARAMETER_NOT_SET;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;

    const char *op = "add";
    int32_t ret;
    alloc_bytes key = ctx->key;
    char* cs = ctx->appIdEnd;
    uint8_t pubkey[32];

    // to free
    yajl_val node = NULL;
    dvKvList kvl = NULL;
    char *jsnData = NULL, *response = NULL, *cipher = NULL;
    ruString json = NULL;

    do {
        if (passwd) {
            if (durationDays < 1 || durationDays > 365) {
                ruWarnLogf("Duration dayse must be between 1 and 365 but is %d",
                           durationDays);
                return RUE_INVALID_PARAMETER;
            }
            op = "publish";
            cs = "";
            ret = mkKey(passwd, pubkey, NULL);
            if (ret != RUE_OK) {
                ruCritLogf("failed deriving key from publish password. Ec: %d", ret);
                break;
            }
            key = pubkey;
        }

        ret = dvAes256Enc(key, cs, data, &cipher);
        if (ret != RUE_OK) {
            ruCritLogf("failed to encrypt data. Ec: %d", ret);
            break;
        }

        jsonEncodeString(cipher, &jsnData);
        json = ruStringNewf(
                "{\"version\":%d,\"op\":\"%s\","
                "\"data\":%s", PROTO_VERSION, op, jsnData);
        if (passwd) {
            ruStringAppendf(json, ",\"duration\":%d", durationDays);
        }
        if (indexWords) {
            ret = encodeWordList(indexWords, json, "words");
            if (ret != RUE_OK) break;
        }
        ruStringAppend(json, "}");

        ret = newKvList(&kvl, JSON_FIELD,
                        ruStringGetCString(json), 0);
        if (ret != RUE_OK) {
            ruCritLogf("failed to create parameter list. Ec: %d", ret);
            break;
        }
        ruVerbLogf("Do request: %s", ruStringGetCString(json));
        ret = doRequest(ctx, ctx->serviceUrl, kvl,
                        &response, NULL);
        if (ret != RUE_OK) {
            ruCritLogf("failed to add data to %s. Ec: %d", ctx->serviceUrl, ret);
            break;
        }
        // parse response
        node = getJson(response);
        ret = parseStatus(node, NULL);
        if (ret != RUE_OK) {
            break;
        }
        ret = parseString(node, "vid", vid);
        if (ret != RUE_OK) {
            break;
        }
        ret = STORE(ctx, *vid, data);

    } while(0);

    yajl_tree_free(node);
    freeKvList(kvl);
    ruStringFree(json,  false);
    ruFree(response);
    ruFree(cipher);
    ruFree(jsnData);
    return ret;
}

static int32_t doGet(dvCtx dc, ruList vids, ruMap* data, const char* passwd,
                     bool recode) {

    if (!dc || !vids || !data) return RUE_PARAMETER_NOT_SET;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;

    int32_t ret = RUE_OK;
    alloc_bytes key = ctx->key;
    uint8_t pubkey[32];

    // to free
    char *response = NULL;
    dvKvList kvl = NULL;
    yajl_val node = NULL;
    ruString json = NULL;
    ruList getvids = NULL;

    do {
        if (!*data) {
            *data = ruMapNew(ruTypeStrFree(),
                                 ruTypePtr(freeGetRes));
        }

        // first check the cache
        ruIterator li = ruListHead(vids, &ret);
        if (ret != RUE_OK) {
            dvSetError("Failed getting vid list iterator. ec: %d", ret);
            break;
        }
        for (char* vid = ruIterNext(li, char*); vid;
             vid = ruIterNext(li, char*)) {
            char* dt = NULL;
            rusize len = 0;
            LOAD(ctx, vid, &dt, &len);
            if (!dt) {
                if (!getvids) {
                    getvids = ruListNew(NULL);
                }
                ruListAppend(getvids, vid);
                continue;
            }
            // we have it
            ret = ruMapPut(*data, ruStrDup(vid),
                           newGetRes(dt, RUE_OK));
            if (ret != RUE_OK) {
                ruCritLogf("failed adding entry '%s' to map", vid);
                break;
            }
        }
        if (ret != RUE_OK) break;
        // everything was cached, we're done
        if (!getvids) break;

        const char *op = "get";
        if (passwd) {
            op = "getpublished";
            ret = mkKey(passwd, pubkey, NULL);
            if (ret != RUE_OK) {
                ruCritLogf("failed deriving key from publish password. Ec: %d", ret);
                break;
            }
            key = pubkey;
        }

        json = ruStringNewf(
                "{\"version\":%d,\"op\":\"%s\"", PROTO_VERSION, op);
        ret = encodeWordList(getvids, json, "vid");
        if (ret != RUE_OK) break;
        ruStringAppend(json, "}");

        ret = newKvList(&kvl, JSON_FIELD,
                        ruStringGetCString(json), 0);
        if (ret != RUE_OK) {
            ruCritLogf("failed to create parameter list. Ec: %d", ret);
            break;
        }
        ruVerbLogf("Do request: %s", ruStringGetCString(json));
        ret = doRequest(ctx, ctx->serviceUrl, kvl,
                        &response, NULL);
        if (ret != RUE_OK) {
            ruCritLogf("failed to get data from %s. Ec: %d",
                       ctx->serviceUrl, ret);
            break;
        }
        // parse response
        node = getJson(response);
        ret = parseStatus(node, NULL);
        if (ret != RUE_OK) {
            break;
        }
        // load/decrypt
        ret = parseVidData(key, node, getvids, recode, data);
    } while(0);

    yajl_tree_free(node);
    freeKvList(kvl);
    ruStringFree(json,  false);
    ruFree(response);
    ruListFree(getvids);

    return ret;
}

static int32_t doUpdate(dvCtx dc, const char* vid, const char* data,
                        ruList indexWords, const char* appid) {

    if (!dc || !vid || !data) return RUE_PARAMETER_NOT_SET;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;

    int32_t ret;

    // to free
    char *jvid = NULL, *jdata = NULL, *response = NULL, *cipher = NULL;
    dvKvList kvl = NULL;
    yajl_val node = NULL;
    ruString json = NULL;
    uint8_t mykey[32];
    alloc_bytes key = ctx->key;
    char *appIdEnd = ctx->appIdEnd;

    do {
        ruVerbLogf("updating vid '%s' with '%s'", vid, data);

        if (appid) {
            // use another app id
            ret = mkKey(appid, mykey, &appIdEnd);
            if (ret) break;
            key = &mykey[0];
        }

        ret = dvAes256Enc(key, appIdEnd, data,
                          &cipher);
        if (ret != RUE_OK) {
            ruCritLogf("failed to encrypt data. Ec: %d", ret);
            break;
        }

        jsonEncodeString(vid, &jvid);
        jsonEncodeString(cipher, &jdata);
        json = ruStringNewf(
                "{\"version\":%d,\"op\":\"update\","
                "\"vid\":%s,\"data\":%s", PROTO_VERSION, jvid, jdata);
        if (indexWords) {
            ret = encodeWordList(indexWords, json, "words");
            if (ret != RUE_OK) break;
        }
        ruStringAppend(json, "}");

        ret = newKvList(&kvl, JSON_FIELD,
                        ruStringGetCString(json), 0);
        if (ret != RUE_OK) {
            ruCritLogf("failed to create parameter list. Ec: %d", ret);
            break;
        }
        ruVerbLogf("Do request: %s", ruStringGetCString(json));
        ret = doRequest(ctx, ctx->serviceUrl, kvl,
                        &response, NULL);
        if (ret != RUE_OK) {
            ruCritLogf("failed to add data to %s. Ec: %d",
                       ctx->serviceUrl, ret);
            break;
        }
        // parse response
        node = getJson(response);
        ret = parseStatus(node, NULL);
        if (ret != RUE_OK) {
            break;
        }
        // update the cache
        ret = STORE(ctx, vid, data);

    } while(0);

    yajl_tree_free(node);
    freeKvList(kvl);
    ruStringFree(json,  false);
    ruFree(response);
    ruFree(jvid);
    ruFree(jdata);
    ruFree(cipher);

    return ret;
}
/******************************************************************************/
/*                             Public Functions                               */
/******************************************************************************/
DVAPI const char* dvVersion(void) {
    return myVersion;
}

DVAPI int32_t dvNew(dvCtx* dc, const char* serviceUrl, const char* appId,
                    KvStore* cache) {
    dvctx ctx = NULL;
    CURLcode cret;
    int32_t ret = RUE_OK;
    if (!dc) return RUE_PARAMETER_NOT_SET;

    cret = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (cret) {
        ruCritLogf("Failed initializing curl. Ec: %d", cret);
        return RUE_GENERAL;
    }

    do {
        ctx = ruMalloc0(1, struct dv_ctx);
        ctx->type = dvctxType;
        ctx->appName = (char *) myName;
        ctx->appVersion = (char *) myVersion;

        ret = setServiceUrl(ctx, serviceUrl);
        if (ret != RUE_OK) break;

        if (appId) {
            ctx->appId = ruStrDup(appId);
            ret = mkKey(ctx->appId, ctx->key, &ctx->appIdEnd);
            if (ret) break;
            dvCleanerAdd(ctx->appId);
        }

        if (cache) {
            ret = ruValidStore(cache);
            if (ret != RUE_OK) {
                ruCritLogf("got bogus cache parameter ec:%d", ret);
                break;
            }
            ctx->store = cache;
            ctx->ownStore = false;
        } else {
            ctx->store = ruNewNullStore();
            ctx->ownStore = true;
        }

        // all good
        *dc = ctx;
        ret = RUE_OK;
    } while(0);

    if (ret != RUE_OK) {
        dvFree(ctx);
    }
    return ret;
}

DVAPI void dvFree(dvCtx dc) {
    if (!dc) return;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return;

    ruFree(ctx->serviceUrl);
    ruFree(ctx->appId);

    if (ctx->ownStore) ruFreeStore(ctx->store);

    ruFree(ctx->proxy);
    ruFree(ctx->proxyUser);
    ruFree(ctx->proxyPass);
    ruFree(ctx->certPath);

    if (ctx->appName != myName) ruFree(ctx->appName);
    if (ctx->appVersion != myVersion) ruFree(ctx->appVersion);
    ruFree(ctx);
}

static int32_t addSearchWord(ruList* indexWords, const char* appId,
                             const char* word, bool indexing) {
    if (!appId || !indexWords || !word) return RUE_PARAMETER_NOT_SET;
    int32_t ret;

    char* term = NULL;
    do {
        ret = dvSearchHash(word, appId, &term, indexing);
        if (ret != RUE_OK) break;

        if (!*indexWords) {
            *indexWords = ruListNew(ruTypeStrFree());
        }
        ruVerbLogf("Adding term:'%s' for word:'%s' with appid:'%s'",
                   term, word, appId);
        ret = ruListAppend(*indexWords, term);
        if (ret != RUE_OK) {
            dvSetError("failed adding term to search list. ec: %d", ret);
            break;
        }
        term = NULL;
    } while (false);

    ruFree(term);

    return ret;
}

DVAPI int32_t dvAddIndexWord(ruList* indexWords, const char* appId, const char* word) {
    return addSearchWord(indexWords, appId, word, true);
}

DVAPI int32_t dvAddSearchWord(ruList* searchWords, const char* appId, const char* word) {
    return addSearchWord(searchWords, appId, word, false);
}

DVAPI int32_t dvAdd(dvCtx dc, const char* data, ruList indexWords, char** vid) {
    return dvPost(dc, data, vid, indexWords, NULL, 0);
}

DVAPI int32_t dvPublish(dvCtx dc, const char* passwd, int durationDays,
                        const char* data, char** vid) {
    if (!passwd) return RUE_PARAMETER_NOT_SET;
    return dvPost(dc, data, vid, NULL, passwd, durationDays);
}

DVAPI int32_t dvUpdate(dvCtx dc, const char* vid, const char* data,
                       ruList indexWords) {
    return doUpdate(dc, vid, data, indexWords, NULL);
}

DVAPI int32_t dvGet(dvCtx dc, ruList vids, ruMap* vidMap) {
    return doGet(dc, vids, vidMap, NULL, false);
}

DVAPI int32_t dvGetPublished(dvCtx dc, const char* passwd, ruList vids,
                             ruMap* vidMap) {
    if (!passwd) return RUE_PARAMETER_NOT_SET;
    return doGet(dc, vids, vidMap, passwd, false);
}

DVAPI int32_t dvSearch(dvCtx dc, ruList searchWords, ruList* vids) {
    char *response = NULL;
    dvKvList kvl = NULL;
    yajl_val node = NULL;
    int32_t ret;

    if (!dc || !searchWords || !vids) return RUE_PARAMETER_NOT_SET;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;

    ruString json = ruStringNewf(
            "{\"version\":%d,\"op\":\"search\"", PROTO_VERSION);

    do {
        ret = encodeWordList(searchWords, json, "words");
        if (ret != RUE_OK) break;
        ruStringAppend(json, "}");

        ret = newKvList(&kvl, JSON_FIELD,
                        ruStringGetCString(json), 0);
        if (ret != RUE_OK) {
            ruCritLogf("failed to create parameter list. Ec: %d", ret);
            break;
        }
        ruVerbLogf("Do request: %s", ruStringGetCString(json));
        ret = doRequest(ctx, ctx->serviceUrl, kvl,
                        &response, NULL);
        if (ret != RUE_OK) {
            ruCritLogf("failed to search vids from %s. Ec: %d",
                       ctx->serviceUrl, ret);
            break;
        }
        // parse response
        node = getJson(response);
        ret = parseStatus(node, NULL);
        if (ret != RUE_OK) {
            break;
        }
        ret = parseSearchData(node, vids);
    } while(0);

    yajl_tree_free(node);
    freeKvList(kvl);
    ruStringFree(json,  false);
    ruFree(response);
    return ret;
}

DVAPI int32_t dvDelete(dvCtx dc, ruList vids) {
    char *response = NULL;
    dvKvList kvl = NULL;
    yajl_val node = NULL;
    int32_t ret;

    if (!dc) return RUE_PARAMETER_NOT_SET;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;

    ruString json = ruStringNewf(
            "{\"version\":%d,\"op\":\"delete\"", PROTO_VERSION);

    do {
        ret = encodeWordList(vids, json, "vid");
        if (ret != RUE_OK) break;
        ruStringAppend(json, "}");

        ret = newKvList(&kvl, JSON_FIELD,
                        ruStringGetCString(json), 0);
        if (ret != RUE_OK) {
            ruCritLogf("failed to create parameter list. Ec: %d", ret);
            break;
        }
        ruVerbLogf("Do request: %s", ruStringGetCString(json));
        ret = doRequest(ctx, ctx->serviceUrl, kvl,
                        &response, NULL);
        if (ret != RUE_OK) {
            ruCritLogf("failed to get data from %s. Ec: %d",
                       ctx->serviceUrl, ret);
            break;
        }
        // parse response
        node = getJson(response);
        ret = parseStatus(node, NULL);
        if (ret != RUE_OK) {
            break;
        }
    } while(0);

    yajl_tree_free(node);
    freeKvList(kvl);
    ruStringFree(json,  false);
    ruFree(response);
    return ret;
}

DVAPI int32_t dvWipe(dvCtx dc, ruList vids) {
    if (!dc) return RUE_PARAMETER_NOT_SET;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;

    int32_t ret = RUE_OK;
    ruList myvids = vids;

    if (!vids) {
        ret = ctx->store->list(ctx->store, "*", &myvids);
        if (ret != RUE_OK) {
            ruCritLogf("failed getting vid list from store. ec: %d", ret);
            return ret;
        }
    } else if (ruListSize(vids, NULL) == -1) {
        return RUE_INVALID_PARAMETER;
    }

    ruIterator li = ruListIter(myvids);
    for (char* vid = ruIterNext(li, char*); vid;
         vid = ruIterNext(li, char*)) {
        ret = ctx->store->set(ctx->store, vid, NULL, 0);
        if (ret != RUE_OK) {
            ruCritLogf("failed clearing '%s' ec: %d", vid, ret);
        }
    }
    if (!vids) {
        // since we made these
        ruListFree(myvids);
    }
    return ret;
}

DVAPI int32_t dvChangeAppId(dvCtx dc, const char* newId, ruList vids,
                            ruMap* vidMap, dvIndexCb indexCb, void* indexCtx) {
    int32_t ret = RUE_GENERAL;

    if (!dc || !newId || !vids || !vidMap) return RUE_PARAMETER_NOT_SET;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;

    ruVerbLogf("Starting conversion for %d items", ruListSize(vids, NULL));

    do {
        char *newCs = NULL;
        ret = getCs(newId, strlen(newId), &newCs);
        if (ret != RUE_OK) break;

        ruVerbLogf("Migrating entries from checksum '%s' to '%s'",
                   ctx->appIdEnd, newCs);

        ret = doGet(dc, vids, vidMap, NULL, true);
        if (ret != RUE_OK) {
            ruWarnLogf("get failed with %d", ret);
            break;
        }
        ruIterator li = ruListIter(vids);
        for (char *vd = ruIterNext(li, char*); li; vd = ruIterNext(li, char*)) {
            if (!ruMapHas(*vidMap, vd, NULL)) {
                dvSetError("No entry for vid '%s'", vd);
                ret = DVE_PROTOCOL_ERROR;
                break;
            }
            dvGetRes gr = NULL;
            ret = ruMapGet(*vidMap, vd, &gr);
            if (ret != RUE_OK) {
                dvSetError("Failed to get '%s' entry from vidMap map. EC: %d",
                           vd, ret);
                break;
            }
            if (gr->status == DVE_INVALID_CREDENTIALS) {
                // we know it didn't match the old checksum
                if (ruStrEquals(newCs, gr->data)) {
                    // if it matched the new checksum then it's already handled
                    ruVerbLogf("Entry '%s' has already been migrated", vd);
                    gr->status = RUE_OK;
                    ruFree(gr->data);
                } else {
                    ruWarnLogf("Entry '%s' failed to decrypt", vd);
                }
                continue;
            }
            if (gr->status == RUE_FILE_NOT_FOUND) {
                ruVerbLogf("Entry '%s' no longer exists", vd);
                continue;
            }
            if (gr->status != RUE_OK) {
                ret = gr->status;
                dvSetError("Failed to get '%s' entry from vidMap map. EC: %d",
                           vd, ret);
                break;
            }

            ruList indexWords = NULL;
            if (indexCb) {
                ret = indexCb(indexCtx, vd, gr->data, &indexWords);
                if (ret != RUE_OK) {
                    ruCritLogf("Failed to get search words for '%s'. EC: %d",
                               vd, ret);
                    break;
                }
            }
            ret = doUpdate(dc, vd, gr->data, indexWords, newId);
            if (ret != RUE_OK) {
                ruWarnLogf("Failed to update vidMap for '%s'. EC: %d", vd, ret);
                break;
            }
            gr->status = ret;
            ruFree(gr->data);
        }
    } while(false);

    return ret;
}

DVAPI int32_t dvSetHeaderCb(dvCtx dc, dvHeaderCb callback, void* cbCtx) {
    if (!dc) return RUE_PARAMETER_NOT_SET;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;
    ctx->hdrCb = callback;
    ctx->hdrCtx = cbCtx;
    return RUE_OK;
}

DVAPI int32_t dvSetPostCb(dvCtx dc, dvPostCb callback, void* cbCtx) {
    if (!dc) return RUE_PARAMETER_NOT_SET;
    dvctx ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;
    ctx->postCb = callback;
    ctx->postCtx = cbCtx;
    return RUE_OK;
}

DVAPI int dvSetProp(dvCtx dc, enum dvCtxOpt opt, const char* value) {
    dvctx ctx = NULL;

    if (!dc || !opt) return RUE_PARAMETER_NOT_SET;
    ctx = getDvCtx(dc);
    if (!ctx) return RUE_INVALID_PARAMETER;
    int64_t num = 0;
    int ret = RUE_OK;
    switch (opt) {
        // User settings, stored
        case DV_PROXY:
            ruFree(ctx->proxy);
            if (value)
                ctx->proxy = ruStrDup(value);
            break;
        case DV_PROXY_USER:
            ruFree(ctx->proxyUser);
            if (value)
                ctx->proxyUser = ruStrDup(value);
            break;
        case DV_PROXY_PASS:
            ruFree(ctx->proxyPass);
            if (value) {
                ctx->proxyPass = ruStrDup(value);
                dvCleanerAdd(value);
            }
            break;
        case DV_SERVICE_URL:
            ret = setServiceUrl(ctx, value);
            break;
        case DV_APP_ID:
            ruFree(ctx->appId);
            ctx->appIdEnd = NULL;
            if (value) {
                ctx->appId = ruStrDup(value);
                ret = mkKey(ctx->appId, ctx->key, &ctx->appIdEnd);
                if (ret) break;
                dvCleanerAdd(ctx->appId);
            }
            break;
        case DV_CONNECT_TIMEOUT:
            ret = setIntOrDefault(value, dvDefaultConnectTimeoutSeconds, &num);
            if (ret == RUE_OK) {
                ctx->curlTimeout = (uint) num;
            }
        case DV_APPNAME:
            if (ctx->appName != myName) ruFree(ctx->appName);
            if (!value) {
                ctx->appName = (char*)myName;
            } else {
                ctx->appName = ruStrDup(value);
            }
            break;
        case DV_APPVERSION:
            if (ctx->appVersion != myVersion) ruFree(ctx->appVersion);
            if (!value) {
                ctx->appVersion = (char*)myVersion;
            } else {
                ctx->appVersion = ruStrDup(value);
            }
            break;
        case DV_CERT_PATH:
            if (value && !ruFileExists(value)) {
                return RUE_CANT_OPEN_FILE;
            }
            ruFree(ctx->certPath);
            if (value)
                ctx->certPath = ruStrDup(value);
            break;
        case DV_SECRET_PLACE_HOLDER:
            ruFree(dvPwReplacement);
            dvPwReplacement = ruStrDup(value);
            break;
        case DV_SECRET:
            dvCleanerAdd(value);
            break;
        case DV_SKIP_CERT_CHECK:
            if (!value || ruStrEquals(value, "0")) {
                ruVerbLog("Enabling certificate verification");
                ctx->skipCertCheck = false;
            } else {
                ruVerbLog("Disabling certificate verification");
                ctx->skipCertCheck = true;
            }
            break;
        case DV_CURL_LOGGING:
            if (!value || ruStrEquals(value, "0")) {
                ruVerbLog("Disabling curl logging");
                ctx->curlDebug = false;
            } else {
                ruVerbLog("Enabling curl logging");
                ctx->curlDebug = true;
            }
            break;
        default:
            ret = RUE_INVALID_PARAMETER;
    }
    ruVerbLogf("setting %d to '%s' results in %d", opt, value, ret);

    return ret;
}
