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

static void setKvListValue(dvKvList l, const char* value, rusize len) {
    if (len) {
        l->val = ruMalloc0(len, char);
        memcpy(l->val, value, len);
        l->len = len;
    } else {
        l->val = ruStrDup(value);
        l->len = strlen(l->val);
    }
}

int32_t newKvList(dvKvList* kvl, const char* key, const char* value, rusize len) {
    dvKvList l = NULL;
    if (!kvl || !key || !value) return RUE_PARAMETER_NOT_SET;
    l = ruMalloc0(1, struct dv_kvList);
    l->type = dvKvListType;
    l->key = ruStrDup(key);
    setKvListValue(l, value, len);
    *kvl = l;
    return RUE_OK;
}

int32_t addKv(dvKvList kvl, const char* key, const char* value, rusize len) {
    dvKvList l = NULL;
    if (!kvl || !key || !value) return RUE_PARAMETER_NOT_SET;
    if (dvKvListType != kvl->type ) return RUE_INVALID_PARAMETER;
    /* go through the list to a match or the end */
    l = kvl;
    while (true) {
        if (ruStrEquals(l->key, key)) {
            // matched, replace existing
            ruFree(l->val);
            setKvListValue(l, value, len);
            return RUE_OK;
        }
        if (!l->next) break;
        l = l->next;
    }
    // add it to the end
    return newKvList(&l->next, key, value, len);
}

static int32_t curlPostCb(void* postCtx, const char* key, void* value, rusize len) {
    // this madness is needed in case there are no preexisting post fields
    dvKvList kvl = *(dvKvList*)postCtx;
    if (!kvl) {
        return newKvList(postCtx, key, (const char*)value, len);
    }
    return addKv(kvl, key, (const char*)value, len);
}

int32_t kvListToString(dvKvList kvl, char** postData) {
    dvKvList l = NULL;
    ruString out = NULL;
    bool isFirst = true;
    if (!kvl || !postData) return RUE_PARAMETER_NOT_SET;
    if (dvKvListType != kvl->type ) return RUE_INVALID_PARAMETER;
    /* go through the list */
    l = kvl;
    out = ruStringNew ("");
    do {
        /* get the key */
        if (isFirst) {
            ruStringAppend(out, l->key);
            isFirst = false;
        } else {
            ruStringAppend(out, "&");
            ruStringAppend(out, l->key);
        }
        ruStringAppend(out, "=");
        /* get the encoded value */
        ruBufferAppendUriEncoded(out, l->val, l->len);

        /* move the iterator on */
        l = l->next;
    } while (l);

    *postData = ruStringGetCString(out);
    ruStringFree(out, true);

    return RUE_OK;
}

int32_t freeKvList(dvKvList kvl) {
    dvKvList l = NULL, parent = NULL;
    if (!kvl) return RUE_PARAMETER_NOT_SET;
    if (dvKvListType != kvl->type ) return RUE_INVALID_PARAMETER;
    /* go through the list */
    l = kvl;
    do {
        /* keep parent address for deletion */
        parent = l;
        /* move the iterator on */
        l = l->next;
        /* free the parent */
        ruFree(parent->key);
        ruFree(parent->val);
        memset(parent, 0, sizeof(struct dv_kvList));
        ruFree(parent);
    } while (l);

    return RUE_OK;
}

static int32_t curlHdrCb(void* headerCtx, const char* key, const char* value) {
    dvHdrCtx sl = (dvHdrCtx)headerCtx;
    if (!sl->headers) {
        sl->headers = ruListNewType(ruTypeStrFree());
    }
    char *h;
    if (!value) {
        // remove the header
        h = ruDupPrintf("%s:", key);
    } else if (!strlen(value)) {
        // set empty header
        h = ruDupPrintf("%s;", key);
    } else {
        // set regular header
        h = ruDupPrintf("%s: %s", key, value);
    }
    ruListAppend(sl->headers, h);
    sl->chunk = curl_slist_append(sl->chunk, h);
    return RUE_OK;
}

int32_t dvErrorFromCurlError(int curlEc) {
    // in 7.62 and CURLE_SSL_CACERT is replaced by CURLE_PEER_FAILED_VERIFICATION
    if (curlEc == CURLE_SSL_CACERT) curlEc = CURLE_PEER_FAILED_VERIFICATION;

    // This function translates several CURL error codes to \ref dvclient errors.
    // It is needed because the toolkit only knows errors for "no connection",
    // "wrong data/protocol" and SSL problems.
    switch(curlEc) {
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_RESOLVE_PROXY:
        case CURLE_OPERATION_TIMEOUTED:
        case CURLE_COULDNT_CONNECT:
            return DVE_NO_INTERNET;

        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_PEER_FAILED_VERIFICATION:
        case CURLE_SSL_CERTPROBLEM:
        case CURLE_SSL_CIPHER:
        case CURLE_SSL_ISSUER_ERROR:
            return DVE_SSL_HANDSHAKE_ERROR;
    }
    return DVE_PROTOCOL_ERROR;
}

/* curl writer function */
static rusize responseWriter( char *ptr, rusize size, rusize nmemb,
                              void *userdata) {
    /* receives utf-8/ascii encoded data */
    rusize len = 0;
    ruBuffer buffer = userdata;
    if (!ptr || !size || !nmemb || !userdata) return len;
    len = size * nmemb;
    ruBufferAppend (buffer, ptr, len);
    return len;
}

/* curl debug function */
static int debug_callback (CURL *h, curl_infotype type, char *str, rusize len,
                           void *userdata) {
    ruString buffer = (ruString ) userdata;
    if (!h || !str || !len || !userdata) return 0;
    ruStringAppend(buffer, "CURL ");
    switch(type) {
        case CURLINFO_TEXT:
            ruStringAppend(buffer, "TEXT: ");
            break;
        case CURLINFO_HEADER_IN:
            ruStringAppend(buffer, "HEADER IN: ");
            break;
        case CURLINFO_HEADER_OUT:
            ruStringAppend(buffer, "HEADER OUT: ");
            break;
        case CURLINFO_DATA_IN:
            ruStringAppend(buffer, "DATA IN: ");
            break;
        case CURLINFO_DATA_OUT:
            ruStringAppend(buffer, "DATA OUT: ");
            break;
        default:
            return 0;
    }
    ruStringAppendn(buffer, str, len);
    if (*(str + len-1) != '\n')
        ruStringAppend(buffer, "\n");
    return 0;
}

#define CURL_CHECK(f) if (ret) { \
    ruCritLogf("Error setting "#f". Curl ec: %s", curl_easy_strerror(ret)); \
}

#define CURL_CHECK_BREAK(f) if (ret) { \
    dvSetError("Error setting "#f". Curl ec: %s", curl_easy_strerror(ret)); \
    break; \
}

/**
 * Post the given data to url and stores the response without the headers
 * in result.
 * \param [in] ctx An initialized toolkit context
 * \param [in] url The url to post the data to
 * \param [in] postData The data to post
 * \param [out] result The body of the response without the headers.
 *                     Must be freed by caller
 * \param [out] resultLen Optional. Where the length of the result will be
 *                        stored.
 * \return A \ref rferrors status of the operation.
 */
int32_t doRequest(dvctx ctx, const char* url, dvKvList postData, char** result,
              rusize* resultLen ) {
    CURL* h;
    CURLcode ret;
    bool isSSL = true;
    bool verifyPeer = true;
    int verifyHost = 2;
    ruBuffer response = NULL, *debug = NULL;
    int returnCode = RUE_GENERAL;
    char* escapedPost = NULL;
    char* proxyAuth = NULL;
    dvKvList kvl = NULL;
    struct dv_hdr_ctx hdrCtx;
    memset(&hdrCtx, 0, sizeof(struct dv_hdr_ctx));

    if (!ctx || !url || !result) return RUE_PARAMETER_NOT_SET;
    if (dvctxType != ctx->type) return RUE_INVALID_PARAMETER;

    if (postData && dvKvListType != postData->type ) {
        /* make sure postData isn't bogus if we have some */
        ruCritLogf("postdate type:%x", postData->type);
        return RUE_INVALID_PARAMETER;
    }

    ruVerbLogf("Request to %s", url);

    isSSL = (ruStrStartsWith(url, "https", NULL) != 0);

    h = curl_easy_init();
    if (!h) {
        ruCritLog("Error calling curl_easy_init. Check your cURL setup.");
        return returnCode;
    }

    do {
        if (ctx->curlDebug && ruGetLogLevel() >= RU_LOG_VERB) {
            /* set debugging options to curl */
            ret = curl_easy_setopt(h, CURLOPT_VERBOSE, 1);
            CURL_CHECK(CURLOPT_VERBOSE)

            ret = curl_easy_setopt(h, CURLOPT_DEBUGFUNCTION, debug_callback);
            CURL_CHECK(CURLOPT_DEBUGFUNCTION)

            debug = ruStringNew ("");
            ret = curl_easy_setopt(h, CURLOPT_DEBUGDATA, debug);
            CURL_CHECK(CURLOPT_DEBUGDATA)
        }

        /* Using with a proxy */
        if (ctx->proxy) {
            /* activate proxy */

            /* establish a proxy tunnel only for https calls (not http) */
            ret = curl_easy_setopt(h, CURLOPT_HTTPPROXYTUNNEL, true);
            CURL_CHECK_BREAK(CURLOPT_HTTPPROXYTUNNEL)

            ret = curl_easy_setopt(h, CURLOPT_PROXY, ctx->proxy);
            CURL_CHECK_BREAK(CURLOPT_PROXY)

            if (ctx->proxyUser && ctx->proxyPass) {
                ret = curl_easy_setopt(h, CURLOPT_PROXYAUTH,
                                       CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NTLM);
                CURL_CHECK_BREAK(CURLOPT_PROXYAUTH)

                proxyAuth = ruDupPrintf("%s:%s", ctx->proxyUser, ctx->proxyPass);

                ret = curl_easy_setopt(h, CURLOPT_PROXYUSERPWD, proxyAuth);
                CURL_CHECK_BREAK(CURLOPT_PROXYUSERPWD)
            }

        } else {
            /* deactivate proxy */
            ret = curl_easy_setopt(h, CURLOPT_HTTPPROXYTUNNEL, false);
            CURL_CHECK_BREAK(CURLOPT_HTTPPROXYTUNNEL)
        }

        /* setup SSL here */
        if (isSSL) {

            if (ctx->skipCertCheck) {
                verifyPeer = false;
                verifyHost = 0;
            } else if (ctx->certPath) {
                if (ruIsFile(ctx->certPath)) {
                    ret = curl_easy_setopt(h, CURLOPT_CAINFO, ctx->certPath);
                    CURL_CHECK_BREAK(CURLOPT_CAINFO)
                } else {
                    ret = curl_easy_setopt(h, CURLOPT_CAPATH, ctx->certPath);
                    CURL_CHECK_BREAK(CURLOPT_CAPATH)
                }
            }

            /* force to verify SSL hosts! 1=verify peer certificate */
            ret = curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, verifyPeer);
            CURL_CHECK_BREAK(CURLOPT_SSL_VERIFYPEER)

            /* 2=validate hostname of peer-certificate */
            ret = curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, verifyHost);
            CURL_CHECK_BREAK(CURLOPT_SSL_VERIFYHOST)
        }

        /* dont output header in result */
        ret = curl_easy_setopt(h, CURLOPT_HEADER, false);
        CURL_CHECK_BREAK(CURLOPT_HEADER)

        /* set connection url */
        ret = curl_easy_setopt(h, CURLOPT_URL, url);
        CURL_CHECK_BREAK(CURLOPT_URL)

        /* run the callbacks */
        if (ctx->hdrCb) {
            ctx->hdrCb(ctx->hdrCtx, curlHdrCb, &hdrCtx);
            if (hdrCtx.chunk) {
                ret = curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrCtx.chunk);
                CURL_CHECK_BREAK(CURLOPT_CONNECTTIMEOUT)
                // HTTPS over a proxy makes a separate CONNECT to the proxy, so
                // tell libcurl to not send the custom headers to the proxy.
                // Keep them separate!
                curl_easy_setopt(h, CURLOPT_HEADEROPT, CURLHEADER_SEPARATE);
                CURL_CHECK_BREAK(CURLOPT_HEADEROPT)
            }
        }
        if (ctx->postCb) {
            if (!postData) {
                // postdata will probably be created here
                ctx->postCb(ctx->postCtx, &curlPostCb, &kvl);
                if (kvl) {
                    postData = kvl;
                }
            } else {
                // just update postdata
                ctx->postCb(ctx->postCtx, &curlPostCb, &postData);
            }
        }
        if (postData) {
            /* set post data only, if array contains values */
            returnCode = kvListToString(postData, &escapedPost);
            if (returnCode != RUE_OK) {
                ruCritLog("Failed to serialize the post data");
                break;
            }
            ruVerbLogf("Set cURL postfields with %s values.", escapedPost);
            ret = curl_easy_setopt(h, CURLOPT_POSTFIELDS, escapedPost);
            CURL_CHECK_BREAK(CURLOPT_POSTFIELDS)

        } else {
            ruVerbLog("Dont set cURL POST data, because it is empty.");
        }

        /* set timeout for this function */
        ret = curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, ctx->curlTimeout);
        CURL_CHECK_BREAK(CURLOPT_CONNECTTIMEOUT)

        /* return result with exec */
        ret = curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, responseWriter);
        CURL_CHECK_BREAK(CURLOPT_WRITEFUNCTION)

        response = ruBufferNew (1024*64);
        ret = curl_easy_setopt(h, CURLOPT_WRITEDATA, response);
        CURL_CHECK_BREAK(CURLOPT_WRITEDATA)

        ret = curl_easy_perform(h);
        if (ret) {
            returnCode = dvErrorFromCurlError(ret);
            dvSetError("Error during perform Curl ec: %s",
                       curl_easy_strerror(ret));
            break;
        }
        returnCode = RUE_OK;

    } while (false);

    if (debug) {
        ruVerbLogf("curl debug '%s'", ruStringGetCString(debug));
        ruStringFree(debug, false);
    }

    curl_easy_cleanup(h);

    if (response) {
        if (resultLen) {
            *resultLen = ruBufferLen(response, NULL);
        }
        *result = ruBufferGetData(response);
        ruVerbLogf("Got response: %s", *result);
        ruBufferFree(response, true);
    }
    ruFree(escapedPost);
    ruFree(proxyAuth);

    // if there was a header callback
    if(hdrCtx.headers) ruListFree(hdrCtx.headers);
    if(hdrCtx.chunk) curl_slist_free_all(hdrCtx.chunk);

    // if there was a post field callback but no postdata
    if(kvl) freeKvList(kvl);

    return returnCode;
}
