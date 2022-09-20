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

dvctx getDvCtx(dvCtx pCtx) {
    dvctx ctx = (dvctx) pCtx;
    if (!ctx || dvctxType != ctx->type ) return NULL;
    return ctx;
}
#define MIN_APPID_LEN 14
int32_t validateAppId(const char*appId) {
    if (!appId) return RUE_PARAMETER_NOT_SET;
    rusize len = strlen(appId);
    if (!len) return RUE_PARAMETER_NOT_SET;
    if (len < MIN_APPID_LEN) {
        dvSetError("appId is less than %d characters long", MIN_APPID_LEN);
        return RUE_INVALID_PARAMETER;
    }
    return RUE_OK;
}

/******************************************************************************/
/*                     Public Functions Error Handling                        */
/******************************************************************************/
#define DV_ERRBUF_SIZE 2048
RU_THREAD_LOCAL char dvError[DV_ERRBUF_SIZE];
RU_THREAD_LOCAL int dvErrInit = 0;

void dvClearError() {
    dvError[0] = '\0';
}

void dvSetError(const char *format, ...) {
    if (!format) {
        dvClearError();
        return;
    }
    va_list args;
    va_start (args, format);
    int32_t msgsize  = vsnprintf(dvError, DV_ERRBUF_SIZE, format, args);
    va_end (args);
    if (msgsize >= 0) {
        dvErrInit = 1;
    }
    ruCritLog(dvError);
}

DVAPI const char* dvLastError() {
    if (!dvErrInit) {
        dvError[0] = '\0';
        dvErrInit = 1;
    }
    return &dvError[0];
}

dvGetRes newGetRes(char* data, int32_t status) {
    dvGetRes out = ruMalloc0(1, struct dv_get_result);
    out->data = data;
    out->status = status;
    return out;
}

void freeGetRes(void* in) {
    dvGetRes gr = (dvGetRes) in;
    if (!gr) return;
    ruFree(gr->data);
    ruFree(gr);
}

DVAPI int32_t dvGetVid(ruMap vidMap, const char* vid, char** pid) {
    if (!vidMap || !vid) return RUE_PARAMETER_NOT_SET;
    dvGetRes gr = NULL;
    int32_t ret = ruMapGet(vidMap, vid, &gr);
    if (ret == RUE_OK && gr) {
        if (*pid) *pid = gr->data;
        ret = gr->status;
    }
    return ret;
}

/******************************************************************************/
/*                          CLEAN LOGGER                                      */
/******************************************************************************/
// password cleaner to store credentials in in case caller wants to clean the logs.
static ruCleaner pwCleaner_ = NULL;
// cleaned log context
static ruLogFunc logger_ = NULL;
static void* userLogData_ = NULL;
// The current dvPwReplacement of a secret when calling dvSetProp with DV_SECRET.
char *dvPwReplacement = dvDefaultSecretPlaceHolder;

static ruCleaner dvGetCleaner() {
    if (!pwCleaner_) {
        pwCleaner_ = ruCleanNew(0);
    }
    return pwCleaner_;
}

static rusize_s pcWriter (void *ctx, void *buf, rusize len) {
    if (logger_) {
        ((char*)buf)[len] = '\0';
        logger_(userLogData_, buf);
    }
    return (rusize_s)len;
}

static rusize_s pcReader (void *msg, void *buf, rusize len) {
    if (!msg) return 0;
    rusize sz = strlen(msg) + 1;
    if (sz > len) sz = len;
    memcpy(buf, msg, sz);
    return (rusize_s)sz;
}

static void dvCleanLogger(void *ctx, const char *message) {
    ruCleaner pc = dvGetCleaner();
    ruCleanIo(pc, &pcReader, (void*)message, &pcWriter, NULL);
}

void dvCleanerAdd(const char* secret) {
    if (dvPwReplacement) {
        ruCleanAdd(dvGetCleaner(), secret, dvPwReplacement);
    } else {
        ruCleanAdd(dvGetCleaner(), secret, dvDefaultSecretPlaceHolder);
    }
}

DVAPI void dvSetCleanLogger(ruLogFunc logger, u_int32_t logLevel, void* userData) {
    logger_ = logger;
    userLogData_ = userData;
    if (logger_) {
        ruSetLogger(dvCleanLogger, logLevel, 0);
    } else {
        ruSetLogger(NULL, logLevel, 0);
    }
}

