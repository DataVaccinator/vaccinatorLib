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

void dvClearError(void) {
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

DVAPI const char* dvLastError(void) {
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

ptr freeGetRes(ptr in) {
    dvGetRes gr = (dvGetRes) in;
    if (!gr) return NULL;
    ruFree(gr->data);
    return ruClear(gr);
}

DVAPI int32_t dvGetVid(ruMap vidMap, const char* vid, char** pid) {
    if (!vidMap || !vid) return RUE_PARAMETER_NOT_SET;
    dvGetRes gr = NULL;
    int32_t ret = ruMapGet(vidMap, vid, &gr);
    if (ret == RUE_OK && gr) {
        if (pid) *pid = gr->data;
        ret = gr->status;
    }
    return ret;
}

/******************************************************************************/
/*                          CLEAN LOGGER                                      */
/******************************************************************************/
void dvCleanerAdd(trans_chars secret) {
    ruCleanAdd(ruGetCleaner(), secret, dvDefaultSecretPlaceHolder);
}

