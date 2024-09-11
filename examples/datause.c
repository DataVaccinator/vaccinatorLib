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
#ifndef APPID
#define APPID        "1Ha6xo2u{mRT18"
#endif
#ifndef PROVIDER_URL
#define PROVIDER_URL "https://my.provider.com/dv"
#endif
#ifndef CACHE_DIR
#define CACHE_DIR    "/path/to/cache"
#endif

//! [DOXYGEN] start
#include <vaccinator.h>
#include <string.h>

int32_t headerCb(void* usrCtx, dvSetHeaderFn setHeader, void* headerCtx) {
    // This a static example that ignores the userCtx
    return setHeader(headerCtx, "Cache-Control", "max-age=60");
}

int32_t postCb(void* usrCtx, dvSetPostFn setPostField, void* postCtx) {
    // abort the request when usrCtx is not set as we need it here
    if (!usrCtx) return RUE_PARAMETER_NOT_SET;

    const char* user = "testuser";
    int32_t ret = setPostField(postCtx, "username", (void*)user, strlen(user));
    // abort the request on failure
    if (ret) return ret;
    // usrCtx could be any kind of structure, we just showcase a string here.
    char* passwd = (char*) usrCtx;
    return setPostField(postCtx, "password", (void*)passwd, strlen(passwd));
}

int main ( int argc, char **argv ) {
    int ret;
    KvStore *kvs = NULL;
    dvCtx dc = NULL;
    const char *name = "John Doe", *address = "Mystreet 42";
    const char *passwd = "mysecret", *logfile = CACHE_DIR "/debug.log";
    char *namevid = NULL, *addrvid = NULL, *a1 = NULL;
    ruList vids = NULL, indexTerms = NULL, searchTerms = NULL, foundVids = NULL;
    ruMap data = NULL;
    ruSinkCtx rsc = NULL;

    do {
        // local cache
        if (!ruIsDir(CACHE_DIR)) {
            ret = ruMkdir(CACHE_DIR, 0755, false);
            if (!ruIsDir(CACHE_DIR)) {
                printf("failed to create folder '%s' ec [%d]\n", CACHE_DIR, ret);
                break;
            }
        }
        kvs = ruNewFileStore(CACHE_DIR, &ret);
        if (ret) break;

        if (argc > 1) {
            a1 = argv[1];
            // -d turns on verbose debug logging
            // -v turns on verbose debug logging with curl debug logging
            if (ruStrEquals(a1, "-v") || ruStrEquals(a1, "-d")) {
                rsc = ruSinkCtxNew(logfile, NULL, NULL);
                ruSetLogger(ruFileLogSink, RU_LOG_VERB, rsc, true, true);
            } else {
                a1 = NULL;
            }
        }

        // setup
        ret = dvNew(&dc, PROVIDER_URL, APPID, kvs);
        if (ret) break;
        // check for easy SSL mode
        if (ruStrEquals("1", ruGetenv("EASYSSL"))) {
            // disable certificate checks
            ret = dvSetProp(dc, DV_SKIP_CERT_CHECK, "1");
            if (ret) break;
        }
        if (ruStrEquals(a1, "-v")) {
            // turn on curl debug logging
            ret = dvSetProp(dc, DV_CURL_LOGGING, "1");
            if (ret) break;
        }
        // sample usage of the header callback
        ret = dvSetHeaderCb(dc, &headerCb, NULL);
        if (ret) break;
        // Mask our password in the logs so it is replace by ^^^SECRET^^^
        // or whatever was set by DV_SECRET_PLACE_HOLDER last
        // APPID has already been masked by dvNew
        ret = dvSetProp(dc, DV_SECRET, passwd);
        if (ret) break;
        // sample usage of the post fields callback
        ret = dvSetPostCb(dc, &postCb, (void *) passwd);
        if (ret) break;

        // add data
        ret = dvAdd(dc, name, NULL, &namevid);
        if (ret) break;
        printf("namevid: %s\n", namevid);

        // add searchable data
        ret = dvAddIndexWord(&indexTerms, APPID, address);
        if (ret) break;
        ret = dvAdd(dc, address, indexTerms, &addrvid);
        if (ret) break;
        printf("addrvid: %s\n", addrvid);

        // retrieve data
        vids = ruListNew(NULL);
        ret = ruListAppend(vids, namevid);
        if (ret) break;
        ret = ruListAppend(vids, addrvid);
        if (ret) break;
        ret = dvGet(dc, vids, &data);
        if (ret) break;
        ruIterator li = ruListIter(vids);
        for(char *out, *vd = ruIterNext(li, char*); li;
            vd = ruIterNext(li, char*)) {
            ret = dvGetVid(data, vd, &out);
            if (ret == RUE_OK) {
                printf("pid for vid: '%s' is: '%s'\n", vd, out);
            }
        }
        ruMapFree(data);
        data = NULL;

        // search data
        ret = dvAddSearchWord(&searchTerms, APPID, "Mystreet");
        if (ret) break;
        ret = dvSearch(dc, searchTerms, &foundVids);
        if (ret) break;
        li = ruListIter(foundVids);
        for(char* vd = ruIterNext(li, char*); li; vd = ruIterNext(li, char*)) {
            printf("found vid: '%s'\n", vd);
        }

        // wipe cache
        ret = dvWipe(dc, vids);
        if (ret) break;

        // delete data
        ret = dvDelete(dc, vids);
        if (ret) break;

        ret = dvDelete(dc, foundVids);
        if (ret) break;

    } while (false);

    if (namevid) free(namevid);
    if (addrvid) free(addrvid);
    if (vids) ruListFree(vids);
    if (indexTerms) ruListFree(indexTerms);
    if (searchTerms) ruListFree(searchTerms);
    if (foundVids) ruListFree(foundVids);
    if (data) ruMapFree(data);
    if (dc) dvFree(dc);
    if (kvs) ruFreeStore(kvs);
    if (a1) {
        printf("You will find debug logging in '%s'\n", logfile);
    }
    ruSinkCtxFree(rsc);

    return ret;
}
//! [DOXYGEN] end
