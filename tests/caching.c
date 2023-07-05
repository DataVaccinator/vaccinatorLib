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
#include "tests.h"

const char *test;
const char *retText = "%s failed wanted ret %d but got %d";

void verifyCacheSize(KvStore *kvs, uint32_t len) {
    // verify cache size to be len entries
    int32_t ret, exp = RUE_OK;
    ruList outList = NULL;

    test = "kvs->list";
    ret = kvs->list(kvs, "*", &outList);
    fail_unless(exp == ret, retText, test, exp, ret);
    test = "ruListSize";
    uint32_t sz = ruListSize(outList, &ret);
    fail_unless(exp == ret, retText, test, exp, ret);
    fail_unless(len == sz, retText, test, len, sz);
    if (outList) ruListFree(outList);
}

void* verifyMapSize(ruMap data) {
    // make sure we have 2 entries
    int32_t ret, exp = RUE_OK;
    uint32_t msz = ruMapSize(data, &ret);
    fail_unless(exp == ret, retText, test, exp, ret);
    fail_unless(2 == msz, retText, test, 2, msz);
    ruMapFree(data);
    return NULL;
}

START_TEST ( run ) {
    int32_t exp, ret;
    KvStore *kvs = NULL;
    dvCtx dc = NULL;
    const char *foo = "foo", *bar = "bar";
    char *fovid = NULL, *bavid = NULL;
    ruList vids = NULL, fovids = NULL;
    ruMap data = NULL;

    do {
        // create the storage folder
        if (!ruIsDir(CACHE_DIR)) {
            ret = ruMkdir(CACHE_DIR, 0755, false);
            if (!ruIsDir(CACHE_DIR)) {
                fprintf(stderr,"failed to create folder '%s' ec [%d]",
                        CACHE_DIR, ret);
                break;
            }
        }

        // setup
        exp = RUE_OK;
        test = "ruNewFileStore";
        kvs = ruNewFileStore(CACHE_DIR, &ret);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvNew";
        ret = dvNew(&dc, PROVIDER_URL, APPID, kvs);
        fail_unless(exp == ret, retText, test, exp, ret);

        if (ruStrCmp("1", ruGetenv("EASYSSL")) == 0) {
            // disable certificate checks
            test = "dvSetProp";
            ret = dvSetProp(dc, DV_SKIP_CERT_CHECK, "1");
            fail_unless(exp == ret, retText, test, exp, ret);
        }
        // start by testing the API
        test = "dvWipe";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvWipe(NULL, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);
        exp = RUE_INVALID_PARAMETER;
        ret = dvWipe(dc, (ruList)foo);
        fail_unless(exp == ret, retText, test, exp, ret);

        // remove all from cache in case of previous test failures
        exp = RUE_OK;
        ret = dvWipe(dc, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);
        verifyCacheSize(kvs, 0);

        // add data for 2 entries
        test = "dvAdd";
        ret = dvAdd(dc, foo, NULL, &fovid);
        fail_unless(exp == ret, retText, test, exp, ret);

        ret = dvAdd(dc, bar, NULL, &bavid);
        fail_unless(exp == ret, retText, test, exp, ret);
        verifyCacheSize(kvs, 2);

        // populate our request list
        vids = ruListNew(NULL);
        test = "ruListAppend";
        ret = ruListAppend(vids, fovid);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = ruListAppend(vids, bavid);
        fail_unless(exp == ret, retText, test, exp, ret);

        // get everything from cache
        test = "dvSetProp";
        ret = dvSetProp(dc, DV_SERVICE_URL, "");
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvGet";
        ret = dvGet(dc, vids, &data);
        fail_unless(exp == ret, retText, test, exp, ret);
        data = verifyMapSize(data);

        // remove fovid from cache
        fovids = ruListNew(NULL);
        test = "ruListAppend";
        ret = ruListAppend(fovids, fovid);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvWipe";
        ret = dvWipe(dc, fovids);
        fail_unless(exp == ret, retText, test, exp, ret);
        verifyCacheSize(kvs, 1);

        // get some from cache
        test = "dvSetProp";
        ret = dvSetProp(dc, DV_SERVICE_URL, PROVIDER_URL);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvGet";
        ret = dvGet(dc, vids, &data);
        fail_unless(exp == ret, retText, test, exp, ret);
        data = verifyMapSize(data);

        // remove all from cache
        test = "dvWipe";
        ret = dvWipe(dc, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);
        verifyCacheSize(kvs, 0);

        // get none from cache
        test = "dvGet";
        ret = dvGet(dc, vids, &data);
        fail_unless(exp == ret, retText, test, exp, ret);
        data = verifyMapSize(data);

        // clean up
        test = "dvDelete";
        ret = dvDelete(dc, vids);
        fail_unless(exp == ret, retText, test, exp, ret);

        // verify cache entries
        verifyCacheSize(kvs, 0);

    } while (false);

    if (fovid) free(fovid);
    if (bavid) free(bavid);
    if (vids) ruListFree(vids);
    if (fovids) ruListFree(fovids);
    if (data) ruMapFree(data);
    if (dc) dvFree(dc);
    if (kvs) ruFreeStore(kvs);

}
END_TEST

TCase* cacheTests ( void ) {
    TCase *tcase = tcase_create("caching");
    tcase_add_test(tcase, run);
    return tcase;
}
