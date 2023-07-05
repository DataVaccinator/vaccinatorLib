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

START_TEST ( api ) {

    int32_t exp, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    dvCtx dc = NULL;
    const char *string = "string";
    char *strptr = NULL;
    ruList list = ruListNew(NULL);
    ruMap map = NULL;

    do {

        test = "dvNew";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvNew(NULL, PROVIDER_URL, APPID, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvNew(&dc, PROVIDER_URL, APPID, (KvStore*)string);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_OK;
        ret = dvNew(&dc, PROVIDER_URL, APPID, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvSetHeaderCb";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvSetHeaderCb(NULL, NULL, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvSetHeaderCb((dvCtx)string, NULL, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvSetPostCb";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvSetPostCb(NULL, NULL, (void *) string);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvSetPostCb((dvCtx)string, NULL, (void *) string);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvAddIndexWord";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvAddIndexWord(NULL, APPID, "ba");
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvAddIndexWord(&list, NULL, "ba");
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvAddIndexWord(&list, APPID, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvAddSearchWord";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvAddSearchWord(NULL, APPID, "ba");
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvAddSearchWord(&list, NULL, "ba");
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvAddSearchWord(&list, APPID, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvNew";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvSetProp(NULL, DV_SERVICE_URL, string);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvSetProp((dvCtx)string, DV_SERVICE_URL, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvSetProp((dvCtx)string, 99999, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);


        test = "dvAdd";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvAdd(NULL, string, NULL, &strptr);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvAdd(dc, NULL, NULL, &strptr);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvAdd(dc, string, NULL, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvAdd((dvCtx)string, string, NULL, &strptr);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvAdd(dc, string, (ruList)string, &strptr);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvUpdate";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvUpdate(NULL, string, string, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvUpdate(dc, NULL, string, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvUpdate(dc, string, NULL, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvUpdate((dvCtx)string, string, string, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvGet";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvGet(NULL, list, &map);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvGet(dc, NULL, &map);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvGet(dc, list, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvGet((dvCtx)string, list, &map);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvGet(dc, (ruList)string, &map);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvSearch";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvSearch(NULL, list, &list);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvSearch(dc, NULL, &list);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvSearch(dc, list, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvSearch((dvCtx)string, list, &list);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvSearch(dc, (ruList)string, &list);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvDelete";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvDelete(NULL, list);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvDelete(dc, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvDelete((dvCtx)string, list);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvDelete(dc, (ruList)string);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvWipe";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvWipe(NULL, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvWipe((dvCtx)string, list);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvWipe(dc, (ruList)string);
        fail_unless(exp == ret, retText, test, exp, ret);


    } while (false);

    if (strptr) free(strptr);
    if (list) ruListFree(list);
    if (map) ruMapFree(map);
    if (dc) dvFree(dc);

}
END_TEST

int32_t headerCb(void* usrCtx, dvSetHeaderFn headerFn, void* headerCtx) {
    return headerFn(headerCtx, "Cache-Control", "max-age=60");
}

int32_t postCb(void* usrCtx, dvSetPostFn postFn, void* postCtx) {
    if (!usrCtx) return 1;
    const char* user = "testuser";
    int32_t ret = postFn(postCtx, "username", (void*)user, strlen(user));
    if (ret) return ret;
    char* passwd = (char*) usrCtx;
    return postFn(postCtx, "password", (void*)passwd, strlen(passwd));
}

START_TEST ( run ) {

    int32_t exp, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    dvCtx dc = NULL;
    const char *foo = "foo", *bar = "bar", *passwd = "mysecret";
    char *fovid = NULL, *bavid = NULL;
    ruList vids = NULL, indexTerms = NULL, searchTerms = NULL,
        fndVids = NULL, fndVids2 = NULL;
    ruMap data = NULL;

    ck_assert_str_eq(myVersion, dvVersion());

    // setup
    exp = RUE_OK;
    test = "dvNew";
    ret = dvNew(&dc, PROVIDER_URL, APPID, NULL);
    fail_unless(exp == ret, retText, test, exp, ret);

    if (ruStrCmp("1", ruGetenv("EASYSSL")) == 0) {
        // disable certificate checks
        test = "dvSetProp";
        ret = dvSetProp(dc, DV_SKIP_CERT_CHECK, "1");
                fail_unless(exp == ret, retText, test, exp, ret);
    }

    test = "dvSetHeaderCb";
    ret = dvSetHeaderCb(dc, &headerCb, NULL);
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "dvSetPostCb";
    ret = dvSetPostCb(dc, &postCb, (void *) passwd);
    fail_unless(exp == ret, retText, test, exp, ret);

    // add data
    test = "dvAdd";
    ret = dvAdd(dc, foo, NULL, &fovid);
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "dvAddIndexWord";
    ret = dvAddIndexWord(&indexTerms, APPID, bar);
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "dvAdd";
    ret = dvAdd(dc, bar, indexTerms, &bavid);
    fail_unless(exp == ret, retText, test, exp, ret);

    // retrieve data
    vids = ruListNew(NULL);
    test = "ruListAppend";
    ret = ruListAppend(vids, fovid);
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "dvGet";
    ret = dvGet(dc, vids, &data);
    fail_unless(exp == ret, retText, test, exp, ret);

    ruIterator li = ruListIter(vids);
    test = "dvGetVid";
    for(char *out, *vd = ruIterNext(li, char*); li;
            vd = ruIterNext(li, char*)) {
        ret = dvGetVid(data, vd, &out);
        fail_unless(exp == ret, retText, test, exp, ret);
        ruVerbLogf("pid for vid: '%s' is: '%s'", vd, out);
        ck_assert_str_eq(foo, out);
    }
    ruMapFree(data);
    data = NULL;

    // search data
    test = "dvAddSearchWord";
    ret = dvAddSearchWord(&searchTerms, APPID, "ba");
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "dvSearch";
    ret = dvSearch(dc, searchTerms, &fndVids);
    fail_unless(exp == ret, retText, test, exp, ret);

    li = ruListIter(fndVids);
    for(char* vd = ruIterNext(li, char*); li; vd = ruIterNext(li, char*)) {
        ruVerbLogf("fndVids vid: '%s'", vd);
        ck_assert_str_ne(fovid, vd);
    }

    // replace search term
    char *t = ruListPop(indexTerms, NULL);
    ruFree(t);
    test = "dvAddIndexWord";
    ret = dvAddIndexWord(&indexTerms, APPID, foo);
    fail_unless(exp == ret, retText, test, exp, ret);

    // update and make searchable
    test = "dvUpdate";
    ret = dvUpdate(dc, fovid, bar, indexTerms);
    fail_unless(exp == ret, retText, test, exp, ret);

    // search updated data
    t = ruListPop(searchTerms, NULL);
    ruFree(t);
    test = "dvAddSearchWord";
    ret = dvAddSearchWord(&searchTerms, APPID, "fo");
    fail_unless(exp == ret, retText, test, exp, ret);
    test = "dvSearch";
    ret = dvSearch(dc, indexTerms, &fndVids2);
    fail_unless(exp == ret, retText, test, exp, ret);

    li = ruListIter(fndVids2);
    bool found = false;
    for(char* vd = ruIterNext(li, char*); li; vd = ruIterNext(li, char*)) {
        ruVerbLogf("fndVids2 vid: '%s'", vd);
        if (ruStrCmp(fovid, vd) == 0) found = true;
    }
    fail_unless(true == found, retText, test, true, found);

    // wipe cache
    test = "dvWipe";
    ret = dvWipe(dc, vids);
    fail_unless(exp == ret, retText, test, exp, ret);

    // delete data
    test = "dvDelete";
    ret = dvDelete(dc, vids);
    fail_unless(exp == ret, retText, test, exp, ret);

    // cleanup from the fndVids
    ret = dvDelete(dc, fndVids);
    fail_unless(exp == ret, retText, test, exp, ret);

    ret = dvDelete(dc, fndVids2);
    fail_unless(exp == ret, retText, test, exp, ret);


    if (fovid) free(fovid);
    if (bavid) free(bavid);
    if (vids) ruListFree(vids);
    if (indexTerms) ruListFree(indexTerms);
    if (fndVids) ruListFree(fndVids);
    if (fndVids2) ruListFree(fndVids2);
    if (data) ruMapFree(data);
    if (dc) dvFree(dc);

}
END_TEST

START_TEST ( publish ) {

    int32_t exp, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    dvCtx dc = NULL;
    const char *foo = "foo", *passwd = "mysecret";
    char *fovid = NULL;
    ruList vids = NULL;
    ruMap data = NULL;

    do {
        // setup
        exp = RUE_OK;
        test = "dvNew";
        ret = dvNew(&dc, PROVIDER_URL, APPID, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        if (ruStrCmp("1", ruGetenv("EASYSSL")) == 0) {
            // disable certificate checks
            test = "dvSetProp";
            ret = dvSetProp(dc, DV_SKIP_CERT_CHECK, "1");
                    fail_unless(exp == ret, retText, test, exp, ret);
        }
        // test publish API
        int durationDays = 1;
        test = "dvPublish";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvPublish(NULL, passwd, durationDays, foo, &fovid);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvPublish(dc, NULL, durationDays, foo, &fovid);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvPublish(dc, passwd, durationDays, NULL, &fovid);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvPublish(dc, passwd, durationDays, foo, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvPublish((dvCtx)passwd, passwd, durationDays, foo, &fovid);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvPublish(dc, passwd, -1, foo, &fovid);
        fail_unless(exp == ret, retText, test, exp, ret);

        // publish data
        exp = RUE_OK;
        ret = dvPublish(dc, passwd, durationDays, foo, &fovid);
        fail_unless(exp == ret, retText, test, exp, ret);

        // retrieve data
        vids = ruListNew(NULL);
        test = "ruListAppend";
        ret = ruListAppend(vids, fovid);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvGetPublished";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvGetPublished(NULL, passwd, vids, &data);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvGetPublished(dc, NULL, vids, &data);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvGetPublished(dc, passwd, NULL, &data);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvGetPublished(dc, passwd, vids, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_INVALID_PARAMETER;
        ret = dvGetPublished((dvCtx)passwd, passwd, vids, &data);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvGetPublished(dc, passwd, (ruList)passwd, &data);
        fail_unless(exp == ret, retText, test, exp, ret);

        exp = RUE_OK;
        ret = dvGetPublished(dc, passwd, vids, &data);
        fail_unless(exp == ret, retText, test, exp, ret);

        ruIterator li = ruListIter(vids);
        test = "dvGetVid";
        for(char *out, *vd = ruIterNext(li, char*); li;
            vd = ruIterNext(li, char*)) {
            ret = dvGetVid(data, vd, &out);
            fail_unless(exp == ret, retText, test, exp, ret);
            ruVerbLogf("pid for vid: '%s' is: '%s'", vd, out);
        }
        ruMapFree(data);
        data = NULL;

    } while (false);

    if (fovid) free(fovid);
    if (vids) ruListFree(vids);
    if (data) ruMapFree(data);
    if (dc) dvFree(dc);

}
END_TEST


TCase* vaccTests ( void ) {
    TCase *tcase = tcase_create("vacc");
    tcase_add_test(tcase, api);
    tcase_add_test(tcase, run);
    tcase_add_test(tcase, publish);
    return tcase;
}
