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



int32_t indexCb (void *usrCtx, const char *vid, const char *data, ruList *indexWords) {
    #define startLen 8
    char termBuf[startLen + 1];
    const char* appId = (const char*) usrCtx;
    char* term = (char*) data;
    if (strlen(term) > startLen) {
        memcpy(termBuf, data, startLen);
        termBuf[startLen] = '\0';
        term = &termBuf[0];
    }
    ruVerbLogf("hashing term '%s' with id '%s'", term, appId);
    return dvAddIndexWord(indexWords, appId, term);
}

START_TEST ( api ) {

    int32_t exp, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    dvCtx dc = NULL;
    ruList vids = NULL;
    ruMap vidMap = NULL;

    do {
        // setup
        exp = RUE_OK;
        test = "dvNew";
        ret = dvNew(&dc, PROVIDER_URL, APPID, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

        test = "dvChangeAppId";
        exp = RUE_PARAMETER_NOT_SET;
        ret = dvChangeAppId(NULL, APPID, vids, &vidMap,
                            indexCb, APPID);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvChangeAppId(dc, NULL, vids, &vidMap,
                            indexCb, APPID);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvChangeAppId(dc, APPID, vids, NULL,
                            indexCb, APPID);
        fail_unless(exp == ret, retText, test, exp, ret);

        // test search API
        exp = RUE_OK;
        vids = ruListNew(NULL);
        ret = dvChangeAppId(dc, APPID, vids, &vidMap,
                            NULL, APPID);
        fail_unless(exp == ret, retText, test, exp, ret);
        ret = dvChangeAppId(dc, APPID, vids, &vidMap,
                            indexCb, NULL);
        fail_unless(exp == ret, retText, test, exp, ret);

    } while (false);

    if (vids) ruListFree(vids);
    if (vidMap) ruMapFree(vidMap);
    if (dc) dvFree(dc);
}
END_TEST

ruList search(dvCtx dc, const char* appId, const char* word, const char* searchvid) {
    int32_t exp = RUE_OK, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    ruList vids = NULL, searchTerms = NULL;
    // search remaining data
    test = "dvAddSearchWord";
    ret = dvAddSearchWord(&searchTerms, appId, word);
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "dvSearch";
    ret = dvSearch(dc, searchTerms, &vids);
    fail_unless(exp == ret, retText, test, exp, ret);

    // delete data
    test = "dvDelete";
    ret = dvDelete(dc, vids);
    fail_unless(exp == ret, retText, test, exp, ret);

    if (searchvid) {
        ruIterator li = ruListIter(vids);
        bool found = false;
        for (char *vd = ruIterNext(li, char*); li;
             vd = ruIterNext(li, char*)) {
            ruVerbLogf("searchvids vid: '%s'", vd);
            if (ruStrEquals(searchvid, vd)) found = true;
        }
        fail_unless(true == found, retText, test, true, found);
    }

    if (searchTerms) ruListFree(searchTerms);
    return vids;
}

void zapSearched(dvCtx dc, const char* appId, const char* word, const char* searchvid) {
    int32_t exp = RUE_OK, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    ruList vids = search(dc, appId, word, searchvid);

    // delete data
    test = "dvDelete";
    ret = dvDelete(dc, vids);
    fail_unless(exp == ret, retText, test, exp, ret);

    if (vids) ruListFree(vids);
}

char* addData(dvCtx dc, const char* appId, const char* pid, int line) {
    int32_t exp = RUE_OK, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    ruList indexTerms = NULL;
    char *vid = NULL;
    ruVerbLogf("appId:'%s' pid:'%s' line:%d", appId, pid, line);

    test = "dvSetProp";
    ret = dvSetProp(dc, DV_APP_ID, appId);
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "indexCb";
    ret = indexCb((void *) appId, NULL, pid, &indexTerms);
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "dvAdd";
    ret = dvAdd(dc, pid, indexTerms, &vid);
    fail_unless(exp == ret, retText, test, exp, ret);

    if (indexTerms) ruListFree(indexTerms);
    ruVerbLogf("vid:'%s' pid:'%s' line:%d", vid, pid, line);
    return vid;
}

void dochange(dvCtx dc, const char* appId, ruList vids, rusize cnt, const char* misvid,
              int line) {
    int32_t exp = RUE_OK, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    ruMap vidMap = NULL;
    ruVerbLogf("appId:'%s' cnt:%d mis:'%s' line:%d",
               appId, cnt, misvid, line);

    // swap ids
    test = "dvChangeAppId";
    ret = dvChangeAppId(dc, appId, vids, &vidMap,
                        indexCb, (void*)appId);
    fail_unless(exp == ret, retText, test, exp, ret);

    // verify map size
    test = "ruMapSize";
    rusize sz = ruMapSize(vidMap, &ret);
    fail_unless(exp == ret, retText, test, exp, ret);
    fail_unless(cnt == sz, retText, test, cnt, sz);

    ruIterator li = ruListIter(vids);
    test = "dvGetVid";
    for(char *out, *vd = ruIterNext(li, char*); li;
                    vd = ruIterNext(li, char*)) {
        ret = dvGetVid(vidMap, vd, &out);
        ruVerbLogf("vid: '%s' data: '%s' status: %d", vd, out, ret);
        if (ruStrEquals(misvid, vd)) {
            exp = DVE_INVALID_CREDENTIALS;
            fail_unless(exp == ret, retText, test, exp, ret);
            fail_unless(NULL == out, retText, test, NULL, out);
        } else {
            exp = RUE_OK;
            fail_unless(exp == ret, retText, test, exp, ret);
            fail_unless(NULL == out, retText, test, NULL, out);
        }
    }
    ruMapFree(vidMap);
    vidMap = NULL;
}

void getdata(dvCtx dc, const char* vid, const char* pid) {
    int32_t exp = RUE_OK, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    ruMap vidMap = NULL;

    ruList fovids = ruListNew(NULL);
    test = "ruListAppend";
    ret = ruListAppend(fovids, vid);
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "dvGet";
    ret = dvGet(dc, fovids, &vidMap);
    fail_unless(exp == ret, retText, test, exp, ret);

    ruIterator li = ruListIter(fovids);
    test = "dvGetVid";
    for(char *out, *vd = ruIterNext(li, char*); li;
        vd = ruIterNext(li, char*)) {
        ret = dvGetVid(vidMap, vd, &out);
        fail_unless(exp == ret, retText, test, exp, ret);
        ruVerbLogf("pid for vid: '%s' is: '%s'", vd, out);
        ck_assert_str_eq(pid, out);
    }
    ruMapFree(vidMap);
    vidMap = NULL;
}

START_TEST ( change ) {
    int32_t exp, ret;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";
    const char *foo = "foo", *bar = "bar", *mis = "mis",
    *oldId = "old" APPID "26", *badId = "bad" APPID "42";
    char *fovid = NULL, *bavid = NULL, *misvid = NULL;
    dvCtx dc = NULL;
    ruList vids = NULL;

    // setup
    exp = RUE_OK;
    test = "dvNew";
    ret = dvNew(&dc, PROVIDER_URL, oldId, NULL);
    fail_unless(exp == ret, retText, test, exp, ret);

    if (ruStrEquals("1", ruGetenv("EASYSSL"))) {
        // disable certificate checks
        test = "dvSetProp";
        ret = dvSetProp(dc, DV_SKIP_CERT_CHECK, "1");
                fail_unless(exp == ret, retText, test, exp, ret);
    }
    // -----------------------------------------------------------------
    // bad one in the middle
    vids = ruListNew(NULL);
    // add data
    fovid = addData(dc, oldId, foo, __LINE__);
    ret = ruListAppend(vids, fovid);

    // bork the appid
    misvid = addData(dc, badId, mis, __LINE__);
    ret = ruListAppend(vids, misvid);

    // reset the appid
    bavid = addData(dc, oldId, bar, __LINE__);
    ret = ruListAppend(vids, bavid);

    // 1 should fail
    dochange(dc, APPID, vids, 3, misvid, __LINE__);

    // update the appid
    exp = RUE_OK;
    test = "dvSetProp";
    ret = dvSetProp(dc, DV_APP_ID, APPID);
    fail_unless(exp == ret, retText, test, exp, ret);

    // retrieve data
    getdata(dc, fovid, foo);
    getdata(dc, bavid, bar);

    zapSearched(dc, APPID, "Ba", bavid);
    zapSearched(dc, badId, "mi", NULL);
    zapSearched(dc, APPID, "FO", NULL);
    if (vids) { ruListFree(vids); vids = NULL; }
    ruFree(fovid);
    ruFree(bavid);
    ruFree(misvid);

    // -----------------------------------------------------------------
    // bad one at the end
    // set the old appid
    exp = RUE_OK;
    test = "dvSetProp";
    ret = dvSetProp(dc, DV_APP_ID, oldId);
    fail_unless(exp == ret, retText, test, exp, ret);

    vids = ruListNew(NULL);

    // add data
    fovid = addData(dc, oldId, foo, __LINE__);
    ret = ruListAppend(vids, fovid);

    // reset the appid
    bavid = addData(dc, oldId, bar, __LINE__);
    ret = ruListAppend(vids, bavid);

    // add another
    misvid = addData(dc, badId, mis, __LINE__);
    ret = ruListAppend(vids, misvid);

    // fix side effect of addData
    test = "dvSetProp";
    ret = dvSetProp(dc, DV_APP_ID, oldId);
    fail_unless(exp == ret, retText, test, exp, ret);

    // 2 should work
    dochange(dc, APPID, vids, 3, misvid, __LINE__);

    // update the appid
    exp = RUE_OK;
    test = "dvSetProp";
    ret = dvSetProp(dc, DV_APP_ID, APPID);
    fail_unless(exp == ret, retText, test, exp, ret);

    // retrieve data
    getdata(dc, fovid, foo);
    getdata(dc, bavid, bar);

    zapSearched(dc, APPID, "Ba", bavid);
    zapSearched(dc, APPID, "FO", NULL);
    zapSearched(dc, badId, "mi", NULL);
    if (vids) { ruListFree(vids); vids = NULL; }
    ruFree(fovid);
    ruFree(bavid);
    ruFree(misvid);

    // -----------------------------------------------------------------
    // rerun with added
    // set the old appid
    exp = RUE_OK;
    test = "dvSetProp";
    ret = dvSetProp(dc, DV_APP_ID, oldId);
    fail_unless(exp == ret, retText, test, exp, ret);

    vids = ruListNew(NULL);

    // add data
    fovid = addData(dc, oldId, foo, __LINE__);
    ret = ruListAppend(vids, fovid);

    // reset the appid
    bavid = addData(dc, oldId, bar, __LINE__);
    ret = ruListAppend(vids, bavid);

    // all should work
    dochange(dc, APPID, vids, 2, NULL, __LINE__);

    // add another
    misvid = addData(dc, oldId, mis, __LINE__);
    ret = ruListAppend(vids, misvid);

    // all should work again
    dochange(dc, APPID, vids, 3, NULL, __LINE__);

    // update the appid
    exp = RUE_OK;
    test = "dvSetProp";
    ret = dvSetProp(dc, DV_APP_ID, APPID);
    fail_unless(exp == ret, retText, test, exp, ret);

    // retrieve data
    getdata(dc, fovid, foo);
    getdata(dc, bavid, bar);
    getdata(dc, misvid, mis);

    zapSearched(dc, APPID, "Ba", bavid);
    zapSearched(dc, APPID, "FO", NULL);
    zapSearched(dc, APPID, "mi", NULL);
    if (vids) { ruListFree(vids); vids = NULL; }
    ruFree(fovid);
    ruFree(bavid);
    ruFree(misvid);
}
END_TEST


TCase* changeTests ( void ) {
    TCase *tcase = tcase_create("change");
    tcase_add_test(tcase, api);
    tcase_add_test(tcase, change);
    return tcase;
}
