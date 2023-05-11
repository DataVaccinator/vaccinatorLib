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

//! [DOXYGEN] start
#include <vaccinator.h>
#include <string.h>

// This index callback simply takes the first 8 characters of the data and
// adds it to the search index. This callback is required for dvChangeAppId if
// index terms are to be migrated. Its use elsewhere is optional.
int32_t indexCb (void *usrCtx, const char *vid, const char *data, ruList *indexWords) {
    // vid is passed in, so it is available should it be of use.
    // This example does not use it, though.
    #define startLen 8
    char termBuf[startLen + 1];
    const char* appId = (const char*) usrCtx;
    char* term = (char*) data;
    if (strlen(term) > startLen) {
        memcpy(termBuf, data, startLen);
        termBuf[startLen] = '\0';
        term = &termBuf[0];
    }
    // The actual index term is added to the list in this step.
    return dvAddIndexWord(indexWords, appId, term);
}

int main ( int argc, char **argv ) {
    int ret = RUE_OK;
    dvCtx dc = NULL;
    const char *name = "John Doe", *address = "Mystreet 42", *oldId = "old" APPID;
    char *namevid = NULL, *addrvid = NULL;
    ruList vids = NULL, indexTerms = NULL;
    ruMap vidMap = NULL;

    do {

        // setup
        ret = dvNew(&dc, PROVIDER_URL, oldId, NULL);
        if (ret != RUE_OK) break;
        // check for easy SSL mode
        if (ruStrCmp("1", ruGetenv("EASYSSL")) == 0) {
            // disable certificate checks
            ret = dvSetProp(dc, DV_SKIP_CERT_CHECK, "1");
            if (ret) break;
        }

        vids = ruListNew(NULL);

        // since we have a search callback let's use it to make our search term
        ret = indexCb((void *) oldId, NULL, name, &indexTerms);
        if (ret != RUE_OK) break;
        // add data
        ret = dvAdd(dc, name, indexTerms, &namevid);
        if (ret != RUE_OK) break;
        ret = ruListAppend(vids, namevid);
        if (ret != RUE_OK) break;
        if (indexTerms) {
            ruListFree(indexTerms);
            indexTerms = NULL;
        }

        ret = indexCb((void *) oldId, NULL, address, &indexTerms);
        if (ret != RUE_OK) break;
        ret = dvAdd(dc, address, indexTerms, &addrvid);
        if (ret != RUE_OK) break;
        ret = ruListAppend(vids, addrvid);
        if (ret != RUE_OK) break;
        if (indexTerms) {
            ruListFree(indexTerms);
            indexTerms = NULL;
        }

        // change appids
        ret = dvChangeAppId(dc, APPID, vids, &vidMap,
                            indexCb, APPID);
        if (ret != RUE_OK) break;
        // verify results
        bool hasErrors = false;
        ruIterator li = ruListIter(vids);
        for(char *out, *vd = ruIterNext(li, char*); li;
            vd = ruIterNext(li, char*)) {
            ret = dvGetVid(vidMap, vd, &out);
            if (ret == DVE_INVALID_CREDENTIALS) {
                printf("vid: '%s' was not decrypted needing the appid with checksum '%s'\n",
                       vd, out);
                hasErrors = true;
            } else if (ret != RUE_OK) {
                printf("vid: '%s' was not migrated with status: %d\n",
                       vd, ret);
                hasErrors = true;
            }
        }
        if (hasErrors) break;

        printf("Successfully converted all entries\n");
        // change to the new appid.
        ret = dvSetProp(dc, DV_APP_ID, APPID);
        if (ret != RUE_OK) break;

    } while (false);

    if (namevid) free(namevid);
    if (addrvid) free(addrvid);
    if (vids) ruListFree(vids);
    if (indexTerms) ruListFree(indexTerms);
    if (vidMap) ruMapFree(vidMap);
    if (dc) dvFree(dc);

    return ret;
}
//! [DOXYGEN] end
