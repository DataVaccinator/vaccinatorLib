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

int main ( int argc, char **argv ) {
    int ret = RUE_OK;
    dvCtx dc = NULL;
    const char *name = "John Doe", *passwd = "mysecret";
    char *namevid = NULL;
    ruList vids = NULL;
    ruMap data = NULL;

    do {
        // setup
        ret = dvNew(&dc, PROVIDER_URL, APPID, NULL);
        if (ret != RUE_OK) break;

        // check for easy SSL mode
        if (ruStrEquals("1", ruGetenv("EASYSSL"))) {
            // disable certificate checks
            ret = dvSetProp(dc, DV_SKIP_CERT_CHECK, "1");
            if (ret) break;
        }

        // publish data
        int durationDays = 1;
        ret = dvPublish(dc, passwd, durationDays, name, &namevid);
        if (ret != RUE_OK) break;

        // retrieve data
        vids = ruListNew(NULL);
        ret = ruListAppend(vids, namevid);
        if (ret != RUE_OK) break;

        ret = dvGetPublished(dc, passwd, vids, &data);
        if (ret != RUE_OK) break;

        ruIterator li = ruListIter(vids);
        for(char *out, *vd = ruIterNext(li, char*); li;
            vd = ruIterNext(li, char*)) {
            ret = dvGetVid(data, vd, &out);
            if (ret != RUE_OK) break;
            printf("pid for vid: '%s' is: '%s'\n", vd, out);
        }
        ruMapFree(data);
        data = NULL;

    } while (false);

    if (namevid) free(namevid);
    if (vids) ruListFree(vids);
    if (data) ruMapFree(data);
    if (dc) dvFree(dc);
    return ret;
}
//! [DOXYGEN] end
