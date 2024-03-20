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

ruJson getJson(trans_chars json) {
    int32_t ret;
    ruJson jsn = ruJsonParse(json, &ret);
    if (ret != RUE_OK) {
        dvSetError(ruLastError());
    }
    return jsn;
}

int32_t parseStatus(ruJson jsn, bool* invalidRequest) {
    int32_t ret = RUE_PARAMETER_NOT_SET;
    if (!jsn) return ret;
    if (invalidRequest) *invalidRequest = true;

    perm_chars strVal = ruJsonKeyStr(jsn, STATUS, &ret);
    if (!strVal) {
        ruCritLog("no status specified");
        return DVE_PROTOCOL_ERROR;
    }
    if (ruStrEquals(STATUS_OK, strVal)) {
        // status: OK
        return RUE_OK;
    }

    /* not ok get the error code */
    int32_t code = (int32_t)ruJsonKeyInt(jsn, "code", &ret);
    if (ret != RUE_OK) {
        ruCritLog("status not ok and no ec set");
        ret = DVE_PROTOCOL_ERROR;
    } else {
        ret = code;
    }
    perm_chars desc = ruJsonKeyStr(jsn, "desc", NULL);
    if (desc) {
        dvSetError(desc);
    }
    if (ruStrEquals(STATUS_INVALID, strVal)) {
        ruVerbLogf("status was invalid. EC: %d", ret);
        if (invalidRequest) *invalidRequest = true;
        return ret;
    }
    if (ruStrEquals(STATUS_ERROR, strVal)) {
        ruCritLogf("status was of unknown type: '%s'", strVal);
    }
    return ret;
}

int32_t parseVidData(alloc_bytes key, ruJson jsn, ruList vids, bool recode,
                     ruMap* data) {
    int32_t ret = RUE_OK;
    if (!jsn || !vids || !data) return RUE_PARAMETER_NOT_SET;

    ruVerbLog("Starting");
    ruJson jdat = ruJsonKeyMap(jsn, "data", NULL);
    if (!jdat) {
        ruWarnLog("response did not include data key");
        return DVE_PROTOCOL_ERROR;
    }

    char *msg = NULL;
    dvGetRes gr = NULL;
    ruIterator li = ruListIter(vids);
    for (char* vid = ruIterNext(li, char*); vid; vid = ruIterNext(li, char*)) {
        ruJson jvd = ruJsonKeyMap(jdat, vid, NULL);
        if (!jvd) {
            ruWarnLogf("response did not include entry for '%s'", vid);
            continue;
        }
        perm_chars nodeValue = ruJsonKeyStr(jvd, STATUS, NULL);
        if (!nodeValue) {
            ruCritLogf("no status specified for entry '%s'", vid);
            ret = DVE_PROTOCOL_ERROR;
            break;
        }

        if (!*data) {
            *data = ruMapNew(ruTypeStrFree(),
                                 ruTypePtr(freeGetRes));
        }

        if (ruStrEquals(STATUS_NOT_FOUND, nodeValue)) {
            ruVerbLogf("status for entry '%s' id not found", vid);
            ret = ruMapPut(*data, ruStrDup(vid),
                           newGetRes(NULL, RUE_FILE_NOT_FOUND));
            if (ret != RUE_OK) {
                ruCritLogf("failed adding entry '%s' to map", vid);
                break;
            }
            continue;
        }
        if (!ruStrEquals(STATUS_OK, nodeValue)) {
            ruWarnLogf("status for entry '%s' was '%s'", vid, nodeValue);
            ret = DVE_PROTOCOL_ERROR;
            break;
        }

        perm_chars cipher = ruJsonKeyStr(jvd, "data", NULL);
        if (!cipher) {
            ruCritLogf("no data specified for entry '%s'", vid);
            continue;
        }
        gr = NULL;
        char rcs[3];
        memset(rcs, 0, sizeof(rcs));
        msg = NULL;
        ret = dvAes256Dec(key, cipher, &msg, &rcs[0]);
        if (ret == DVE_INVALID_CREDENTIALS) {
            if (recode) {
                // store the checksum
                gr = newGetRes(ruStrDup(&rcs[0]), ret);
            } else {
                gr = newGetRes(NULL, ret);
            }
        } else {
            if (ret != RUE_OK) {
                ruWarnLogf("failed decrypting entry '%s' ec: %d", vid, ret);
                break;
            }
            gr = newGetRes(msg, RUE_OK);
            msg = NULL;
        }
        ruFree(msg);
        ret = ruMapPut(*data, ruStrDup(vid), gr);
        if (ret != RUE_OK) {
            ruCritLogf("failed adding entry '%s' to map", vid);
            break;
        }
        gr = NULL;
    }

    // clean up
    if (gr) freeGetRes(gr);
    ruFree(msg);
    if (ret != RUE_OK) {
        if(*data) {
            ruMapFree(*data);
            *data = NULL;
        }
    }

    return ret;
}

int32_t parseSearchData(ruJson jsn, ruList* vids) {
    if (!jsn || !vids) return RUE_PARAMETER_NOT_SET;

    ruVerbLog("Starting");
    ruJson jvids = ruJsonKeyArray(jsn, "vids", NULL);
    if (!jvids) {
        ruWarnLog("response did not include vids key");
        return DVE_PROTOCOL_ERROR;
    }
    rusize i, last = ruJsonArrayLen(vids, NULL);
    ruVerbLogf("number of vids: %d" , (int)last);
    int32_t ret = RUE_OK;
    for (i = 0; i < last; i++) {
        perm_chars vid = ruJsonIdxStr(vids, i, NULL);
        if (!vid) {
            ruWarnLog("array entry was no string");
            continue;
        }
        if (!*vids) {
            *vids = ruListNew(ruTypeStrFree());
        }
        ret = ruListAppend(*vids, ruStrDup(vid));
        if (ret != RUE_OK) {
            ruCritLogf("failed adding entry '%s' to list", vid);
            break;
        }
    }
    return ret;
}
