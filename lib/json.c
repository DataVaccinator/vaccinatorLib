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

int32_t jsonEncodeString(const char*input, char** output) {
    yajl_gen g;
    int stat;
    const uchar* buf;
    rusize olen;
    int32_t ret;

    if (!input || !output) return RUE_PARAMETER_NOT_SET;

    g = yajl_gen_alloc(NULL);
    if (!g) {
        ruCritLog("Failed to allocate yail generator");
        return RUE_OUT_OF_MEMORY;
    }
    do {
        stat = yajl_gen_config(g, yajl_gen_validate_utf8, 1);
        if (!stat) {
            ruCritLog("Failed to configure yail generator");
            ret = RUE_GENERAL;
            break;
        }
        stat = yajl_gen_string(g, (const uchar*)input,
                               strlen(input));
        if (stat != yajl_status_ok) {
            ruCritLogf("Failed to generate string [%s]", input);
            ret = RUE_GENERAL;
            break;
        }
        stat = yajl_gen_get_buf(g, &buf, &olen);
        if (stat != yajl_status_ok) {
            ruCritLogf("Failed to get encoded string. EC: %d", stat);
            ret = RUE_GENERAL;
            break;
        }
        *output = ruStrDup((const char*)buf);
        ret = RUE_OK;

    } while(false);

    if (g) yajl_gen_free(g);

    return ret;
}

yajl_val getJson(const char* json) {
    yajl_val node;
    char errbuf[1024];
    node = yajl_tree_parse((const char *) json, errbuf, sizeof(errbuf));
    /* parse error handling */
    if (node == NULL) {
        if (strlen(errbuf)) {
            dvSetError("parse_error: %s\nContent: %s", errbuf, json);
        } else {
            dvSetError("parse_error: unknown error\nContent: %s", json);
        }
        return NULL;
    }
    return node;
}

int32_t parseString(yajl_val node, const char* key, char** value) {
    const char * path[] = { key, (const char *) 0 };
    yajl_val v = yajl_tree_get(node, path, yajl_t_string);
    if (v) {
        *value = ruStrDup(YAJL_GET_STRING(v));
        ruVerbLogf("%s is %s" , key, *value);
        return RUE_OK;
    }
    ruCritLogf("no %s specified", key);
    return DVE_PROTOCOL_ERROR;
}

int32_t parseStatus(yajl_val node, bool* invalidRequest) {
    if (!node) return RUE_PARAMETER_NOT_SET;
    if (invalidRequest) *invalidRequest = true;

    const char *path[] = {STATUS, (const char *) 0};
    yajl_val v = yajl_tree_get(node, path, yajl_t_string);
    char *nodeValue = NULL; /* do not free */

    if (!v) {
        ruCritLog("no status specified");
        return DVE_PROTOCOL_ERROR;
    }
    nodeValue = YAJL_GET_STRING(v);
    if (ruStrCmp(STATUS_OK, nodeValue) == 0) {
        // status: OK
        return RUE_OK;
    }

    /* not ok get the error code */
    int32_t ret;
    path[0] = "code";
    v = yajl_tree_get(node, path, yajl_t_number);
    if (v) {
        ret = (int)YAJL_GET_INTEGER(v);
    } else {
        ruCritLog("status not ok and no ec set");
        ret = DVE_PROTOCOL_ERROR;
    }
    path[0] = "desc";
    v = yajl_tree_get(node, path, yajl_t_string);
    if (v) {
        char *desc = YAJL_GET_STRING(v);
        dvSetError(desc);
    }
    if (ruStrCmp(STATUS_INVALID, nodeValue) == 0) {
        ruVerbLogf("status was invalid. EC: %d", ret);
        if (invalidRequest) *invalidRequest = true;
        return ret;
    }
    if (ruStrCmp(STATUS_ERROR, nodeValue) != 0) {
        ruCritLogf("status was of unknown type: '%s'", nodeValue);
    }
    return ret;
}

int32_t parseVidData(uchar* key, yajl_val node, ruList vids, bool recode,
                     ruMap* data) {
    int32_t ret = RUE_OK;
    if (!node || !vids || !data) return RUE_PARAMETER_NOT_SET;

    ruVerbLog("Starting");
    const char * path[] = { "data", (const char *) 0 };
    yajl_val vd, dta = yajl_tree_get(node, path, yajl_t_object);
    if (!YAJL_IS_OBJECT(dta)) {
        ruWarnLog("response did not include data key");
        return DVE_PROTOCOL_ERROR;
    }

    char *msg = NULL;
    dvGetRes gr = NULL;
    ruIterator li = ruListIter(vids);
    for (char* vid = ruIterNext(li, char*); vid; vid = ruIterNext(li, char*)) {
        path[0] = vid;
        vd = yajl_tree_get(dta, path, yajl_t_object);
        if (!vd || !YAJL_IS_OBJECT(vd)) {
            ruWarnLogf("response did not include entry for '%s'", vid);
            continue;
        }
        char *nodeValue = NULL; /* do not free */
        yajl_val v;
        path[0] = STATUS;
        v = yajl_tree_get(vd, path, yajl_t_string);
        if (!v) {
            ruCritLogf("no status specified for entry '%s'", vid);
            ret = DVE_PROTOCOL_ERROR;
            break;
        }

        if (!*data) {
            *data = ruMapNewString(free, freeGetRes);
        }

        nodeValue = YAJL_GET_STRING(v);
        if (ruStrCmp(STATUS_NOT_FOUND, nodeValue) == 0) {
            ruVerbLogf("status for entry '%s' id not found", vid);
            ret = ruMapPut(*data, ruStrDup(vid),
                           newGetRes(NULL, RUE_FILE_NOT_FOUND));
            if (ret != RUE_OK) {
                ruCritLogf("failed adding entry '%s' to map", vid);
                break;
            }
            continue;
        }
        if (ruStrCmp(STATUS_OK, nodeValue) != 0) {
            ruWarnLogf("status for entry '%s' was '%s'", vid, nodeValue);
            ret = DVE_PROTOCOL_ERROR;
            break;
        }
        path[0] = "data";
        v = yajl_tree_get(vd, path, yajl_t_string);
        if (!v) {
            ruCritLogf("no data specified for entry '%s'", vid);
            continue;
        }

        char *cipher = YAJL_GET_STRING(v);
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

int32_t parseSearchData(yajl_val node, ruList* vids) {
    if (!node || !vids) return RUE_PARAMETER_NOT_SET;

    ruVerbLog("Starting");
    const char * path[] = { "vids", (const char *) 0 };
    yajl_val dta = yajl_tree_get(node, path, yajl_t_array);
    if (!YAJL_IS_ARRAY(dta)) {
        ruWarnLog("response did not include vids key");
        return DVE_PROTOCOL_ERROR;
    }
    ruVerbLogf("number of vids: %d" , (int)dta->u.array.len);
    int32_t ret = RUE_OK;
    for (uint i = 0; i < dta->u.array.len; i++) {
        yajl_val vid = dta->u.array.values[i];
        if (!YAJL_IS_STRING(vid)) {
            ruWarnLog("array entry was no string");
            continue;
        }
        if (!*vids) {
            *vids = ruListNew(free);
        }
        ret = ruListAppend(*vids, ruStrDup(YAJL_GET_STRING(vid)));
        if (ret != RUE_OK) {
            ruCritLogf("failed adding entry '%s' to map", vid);
            break;
        }
    }
    return ret;
}
