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

START_TEST ( run ) {

    int32_t ret, exp;
    const char *test;
    const char *retText = "%s failed wanted ret %d but got %d";

    test = "dvSha256";
    exp = RUE_OK;
    char *out = NULL;
    char *want = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
    ret = dvSha256("foo", &out);
    fail_unless(exp == ret, retText, test, exp, ret);
    ck_assert_str_eq(want, out);
    ruFree(out);

    #define cipherBufLen 64
    uchar cipher[cipherBufLen];
    uchar hex[cipherBufLen * 2];

    // pkcs#7 padding
    const char* str = "";
    want = "10101010101010101010101010101010";
    getPaddedEnd(str, cipher, cipherBufLen);
    memset(hex, 0, cipherBufLen);
    hexify(cipher, BLOCKSIZE, &hex[0]);
    ck_assert_str_eq(want, (const char*)hex);

    str = "123";
    want = "3132330d0d0d0d0d0d0d0d0d0d0d0d0d";
    getPaddedEnd(str, cipher, cipherBufLen);
    memset(hex, 0, cipherBufLen);
    hexify(cipher, BLOCKSIZE, &hex[0]);
//    ruVerbLogf("padding of: '%s' is: '%s'", str, hex);
    ck_assert_str_eq(want, (const char*)hex);

    str = "1234567890123456";
    want = "10101010101010101010101010101010";
    getPaddedEnd(str, cipher, cipherBufLen);
    memset(hex, 0, cipherBufLen);
    hexify(cipher, BLOCKSIZE, &hex[0]);
    ck_assert_str_eq(want, (const char*)hex);

    // post normal
    const char* appId = APPID;
    uchar key[32];
    char* cs = NULL;
    test = "mkKey";
    ret = mkKey(appId, key, &cs);
    fail_unless(exp == ret, retText, test, exp, ret);

    str = "123";
    test = "dvAes256Enc";
    ret = dvAes256Enc(key, cs, str, &out);
    fail_unless(exp == ret, retText, test, exp, ret);

    char *msg = NULL;
    test = "dvAes256Dec";
    ret = dvAes256Dec(key, out, &msg, NULL);
    fail_unless(exp == ret, retText, test, exp, ret);
    ck_assert_str_eq(str, msg);

    ruFree(msg);
    ruFree(out);

    // publish
    cs = NULL;
    test = "mkKey";
    ret = mkKey(appId, key, NULL);
    fail_unless(exp == ret, retText, test, exp, ret);

    test = "dvAes256Enc";
    ret = dvAes256Enc(key, cs, str, &out);
    fail_unless(exp == ret, retText, test, exp, ret);
//    ruVerbLogf("recipe: '%s'", out);

    msg = NULL;
    test = "dvAes256Dec";
    ret = dvAes256Dec(key, out, &msg, NULL);
    fail_unless(exp == ret, retText, test, exp, ret);
//    ruVerbLogf("data: '%s'", msg);
    ck_assert_str_eq(str, msg);
    ruFree(msg);
    ruFree(out);

    // intentionally freezing the appid here, because changing it screws up the
    // test results
    appId = "1Ha6xo2u{mRT18";
    const char* search = "0";
    test = "dvSearchHash";
    bool indexing = true;
    exp = RUE_PARAMETER_NOT_SET;
    ret = dvSearchHash(NULL, appId, &out, indexing);
    fail_unless(exp == ret, retText, test, exp, ret);
    ret = dvSearchHash(search, NULL, &out, indexing);
    fail_unless(exp == ret, retText, test, exp, ret);
    ret = dvSearchHash(search, appId, NULL, indexing);
    fail_unless(exp == ret, retText, test, exp, ret);

    exp = RUE_INVALID_PARAMETER;
    ret = dvSearchHash("", appId, &out, indexing);
    fail_unless(exp == ret, retText, test, exp, ret);
    ret = dvSearchHash(search, "", &out, indexing);
    fail_unless(exp == ret, retText, test, exp, ret);
    ret = dvSearchHash("", appId, &out, indexing);
    fail_unless(exp == ret, retText, test, exp, ret);

    char *iwd = NULL, *swd = NULL;
    exp = RUE_OK;
    search = "123";
    ret = dvSearchHash(search, appId, &iwd, true);
    fail_unless(exp == ret, retText, test, exp, ret);
    want = "c27e33eb6af51f8fecc753ce2568a578";
    ck_assert_str_eq(want, iwd);
    ret = dvSearchHash(search, appId, &swd, false);
    fail_unless(exp == ret, retText, test, exp, ret);
    want = "c27e33";
    ck_assert_str_eq(want, swd);
    ruFree(iwd);
    ruFree(swd);

    search = "1234567890123456";
    ret = dvSearchHash(search, appId, &iwd, true);
    fail_unless(exp == ret, retText, test, exp, ret);
    want = "c27e3389c9b07005613f5fa83b2cbbba";
    ck_assert_str_eq(want, iwd);
    ret = dvSearchHash(search, appId, &swd, false);
    fail_unless(exp == ret, retText, test, exp, ret);
    want = "c27e3389c9b07005613f5fa83b2cbbba";
    ck_assert_str_eq(want, swd);
    ruFree(iwd);
    ruFree(swd);

    search = "12345678901234567";
    ret = dvSearchHash(search, appId, &iwd, true);
    fail_unless(exp == ret, retText, test, exp, ret);
    want = "c27e3389c9b07005613f5fa83b2cbbba8a6f93b99dcd92a63e028a9da3201db3";
    ck_assert_str_eq(want, iwd);
    ret = dvSearchHash(search, appId, &swd, false);
    fail_unless(exp == ret, retText, test, exp, ret);
    want = "c27e3389c9b07005613f5fa83b2cbbba8a";
    ck_assert_str_eq(want, swd);
    ruFree(iwd);
    ruFree(swd);

}
END_TEST


TCase* cipherTests (void) {
    TCase *tcase = tcase_create("cipher");
    tcase_add_test(tcase, run);
    return tcase;
}
