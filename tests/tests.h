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
#ifndef VACCINATOR_TESTS_H
#define VACCINATOR_TESTS_H

#define APPID "1Ha6xo2u{mRT18"

#ifndef PROVIDER_URL
#define PROVIDER_URL   "https://my.provider.com/dv"
#endif

#ifndef VAULT_ID
#define VAULT_ID   "42"
#endif

#ifndef VAULT_PW
#define VAULT_PW   "nosecret"
#endif

#ifndef CACHE_DIR
#define CACHE_DIR   ""
#endif

#include <vaccinator.h>
#include <check.h>
#include "../lib/lib.h"

// crypto.c
void hexify(trans_bytes ibuf, int ilen, alloc_bytes obuf);
int32_t getIv();
int32_t dvSha256(const char* str, char** hash);
void getPaddedEnd(const char* str, alloc_bytes last, rusize lastLen);



/* Only need to export C interface if used by C++ source code */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

TCase* cipherTests (void);
TCase* vaccTests (void);
TCase* cacheTests(void);
TCase* changeTests (void);

#ifdef __cplusplus
}   /* extern "C" */
#endif /* __cplusplus */

#endif //VACCINATOR_TESTS_H
