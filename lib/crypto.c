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
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

void getPaddedEnd(const char* str, alloc_bytes last, rusize lastLen);

static int32_t ascii2uc (const char c, alloc_bytes uc) {
    if( ( c >= '0' ) && ( c <= '9' ) )
        *uc = c - '0';
    else if( ( c >= 'a' ) && ( c <= 'f' ) )
        *uc = c - 'a' + 10;
    else if( ( c >= 'A' ) && ( c <= 'F' ) )
        *uc = c - 'A' + 10;
    else
        return RUE_INVALID_PARAMETER;
    return RUE_OK;
}

static int32_t unhexify(const char *str, size_t *neededLen,
                        size_t oLen, alloc_bytes oPtr) {
    uint8_t uc, uc2;
    int32_t ret;
    *neededLen = strlen(str );

    /* Must be even number of bytes. */
    if (( *neededLen ) & 1 ) {
        return RUE_INVALID_PARAMETER;
    }
    *neededLen /= 2;

    if ((*neededLen) > oLen ) {
        return RUE_OUT_OF_MEMORY;
    }

    while (*str != 0) {
        ret = ascii2uc(*(str++), &uc);
        if (ret != RUE_OK) return ret;

        ret = ascii2uc(*(str++), &uc2);
        if (ret != RUE_OK) return ret;

        *(oPtr++) = ( uc << 4 ) | uc2;
    }
    return RUE_OK;
}

static int sha256(const char* str, rusize len, alloc_bytes digest) {
    return mbedtls_sha256((alloc_bytes)str, len, digest,0);
}

static int32_t mkIv(alloc_bytes iv, rusize len) {
    if (len < BLOCKSIZE) return RUE_OUT_OF_MEMORY;
    if (!iv) return RUE_PARAMETER_NOT_SET;

    // we just use a timestamp and a counter in case we're really quick
    static uint32_t threadcounter = 0;
    ruTimeVal now;
    const char* seedForm = "%010u.%05u.%03u";
    // seedlen '1650466778.042061.001'
    //         0----5----0----5----0-2 22 with \0
    #define seedLen 22
    char seed[seedLen];
    // just enough room here
    uint8_t digest[MBEDTLS_MD_MAX_SIZE];

    ruGetTimeVal(&now);
    threadcounter = (threadcounter + 1) % 1000;
    snprintf(&seed[0], seedLen, seedForm,
             now.sec, now.usec, threadcounter);
//    ruVerbLogf("seed: %s", seed);

    int r = mbedtls_sha256((alloc_bytes) seed, strlen(seed),
                           digest , 0);
    if (r) {
        dvSetError("Failed getting digest. PSA status: %d", r);
        return RUE_GENERAL;
    }
    memcpy(iv, digest, BLOCKSIZE);
    return RUE_OK;
}

static int32_t dvB64Decode(const char* b64, alloc_bytes* data, rusize* len) {
    if (!b64 || !data || !len) return RUE_PARAMETER_NOT_SET;

    size_t dlen = 0, olen = 0, ilen = strlen(b64);

    int r = mbedtls_base64_decode(NULL, dlen, &olen,
                                  (trans_bytes)b64, ilen);
    if (r != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        dvSetError("mbedtls_base64_decode returned %d instread of %d",
                   r, MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL);
        return RUE_GENERAL;
    }
    dlen = olen;
    alloc_bytes out = ruMalloc0(dlen, uint8_t);
    r = mbedtls_base64_decode((alloc_bytes)out, dlen, &olen,
                              (trans_bytes)b64, ilen);
    if (r) {
        dvSetError("mbedtls_base64_decode failed: %d", r);
        ruFree(out);
        return RUE_GENERAL;
    }
    *data = out;
    *len = dlen;
    return RUE_OK;
}

static int32_t aesEnc(trans_bytes key, const char* str, alloc_bytes startIv, alloc_bytes cipher,
               int32_t* outLen) {
    int32_t len = (int32_t)strlen(str);
    int32_t blocks = len / BLOCKSIZE;
    int32_t outsz = (blocks+1) * BLOCKSIZE + MACSIZE;
    if (*outLen < outsz) {
        *outLen = outsz;
        return RUE_OUT_OF_MEMORY;
    }
    uint8_t mac[MACSIZE];
    uint8_t iv[BLOCKSIZE];
    uint8_t last[BLOCKSIZE];
    mbedtls_aes_context ac;

    getPaddedEnd(str, last, sizeof(last));
    int r, ret = RUE_GENERAL;

    r = mkIv(iv, BLOCKSIZE);
    if (r != RUE_OK) return r;
    memcpy(startIv, iv, BLOCKSIZE);

    alloc_bytes out = cipher;
    do {
        r = sha256(str, strlen(str), mac);
        if (r) {
            dvSetError("Failed getting mac. PSA status: %d", r);
            ret = RUE_GENERAL;
            break;
        }

        mbedtls_aes_init(&ac);

        r = mbedtls_aes_setkey_enc(&ac, key, KEYBITS);
        if (r) {
            dvSetError("Failed setting crypto key. EC: %d", r);
            ret = RUE_GENERAL;
            break;
        }
        r = mbedtls_aes_crypt_cbc(&ac, MBEDTLS_AES_ENCRYPT,
                                  blocks * BLOCKSIZE, iv,
                                  (trans_bytes)str, out);
        if (r) {
            dvSetError("Failed encrypting the payload. EC: %d", r);
            ret = RUE_GENERAL;
            break;
        }
        out += (blocks * BLOCKSIZE);
        r = mbedtls_aes_crypt_cbc(&ac, MBEDTLS_AES_ENCRYPT,
                                  BLOCKSIZE, iv,
                                  last, out);
        if (r) {
            dvSetError("Failed encrypting the last block. EC: %d", r);
            ret = RUE_GENERAL;
            break;
        }

        out += BLOCKSIZE;
        r = mbedtls_aes_crypt_cbc(&ac, MBEDTLS_AES_ENCRYPT,
                                  MACSIZE, iv,
                                  mac, out);
        if (r) {
            dvSetError("Failed encrypting the mac blocks. EC: %d", r);
            ret = RUE_GENERAL;
            break;
        }
        // all good
        ret = RUE_OK;
    } while (false);

    mbedtls_aes_free(&ac);
    return ret;
}

static int32_t aesDec(trans_bytes key, trans_bytes cipher, rusize cipherLen,
               alloc_bytes startIv, char** text) {

    if (!key || !cipher || !cipherLen || !startIv || !text) {
        return RUE_PARAMETER_NOT_SET;
    }

    int r, ret = RUE_GENERAL;
    mbedtls_aes_context ac;
    uint8_t mac[MACSIZE];

    // free
    alloc_bytes out = NULL;

    do {
        // setup
        mbedtls_aes_init(&ac);
        r = mbedtls_aes_setkey_dec(&ac, key, KEYBITS);
        if (r) {
            dvSetError("Failed setting crypto key. EC: %d", r);
            ret = RUE_GENERAL;
            break;
        }
        // decrypt
        out = ruMalloc0(cipherLen, uint8_t);
        r = mbedtls_aes_crypt_cbc(&ac, MBEDTLS_AES_DECRYPT,
                                  cipherLen, startIv,
                                  cipher, out);
        if (r) {
            dvSetError("Failed decrypting the payload. EC: %d", r);
            ret = RUE_GENERAL;
            break;
        }
        // get mac start
        alloc_bytes cmac = out + cipherLen - MACSIZE;
        // strip padding
        alloc_bytes ptr = cmac-1;
        uint8_t pad = *ptr;
        if (pad > 16) {
            dvSetError("Invalid padding after decryption");
            ret = DVE_INVALID_CREDENTIALS;
            break;
        }
        while (pad) {
            pad--;
            *ptr = '\0';
            ptr--;
        }
        // calculate mac
        r = sha256((const char*)out, strlen((const char*)out), mac);
        if (r) {
            dvSetError("Failed getting mac. PSA status: %d", r);
            ret = RUE_GENERAL;
            break;
        }
        // check mac
        if (memcmp(mac, cmac, MACSIZE) != 0) {
            dvSetError("MAC mismatch");
            ret = DVE_INVALID_CREDENTIALS;
            break;
        }
        // all good
        *text = (char*)out;
        out = NULL;
        ret = RUE_OK;
    } while (false);

    ruFree(out);
    mbedtls_aes_free(&ac);
    return ret;
}

void hexify(trans_bytes ibuf, int ilen, alloc_bytes obuf) {
    uint8_t l, h;

    while(ilen != 0 ) {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 ) {
            *obuf++ = '0' + h;
        } else {
            *obuf++ = 'a' + h - 10;
        }

        if( l < 10 ) {
            *obuf++ = '0' + l;
        } else {
            *obuf++ = 'a' + l - 10;
        }

        ++ibuf;
        ilen--;
    }
}

int32_t dvSearchHash(const char* word, const char* key, char** hash, bool indexing) {
    if (!word || !key || !hash) return RUE_PARAMETER_NOT_SET;

    char* term = ruUtf8ToLower(word);
    rusize termLen = strlen(term);
    rusize keyLen = strlen(key);

    if (!termLen || !keyLen) {
        ruFree(term);
        return RUE_INVALID_PARAMETER;
    }

    int d = 0;
    // integer and our return code as needed
    int32_t ret;
    // need room 4  char + hash +  key   + \0
    rusize poolSz =   1  +  64  + keyLen +  1;
    // our work area
    char *work = ruMalloc0(poolSz, char);
    // initial hash and running encoded hash
    char *sha = "f1748e9819664b324ae079a9ef22e33e9014ffce302561b9bf71a37916c1d2a3";
    uint8_t sha2[32];
    uint8_t encHash[65];
    memcpy((void*)&encHash[0], sha, 65);

    // term is padded to the next 16 byte boundary
    rusize paddedLen = (termLen/16) * 16;
    // unless we were mod 0 we'll have to append
    if (paddedLen < termLen) paddedLen += 16;
    // output is double paddedLen for hex encoding + terminator
    rusize outLen = (paddedLen * 2) + 1;
    // where our result goes
    char* outHash = ruMalloc0(outLen, char);

    char *ptr = (char*)term;
    char *optr = outHash;

    if (d) ruVerbLogf("term: '%s' key: '%s'", term, key);

    char *work2 = work + 1;
    rusize poolSz2 = poolSz - 1;
    rusize c = 0;

    do {
        uint8_t digest[32];
        // separating the character out to allow hashing \0
        *work = *ptr;
        snprintf(work2, poolSz2, "%s%s", &encHash[0], key);
        if (d) ruVerbLogf("work: %x + '%s'", (uint8_t)*work, work2);
        ret = sha256(work, poolSz, digest);
        if (ret) {
            dvSetError("Failed getting digest. PSA status: %d", ret);
            ret = RUE_GENERAL;
            break;
        }
        if (indexing && c == 0) {
            // this is the first character so copy the digest for our random padding
            memcpy(sha2, digest, 32);
        }
        hexify((trans_bytes) &digest[0], 32, &encHash[0]);
        encHash[64] = '\0';
        if (d) ruVerbLogf("hash: ' %s '", encHash);
        memcpy(optr, encHash, 2);
        ptr++;
        optr += 2;
        if (c == termLen) {
            // move our pointer to continue with the sha after the terminator
            ptr = (char*)&sha2[0];
        }
        c++;
        // if we're searching no need for padding
        if (!indexing && c == termLen) break;
    } while(c < paddedLen);

    if (ret == RUE_OK) {
        *hash = outHash;
        outHash = NULL;
    }
    ruFree(term);
    ruFree(work);
    ruFree(outHash);

    return ret;
}

int32_t dvSha256(const char* str, char** hash) {
    uint8_t digest[32];
    dvClearError();
    if (!str || !hash) return RUE_PARAMETER_NOT_SET;

    int r = sha256(str, strlen(str), digest);
    if (r) {
        dvSetError("Failed getting digest. PSA status: %d", r);
        return RUE_GENERAL;
    }
    *hash = ruMalloc0(65, char);
    hexify((trans_bytes) &digest[0], 32, (alloc_bytes ) *hash);
    return RUE_OK;
}

int32_t getCs(const char* appId, rusize idLen, char** csStart) {
    if (!appId || !idLen || !csStart) return RUE_PARAMETER_NOT_SET;
    if (idLen < MIN_APPID_LEN) {
        dvSetError("App-Id length must at least be %d but only is %d",
                   MIN_APPID_LEN, idLen);
        return RUE_INVALID_PARAMETER;
    }
    *csStart = (char*)(appId + idLen - 2);
    return RUE_OK;
}

/**
 * Processes the given appId and extracts key and checksum start address
 * @param appId The appid to work with
 * @param key Start address of 32 byte buffer to write the key into
 * @param csStart Where the start address of the checksum will be stored.
 *                This is the address in appId so appId must persist for this
 *                address to stay valid.
 * @return RUE_OK on success
 */
int32_t mkKey(const char* appId, alloc_bytes key, char** csStart) {
    if (!appId || !key) return RUE_PARAMETER_NOT_SET;
    rusize alen = strlen(appId);
    int r = sha256(appId, alen, key);
    if (r) {
        dvSetError("Failed getting digest. PSA status: %d", r);
        return RUE_GENERAL;
    }
    if (csStart) {
        return getCs(appId, alen, csStart);
    }
    return RUE_OK;
}

void getPaddedEnd(const char* str, alloc_bytes last, rusize lastLen) {
    int32_t len = (int32_t)strlen(str);
    int32_t blocks = len / BLOCKSIZE;
    int32_t mod = len % BLOCKSIZE;
    int32_t pad = BLOCKSIZE - mod;
    memset(last, pad, lastLen);
    memcpy(last, str+(blocks*BLOCKSIZE), mod);
}

int32_t dvAes256Enc(trans_bytes key, const char* cs, const char* str, char** cipherText) {
    int32_t ret, ciphsz = 0;
    uint8_t iv[BLOCKSIZE];
    // cipher bytes
    alloc_bytes cipher = NULL;
    // for cipherText
    char *out = NULL;

    if (!key || !str || !cipherText) return RUE_PARAMETER_NOT_SET;

    // recipe:cs:iv:encoding:payload recipe start aes-256-cbc:f7:[16]:b:
    int32_t prelen = 18 // aes-256-cbc:dd::b: recipe:cs::encoding:
            + (BLOCKSIZE*2) // iv * 2 because hex encoding
            + 1;        // teminator \0
    rusize dlen = 0;
    rusize blen = 0;  // payload base64 encoded set at run time

    do {
        ruVerbLogf("looking to recipe '%s'", str);
        // get length estimates
        // cipher text
        ret = aesEnc(key, str, iv, NULL, &ciphsz);
        if (ret != RUE_OUT_OF_MEMORY) {
            break;
        }
        // base64 encoded cipher text
        ret = mbedtls_base64_encode(NULL, dlen, &blen, NULL, ciphsz);
        if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
            dvSetError("mbedtls_base64_encode returned %d instread of %d",
                       ret, MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL);
            ret = RUE_GENERAL;
            break;
        }

        // do it!
        // alloc cipher bytes
        cipher = ruMalloc0(ciphsz, uint8_t);
        ret = aesEnc(key, str, iv, cipher, &ciphsz);
        if (ret != RUE_OK) {
            break;
        }
        // set what we learned
        dlen = blen;
        // alloc output for recipe:cs:iv:encoding:payload
        char *p = out = ruMalloc0(prelen+dlen, char);
        // recipe:cs:
        sprintf(p, "aes-256-cbc:%s:", cs? cs : "");
        p += strlen(out);
        // iv
        hexify((trans_bytes) iv, BLOCKSIZE, (alloc_bytes ) p);
        p += BLOCKSIZE*2;
        // :encoding:
        sprintf(p, ":b:");
        p += 3;
        // payload
        ret = mbedtls_base64_encode((alloc_bytes)p, dlen, &blen,
                                    cipher, ciphsz);
        if (ret) {
            dvSetError("mbedtls_base64_encode failed: %d", ret);
            ret = RUE_GENERAL;
            break;
        }
        p+= dlen;
        // redundant terminator
        *p = '\0';
        // all good
        *cipherText = out;
        out = NULL;
        // for readability, it is already 0
        ret = RUE_OK;
    } while(false);

    ruFree(cipher);
    ruFree(out);
    return ret;
}

int32_t dvAes256Dec(trans_bytes key, const char* cipherRecipe, char** data, char* cs) {
    int32_t ret = RUE_GENERAL;
    uint8_t iv[BLOCKSIZE];

    if (!key || !cipherRecipe || !data) return RUE_PARAMETER_NOT_SET;

    // free
    ruList rPieces = NULL;
    alloc_bytes cipher = NULL;
    char* msg = NULL;

    do {
        // recipe:cs:iv:encoding:payload
        // aes-256-cbc:18:835cc...c20:b:YOB4WAENU9TmlIykp1VV0w==
        ruVerbLogf("looking at recipe '%s'", cipherRecipe);
        // sanity check
        if (!ruStrStartsWith(cipherRecipe, "aes-256-cbc:", NULL)) {
            dvSetError("recipe '%s' is incompatible", cipherRecipe);
            ret = DVE_PROTOCOL_ERROR;
            break;
        }
        // split it
        rPieces = ruStrSplit(cipherRecipe, ":", 5);
        if (!rPieces) {
            dvSetError("failed splitting recipe '%s'", cipherRecipe);
            ret = DVE_PROTOCOL_ERROR;
            break;
        }
        if (cs) {
            // get the checksum
            char *checksum = ruListIdx(rPieces, 1, char*, &ret);
            if (ret != RUE_OK) {
                dvSetError("failed getting cs from recipe ec:%d", ret);
                break;
            }
            memcpy(cs, checksum, 2);
        }
        // get the iv
        char *hexIv = ruListIdx(rPieces, 2, char*, &ret);
        if (ret != RUE_OK) {
            dvSetError("failed getting iv from recipe ec:%d", ret);
            break;
        }
        rusize nl = BLOCKSIZE;
        ret = unhexify(hexIv, &nl, BLOCKSIZE, iv);
        if (ret != RUE_OK) {
            dvSetError("failed to unhexify iv '%s' ec:%d", iv, ret);
            break;
        }
        // get and verify the codec
        char *codec = ruListIdx(rPieces, 3, char*, &ret);
        if (ret != RUE_OK) {
            dvSetError("failed getting codec from recipe ec:%d", ret);
            break;
        }
        if (!ruStrEquals(codec, "b")) {
            dvSetError("invalid codec '%s' in recipe", codec);
            ret = DVE_PROTOCOL_ERROR;
            break;
        }
        // decode
        char* b64 = ruListIdx(rPieces, 4, char*, &ret);
        if (ret != RUE_OK) {
            dvSetError("failed getting payload from recipe ec:%d", ret);
            break;
        }
        rusize clen = 0;
        ret = dvB64Decode(b64, &cipher, &clen);
        if (ret != RUE_OK) {
            dvSetError("failed decoding payload from recipe ec:%d", ret);
            break;
        }
        // decrypt
        ret = aesDec(key, cipher, clen, iv, &msg);
        if (ret != RUE_OK) {
            dvSetError("failed decrypting payload from recipe ec:%d", ret);
            break;
        }
        // all good
        *data = msg;
        msg = NULL;
        ret = RUE_OK;

    } while(false);

    ruFree(msg);
    ruFree(cipher);
    ruListFree(rPieces);

    return ret;
}
