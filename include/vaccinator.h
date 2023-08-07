/**
 * \mainpage
 * \copyright 2022 Datavaccinator
 *
 * \section dvintro Introduction
 * This is a \ref dvclient library which is designed for native use on PC based
 * computer systems running Linux/Unix or Microsoft Windows operating systems.
 *
 * \ref vacc protects your sensitive data known as \ref pid against abuse.
 * The service allows you to split out your \ref pid data at the very moment it is
 * generated and uses advanced pseudonymisation techniques to replace it with
 * a corresponding \ref vid.
 *
 * Thus, \ref vacc reduces cyber security risks in the health, industry,
 * finance and any other sector and helps service providers, device manufacturers,
 * data generating and data handling parties to manage sensitive data in a secure
 * and GDPR-compliant manner. In contrast to other offerings, \ref vacc
 * industrialises pseudonymisation, thereby making pseudonymisation replicable
 * and affordable.
 *
 * The API of this library has two main parts to it:
 * \li The \ref dvgeneral contains global and lifecycle functions.
 * \li The general \ref dvmain contains most of the runtime functions.
 * \li The specialized \ref dvpublish relates to the part of sharing \ref pid
 * data with other parties.
 * \li The \ref dverrors are for \ref dvclient and the others are \ref ruerror.
 *
 * \subsection payload Data Specification
 * The general \ref vault data specification can be found here
 * https://github.com/DataVaccinator/dv-vault/blob/master/docs/DataVaccinator-protocol.adoc#data
 * This section focuses on the implementation of the \b payload part.
 * It is documented here to facilitate cross platform compatibility with other
 * \ref dvclient implementations.
 * Our \b payload is authenticated
 * https://en.wikipedia.org/wiki/Authenticated_encryption#MAC-then-Encrypt_(MtE)
 * style.
 *
 * The following use of \b bytes in variables implies usage of actual bytes and not hex encoded
 * representations thereof.
 * Our \b payload is implemented in the following way:
 *
 * \b cs = last 2 bytes of the \ref appid \n
 * \b ivbytes = randomBytes ( 16 ) \n
 * \b ivhex = hexencode ( \b ivbytes ) \n
 * \n
 * \b sumbytes = sha256 ( \ref pid ) \n
 * \b bytes = \ref pid + \ref pkcs7 + \b sumbytes \n
 * \b cipherbytes = aes256cbc ( \b ivbytes , \b bytes ) \n
 * \b payload = base64 (\b cipherbytes ) \n
 * \n
 * \b data = "aes-256-cbc:" + \b cs + ":" + \b ivhex + ":b:" + \b payload
 *
 *
 * \subsection usage Example Usage
 * This usage example can also be found under examples/datause.c:
 * \snippet datause.c DOXYGEN
 *
 * \defgroup glos Glossary
 * This section defines various terms used in this documentation.
 * @{
 *
 * \subsection appid app-id
 * The App-Id is a form of recoverable password based on someone's physical
 * world identification, such as a passport or government ID card.
 * Get more information at
 * https://github.com/DataVaccinator/APP-ID/blob/master/docs/appid_manual/appid-manual.adoc
 *
 * \subsection curl cURL
 * cURL and libcurl is a free and easy-to-use client-side URL transfer library.
 * Get more information at https://curl.se.
 *
 * \subsection vacc DataVaccinator
 * This term describes the overall use of the \ref vault, a potential
 * \ref provider and a \ref dvclient in order to protect sensitive \ref pid data
 * via pseudonymisation.
 *
 * \subsection dvclient DataVaccinator Client
 * Software using this or another \ref vacc client library to pseudonymise \ref pid.
 *
 * \subsection vault DataVaccinator Vault
 * The service that stores your \ref pid data. Get more information at https://www.datavaccinator.com
 *
 * \subsection iwd index word
 * This is a term that is sent to the \ref vault to index the associated
 * \ref pid data. It is there to be found by a \ref swd using the \ref dvSearch
 * function. An \ref iwd is always made lowercase so that it essentially becomes
 * caseless.
 *
 * \subsection swd search word
 * This is a term that is used in \ref dvSearch to retrieve \ref vid entries whose
 * \ref pid was indexed using \ref iwd entries. A \ref swd must be the start of an
 * \ref iwd to find the assoiacted \ref vid entry. A \ref swd is always made
 * lowercase so that it essentially becomes caseless.
 *
 * \subsection provider Service Provider
 * The service provider is between the \ref dvclient and the \ref vault. It receives all REST
 * calls and forwards \ref pid data to the \ref vault and relays \ref vid data
 * back to the \ref dvclient. It may authenticate users and otherwise process
 * \ref vid data.
 *
 * \subsection pid PID
 * PID stands for Personal Identifiers. See https://en.wikipedia.org/wiki/Personal_identifier
 *
 * \subsection pkcs7 PKCS#7 Padding
 * See https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
 *
 * \subsection sid SID
 * The \ref provider identifier. It is used with the \ref spw by the \ref vault
 * to authenticate a \ref provider or a \ref dvclient.
 *
 * \subsection spw SPW
 * The \ref provider password. It is used with the \ref sid by the \ref vault
 * to authenticate a \ref provider or a \ref dvclient.
 *
 * \subsection vid VID
 * VID stands for Vaccination Identifier. It is an alias representing a piece of
 * \ref pid stored in the \ref vault.
 *
 * \subsection vidMap VID Map
 * This is an \ref ruMap return by \ref dvGet ,\ref dvGetPublished and
 * \ref dvChangeAppId . Its key is is a \ref vid entry. Its value usually
 * consists of the associated \ref pid and a status code. The value is retrieved
 * using \ref dvGetVid and should be copied to persist. This map must be freed
 * with \ref ruMapFree when no longer needed.
 * The status code may be one of the following:
 * \li \ref RUE_OK Everything is OK and the \ref pid data is present. When the
 *          map came from \ref dvChangeAppId these entries have data set to NULL.
 * \li \ref RUE_FILE_NOT_FOUND The entry has not be found in the \ref vault and
 *          data is NULL.
 * \li \ref DVE_INVALID_CREDENTIALS The wrong \ref appid was used to decrypt.
 *          When the map came from \ref dvChangeAppId the data contains the
 *          checksum of the encrypted entry, otherwise data is NULL.
 *
 *  @}
 */
#ifndef VACCINATOR_H
#define VACCINATOR_H

#include <regify-util.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** \cond noworry */
#if defined(vaccinator_EXPORTS)
    #if (defined(WINDOWS) || defined(WIN32) || defined(__BORLANDC__))
        #ifdef DV_BUILDING
            #define DVAPI extern __declspec(dllexport)
        #else
            #define DVAPI extern __declspec(dllimport)
        #endif
    #else
        #if defined(__GNUC__) && (__GNUC__ * 100 + __GNUC_MINOR__) >= 303
            #define DVAPI __attribute__ ((visibility ("default")))
        #endif
    #endif
#else
    #define DVAPI
#endif
/** \endcond */

/**
 * Opaque pointer to a datavaccinator object.
 * \ingroup dvgeneral
 */
typedef void* dvCtx;

/**
 * \defgroup dvmain Data API
 * \brief This section contains the general \ref dvclient API calls.
 *
 * @{
 *
 */

/**
 * Adds the given word as an \ref iwd to the referenced \ref ruList. This function
 * is  used when \ref pid is sent to the \ref vault with the functions
 * \ref dvAdd and \ref dvUpdate. For making \ref swd terms use
 * \ref dvAddSearchWord instead.
 * @param indexWords Pointer to an \ref ruList that the \ref iwd will be
 *                    added to. This list will be created if NULL, otherwise
 *                    the given term will be added to the list present. The list
 *                    must be freed with \ref ruListFree when done with it.
 * @param appId The \ref appid to use for term hashing.
 * @param word \ref iwd under which data should be found via \ref dvSearch.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvAddIndexWord(ruList* indexWords, const char* appId, const char* word);

/**
 * Adds the given word as a \ref swd to the referenced \ref ruList. This function is
 * used when searching for matching \ref pid data with \ref dvSearch .
 * @param searchWords Pointer to an \ref ruList that the \ref swd will be
 *                    added to. This list will be created if NULL, otherwise
 *                    the given term will be added to the list present. The list
 *                    must be freed with \ref ruListFree when done with it.
 * @param appId The \ref appid to use for term hashing.
 * @param word \ref swd under which \ref vid entries should be found via
 *             \ref dvSearch.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvAddSearchWord(ruList* searchWords, const char* appId, const char* word);

/**
 * Creates a new \ref pid entry in the \ref vault.
 * @param dc The \ref dvCtx to work with.
 * @param data The \ref pid data to vaccinate.
 * @param indexWords Optional \ref iwd terms under which this data should be
 *                    found via \ref dvSearch. Use NULL for none.
 * @param vid Where the corresponding \ref vid for the given data
 *            will be stored on success. Free this with \ref ruFree when done
 *            with it.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvAdd(dvCtx dc, const char* data,
                    ruList indexWords, char** vid);

/**
 * Updates an existing \ref pid entry in the \ref vault with new \ref pid.
 * @param dc The \ref dvCtx to work with.
 * @param vid The \ref vid whose data to update.
 * @param data The \ref pid to update it with.
 * @param indexWords Optional \ref iwd terms under which this data should be
 *                   found via \ref dvSearch. Use NULL for none.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvUpdate(dvCtx dc, const char* vid, const char* data,
                       ruList indexWords);

/**
 * Retrieves a \ref vidMap for the given list of \ref vid entries.
 * @param dc The \ref dvCtx to work with.
 * @param vids An \ref ruList of \ref vid entries to retrieve the \ref vidMap for.
 * @param vidMap Where the returned \ref vidMap will be stored.
 *               It is good practice to iterate over the given list of \ref vid
 *               entries and to use \ref dvGetVid to retrieve its entries.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvGet(dvCtx dc, ruList vids, ruMap* vidMap);

/**
 * Retrieves the associated \ref pid data for given \ref vid from the given
 * \ref vidMap and returns its associated status code.
 * @param vidMap The \ref vidMap to retrieve the value from.
 * @param vid \ref vid entry to retrieve.
 * @param pid Where to store the returned \ref pid data. This data should be
 *            copied and must not be freed. It is freed along with the vidMap.
 * @return The status code of the associated \ref vidMap entry or
 *         \ref RUE_PARAMETER_NOT_SET etc for missing/invalid parameters.
 */
DVAPI int32_t dvGetVid(ruMap vidMap, const char* vid, char** pid);

/**
 * Retrieves an \ref ruList of \ref vid entries that matched the given \ref swd
 * entries.
 * @param dc The \ref dvCtx to work with.
 * @param searchWords An \ref ruList of previously in \ref dvAddSearchWord
 *                    specified \ref swd terms to query. These terms are ANDed.
 * @param vids Where the \ref ruList of found \ref vid values will be stored.
 *             The returned \ref ruList should be freed with \ref ruListFree
 *             when no longer needed. The individual list entries may need to be
 *             copied as they are freed along with the list.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvSearch(dvCtx dc, ruList searchWords, ruList* vids);

/**
 * Deletes given list of \ref vid entries from the \ref vault.
 * @param dc The \ref dvCtx to work with.
 * @param vids List of \ref vid entries to be deleted.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvDelete(dvCtx dc, ruList vids);

/*
 * Wipes data of given \ref vid from the local cache.
 * @param ctx The \ref dvCtx to work with.
 * @param vid The \ref vid whose data to wipe.
 * @return \ref RUE_OK on success or an error code.
 */
//DVAPI int32_t dvWipeOne(dvCtx ctx, const char* vid);

/**
 * Wipes all or given list of \ref vid entries from the local cache.
 * @param dc The \ref dvCtx to work with.
 * @param vids List of \ref vid entries to be deleted. Leave NULL to wipe all entries.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvWipe(dvCtx dc, ruList vids);

/**
 * A function that generates a list of \ref iwd entries based on the given \ref pid.
 * @param usrCtx Opaque context to be passed to the function.
 * @param vid The \ref vid that represents the given \ref pid data. This is
 *            supplied in case it is useful.
 * @param data The \ref pid data to vaccinate and extract \ref iwd entries from.
 * @param indexWords Where the \ref ruList of \ref iwd entries should be stored.
 *                    The returned \ref ruList will be freed with \ref ruListFree
 *                    when no longer needed.
 * @return \ref RUE_OK on success or an error code.
 */
typedef int32_t (*dvIndexCb) (void* usrCtx, const char* vid,
                              const char* data, ruList* indexWords);

/**
 * This function re-encrypts all given \ref vid references with the \ref appid
 * given in newId.
 *
 * This may be needed if a user's \ref appid has been changed as a result of a
 * compromise due to a leakage. Be sure to iterate over the returned
 * \ref vidMap.
 * @param dc The \ref dvCtx with the old \ref appid to work with.
 * @param newId The new \ref appid to re-encrypt each \ref pid entry with.
 * @param vids The list of \ref vid entries that need re-encrypting.
 * @param vidMap Where the returned \ref vidMap will be stored.
 *               It is good practice to iterate over the given list of \ref vid
 *               entries and to use \ref dvGetVid to check their stati.
 * @param indexCb An optional \ref dvIndexCb to call to set \ref iwd terms of
 *                each re-encrypted \ref pid entry.
 * @param indexCtx An optional context that will be passed into \b indexCb
 *                 as the \b usrCtx parameter.
 * @return \ref RUE_OK on success or an error code. Total success is only
 *              provided when the returned \ref vidMap solely consists of
 *              entries with status \ref RUE_OK.
 *
 * This example to change the \ref appid can also be found in
 * examples/changeappid.c:
 * \snippet changeappid.c DOXYGEN
 */
DVAPI int32_t dvChangeAppId(dvCtx dc, const char* newId, ruList vids,
                            ruMap* vidMap, dvIndexCb indexCb, void* indexCtx);

/**
 * @}
 */

/**
 * \defgroup dvpublish Publishing API
 * \brief This section contains the general publishing API calls.
 *
 * The publishing API are additional functions for specific purpose. In
 * distributed systems it may be necessary to provide the \ref pid payload to
 * external parties. An example could be the health or police sector, where
 * datasets including sensitive \ref pid may need to be exchanged. But even in
 * such cases, the pseudonymisation should not become broken. Thus, it is the
 * better to exchange pseudonymized datasets with \ref vid entries and then
 * grant access to the \ref pid payload to the receiving party.
 *
 * This is what the publishing functions allow you to do. Obviously, the
 * receiving party should not know your \ref appid and therefore the publishing
 * functions need a separate password for encryption. This is a new key you then
 * share with the receiving party, together with the created \ref vid entries.
 *
 * \subsubsection pubbehavior Published payloads have different behavior:
 * -# They have an expiration date which has them automatically deleted in the
 *    \ref vault when they expire.
 * -# They cannot get updated.
 * -# They do not support the Search API.
 * -# They can be accessed by another \ref provider if they know the \ref vid.
 * -# They are encrypted with a different password than your usual \ref appid.
 * -# There is no caching for published items.
 *
 * Below is a typical process for exchanging pseudonymized information, herein referred
 * to as \b exchange \b data, using \ref vacc :
 * -# Make sure the receiving party is has a login to your \ref vault instance:
 *  -# They need their own \ref sid and \ref spw.
 *  -# Their system has to be IP whitelisted.
 *  -# You may have to contact your \ref vault provider to enable this (if
 *     you’re not hosting the \ref vault by yourself).
 * -# Exchange a secure password for usage with \ref vacc between you and
 *    the receiving party.
 * -# Push the \ref pid datasets to exchange to the \ref vault using the
 *    \ref dvPublish function and attach the resulting \ref vid entries to your
 *    \b exchange \b data.
 * -# Send your \b exchange \b data to the receiving party.
 * -# The receiving party uses its \ref sid / \ref spw and the
 *    \ref dvGetPublished function to retrieve the \ref pid information as
 *    needed using your supplied \ref vid entries.
 *
 * This publishing example can also be found under examples/publish.c:
 * \snippet publish.c DOXYGEN
 *
 * @{
 *
 */

/**
 * Creates a new \ref pid entry for publishing.
 * @param dc The \ref dvCtx to work with.
 * @param passwd A password which will be used in place of the regular \ref appid.
 *               This password must be shared with the receiving party in order
 *               to allow them access to this \ref pid data.
 * @param durationDays The numbers of days from now until the published
 *                     data will be deleted from the \ref vault. Allowed values
 *                     are between 1 and 365.
 * @param data The \ref pid data to vaccinate.
 * @param vid Where the corresponding \ref vid for the given data
 *            will be stored on success. Free this with \ref ruFree when done
 *            with it.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvPublish(dvCtx dc, const char* passwd, int durationDays,
                        const char* data, char** vid);

/**
 * Retrieves a \ref vidMap for the given list of published \ref vid entries.
 * @param dc The \ref dvCtx to work with.
 * @param passwd The password that was used when \ref dvPublish was called by
 *               the publishing party.
 * @param vids An \ref ruList of \ref vid entries to retrieve the \ref vidMap for.
 * @param vidMap Where the returned \ref vidMap will be stored.
 *               It is good practice to iterate over the given list of \ref vid
 *               entries and to use \ref dvGetVid to retrieve its entries.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvGetPublished(dvCtx dc, const char* passwd, ruList vids, ruMap* vidMap);

/**
 * @}
 */

/**
 * \defgroup dvgeneral General API
 * \brief This section contains global and lifecycle functions.
 *
 * @{
 *
 */

/**
 * \brief The default number of seconds to wait for a connection
 *
 **/
#define dvDefaultConnectTimeoutSeconds 8

/**
 * The default place holder for any secret specified in \ref dvSetProp with
 * \ref DV_SECRET when \ref DV_SECRET_PLACE_HOLDER has not been specified.
 */
#define dvDefaultSecretPlaceHolder "^^^SECRET^^^"

/**
 * Creates a new Datavaccinator context object.
 * @param dc Where the new \ref dvCtx will be stored. Free with \ref dvFree.
 * @param serviceUrl The URL of the \ref provider that this \ref dvclient talks
 *                   to. This may also be the \ref vault URL directly if you use
 *                   the \ref dvSetPostCb to supply the required
 *                   \ref sid / \ref spw credentials.
 * @param appId This is the end users application password for data encryption.
 * @param cache A \ref KvStore instance that can be used as a local data cache.
 *              The caller must preserve the KvStore instance for the life of
 *              this context and may/should free it afterwards. If NULL no
 *              caching will be done.
 * @return \ref RUE_OK on success or an error code.
 */
DVAPI int32_t dvNew(dvCtx* dc, const char* serviceUrl, const char* appId,
                    KvStore* cache);

/**
 * Frees a \ref dvCtx that was created with \ref dvNew when it is no longer needed.
 * @param dc The \ref dvCtx to free.
 */
DVAPI void dvFree(dvCtx dc);

/**
 * Header setter function interface.
 * When this function is called a header is set or removed. If a header matches
 * a header that is already set, the given header takes precedence.
 * To remove an existing header set its name with a null value.
 * To set an empty header set its name with the value of an empty string.
 * The header name must not include a colon. The caller is responsible for
 * header encoding. The header value must not include line endings such as CRLF.
 * @param ctx Opaque context to be passed to the function.
 * @param name Name of the header to be set. Must only persist for the duration
 *             of this function call.
 * @param value Value of the header in unencoded format. Must only persist for
 *              the duration of this function call.
 * @return \ref RUE_OK on success or an error code.
 */
typedef int32_t (*dvSetHeaderFn) (void* ctx, const char* name, const char* value);

/**
 * Interface of function to be called when it's time to set request headers.
 * @param usrCtx Opaque context passed as cbCtx to the \ref dvSetHeaderCb function.
 * @param setHeader The \ref dvSetHeaderFn function to call in order to set the
 *                 desired headers.
 * @param headerCtx Opaque context to be passed as ctx to the given
 *                  \ref dvSetHeaderFn function.
 * @return \ref RUE_OK on success or error code which will cause the
 *              request to be aborted.
 */
typedef int32_t (*dvHeaderCb) (void* usrCtx, dvSetHeaderFn setHeader, void* headerCtx);

/**
 * Sets the function to call when the request headers are being written.
 * @param dc The \ref dvCtx to work with.
 * @param callback The \ref dvHeaderCb to call.
 * @param cbCtx An optional context that will be passed into the \ref dvHeaderCb
 *              as the \b usrCtx parameter.
 * @return \ref RUE_OK on success or an error code.
 *
 * @b Example
 * ~~~~~{.c}
int32_t headerCb(void* usrCtx, dvSetHeaderFn setHeader, void* headerCtx) {
    return setHeader(headerCtx, "Cache-Control", "max-age=60");
}

int main ( int argc, char **argv ) {
    ...
    dvSetHeaderCb(ctx, &headerCb, NULL);
    ...
}
 * ~~~~~
 *
 * @remark Error handling has been omitted for brevity.
 *
 */
DVAPI int32_t dvSetHeaderCb(dvCtx dc, dvHeaderCb callback, void* cbCtx);

/**
 * Post field setter function interface.
 * @param ctx Opaque context to be passed to the function.
 * @param name Name of the header to be set. Must only persist for the duration
 *             of this function call.
 * @param buf Data for the value of the field in unencoded format. Must only
 *            persist for the duration of this function call.
 * @param len Length of the given buf parameter.
 * @return \ref RUE_OK on success or an error code.
 */
typedef int32_t (*dvSetPostFn) (void* ctx, const char* name, void* buf, size_t len);

/**
 * Interface of function to be called when it's time to set the post fields.
 *
 * This function can be used to send additional post fields and their associated
 * values to a \ref provider in order to facilitate their particular functionality.
 *
 * The usage of this callback is subject to the following rules:
 * \li The use of the post field \b json is reserved for the data that is sent to
 * the \ref vault service. Attempting to set the post value of \b json will
 * result in a \ref RUE_INVALID_PARAMETER error.
 * \li Be sure to post \ref sid in \b sid and \ref spw in \b spwd if you are
 * interfacing with the \ref vault directly.
 *
 * @param usrCtx Opaque context passed as cbCtx to the \ref dvSetPostCb function.
 * @param setPostField The \ref dvSetPostFn function to call in order to set the
 *                     desired post fields.
 * @param postCtx Opaque context to be passed as ctx to the given
 *                \ref dvSetPostFn function.
 * @return \ref RUE_OK on success or error code which will cause the
 *              request to be aborted.
 */
typedef int32_t (*dvPostCb) (void* usrCtx, dvSetPostFn setPostField, void* postCtx);

/**
 * Sets the function to call when the post fields are being written.
 * @param dc The \ref dvCtx to work with.
 * @param callback The \ref dvPostCb to call.
 * @param cbCtx An optional context that will be passed into the \ref dvPostCb
 *              as the \b usrCtx parameter.
 * @return \ref RUE_OK on success or an error code.
 *
 * @b Example
 * ~~~~~{.c}
int32_t postCb(void* usrCtx, dvSetPostFn setPostField, void* postCtx) {
    char* myvalue = (char*) usrCtx;
    return setPostField(postCtx, "myfield", (void*)myvalue, strlen(myvalue));
}

int main ( int argc, char **argv ) {
    ...
    const char *myvalue = "my special value";
    dvSetPostCb(ctx, &postCb, (void*)myvalue);
    ...
}
 * ~~~~~
 *
 * @remark Error handling has been omitted for brevity.
 *
 */
DVAPI int32_t dvSetPostCb(dvCtx dc, dvPostCb callback, void* cbCtx);

/**
 * \brief Returns the build version of this package.
 *
 * This is the actual build version and should not be confused with
 * \ref DV_APPVERSION which is sent to the service providers.
 * \return Version of this package. This string is static and must not be freed.
 */
DVAPI const char* dvVersion(void);

/**
 * \brief Sets the global logging function for this process.
 *
 * This function is like \ref ruSetLogger with the difference that log data has
 * its credentials sanitized out. This is the preferred alternative to
 * \ref ruSetLogger when using the \ref dvclient. You can specify
 * credentials to be sanitized out by calling \ref dvSetProp with \ref DV_SECRET.
 * @param logger Logging function that will be called with messages.
 * @param logLevel Loglevel to determine what gets logged.
 * @param userData Opaque custom user data that will be passed to the
 *                 \ref ruLogFunc implementation.
 */
DVAPI void dvSetCleanLogger(ruLogFunc logger, uint32_t logLevel, perm_ptr userData);

/**
 * \brief Constants used to set \ref dvclient context parameters.
 */
enum dvCtxOpt {
    /** Proxy URL in the form of protocol://hostname:port */
    DV_PROXY = (uint32_t)57, /* force integer size */
    /** Proxy username */
    DV_PROXY_USER,
    /** Proxy password */
    DV_PROXY_PASS,
    /** The service provider URL */
    DV_SERVICE_URL,
    /** The \ref appid */
    DV_APP_ID,
    /** Timeout in seconds used for network connections.
     *  Defaults to \b @NAME@. */
    DV_CONNECT_TIMEOUT,
    /** The name this client claims to be during connect.
     *  Defaults to \ref dvDefaultConnectTimeoutSeconds */
    DV_APPNAME,
    /** The version this client claims to be during connect.
     *  Defaults to \b @PROJECT_VERSION@. */
    DV_APPVERSION,
    /** File path to certificate authority file or directory. */
    DV_CERT_PATH,
    /**
     * A secret to replace in the logs when calling \ref ruVerbLogf type functions.
     * This happens when the logger is initialized by calling \ref dvSetCleanLogger.
     * The secret is replaced with whatever the value of \ref DV_SECRET_PLACE_HOLDER
     * is at the time of this call, not at the time the log call.
     */
    DV_SECRET,
    /**
     * The place holder that will replace a given \ref DV_SECRET in a
     * log cleaned using \ref ruVerbLogf. When this has not been set or set to
     * NULL, it is replaced with \ref dvDefaultSecretPlaceHolder instead. This
     * value is not thread safe and it is copied when \ref dvSetProp is called with
     * \ref DV_SECRET, so it may be set to various values for given secrets.
     */
    DV_SECRET_PLACE_HOLDER,
    /**
     * This will disable SSL certificate verification when set to non 0.
     * Helpful when developing.
     */
    DV_SKIP_CERT_CHECK,
    /**
     * This will turn on cURL debug logging e when set to non 0 and the
     * general log level is at \ref RU_LOG_VERB.
     */
    DV_CURL_LOGGING,
    /**
     * \cond noworry Not used */
    DV_NO_CTX_OP = ~0
    /** \endcond */
};

/**
 * \brief Sets a \ref dvclient context \ref dvCtxOpt option.
 *
 * \param [in] dc The \ref dvCtx to set the option for.
 * \param [in] opt The \ref dvCtxOpt option to set.
 * \param [in] value The value to set it to or NULL to unset it.
 *                   The given string will be copied.
 * \return A \ref rferrors status of the operation.
 */
DVAPI int dvSetProp(dvCtx dc, enum dvCtxOpt opt, const char* value);

/**
 * \brief Returns an English textual representation of the last error this thread
 * generated.
 *
 * Note, not all functions use this, so this function should only be
 * called after a function that does use it is called, else misleading
 * information will appear.
 * \ingroup errors
 * @return Last error message. Must be copied if it is to persist.
 */
DVAPI const char* dvLastError(void);

/**
 * @}
 */

/**
 * \defgroup dverrors Error Codes
 * \brief This section contains \ref vacc specifiic error codes.
 *
 * @{
 *
 */

#define DVE_OFFSET 5100
/**
 * Invalid key or password.
 */
#define DVE_INVALID_CREDENTIALS	10 + DVE_OFFSET
/**
 * A problem occurred while securely accessing the internet (SSL/TLS handshake failed).
 */
#define DVE_SSL_HANDSHAKE_ERROR	52 + DVE_OFFSET
/**
 * Internet connection problem
 */
#define DVE_NO_INTERNET	        58 + DVE_OFFSET
/**
 * Internal Protocol Error
 */
#define DVE_PROTOCOL_ERROR	    59 + DVE_OFFSET

/**
 * @}
 */

#ifdef __cplusplus
}   /* extern "C" */
#endif /* __cplusplus */

#endif //VACCINATOR_H
