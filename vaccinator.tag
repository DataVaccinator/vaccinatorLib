<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<tagfile doxygen_version="1.9.1">
  <compound kind="group">
    <name>glos</name>
    <title>Glossary</title>
    <filename>group__glos.html</filename>
    <docanchor file="group__glos.html" title="app-id">appid</docanchor>
    <docanchor file="group__glos.html" title="cURL">curl</docanchor>
    <docanchor file="group__glos.html" title="DataVaccinator">vacc</docanchor>
    <docanchor file="group__glos.html" title="DataVaccinator Client">dvclient</docanchor>
    <docanchor file="group__glos.html" title="DataVaccinator Vault">vault</docanchor>
    <docanchor file="group__glos.html" title="index word">iwd</docanchor>
    <docanchor file="group__glos.html" title="search word">swd</docanchor>
    <docanchor file="group__glos.html" title="Service Provider">provider</docanchor>
    <docanchor file="group__glos.html" title="PID">pid</docanchor>
    <docanchor file="group__glos.html" title="PKCS#7 Padding">pkcs7</docanchor>
    <docanchor file="group__glos.html" title="SID">sid</docanchor>
    <docanchor file="group__glos.html" title="SPW">spw</docanchor>
    <docanchor file="group__glos.html" title="VID">vid</docanchor>
    <docanchor file="group__glos.html" title="VID Map">vidMap</docanchor>
  </compound>
  <compound kind="group">
    <name>dvmain</name>
    <title>Data API</title>
    <filename>group__dvmain.html</filename>
    <member kind="typedef">
      <type>int32_t(*</type>
      <name>dvIndexCb</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>ga4691f806b2af80220aae15c1a9704109</anchor>
      <arglist>)(void *usrCtx, const char *vid, const char *data, ruList *indexWords)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvAddIndexWord</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>ga6dfc8b2ed6af09b22f2f116d1708497f</anchor>
      <arglist>(ruList *indexWords, const char *appId, const char *word)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvAddSearchWord</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>ga4ae1ed35dc5b28013853e346b91140f3</anchor>
      <arglist>(ruList *searchWords, const char *appId, const char *word)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvAdd</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>ga2b0d4185bf183f6352c59b8ac02161ac</anchor>
      <arglist>(dvCtx dc, const char *data, ruList indexWords, char **vid)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvUpdate</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>ga85739c5f18cab8c27e54ba846fbe8d6f</anchor>
      <arglist>(dvCtx dc, const char *vid, const char *data, ruList indexWords)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvGet</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>ga0ec9b624e6f09b04d055d48270ff0600</anchor>
      <arglist>(dvCtx dc, ruList vids, ruMap *vidMap)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvGetVid</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>ga4d4b918694b348de535c309e475eb95b</anchor>
      <arglist>(ruMap vidMap, const char *vid, char **pid)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvSearch</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>gadf8fd43e07b1a4f8c016980b5b2c7bfe</anchor>
      <arglist>(dvCtx dc, ruList searchWords, ruList *vids)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvDelete</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>ga9653a88c3d7386425171871e991ae994</anchor>
      <arglist>(dvCtx dc, ruList vids)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvWipe</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>gaf6bbf55e624aa89a0bed30b794dd2758</anchor>
      <arglist>(dvCtx dc, ruList vids)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvChangeAppId</name>
      <anchorfile>group__dvmain.html</anchorfile>
      <anchor>ga4677d4d2f41d30b0ef86e85c8ba00e63</anchor>
      <arglist>(dvCtx dc, const char *newId, ruList vids, ruMap *vidMap, dvIndexCb indexCb, void *indexCtx)</arglist>
    </member>
  </compound>
  <compound kind="group">
    <name>dvpublish</name>
    <title>Publishing API</title>
    <filename>group__dvpublish.html</filename>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvPublish</name>
      <anchorfile>group__dvpublish.html</anchorfile>
      <anchor>gad608e74c9863c749fae3472172651265</anchor>
      <arglist>(dvCtx dc, const char *passwd, int durationDays, const char *data, char **vid)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvGetPublished</name>
      <anchorfile>group__dvpublish.html</anchorfile>
      <anchor>ga139e8e1a3239cd14002b01c02e4490d3</anchor>
      <arglist>(dvCtx dc, const char *passwd, ruList vids, ruMap *vidMap)</arglist>
    </member>
    <docanchor file="group__dvpublish.html" title="Published payloads have different behavior:">pubbehavior</docanchor>
  </compound>
  <compound kind="group">
    <name>dvgeneral</name>
    <title>General API</title>
    <filename>group__dvgeneral.html</filename>
    <member kind="define">
      <type>#define</type>
      <name>dvDefaultConnectTimeoutSeconds</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga2c94fe4e427b19760b70b6a0886a5442</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>dvDefaultSecretPlaceHolder</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga050160776a791bf4156f5d0da0f50d76</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void *</type>
      <name>dvCtx</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gae4d6bb2909a269a91d4d20f20c5ed050</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>int32_t(*</type>
      <name>dvSetHeaderFn</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga04129067ed3fc1c71898b939fe4018c7</anchor>
      <arglist>)(void *ctx, const char *name, const char *value)</arglist>
    </member>
    <member kind="typedef">
      <type>int32_t(*</type>
      <name>dvHeaderCb</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga5572434f0d6a452e9eac301c53afaf76</anchor>
      <arglist>)(void *usrCtx, dvSetHeaderFn setHeader, void *headerCtx)</arglist>
    </member>
    <member kind="typedef">
      <type>int32_t(*</type>
      <name>dvSetPostFn</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga005e918ec4bbf9cfc4ac5b34b2f80124</anchor>
      <arglist>)(void *ctx, const char *name, void *buf, size_t len)</arglist>
    </member>
    <member kind="typedef">
      <type>int32_t(*</type>
      <name>dvPostCb</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gaa1d2a8effa4d10ae3ca38d95271ac55c</anchor>
      <arglist>)(void *usrCtx, dvSetPostFn setPostField, void *postCtx)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>dvCtxOpt</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga59d119d7c5cbaa850d9b7bd96792479f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_PROXY</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fa12985f877bad1b88bc0e59f8f12b63a1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_PROXY_USER</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fab53276333138b8c2e8b22a072df57251</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_PROXY_PASS</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fa59f3fa487cda0c9ad6a25ce81b4ab626</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_SERVICE_URL</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fafa9d228f6615a009b997e6a41f78e07f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_APP_ID</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fa37a1b948f55aff22cbbcb404ae228358</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_CONNECT_TIMEOUT</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fa396749bec849cdae2e57a8dee631a192</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_APPNAME</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fac45683461bcfc7c354aa8fde088a4a2f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_APPVERSION</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fadbc4bea1a4138f32d109274462adb434</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_CERT_PATH</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fa9fc27b11e2664b68c6ada11c51e9ab83</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_SKIP_CERT_CHECK</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fadefbba382d201f196697b44487f8932c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DV_CURL_LOGGING</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gga59d119d7c5cbaa850d9b7bd96792479fa711b015868f7ab71a58e8444ceade44c</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvNew</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gaa569238d6383532ab3e56ff82195457a</anchor>
      <arglist>(dvCtx *dc, const char *serviceUrl, const char *appId, KvStore *cache)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI void</type>
      <name>dvFree</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga9d755a06f9460016c54ca265d25cf7b5</anchor>
      <arglist>(dvCtx dc)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvSetHeaderCb</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga13fea75e53e6c0e9db771b2d36b8f1f4</anchor>
      <arglist>(dvCtx dc, dvHeaderCb callback, void *cbCtx)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int32_t</type>
      <name>dvSetPostCb</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>gaaa640880e6e7f700af67988f96eeff3f</anchor>
      <arglist>(dvCtx dc, dvPostCb callback, void *cbCtx)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI const char *</type>
      <name>dvVersion</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga2cab763f3aa1b83617c9a7081ac83e5e</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI int</type>
      <name>dvSetProp</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga7088569c7029864b3cb1bcc0ae3b46cf</anchor>
      <arglist>(dvCtx dc, enum dvCtxOpt opt, const char *value)</arglist>
    </member>
    <member kind="function">
      <type>DVAPI const char *</type>
      <name>dvLastError</name>
      <anchorfile>group__dvgeneral.html</anchorfile>
      <anchor>ga99e793818faf1530b55c08d40c4d6c45</anchor>
      <arglist>(void)</arglist>
    </member>
  </compound>
  <compound kind="group">
    <name>dverrors</name>
    <title>Error Codes</title>
    <filename>group__dverrors.html</filename>
    <member kind="define">
      <type>#define</type>
      <name>DVE_OFFSET</name>
      <anchorfile>group__dverrors.html</anchorfile>
      <anchor>gaabee1fba289969f43fedab85121dc36f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>DVE_INVALID_CREDENTIALS</name>
      <anchorfile>group__dverrors.html</anchorfile>
      <anchor>ga3562e5ab93197693595f8545117bc1cc</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>DVE_SSL_HANDSHAKE_ERROR</name>
      <anchorfile>group__dverrors.html</anchorfile>
      <anchor>ga440eb0ae8f0ea7898c013d0d680329dc</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>DVE_NO_INTERNET</name>
      <anchorfile>group__dverrors.html</anchorfile>
      <anchor>gaf8ae4bb0c45e6a05073c395c063ca55e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>DVE_PROTOCOL_ERROR</name>
      <anchorfile>group__dverrors.html</anchorfile>
      <anchor>ga8b5734bed2ace469e8c205220cb47e96</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="page">
    <name>index</name>
    <title></title>
    <filename>index.html</filename>
    <docanchor file="index.html" title="Introduction">dvintro</docanchor>
    <docanchor file="index.html" title="Data Specification">payload</docanchor>
    <docanchor file="index.html" title="Example Usage">usage</docanchor>
  </compound>
</tagfile>
