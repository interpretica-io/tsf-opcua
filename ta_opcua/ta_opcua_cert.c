/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA core: feature discovery and test certificates
 *
 * Certificate generation and reading, used only to make test
 * material - a self-signed server/client certificate, an expired one, a
 * certificate whose ApplicationUri does not match. It needs an
 * encryption build of open62541; without one it answers TE_ENOTSUP and
 * the security tests that need certificates skip.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <open62541/types.h>
#include <open62541/util.h>
#include <open62541/plugin/log_stdout.h>
#ifdef UA_ENABLE_ENCRYPTION
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/certificategroup.h>
#endif

#include "ta_opcua_int.h"

int
ta_opcua_features(unsigned int *features, ta_opcua_out *out)
{
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    unsigned int f = 0;

#ifdef UA_ENABLE_ENCRYPTION
    f |= TA_OPCUA_FEAT_ENCRYPTION | TA_OPCUA_FEAT_CERTGEN;
#endif
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    f |= TA_OPCUA_FEAT_EVENTS;
#endif
#ifdef UA_ENABLE_HISTORIZING
    f |= TA_OPCUA_FEAT_HISTORY;
#endif
    *features = f;
    buf_kvf(&b, "open62541", "%s", UA_OPEN62541_VERSION);
    buf_kvf(&b, "encryption", "%d", (f & TA_OPCUA_FEAT_ENCRYPTION) ? 1 : 0);
    buf_kvf(&b, "events", "%d", (f & TA_OPCUA_FEAT_EVENTS) ? 1 : 0);
    buf_kvf(&b, "history", "%d", (f & TA_OPCUA_FEAT_HISTORY) ? 1 : 0);
    out->result = buf_take(&b);
    return TA_OPCUA_OK;
}

static int
write_file(const char *path, const UA_ByteString *bs)
{
    FILE *f = fopen(path, "wb");

    if (f == NULL)
        return TA_OPCUA_EFAIL;
    if (bs->length > 0 && fwrite(bs->data, 1, bs->length, f) != bs->length)
    {
        fclose(f);
        return TA_OPCUA_EFAIL;
    }
    fclose(f);
    return TA_OPCUA_OK;
}

int
ta_opcua_cert_make(const char *params, ta_opcua_out *out)
{
#ifndef UA_ENABLE_ENCRYPTION
    (void)params;
    return out_err(out, TA_OPCUA_ENOTSUP, "no encryption build");
#else
    char *certp = ta_opcua_opt(params, "cert");
    char *keyp = ta_opcua_opt(params, "key");
    char *uri = ta_opcua_opt(params, "app_uri");
    char *cn = ta_opcua_opt(params, "cn");
    char *dns = ta_opcua_opt(params, "dns");
    long long days = ta_opcua_opt_int(params, "expires_in_days", 365);
    UA_ByteString key = UA_BYTESTRING_NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL;
    UA_String subject[3];
    UA_String altName[2];
    UA_KeyValueMap kvm = UA_KEYVALUEMAP_NULL;
    UA_UInt16 kbits = (UA_UInt16)ta_opcua_opt_int(params, "bits", 2048);
    UA_UInt32 expdays;
    char subj_cn[256];
    char alt_uri[512];
    char alt_dns[256];
    UA_StatusCode st;
    int rc = TA_OPCUA_OK;

    if (certp == NULL || keyp == NULL)
    {
        rc = out_err(out, TA_OPCUA_EINVAL, "cert and key paths required");
        goto out;
    }
    snprintf(subj_cn, sizeof(subj_cn), "CN=%s",
             cn != NULL ? cn : "tsf-opcua");
    subject[0] = UA_STRING_ALLOC("C=PT");
    subject[1] = UA_STRING_ALLOC("O=Interpretica");
    subject[2] = UA_STRING_ALLOC(subj_cn);
    snprintf(alt_uri, sizeof(alt_uri), "URI:%s",
             uri != NULL ? uri : "urn:tsf-opcua:client");
    snprintf(alt_dns, sizeof(alt_dns), "DNS:%s",
             dns != NULL ? dns : "localhost");
    altName[0] = UA_STRING_ALLOC(alt_uri);
    altName[1] = UA_STRING_ALLOC(alt_dns);

    expdays = (UA_UInt32)(days > 0 ? days : 1);
    {
        UA_KeyValuePair kv[2];

        kv[0].key = UA_QUALIFIEDNAME(0, "expires-in-days");
        UA_Variant_setScalar(&kv[0].value, &expdays,
                             &UA_TYPES[UA_TYPES_UINT32]);
        kv[1].key = UA_QUALIFIEDNAME(0, "key-size-bits");
        UA_Variant_setScalar(&kv[1].value, &kbits,
                             &UA_TYPES[UA_TYPES_UINT16]);
        kvm.map = kv;
        kvm.mapSize = 2;

        st = UA_CreateCertificate(UA_Log_Stdout, subject, 3, altName, 2,
                                  UA_CERTIFICATEFORMAT_DER, &kvm, &key, &cert);
    }
    if (st != UA_STATUSCODE_GOOD)
    {
        rc = out_err(out, TA_OPCUA_EFAIL, "create certificate: %s",
                     UA_StatusCode_name(st));
        goto clean;
    }
    if (write_file(keyp, &key) != TA_OPCUA_OK ||
        write_file(certp, &cert) != TA_OPCUA_OK)
    {
        rc = out_err(out, TA_OPCUA_EFAIL, "cannot write cert/key");
        goto clean;
    }
    {
        ta_opcua_buf b = TA_OPCUA_BUF_INIT;

        buf_kv(&b, "cert", certp);
        buf_kv(&b, "key", keyp);
        buf_kvf(&b, "cert_len", "%zu", cert.length);
        out->result = buf_take(&b);
    }
clean:
    UA_ByteString_clear(&key);
    UA_ByteString_clear(&cert);
    UA_String_clear(&subject[0]);
    UA_String_clear(&subject[1]);
    UA_String_clear(&subject[2]);
    UA_String_clear(&altName[0]);
    UA_String_clear(&altName[1]);
out:
    free(certp);
    free(keyp);
    free(uri);
    free(cn);
    free(dns);
    return rc;
#endif
}

int
ta_opcua_cert_info(const char *path, ta_opcua_out *out)
{
#ifndef UA_ENABLE_ENCRYPTION
    (void)path;
    return out_err(out, TA_OPCUA_ENOTSUP, "no encryption build");
#else
    UA_ByteString cert = UA_BYTESTRING_NULL;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    UA_String subj = UA_STRING_NULL;
    UA_DateTime expiry = 0;
    size_t keysize = 0;
    int rc = TA_OPCUA_OK;

    if (file_load(path, &cert) != TA_OPCUA_OK)
        return out_err(out, TA_OPCUA_ENOENT, "cannot read certificate");

    if (UA_CertificateUtils_getSubjectName(&cert, &subj) == UA_STATUSCODE_GOOD)
    {
        char *s = strndup((const char *)subj.data, subj.length);

        buf_kv(&b, "subject", s);
        free(s);
        UA_String_clear(&subj);
    }
    if (UA_CertificateUtils_getExpirationDate(&cert, &expiry) ==
        UA_STATUSCODE_GOOD)
    {
        buf_kvf(&b, "expires_ua", "%" PRId64, (int64_t)expiry);
        buf_kvf(&b, "expired", "%d",
                expiry < UA_DateTime_now() ? 1 : 0);
    }
    if (UA_CertificateUtils_getKeySize(&cert, &keysize) == UA_STATUSCODE_GOOD)
        buf_kvf(&b, "key_size_bits", "%zu", keysize);
    out->result = buf_take(&b);
    UA_ByteString_clear(&cert);
    return rc;
#endif
}

int
ta_opcua_crl_make(const char *params, ta_opcua_out *out)
{
    /* CRL authoring needs the crypto backend's X.509 toolkit directly;
     * open62541 exposes no portable CRL writer. A suite that needs a CRL
     * supplies one as a fixture. Reported as not supported so a test
     * skips rather than fails. */
    (void)params;
    return out_err(out, TA_OPCUA_ENOTSUP, "CRL authoring not supported");
}
