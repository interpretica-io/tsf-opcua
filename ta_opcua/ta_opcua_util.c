/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA core: text, options and the value codec
 *
 * The wire form of a value is "<Type>:<payload>" (scalar) or
 * "<Type>[<n>]:<e1>,<e2>,..." (one-dimensional array). Payloads:
 *
 *   Null                (no payload)            Boolean   true / false
 *   SByte..UInt64       decimal                 Float     %.9g
 *   Double              %.17g (inf, -inf, nan)  String    escaped text
 *   DateTime            UA ticks (100 ns since 1601-01-01), decimal
 *   ByteString          lower-case hex          Guid      8-4-4-4-12
 *   NodeId              "ns=2;s=Temperature"    StatusCode 0x%08X
 *   QualifiedName       "<ns>:<name>"           LocalizedText "<locale>|<text>"
 *   XmlElement          escaped text
 *   ExtensionObject     "<type NodeId>|<hex of the binary body>"
 *   Opaque              "<type name>|<hex of the binary encoding>"
 *
 * Every element is escaped with ta_opcua_esc(), so ',', '|', TAB and
 * newlines never appear inside an element unescaped.
 */

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <open62541/types.h>

#include "ta_opcua_int.h"

/* ---- buffer ------------------------------------------------------- */

void
buf_addv(ta_opcua_buf *b, const char *fmt, va_list ap)
{
    va_list ap2;
    int n;

    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap2);
    va_end(ap2);
    if (n < 0)
        return;
    if (b->len + (size_t)n + 1 > b->size)
    {
        size_t sz = b->size == 0 ? 256 : b->size;
        char *p;

        while (sz < b->len + (size_t)n + 1)
            sz *= 2;
        p = realloc(b->ptr, sz);
        if (p == NULL)
            return;
        b->ptr = p;
        b->size = sz;
    }
    vsnprintf(b->ptr + b->len, (size_t)n + 1, fmt, ap);
    b->len += (size_t)n;
}

void
buf_add(ta_opcua_buf *b, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    buf_addv(b, fmt, ap);
    va_end(ap);
}

void
buf_kv(ta_opcua_buf *b, const char *key, const char *val)
{
    char *e = ta_opcua_esc(val != NULL ? val : "");

    buf_add(b, "%s=%s\n", key, e != NULL ? e : "");
    free(e);
}

void
buf_kvf(ta_opcua_buf *b, const char *key, const char *fmt, ...)
{
    ta_opcua_buf t = TA_OPCUA_BUF_INIT;
    va_list ap;

    va_start(ap, fmt);
    buf_addv(&t, fmt, ap);
    va_end(ap);
    buf_kv(b, key, t.ptr);
    buf_free(&t);
}

void
buf_field(ta_opcua_buf *b, const char *key, const char *val)
{
    char *e = ta_opcua_esc(val != NULL ? val : "");
    bool first = b->len == 0 || b->ptr[b->len - 1] == '\n';

    buf_add(b, "%s%s=%s", first ? "" : "\t", key, e != NULL ? e : "");
    free(e);
}

void
buf_fieldf(ta_opcua_buf *b, const char *key, const char *fmt, ...)
{
    ta_opcua_buf t = TA_OPCUA_BUF_INIT;
    va_list ap;

    va_start(ap, fmt);
    buf_addv(&t, fmt, ap);
    va_end(ap);
    buf_field(b, key, t.ptr);
    buf_free(&t);
}

void
buf_eor(ta_opcua_buf *b)
{
    buf_add(b, "\n");
}

char *
buf_take(ta_opcua_buf *b)
{
    char *p = b->ptr != NULL ? b->ptr : strdup("");

    b->ptr = NULL;
    b->len = b->size = 0;
    return p;
}

void
buf_free(ta_opcua_buf *b)
{
    free(b->ptr);
    b->ptr = NULL;
    b->len = b->size = 0;
}

int
out_err(ta_opcua_out *out, int rc, const char *fmt, ...)
{
    ta_opcua_buf t = TA_OPCUA_BUF_INIT;
    va_list ap;

    va_start(ap, fmt);
    buf_addv(&t, fmt, ap);
    va_end(ap);
    free(out->errmsg);
    out->errmsg = buf_take(&t);
    return rc;
}

void
ta_opcua_out_clear(ta_opcua_out *out)
{
    free(out->result);
    free(out->report);
    free(out->errmsg);
    out->result = out->report = out->errmsg = NULL;
}

/* ---- escaping and options ----------------------------------------- */

static bool
must_esc(unsigned char c)
{
    return c == '%' || c == ',' || c == '|' || c == '\t' || c == '\n' ||
           c == '\r';
}

char *
ta_opcua_esc(const char *s)
{
    size_t n = 0;
    const char *p;
    char *r;
    char *q;

    for (p = s; *p != '\0'; p++)
        n += must_esc((unsigned char)*p) ? 3 : 1;
    r = malloc(n + 1);
    if (r == NULL)
        return NULL;
    for (p = s, q = r; *p != '\0'; p++)
    {
        if (must_esc((unsigned char)*p))
        {
            sprintf(q, "%%%02X", (unsigned char)*p);
            q += 3;
        }
        else
        {
            *q++ = *p;
        }
    }
    *q = '\0';
    return r;
}

static int
hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

char *
ta_opcua_unesc(char *s)
{
    char *r = s;
    char *w = s;

    while (*r != '\0')
    {
        if (r[0] == '%' && hexval(r[1]) >= 0 && hexval(r[2]) >= 0)
        {
            *w++ = (char)(hexval(r[1]) * 16 + hexval(r[2]));
            r += 3;
        }
        else
        {
            *w++ = *r++;
        }
    }
    *w = '\0';
    return s;
}

char *
ta_opcua_opt(const char *params, const char *key)
{
    size_t klen = strlen(key);
    const char *p = params;

    if (p == NULL)
        return NULL;
    while (*p != '\0')
    {
        const char *eol = strchr(p, '\n');
        size_t len = eol != NULL ? (size_t)(eol - p) : strlen(p);

        if (len > klen && strncmp(p, key, klen) == 0 && p[klen] == '=')
        {
            char *v = strndup(p + klen + 1, len - klen - 1);

            if (v != NULL && len - klen - 1 > 0 && v[len - klen - 2] == '\r')
                v[len - klen - 2] = '\0';
            return v != NULL ? ta_opcua_unesc(v) : NULL;
        }
        if (len == klen && strncmp(p, key, klen) == 0)
            return strdup("");
        if (eol == NULL)
            break;
        p = eol + 1;
    }
    return NULL;
}

long long
ta_opcua_opt_int(const char *params, const char *key, long long dflt)
{
    char *v = ta_opcua_opt(params, key);
    long long r = dflt;
    char *end;

    if (v != NULL && *v != '\0')
    {
        errno = 0;
        r = strtoll(v, &end, 0);
        if (errno != 0 || *end != '\0')
            r = dflt;
    }
    free(v);
    return r;
}

double
ta_opcua_opt_dbl(const char *params, const char *key, double dflt)
{
    char *v = ta_opcua_opt(params, key);
    double r = dflt;
    char *end;

    if (v != NULL && *v != '\0')
    {
        r = strtod(v, &end);
        if (*end != '\0')
            r = dflt;
    }
    free(v);
    return r;
}

bool
ta_opcua_opt_bool(const char *params, const char *key, bool dflt)
{
    char *v = ta_opcua_opt(params, key);
    bool r = dflt;

    if (v != NULL)
        r = strcmp(v, "1") == 0 || strcmp(v, "true") == 0 ||
            strcmp(v, "yes") == 0 || *v == '\0';
    free(v);
    return r;
}

uint64_t
ta_opcua_now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000;
}

/* ---- NodeId ------------------------------------------------------- */

char *
nodeid_print(const UA_NodeId *id)
{
    UA_String s = UA_STRING_NULL;
    char *r;

    if (UA_NodeId_isNull(id))
        return strdup("");
    if (UA_NodeId_print(id, &s) != UA_STATUSCODE_GOOD)
        return strdup("");
    r = strndup((const char *)s.data, s.length);
    UA_String_clear(&s);
    return r;
}

int
nodeid_parse(const char *s, UA_NodeId *id)
{
    UA_NodeId_init(id);
    if (s == NULL || *s == '\0')
        return TA_OPCUA_EINVAL;
    return UA_NodeId_parse(id, UA_STRING((char *)s)) == UA_STATUSCODE_GOOD ?
           TA_OPCUA_OK : TA_OPCUA_EINVAL;
}

void
ts_print(ta_opcua_buf *b, const char *key, UA_DateTime t, bool has)
{
    if (has)
        buf_fieldf(b, key, "%" PRId64, (int64_t)t);
    else
        buf_field(b, key, "none");
}

/* ---- types -------------------------------------------------------- */

static const struct {
    const char *name;
    int         kind;   /* UA_TYPES_* index */
} type_names[] = {
    { "Boolean", UA_TYPES_BOOLEAN },
    { "SByte", UA_TYPES_SBYTE },
    { "Byte", UA_TYPES_BYTE },
    { "Int16", UA_TYPES_INT16 },
    { "UInt16", UA_TYPES_UINT16 },
    { "Int32", UA_TYPES_INT32 },
    { "UInt32", UA_TYPES_UINT32 },
    { "Int64", UA_TYPES_INT64 },
    { "UInt64", UA_TYPES_UINT64 },
    { "Float", UA_TYPES_FLOAT },
    { "Double", UA_TYPES_DOUBLE },
    { "String", UA_TYPES_STRING },
    { "DateTime", UA_TYPES_DATETIME },
    { "Guid", UA_TYPES_GUID },
    { "ByteString", UA_TYPES_BYTESTRING },
    { "XmlElement", UA_TYPES_XMLELEMENT },
    { "NodeId", UA_TYPES_NODEID },
    { "StatusCode", UA_TYPES_STATUSCODE },
    { "QualifiedName", UA_TYPES_QUALIFIEDNAME },
    { "LocalizedText", UA_TYPES_LOCALIZEDTEXT },
    { "ExtensionObject", UA_TYPES_EXTENSIONOBJECT },
};

const char *
val_type_name(const UA_DataType *t)
{
    size_t i;

    if (t == NULL)
        return "Null";
    for (i = 0; i < sizeof(type_names) / sizeof(type_names[0]); i++)
    {
        if (t == &UA_TYPES[type_names[i].kind])
            return type_names[i].name;
    }
    return "Opaque";
}

const UA_DataType *
val_type_by_name(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(type_names) / sizeof(type_names[0]); i++)
    {
        if (strcmp(name, type_names[i].name) == 0)
            return &UA_TYPES[type_names[i].kind];
    }
    return NULL;
}

static void
hex_add(ta_opcua_buf *b, const UA_Byte *d, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        buf_add(b, "%02x", d[i]);
}

static void
esc_add(ta_opcua_buf *b, const UA_Byte *d, size_t n)
{
    char *raw = strndup((const char *)(d != NULL ? (const char *)d : ""), n);
    char *e = raw != NULL ? ta_opcua_esc(raw) : NULL;

    buf_add(b, "%s", e != NULL ? e : "");
    free(e);
    free(raw);
}

/* One element of a value. */
static void
elem_print(ta_opcua_buf *b, const UA_DataType *t, const void *p)
{
    char *s;

    switch (t->typeKind)
    {
        case UA_DATATYPEKIND_BOOLEAN:
            buf_add(b, "%s", *(const UA_Boolean *)p ? "true" : "false");
            break;
        case UA_DATATYPEKIND_SBYTE:
            buf_add(b, "%d", *(const UA_SByte *)p);
            break;
        case UA_DATATYPEKIND_BYTE:
            buf_add(b, "%u", *(const UA_Byte *)p);
            break;
        case UA_DATATYPEKIND_INT16:
            buf_add(b, "%d", *(const UA_Int16 *)p);
            break;
        case UA_DATATYPEKIND_UINT16:
            buf_add(b, "%u", *(const UA_UInt16 *)p);
            break;
        case UA_DATATYPEKIND_INT32:
            buf_add(b, "%" PRId32, *(const UA_Int32 *)p);
            break;
        case UA_DATATYPEKIND_UINT32:
            buf_add(b, "%" PRIu32, *(const UA_UInt32 *)p);
            break;
        case UA_DATATYPEKIND_INT64:
            buf_add(b, "%" PRId64, *(const UA_Int64 *)p);
            break;
        case UA_DATATYPEKIND_UINT64:
            buf_add(b, "%" PRIu64, *(const UA_UInt64 *)p);
            break;
        case UA_DATATYPEKIND_FLOAT:
            buf_add(b, "%.9g", (double)*(const UA_Float *)p);
            break;
        case UA_DATATYPEKIND_DOUBLE:
            buf_add(b, "%.17g", *(const UA_Double *)p);
            break;
        case UA_DATATYPEKIND_STRING:
        case UA_DATATYPEKIND_XMLELEMENT:
        {
            const UA_String *str = p;

            esc_add(b, str->data, str->length);
            break;
        }
        case UA_DATATYPEKIND_DATETIME:
            buf_add(b, "%" PRId64, *(const UA_DateTime *)p);
            break;
        case UA_DATATYPEKIND_GUID:
        {
            UA_String g = UA_STRING_NULL;

            UA_Guid_print(p, &g);
            esc_add(b, g.data, g.length);
            UA_String_clear(&g);
            break;
        }
        case UA_DATATYPEKIND_BYTESTRING:
        {
            const UA_ByteString *bs = p;

            hex_add(b, bs->data, bs->length);
            break;
        }
        case UA_DATATYPEKIND_NODEID:
            s = nodeid_print(p);
            esc_add(b, (const UA_Byte *)s, strlen(s));
            free(s);
            break;
        case UA_DATATYPEKIND_STATUSCODE:
            buf_add(b, "0x%08" PRIX32, *(const UA_StatusCode *)p);
            break;
        case UA_DATATYPEKIND_QUALIFIEDNAME:
        {
            const UA_QualifiedName *qn = p;

            buf_add(b, "%u:", qn->namespaceIndex);
            esc_add(b, qn->name.data, qn->name.length);
            break;
        }
        case UA_DATATYPEKIND_LOCALIZEDTEXT:
        {
            const UA_LocalizedText *lt = p;

            esc_add(b, lt->locale.data, lt->locale.length);
            buf_add(b, "|");
            esc_add(b, lt->text.data, lt->text.length);
            break;
        }
        case UA_DATATYPEKIND_EXTENSIONOBJECT:
        {
            const UA_ExtensionObject *eo = p;

            if (eo->encoding == UA_EXTENSIONOBJECT_ENCODED_BYTESTRING ||
                eo->encoding == UA_EXTENSIONOBJECT_ENCODED_XML)
            {
                s = nodeid_print(&eo->content.encoded.typeId);
                esc_add(b, (const UA_Byte *)s, strlen(s));
                free(s);
                buf_add(b, "|");
                hex_add(b, eo->content.encoded.body.data,
                        eo->content.encoded.body.length);
            }
            else if (eo->encoding >= UA_EXTENSIONOBJECT_DECODED &&
                     eo->content.decoded.type != NULL)
            {
                UA_ByteString body = UA_BYTESTRING_NULL;

                s = nodeid_print(&eo->content.decoded.type->binaryEncodingId);
                esc_add(b, (const UA_Byte *)s, strlen(s));
                free(s);
                buf_add(b, "|");
                if (UA_encodeBinary(eo->content.decoded.data,
                                    eo->content.decoded.type, &body,
                                    NULL) == UA_STATUSCODE_GOOD)
                    hex_add(b, body.data, body.length);
                UA_ByteString_clear(&body);
            }
            else
            {
                buf_add(b, "|");
            }
            break;
        }
        default:
        {
            UA_ByteString body = UA_BYTESTRING_NULL;

            esc_add(b, (const UA_Byte *)t->typeName,
                    t->typeName != NULL ? strlen(t->typeName) : 0);
            buf_add(b, "|");
            if (UA_encodeBinary(p, t, &body, NULL) == UA_STATUSCODE_GOOD)
                hex_add(b, body.data, body.length);
            UA_ByteString_clear(&body);
            break;
        }
    }
}

char *
val_print(const UA_Variant *v)
{
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    const char *tn;
    size_t i;

    if (v == NULL || v->type == NULL)
        return strdup("Null:");
    tn = val_type_name(v->type);
    if (UA_Variant_isScalar(v))
    {
        buf_add(&b, "%s:", tn);
        elem_print(&b, v->type, v->data);
    }
    else
    {
        buf_add(&b, "%s[%zu]:", tn, v->arrayLength);
        for (i = 0; i < v->arrayLength; i++)
        {
            if (i > 0)
                buf_add(&b, ",");
            elem_print(&b, v->type,
                       (const char *)v->data + i * v->type->memSize);
        }
    }
    return buf_take(&b);
}

int
hex_to_bytes(const char *s, UA_ByteString *bs)
{
    size_t n = strlen(s);
    size_t i;

    UA_ByteString_init(bs);
    if (n % 2 != 0)
        return TA_OPCUA_EINVAL;
    if (n == 0)
        return TA_OPCUA_OK;
    if (UA_ByteString_allocBuffer(bs, n / 2) != UA_STATUSCODE_GOOD)
        return TA_OPCUA_ENOMEM;
    for (i = 0; i < n / 2; i++)
    {
        int hi = hexval(s[2 * i]);
        int lo = hexval(s[2 * i + 1]);

        if (hi < 0 || lo < 0)
        {
            UA_ByteString_clear(bs);
            return TA_OPCUA_EINVAL;
        }
        bs->data[i] = (UA_Byte)(hi * 16 + lo);
    }
    return TA_OPCUA_OK;
}

static int
hex_parse(const char *s, UA_ByteString *bs)
{
    return hex_to_bytes(s, bs);
}

static int
int_parse(const char *s, long long lo, long long hi, long long *r)
{
    char *end;

    errno = 0;
    *r = strtoll(s, &end, 0);
    if (*s == '\0' || *end != '\0' || errno != 0 || *r < lo || *r > hi)
        return TA_OPCUA_EINVAL;
    return TA_OPCUA_OK;
}

static int
uint_parse(const char *s, unsigned long long hi, unsigned long long *r)
{
    char *end;

    errno = 0;
    if (*s == '-')
        return TA_OPCUA_EINVAL;
    *r = strtoull(s, &end, 0);
    if (*s == '\0' || *end != '\0' || errno != 0 || *r > hi)
        return TA_OPCUA_EINVAL;
    return TA_OPCUA_OK;
}

/* Parse one escaped element @p e into @p p of type @p t. */
static int
elem_parse(char *e, const UA_DataType *t, void *p)
{
    long long i;
    unsigned long long u;
    char *bar;
    int rc = TA_OPCUA_OK;

#define INT_CASE(_kind, _ctype, _lo, _hi) \
        case _kind:                                              \
            rc = int_parse(ta_opcua_unesc(e), _lo, _hi, &i);     \
            *(_ctype *)p = (_ctype)i;                            \
            break
#define UINT_CASE(_kind, _ctype, _hi) \
        case _kind:                                              \
            rc = uint_parse(ta_opcua_unesc(e), _hi, &u);         \
            *(_ctype *)p = (_ctype)u;                            \
            break

    switch (t->typeKind)
    {
        case UA_DATATYPEKIND_BOOLEAN:
            ta_opcua_unesc(e);
            if (strcmp(e, "true") == 0 || strcmp(e, "1") == 0)
                *(UA_Boolean *)p = true;
            else if (strcmp(e, "false") == 0 || strcmp(e, "0") == 0)
                *(UA_Boolean *)p = false;
            else
                rc = TA_OPCUA_EINVAL;
            break;
        INT_CASE(UA_DATATYPEKIND_SBYTE, UA_SByte, -128, 127);
        UINT_CASE(UA_DATATYPEKIND_BYTE, UA_Byte, 255);
        INT_CASE(UA_DATATYPEKIND_INT16, UA_Int16, -32768, 32767);
        UINT_CASE(UA_DATATYPEKIND_UINT16, UA_UInt16, 65535);
        INT_CASE(UA_DATATYPEKIND_INT32, UA_Int32, INT32_MIN, INT32_MAX);
        UINT_CASE(UA_DATATYPEKIND_UINT32, UA_UInt32, UINT32_MAX);
        INT_CASE(UA_DATATYPEKIND_INT64, UA_Int64, INT64_MIN, INT64_MAX);
        UINT_CASE(UA_DATATYPEKIND_UINT64, UA_UInt64, UINT64_MAX);
        INT_CASE(UA_DATATYPEKIND_DATETIME, UA_DateTime, INT64_MIN, INT64_MAX);
        case UA_DATATYPEKIND_FLOAT:
        case UA_DATATYPEKIND_DOUBLE:
        {
            char *end;
            double d;

            ta_opcua_unesc(e);
            d = strtod(e, &end);
            if (*e == '\0' || *end != '\0')
                rc = TA_OPCUA_EINVAL;
            if (t->typeKind == UA_DATATYPEKIND_FLOAT)
                *(UA_Float *)p = (UA_Float)d;
            else
                *(UA_Double *)p = d;
            break;
        }
        case UA_DATATYPEKIND_STRING:
        case UA_DATATYPEKIND_XMLELEMENT:
            *(UA_String *)p = UA_STRING_ALLOC(ta_opcua_unesc(e));
            break;
        case UA_DATATYPEKIND_GUID:
            rc = UA_Guid_parse(p, UA_STRING(ta_opcua_unesc(e))) ==
                 UA_STATUSCODE_GOOD ? TA_OPCUA_OK : TA_OPCUA_EINVAL;
            break;
        case UA_DATATYPEKIND_BYTESTRING:
            rc = hex_parse(ta_opcua_unesc(e), p);
            break;
        case UA_DATATYPEKIND_NODEID:
            rc = nodeid_parse(ta_opcua_unesc(e), p);
            break;
        case UA_DATATYPEKIND_STATUSCODE:
            rc = uint_parse(ta_opcua_unesc(e), UINT32_MAX, &u);
            *(UA_StatusCode *)p = (UA_StatusCode)u;
            break;
        case UA_DATATYPEKIND_QUALIFIEDNAME:
        {
            UA_QualifiedName *qn = p;
            char *colon = strchr(e, ':');

            if (colon == NULL)
                return TA_OPCUA_EINVAL;
            *colon = '\0';
            rc = uint_parse(e, 65535, &u);
            qn->namespaceIndex = (UA_UInt16)u;
            qn->name = UA_STRING_ALLOC(ta_opcua_unesc(colon + 1));
            break;
        }
        case UA_DATATYPEKIND_LOCALIZEDTEXT:
        {
            UA_LocalizedText *lt = p;

            bar = strchr(e, '|');
            if (bar == NULL)
                return TA_OPCUA_EINVAL;
            *bar = '\0';
            lt->locale = UA_STRING_ALLOC(ta_opcua_unesc(e));
            lt->text = UA_STRING_ALLOC(ta_opcua_unesc(bar + 1));
            break;
        }
        case UA_DATATYPEKIND_EXTENSIONOBJECT:
        {
            UA_ExtensionObject *eo = p;

            bar = strchr(e, '|');
            if (bar == NULL)
                return TA_OPCUA_EINVAL;
            *bar = '\0';
            eo->encoding = UA_EXTENSIONOBJECT_ENCODED_BYTESTRING;
            rc = nodeid_parse(ta_opcua_unesc(e), &eo->content.encoded.typeId);
            if (rc == TA_OPCUA_OK)
                rc = hex_parse(bar + 1, &eo->content.encoded.body);
            break;
        }
        default:
            rc = TA_OPCUA_ENOTSUP;
            break;
    }
#undef INT_CASE
#undef UINT_CASE
    return rc;
}

int
val_parse(const char *s, UA_Variant *v)
{
    char *copy;
    char *colon;
    char *br;
    char *payload;
    const UA_DataType *t;
    bool array = false;
    size_t n = 1;
    size_t i;
    void *data = NULL;
    int rc = TA_OPCUA_OK;

    UA_Variant_init(v);
    if (s == NULL)
        return TA_OPCUA_EINVAL;
    copy = strdup(s);
    if (copy == NULL)
        return TA_OPCUA_ENOMEM;
    colon = strchr(copy, ':');
    if (colon == NULL)
    {
        free(copy);
        return TA_OPCUA_EINVAL;
    }
    *colon = '\0';
    payload = colon + 1;
    br = strchr(copy, '[');
    if (br != NULL)
    {
        unsigned long long len;

        array = true;
        *br = '\0';
        if (strchr(br + 1, ']') == NULL)
        {
            free(copy);
            return TA_OPCUA_EINVAL;
        }
        *strchr(br + 1, ']') = '\0';
        if (uint_parse(br + 1, 1u << 24, &len) != TA_OPCUA_OK)
        {
            free(copy);
            return TA_OPCUA_EINVAL;
        }
        n = (size_t)len;
    }
    if (strcmp(copy, "Null") == 0)
    {
        free(copy);
        return TA_OPCUA_OK;
    }
    t = val_type_by_name(copy);
    if (t == NULL)
    {
        free(copy);
        return TA_OPCUA_ENOTSUP;
    }

    data = UA_Array_new(n > 0 ? n : 1, t);
    if (data == NULL)
    {
        free(copy);
        return TA_OPCUA_ENOMEM;
    }
    if (!array)
    {
        rc = elem_parse(payload, t, data);
    }
    else
    {
        char *p = payload;

        for (i = 0; i < n && rc == TA_OPCUA_OK; i++)
        {
            char *comma = strchr(p, ',');

            if (comma == NULL && i + 1 < n)
            {
                rc = TA_OPCUA_EINVAL;
                break;
            }
            if (comma != NULL)
                *comma = '\0';
            rc = elem_parse(p, t, (char *)data + i * t->memSize);
            p = comma != NULL ? comma + 1 : p + strlen(p);
        }
        if (rc == TA_OPCUA_OK && n > 0 && *p != '\0')
            rc = TA_OPCUA_EINVAL;
    }
    if (rc != TA_OPCUA_OK)
    {
        UA_Array_delete(data, n > 0 ? n : 1, t);
        free(copy);
        return rc;
    }
    if (!array)
    {
        UA_Variant_setScalar(v, data, t);
    }
    else
    {
        if (n == 0)
        {
            UA_Array_delete(data, 1, t);
            data = UA_EMPTY_ARRAY_SENTINEL;
        }
        UA_Variant_setArray(v, data, n, t);
    }
    free(copy);
    return TA_OPCUA_OK;
}

void
dv_fields(ta_opcua_buf *b, const UA_DataValue *dv)
{
    char *val = val_print(dv->hasValue ? &dv->value : NULL);

    buf_field(b, "value", val);
    free(val);
    buf_fieldf(b, "status", "0x%08" PRIX32,
               dv->hasStatus ? dv->status : UA_STATUSCODE_GOOD);
    ts_print(b, "source_ts", dv->sourceTimestamp, dv->hasSourceTimestamp);
    ts_print(b, "server_ts", dv->serverTimestamp, dv->hasServerTimestamp);
    buf_fieldf(b, "source_ps", "%u",
               dv->hasSourcePicoseconds ? dv->sourcePicoseconds : 0);
    buf_fieldf(b, "server_ps", "%u",
               dv->hasServerPicoseconds ? dv->serverPicoseconds : 0);
}

/* ---- security policies -------------------------------------------- */

#define POLICY_BASE "http://opcfoundation.org/UA/SecurityPolicy#"

static const struct {
    const char *name;
    const char *uri;
} policies[] = {
    { "none", POLICY_BASE "None" },
    { "basic128rsa15", POLICY_BASE "Basic128Rsa15" },
    { "basic256", POLICY_BASE "Basic256" },
    { "basic256sha256", POLICY_BASE "Basic256Sha256" },
    { "aes128_sha256_rsaoaep", POLICY_BASE "Aes128_Sha256_RsaOaep" },
    { "aes256_sha256_rsapss", POLICY_BASE "Aes256_Sha256_RsaPss" },
};

const char *
policy_uri(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(policies) / sizeof(policies[0]); i++)
    {
        if (strcasecmp(name, policies[i].name) == 0 ||
            strcmp(name, policies[i].uri) == 0)
            return policies[i].uri;
    }
    return NULL;
}

const char *
policy_name(const UA_String *uri)
{
    size_t i;

    for (i = 0; i < sizeof(policies) / sizeof(policies[0]); i++)
    {
        if (uri->length == strlen(policies[i].uri) &&
            memcmp(uri->data, policies[i].uri, uri->length) == 0)
            return policies[i].name;
    }
    return "other";
}

const char *
mode_name(UA_MessageSecurityMode m)
{
    switch (m)
    {
        case UA_MESSAGESECURITYMODE_NONE: return "none";
        case UA_MESSAGESECURITYMODE_SIGN: return "sign";
        case UA_MESSAGESECURITYMODE_SIGNANDENCRYPT: return "signencrypt";
        default: return "invalid";
    }
}

int
mode_parse(const char *s, UA_MessageSecurityMode *m)
{
    if (s == NULL || *s == '\0' || strcmp(s, "any") == 0)
        *m = UA_MESSAGESECURITYMODE_INVALID;
    else if (strcmp(s, "none") == 0)
        *m = UA_MESSAGESECURITYMODE_NONE;
    else if (strcmp(s, "sign") == 0)
        *m = UA_MESSAGESECURITYMODE_SIGN;
    else if (strcmp(s, "signencrypt") == 0)
        *m = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    else
        return TA_OPCUA_EINVAL;
    return TA_OPCUA_OK;
}

/* ---- files -------------------------------------------------------- */

int
file_load(const char *path, UA_ByteString *bs)
{
    FILE *f = fopen(path, "rb");
    long n;

    UA_ByteString_init(bs);
    if (f == NULL)
        return TA_OPCUA_ENOENT;
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return TA_OPCUA_EFAIL;
    }
    if (n > 0 &&
        UA_ByteString_allocBuffer(bs, (size_t)n) != UA_STATUSCODE_GOOD)
    {
        fclose(f);
        return TA_OPCUA_ENOMEM;
    }
    if (n > 0 && fread(bs->data, 1, (size_t)n, f) != (size_t)n)
    {
        UA_ByteString_clear(bs);
        fclose(f);
        return TA_OPCUA_EFAIL;
    }
    fclose(f);
    return TA_OPCUA_OK;
}

int
file_list_load(const char *list, UA_ByteString **arr, size_t *n)
{
    char *copy;
    char *tok;
    char *save = NULL;
    int rc = TA_OPCUA_OK;

    *arr = NULL;
    *n = 0;
    if (list == NULL || *list == '\0')
        return TA_OPCUA_OK;
    copy = strdup(list);
    if (copy == NULL)
        return TA_OPCUA_ENOMEM;
    for (tok = strtok_r(copy, ",", &save); tok != NULL;
         tok = strtok_r(NULL, ",", &save))
    {
        UA_ByteString *na = realloc(*arr, (*n + 1) * sizeof(**arr));

        if (na == NULL)
        {
            rc = TA_OPCUA_ENOMEM;
            break;
        }
        *arr = na;
        rc = file_load(ta_opcua_unesc(tok), &(*arr)[*n]);
        if (rc != TA_OPCUA_OK)
            break;
        (*n)++;
    }
    free(copy);
    if (rc != TA_OPCUA_OK)
    {
        file_list_free(*arr, *n);
        *arr = NULL;
        *n = 0;
    }
    return rc;
}

void
file_list_free(UA_ByteString *arr, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        UA_ByteString_clear(&arr[i]);
    free(arr);
}
