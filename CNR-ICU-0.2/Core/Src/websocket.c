/**
* \file    websocket.c
* \brief   RFC 6455 WebSocket protocol - framing and handshake, no transport.
*
* This block opens with two stars and carries a \file tag rather than the
* four-star banner printed in GL11-C 2.4, because Doxygen ignores any block
* opening with three or more stars. Everything else follows 2.4 unchanged.
*
* Module name: websocket.c
*
* Copyright 2026 \@PINETICS as an unpublished work.
* All Rights Reserved.
*
* The information contained herein is confidential property of PINETICS. The
* user is prohibited from copying, transfer or disclosure of such information
* except by express written agreement with PINETICS.
*
* First written on 24-AUG-2026 by
*
* Module Description:
* See websocket.h for what this module is and why it owns no transport.
*
* ENDIANNESS (GL11-C 13.4). WebSocket extended payload lengths are BIG ENDIAN
* on the wire and this processor is little endian, so every multi-byte length
* is assembled and emitted BYTE BY BYTE below. No cast of a buffer pointer to
* uint16_t/uint64_t appears anywhere in this file, deliberately: such a cast
* would work on a big-endian target, fail here, and the symptom would be an
* absurd payload length rather than anything naming the cause. It would also
* be an unaligned access.
*
* APPROVED EXCEPTIONS (GL11-C 1.1)
* 1. Integer types. GL11-C 13.1 mandates uint8 / uint32 style typedefs. This
*    project uses the C99 <stdint.h> names together with mbedTLS's own types,
*    because every interface it calls is declared in those terms. Ruled by the
*    project owner on 12-08-2026.
*
****************************************************************/

/* Include section
***************************************************/
#include "websocket.h"

#include "mbedtls/sha1.h"
#include "mbedtls/base64.h"

#include <string.h>

/* Defines section
***************************************************/

/* RFC 6455 1.3. Appended to the client key before hashing. Not a secret - it
   is in the published standard - and its only job is to make the server prove
   it understands WebSocket rather than merely echoing bytes. */
#define WS_GUID  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* Random bytes behind the base64 key. RFC 6455 4.1 specifies 16 exactly. */
#define WS_KEY_RAW_BYTES        16U

/* SHA-1 output, which is what the accept value is base64 of. */
#define WS_SHA1_BYTES           20U

/**
  * @brief  Largest payload this module will accept in one frame.
  *
  * The RFC permits a 64-bit length. This refuses anything above 64 KiB, which
  * is far more than the 2048-byte MBEDTLS_SSL_IN_CONTENT_LEN this project can
  * receive in a single TLS record anyway.
  *
  * IT IS A REJECTION, NOT A TRUNCATION. A frame this module cannot handle is
  * reported as WS_ERR_TOO_LONG so the caller can close the connection.
  * Silently clamping the length would desynchronise the frame stream: the
  * next header would be read from the middle of a payload, and every frame
  * after it would be garbage with no indication of where it went wrong.
  */
#define WS_MAX_PAYLOAD_ACCEPT   65536ULL

/* Function Prototype section
***************************************************/
/* None - every function here is exported. */

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t ws_make_key(mbedtls_ctr_drbg_context *drbg,
*                                    char *key_b64, size_t max)
*    \return WS_OK, WS_ERR_BUFFER or WS_ERR_CRYPTO.
*    \param  drbg - a SEEDED DRBG.
*    \param  key_b64 - receives the base64 key.
*    \param  max - size of key_b64.
* \author
* \date 24-AUG-2026
* \brief Generates a fresh Sec-WebSocket-Key. See the header.
**************************************************/
int32_t ws_make_key(mbedtls_ctr_drbg_context *drbg, char *key_b64, size_t max)
{
    uint8_t raw[WS_KEY_RAW_BYTES];
    size_t  written = 0U;
    int32_t status = WS_OK;

    if ((drbg == NULL) || (key_b64 == NULL) || (max < WS_KEY_B64_SIZE))
    {
        status = WS_ERR_BUFFER;
    }
    else if (mbedtls_ctr_drbg_random(drbg, raw, sizeof(raw)) != 0)
    {
        status = WS_ERR_CRYPTO;
    }
    else if (mbedtls_base64_encode((unsigned char *)key_b64, max, &written,
                                   raw, sizeof(raw)) != 0)
    {
        status = WS_ERR_CRYPTO;
    }
    else
    {
        /* mbedtls_base64_encode NUL terminates, but written excludes the NUL.
           Terminating again costs nothing and does not depend on that. */
        key_b64[written] = '\0';
    }

    return status;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t ws_expected_accept(const char *key_b64,
*                                           char *accept_b64, size_t max)
*    \return WS_OK, WS_ERR_BUFFER or WS_ERR_CRYPTO.
*    \param  key_b64 - the key that was sent.
*    \param  accept_b64 - receives the expected accept value.
*    \param  max - size of accept_b64.
* \author
* \date 24-AUG-2026
* \brief base64(SHA-1(key + GUID)). See the header for why it must be checked.
**************************************************/
int32_t ws_expected_accept(const char *key_b64, char *accept_b64, size_t max)
{
    mbedtls_sha1_context ctx;
    uint8_t  digest[WS_SHA1_BYTES];
    size_t   written = 0U;
    size_t   key_len;
    int32_t  status = WS_OK;

    if ((key_b64 == NULL) || (accept_b64 == NULL) || (max < WS_ACCEPT_B64_SIZE))
    {
        return WS_ERR_BUFFER;
    }
    else
    {
        /* Arguments usable. */
    }

    key_len = strlen(key_b64);

    mbedtls_sha1_init(&ctx);

    /* mbedtls_sha1_starts_ret / _update_ret / _finish_ret - the _ret forms.
       The older void-returning names are deprecated in mbedTLS 2.x and absent
       in 3.x, and they hide exactly the failures this chain must not ignore. */
    if (mbedtls_sha1_starts_ret(&ctx) != 0)
    {
        status = WS_ERR_CRYPTO;
    }
    else if (mbedtls_sha1_update_ret(&ctx, (const unsigned char *)key_b64,
                                     key_len) != 0)
    {
        status = WS_ERR_CRYPTO;
    }
    else if (mbedtls_sha1_update_ret(&ctx, (const unsigned char *)WS_GUID,
                                     sizeof(WS_GUID) - 1U) != 0)
    {
        /* sizeof - 1 to drop the NUL. strlen would give the same answer at
           run time; sizeof gives it at compile time on a literal. */
        status = WS_ERR_CRYPTO;
    }
    else if (mbedtls_sha1_finish_ret(&ctx, digest) != 0)
    {
        status = WS_ERR_CRYPTO;
    }
    else if (mbedtls_base64_encode((unsigned char *)accept_b64, max, &written,
                                   digest, sizeof(digest)) != 0)
    {
        status = WS_ERR_CRYPTO;
    }
    else
    {
        accept_b64[written] = '\0';
    }

    mbedtls_sha1_free(&ctx);

    return status;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t ws_parse_header(const uint8_t *buf, uint32_t len,
*                                        ws_frame_hdr_t *out)
*    \return Header length in bytes, or a negative WS_ERR_*.
*    \param  buf - bytes received so far.
*    \param  len - how many.
*    \param  out - receives the decoded header.
* \author
* \date 24-AUG-2026
* \brief Decodes a frame header. WS_ERR_NEED_MORE is normal - see the header.
**************************************************/
int32_t ws_parse_header(const uint8_t *buf, uint32_t len, ws_frame_hdr_t *out)
{
    uint32_t need = 2U;          /* the two fixed bytes, always present */
    uint8_t  len7;
    uint32_t i;

    if ((buf == NULL) || (out == NULL))
    {
        return WS_ERR_BUFFER;
    }
    else
    {
        /* Arguments usable. */
    }

    if (len < need)
    {
        return WS_ERR_NEED_MORE;
    }
    else
    {
        /* At least the fixed part is present. */
    }

    out->fin    = ((buf[0] & 0x80U) != 0U) ? 1U : 0U;
    out->opcode = (uint8_t)(buf[0] & 0x0FU);
    out->masked = ((buf[1] & 0x80U) != 0U) ? 1U : 0U;
    len7        = (uint8_t)(buf[1] & 0x7FU);

    /* RSV1-3 must be zero unless an extension negotiated them, and this client
       offers no extensions - so a set bit means the peer is speaking something
       we did not agree to. Treated as a bad frame rather than ignored, because
       permessage-deflate sets RSV1 and its payload is compressed: ignoring the
       bit would hand compressed bytes to the UART as if they were data. */
    if ((buf[0] & 0x70U) != 0U)
    {
        return WS_ERR_BAD_OPCODE;
    }
    else
    {
        /* No reserved bits set. */
    }

    switch (out->opcode)
    {
        case WS_OP_CONTINUATION:
        case WS_OP_TEXT:
        case WS_OP_BINARY:
        case WS_OP_CLOSE:
        case WS_OP_PING:
        case WS_OP_PONG:
            break;
        default:
            return WS_ERR_BAD_OPCODE;
    }

    /* A SERVER MUST NOT MASK. RFC 6455 5.1. Accepting one would mean applying
       an unmask to bytes that were never masked. */
    if (out->masked != 0U)
    {
        return WS_ERR_MASKED;
    }
    else
    {
        /* Unmasked, as required. */
    }

    /* Control frames carry at most 125 bytes and are never fragmented -
       RFC 6455 5.5. A control frame claiming an extended length is malformed,
       and letting it through would mean waiting for a payload the peer is not
       going to send. */
    if (((out->opcode & 0x08U) != 0U) && ((len7 > 125U) || (out->fin == 0U)))
    {
        return WS_ERR_BAD_OPCODE;
    }
    else
    {
        /* Either a data frame, or a well-formed control frame. */
    }

    /* THE THREE LENGTH FORMS, assembled byte by byte because the wire is big
       endian and this processor is not - see the endianness note at the top. */
    if (len7 < 126U)
    {
        out->payload_len = (uint64_t)len7;
    }
    else if (len7 == 126U)
    {
        need += 2U;
        if (len < need)
        {
            return WS_ERR_NEED_MORE;
        }
        else
        {
            out->payload_len = ((uint64_t)buf[2] << 8) | (uint64_t)buf[3];
        }
    }
    else
    {
        need += 8U;
        if (len < need)
        {
            return WS_ERR_NEED_MORE;
        }
        else
        {
            out->payload_len = 0U;
            for (i = 0U; i < 8U; i++)
            {
                out->payload_len = (out->payload_len << 8) | (uint64_t)buf[2U + i];
            }

            /* The RFC reserves the top bit of a 64-bit length; a peer setting
               it is malformed. Checked before the size limit so the message is
               about the right fault. */
            if ((buf[2] & 0x80U) != 0U)
            {
                return WS_ERR_TOO_LONG;
            }
            else
            {
                /* Top bit clear, as required. */
            }
        }
    }

    if (out->payload_len > WS_MAX_PAYLOAD_ACCEPT)
    {
        return WS_ERR_TOO_LONG;
    }
    else
    {
        /* Within what this module will handle. */
    }

    /* No mask key can follow, because a masked server frame was rejected
       above. The field is zeroed so a caller that reads it regardless does
       not act on whatever was in the struct beforehand. */
    (void)memset(out->mask_key, 0, sizeof(out->mask_key));

    out->header_len = (uint8_t)need;

    return (int32_t)need;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t ws_build_frame(uint8_t opcode,
*                                       const uint8_t *payload, uint32_t len,
*                                       mbedtls_ctr_drbg_context *drbg,
*                                       uint8_t *out, uint32_t out_max)
*    \return Bytes written, or a negative WS_ERR_*.
*    \param  opcode - one of WS_OP_*.
*    \param  payload - may be NULL when len is 0.
*    \param  len - payload length.
*    \param  drbg - a SEEDED DRBG, for the mask key.
*    \param  out - receives header plus masked payload.
*    \param  out_max - size of out.
* \author
* \date 24-AUG-2026
* \brief Builds one masked client frame. See the header on why masking is
*        mandatory and why it is not encryption.
**************************************************/
int32_t ws_build_frame(uint8_t opcode, const uint8_t *payload, uint32_t len,
                       mbedtls_ctr_drbg_context *drbg,
                       uint8_t *out, uint32_t out_max)
{
    uint8_t  mask[4];
    uint32_t pos = 0U;
    uint32_t i;

    if ((out == NULL) || (drbg == NULL) || ((payload == NULL) && (len > 0U)))
    {
        return WS_ERR_BUFFER;
    }
    else
    {
        /* Arguments usable. */
    }

    /* Control frames: at most 125 bytes, always final. Enforced on the way out
       as well as the way in, so this module cannot itself emit a frame it
       would reject. */
    if (((opcode & 0x08U) != 0U) && (len > 125U))
    {
        return WS_ERR_BUFFER;
    }
    else
    {
        /* Fine. */
    }

    if (mbedtls_ctr_drbg_random(drbg, mask, sizeof(mask)) != 0)
    {
        return WS_ERR_CRYPTO;
    }
    else
    {
        /* Fresh mask key obtained. */
    }

    /* FIN set: this module never fragments what it sends. The frames it emits
       are pings, pongs, closes and short application messages, none of which
       benefit from fragmentation. */
    if (out_max < 2U)
    {
        return WS_ERR_BUFFER;
    }
    else
    {
        out[pos] = (uint8_t)(0x80U | (opcode & 0x0FU));
        pos++;
    }

    /* Mask bit always set - see the header. */
    if (len < 126U)
    {
        out[pos] = (uint8_t)(0x80U | (uint8_t)len);
        pos++;
    }
    else if (len <= 0xFFFFU)
    {
        if (out_max < (pos + 3U))
        {
            return WS_ERR_BUFFER;
        }
        else
        {
            out[pos] = 0x80U | 126U;                     pos++;
            out[pos] = (uint8_t)((len >> 8) & 0xFFU);    pos++;
            out[pos] = (uint8_t)(len & 0xFFU);           pos++;
        }
    }
    else
    {
        if (out_max < (pos + 9U))
        {
            return WS_ERR_BUFFER;
        }
        else
        {
            out[pos] = 0x80U | 127U;                     pos++;
            /* Big endian, byte by byte. len is 32-bit so the top four bytes
               are always zero - written explicitly rather than assumed. */
            out[pos] = 0U; pos++;
            out[pos] = 0U; pos++;
            out[pos] = 0U; pos++;
            out[pos] = 0U; pos++;
            out[pos] = (uint8_t)((len >> 24) & 0xFFU);   pos++;
            out[pos] = (uint8_t)((len >> 16) & 0xFFU);   pos++;
            out[pos] = (uint8_t)((len >> 8) & 0xFFU);    pos++;
            out[pos] = (uint8_t)(len & 0xFFU);           pos++;
        }
    }

    if (out_max < (pos + 4U + len))
    {
        return WS_ERR_BUFFER;
    }
    else
    {
        /* Room for the mask key and the payload. */
    }

    for (i = 0U; i < 4U; i++)
    {
        out[pos] = mask[i];
        pos++;
    }

    /* Mask as it is copied. The rotation starts at 0 because this is the whole
       payload of a single frame - the offset argument that ws_unmask() needs
       exists for the receive side, where a payload arrives in pieces. */
    for (i = 0U; i < len; i++)
    {
        out[pos] = (uint8_t)(payload[i] ^ mask[i & 3U]);
        pos++;
    }

    return (int32_t)pos;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: void ws_unmask(uint8_t *data, uint32_t len,
*                               const uint8_t mask_key[4], uint64_t offset)
*    \return void
*    \param  data - bytes to unmask, in place.
*    \param  len - how many.
*    \param  mask_key - the four bytes from the frame header.
*    \param  offset - payload bytes of this frame already unmasked.
* \author
* \date 24-AUG-2026
* \brief Unmasks in place, continuing the rotation from offset. See the header
*        for why the offset matters on a stream.
**************************************************/
void ws_unmask(uint8_t *data, uint32_t len, const uint8_t mask_key[4],
               uint64_t offset)
{
    uint32_t i;

    if ((data == NULL) || (mask_key == NULL))
    {
        return;
    }
    else
    {
        /* Arguments usable. */
    }

    for (i = 0U; i < len; i++)
    {
        /* & 3 rather than % 4: identical for a power of two, and does not
           depend on the compiler recognising the strength reduction. */
        data[i] = (uint8_t)(data[i] ^ mask_key[(offset + (uint64_t)i) & 3U]);
    }
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: const char *ws_opcode_name(uint8_t opcode)
*    \return A short constant string. Never NULL.
*    \param  opcode - any value.
* \author
* \date 24-AUG-2026
* \brief Names an opcode for logging.
**************************************************/
const char *ws_opcode_name(uint8_t opcode)
{
    const char *name;

    switch (opcode)
    {
        case WS_OP_CONTINUATION: name = "CONT";   break;
        case WS_OP_TEXT:         name = "TEXT";   break;
        case WS_OP_BINARY:       name = "BINARY"; break;
        case WS_OP_CLOSE:        name = "CLOSE";  break;
        case WS_OP_PING:         name = "PING";   break;
        case WS_OP_PONG:         name = "PONG";   break;
        default:                 name = "?";      break;
    }

    return name;
}

#if WS_SELFTEST_ENABLE

#include <stdio.h>

/* ==========================================================================
 * SELF-TEST.  See the note at ws_selftest() in websocket.h for why this
 * exists rather than a host unit test.
 * ==========================================================================
 * Every constant below was produced by an independent implementation, not by
 * this module and not by hand. The handshake pairs come from Python's hashlib
 * and base64 - and the first is the worked example in RFC 6455 section 1.3.
 * The header bytes and the masked payload were emitted by a Python script
 * following the RFC's wire format directly.
 * ======================================================================= */

/* RFC 6455 1.3 first, then two more from Python's hashlib. */
static const char *const WS_TEST_KEYS[] = {
    "dGhlIHNhbXBsZSBub25jZQ==",
    "x3JJHMbDL1EzLkh9GBhXDw==",
    "AAAAAAAAAAAAAAAAAAAAAA=="
};
static const char *const WS_TEST_ACCEPTS[] = {
    "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
    "HSmrc0sMlYUkAGmm5OPpG2HaGWk=",
    "ICX+Yqv66kxgM0FcWaLWlFLwTAI="
};

/* One decoded header expectation per wire pattern. */
typedef struct
{
    uint8_t  wire[10];
    uint8_t  wire_len;
    uint8_t  fin;
    uint8_t  opcode;
    uint32_t payload_len;
    uint8_t  header_len;
    const char *why;
} ws_hdr_case_t;

static const ws_hdr_case_t WS_HDR_CASES[] = {
    { {0x82,0x05},                                    2, 1, 0x2,     5,  2, "binary, tiny" },
    { {0x81,0x7D},                                    2, 1, 0x1,   125,  2, "text, largest 7-bit" },
    { {0x82,0x7E,0x00,0x7E},                          4, 1, 0x2,   126,  4, "smallest 16-bit form" },
    { {0x82,0x7E,0xFF,0xFF},                          4, 1, 0x2, 65535,  4, "largest 16-bit form" },
    { {0x82,0x7F,0,0,0,0,0,0x01,0x00,0x00},          10, 1, 0x2, 65536, 10, "smallest 64-bit form" },
    { {0x02,0x0A},                                    2, 0, 0x2,    10,  2, "NOT final - fragment" },
    { {0x80,0x07},                                    2, 1, 0x0,     7,  2, "continuation" },
    { {0x89,0x00},                                    2, 1, 0x9,     0,  2, "ping, empty" },
    { {0x88,0x02},                                    2, 1, 0x8,     2,  2, "close with status" }
};

/* "Hello From PINETICS!!!" masked with 37 FA 21 3D, per the RFC's algorithm. */
static const uint8_t WS_TEST_PLAIN[] = {
    0x48,0x65,0x6C,0x6C,0x6F,0x20,0x46,0x72,0x6F,0x6D,0x20,
    0x50,0x49,0x4E,0x45,0x54,0x49,0x43,0x53,0x21,0x21,0x21
};
static const uint8_t WS_TEST_MASK[4]  = { 0x37, 0xFA, 0x21, 0x3D };
static const uint8_t WS_TEST_MASKED[] = {
    0x7F,0x9F,0x4D,0x51,0x58,0xDA,0x67,0x4F,0x58,0x97,0x01,
    0x6D,0x7E,0xB4,0x64,0x69,0x7E,0xB9,0x72,0x1C,0x16,0xDB
};

int32_t ws_selftest(mbedtls_ctr_drbg_context *drbg)
{
    int32_t  failures = 0;
    uint32_t i;

    printf("ws: self-test - RFC 6455 vectors\r\n");

    /* ---- 1. handshake ---------------------------------------------------
       If the first of these passes, the SHA-1 + GUID + base64 chain is right
       against the specification's own worked example. */
    for (i = 0U; i < (sizeof(WS_TEST_KEYS) / sizeof(WS_TEST_KEYS[0])); i++)
    {
        char got[WS_ACCEPT_B64_SIZE];

        if (ws_expected_accept(WS_TEST_KEYS[i], got, sizeof(got)) != WS_OK)
        {
            printf("ws:   FAIL accept[%lu] returned an error\r\n",
                   (unsigned long)i);
            failures++;
        }
        else if (strcmp(got, WS_TEST_ACCEPTS[i]) != 0)
        {
            printf("ws:   FAIL accept[%lu] got %s want %s\r\n",
                   (unsigned long)i, got, WS_TEST_ACCEPTS[i]);
            failures++;
        }
        else
        {
            /* Matches. */
        }
    }

    /* ---- 2. header decoding --------------------------------------------- */
    for (i = 0U; i < (sizeof(WS_HDR_CASES) / sizeof(WS_HDR_CASES[0])); i++)
    {
        const ws_hdr_case_t *c = &WS_HDR_CASES[i];
        ws_frame_hdr_t h;
        int32_t rc = ws_parse_header(c->wire, c->wire_len, &h);

        if ((rc != (int32_t)c->header_len)
            || (h.fin != c->fin) || (h.opcode != c->opcode)
            || (h.payload_len != (uint64_t)c->payload_len))
        {
            printf("ws:   FAIL header \"%s\": rc=%ld fin=%u op=0x%X len=%lu\r\n",
                   c->why, (long)rc, (unsigned)h.fin, (unsigned)h.opcode,
                   (unsigned long)h.payload_len);
            failures++;
        }
        else
        {
            /* Decoded as expected. */
        }

        /* EVERY TRUNCATION MUST SAY NEED_MORE, not guess. A TCP read can split
           a header anywhere, including between the two fixed bytes, and a
           parser that returns something plausible from a partial header
           desynchronises the whole stream. */
        {
            uint32_t cut;

            for (cut = 0U; cut < c->wire_len; cut++)
            {
                if (ws_parse_header(c->wire, cut, &h) != WS_ERR_NEED_MORE)
                {
                    printf("ws:   FAIL \"%s\" accepted a %lu-byte partial "
                           "header\r\n", c->why, (unsigned long)cut);
                    failures++;
                }
                else
                {
                    /* Correctly asked for more. */
                }
            }
        }
    }

    /* ---- 3. frames that must be REJECTED --------------------------------- */
    {
        ws_frame_hdr_t h;
        /* A masked server frame - RFC 6455 5.1 forbids it. */
        const uint8_t masked_srv[]  = { 0x82, 0x85, 0, 0, 0, 0 };
        /* Opcode 0x3 is reserved. */
        const uint8_t bad_opcode[]  = { 0x83, 0x00 };
        /* RSV1 set - permessage-deflate, which was never negotiated. */
        const uint8_t rsv_set[]     = { 0xC2, 0x05 };
        /* A ping claiming 200 bytes; control frames cap at 125. */
        const uint8_t fat_control[] = { 0x89, 0x7E, 0x00, 0xC8 };

        if (ws_parse_header(masked_srv, sizeof(masked_srv), &h) != WS_ERR_MASKED)
        {
            printf("ws:   FAIL a masked server frame was accepted\r\n");
            failures++;
        }
        if (ws_parse_header(bad_opcode, sizeof(bad_opcode), &h)
            != WS_ERR_BAD_OPCODE)
        {
            printf("ws:   FAIL reserved opcode 0x3 was accepted\r\n");
            failures++;
        }
        if (ws_parse_header(rsv_set, sizeof(rsv_set), &h) != WS_ERR_BAD_OPCODE)
        {
            printf("ws:   FAIL RSV1 was ignored - compressed data would reach "
                   "the UART as payload\r\n");
            failures++;
        }
        if (ws_parse_header(fat_control, sizeof(fat_control), &h)
            != WS_ERR_BAD_OPCODE)
        {
            printf("ws:   FAIL an oversized control frame was accepted\r\n");
            failures++;
        }
    }

    /* ---- 4. unmasking, in one piece and in three ------------------------- */
    {
        uint8_t  buf[sizeof(WS_TEST_MASKED)];
        uint32_t split[3] = { 7U, 9U, 6U };
        uint32_t pos = 0U;
        uint64_t off = 0U;
        uint32_t k;

        (void)memcpy(buf, WS_TEST_MASKED, sizeof(buf));
        ws_unmask(buf, (uint32_t)sizeof(buf), WS_TEST_MASK, 0U);
        if (memcmp(buf, WS_TEST_PLAIN, sizeof(buf)) != 0)
        {
            printf("ws:   FAIL unmask in one piece\r\n");
            failures++;
        }

        /* THE OFFSET CASE. Unmasking a payload that arrived in three reads
           must give the same answer as one read. An implementation that
           restarts the rotation gets the first chunk right and turns
           everything after it into line noise - which reads as a hardware
           fault rather than a software one. */
        (void)memcpy(buf, WS_TEST_MASKED, sizeof(buf));
        for (k = 0U; k < 3U; k++)
        {
            ws_unmask(&buf[pos], split[k], WS_TEST_MASK, off);
            pos += split[k];
            off += (uint64_t)split[k];
        }
        if (memcmp(buf, WS_TEST_PLAIN, sizeof(buf)) != 0)
        {
            printf("ws:   FAIL unmask split 7/9/6 - the offset is not being "
                   "carried between chunks\r\n");
            failures++;
        }
    }

    /* ---- 5. build then decode, a round trip ------------------------------ */
    if (drbg != NULL)
    {
        uint8_t frame[64];
        int32_t n = ws_build_frame(WS_OP_BINARY, WS_TEST_PLAIN,
                                   (uint32_t)sizeof(WS_TEST_PLAIN),
                                   drbg, frame, (uint32_t)sizeof(frame));

        if (n <= 0)
        {
            printf("ws:   FAIL build_frame returned %ld\r\n", (long)n);
            failures++;
        }
        else
        {
            /* The frame we built is MASKED, so ws_parse_header() will refuse
               it - correctly, since it only accepts server-to-client frames.
               Decode the pieces directly instead: bit 7 of byte 1 set, length
               in the low 7 bits, then the mask key, then the payload. */
            uint8_t  mask[4];
            uint8_t  body[sizeof(WS_TEST_PLAIN)];
            uint32_t hdr_len = 2U;

            if (((frame[1] & 0x80U) == 0U)
                || ((frame[1] & 0x7FU) != sizeof(WS_TEST_PLAIN)))
            {
                printf("ws:   FAIL built frame is unmasked or mis-sized\r\n");
                failures++;
            }
            else
            {
                (void)memcpy(mask, &frame[hdr_len], 4U);
                (void)memcpy(body, &frame[hdr_len + 4U], sizeof(body));
                ws_unmask(body, (uint32_t)sizeof(body), mask, 0U);
                if (memcmp(body, WS_TEST_PLAIN, sizeof(body)) != 0)
                {
                    printf("ws:   FAIL build/unmask round trip\r\n");
                    failures++;
                }
            }
        }
    }
    else
    {
        printf("ws:   (round trip skipped - no DRBG supplied)\r\n");
    }

    if (failures == 0)
    {
        printf("ws: self-test PASSED - all vectors match\r\n");
    }
    else
    {
        printf("ws: *** self-test FAILED - %ld problem(s) above ***\r\n",
               (long)failures);
        printf("ws:     the WebSocket path must not be trusted until these "
               "pass.\r\n");
    }

    return failures;
}

#endif /* WS_SELFTEST_ENABLE */
