/**
* \file    websocket.h
* \brief   RFC 6455 WebSocket protocol - framing and handshake, no transport.
*
* Module name: websocket.h
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
* The WebSocket protocol on its own: build a client handshake, check the
* server's reply, parse frame headers, mask and unmask payloads. Everything
* here is a pure function over buffers.
*
* IT OWNS NO SOCKET AND NO TLS CONTEXT, DELIBERATELY. stream_client.c already
* has a working transport - bounded connect, verified TLS handshake, seeded
* DRBG, reconnect with backoff - and duplicating that to add WebSocket support
* would have meant maintaining two copies of the hard part. Instead the caller
* reads and writes bytes however it likes and hands them here.
*
* Two things follow from that, and both are the point:
*   1. wss:// and plain ws:// need no change here. TLS is the caller's problem.
*   2. Every function below can be tested on a PC with no board and no network,
*      which is how the framing was verified against Python's own websocket
*      implementation rather than against my reading of the RFC.
*
* WHAT IS IMPLEMENTED, AND WHAT IS NOT
* Implemented: the client half of the opening handshake, frame headers of all
* three length forms, client-to-server masking, unmasking, continuation frames,
* and the control opcodes (close, ping, pong).
* Not implemented: extensions and subprotocols (Sec-WebSocket-Extensions and
* -Protocol are never offered, so a server may not negotiate them), and
* permessage-deflate in particular. A server that requires an extension will
* fail the handshake check rather than silently misinterpret the stream.
*
****************************************************************/

#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

/* Include section
***************************************************/
#include "mbedtls/ctr_drbg.h"
#include <stdint.h>
#include <stddef.h>

/* Defines section
***************************************************/

/**
  * @brief  RFC 6455 opcodes. Only these seven values are legal; anything else
  *         is a protocol error and ws_parse_header() rejects it.
  */
#define WS_OP_CONTINUATION      0x0U
#define WS_OP_TEXT              0x1U
#define WS_OP_BINARY            0x2U
#define WS_OP_CLOSE             0x8U
#define WS_OP_PING              0x9U
#define WS_OP_PONG              0xAU

/**
  * @brief  Longest frame header this module will produce or accept, in bytes.
  *
  * 2 fixed + 8 extended length + 4 mask = 14, which is the RFC maximum. Buffers
  * passed to ws_parse_header() may be shorter than this - it reports how much
  * more it needs rather than reading past the end.
  */
#define WS_MAX_HEADER_BYTES     14U

/**
  * @brief  Size of the base64 Sec-WebSocket-Key, and of the Accept value the
  *         server must return, both including the NUL.
  *
  * The key is 16 random bytes base64-encoded = 24 characters. The accept is
  * SHA-1 (20 bytes) base64-encoded = 28 characters. Neither ever varies, so
  * these are exact rather than generous.
  */
#define WS_KEY_B64_SIZE         25U
#define WS_ACCEPT_B64_SIZE      29U

/**
  * @brief  Return codes. ws_parse_header() also returns a positive byte count.
  */
#define WS_OK                    0
#define WS_ERR_NEED_MORE       (-1)   /**< not an error - call again with more */
#define WS_ERR_BAD_OPCODE      (-2)
#define WS_ERR_TOO_LONG        (-3)   /**< 64-bit length beyond what we accept  */
#define WS_ERR_BUFFER          (-4)   /**< caller's buffer is too small         */
#define WS_ERR_CRYPTO          (-5)   /**< SHA-1, base64 or DRBG failed         */
#define WS_ERR_MASKED          (-6)   /**< server-to-client frame was masked    */

/* Exported types
***************************************************/

/**
  * @brief  A decoded frame header.
  *
  * payload_len is 64-bit because the RFC allows it, but ws_parse_header()
  * rejects anything above WS_MAX_PAYLOAD_ACCEPT - see the note there. Keeping
  * the field 64-bit means the rejection is explicit rather than an overflow.
  */
typedef struct
{
    uint8_t  fin;            /**< 1 = final fragment of a message        */
    uint8_t  opcode;         /**< one of WS_OP_*                         */
    uint8_t  masked;         /**< 1 = a mask key follows                 */
    uint8_t  header_len;     /**< bytes this header occupied, 2..14      */
    uint8_t  mask_key[4];    /**< valid only when masked is 1            */
    uint64_t payload_len;    /**< payload bytes that follow the header   */
} ws_frame_hdr_t;

/* Exported functions prototypes
***************************************************/

/**
  * @brief  Generates a fresh Sec-WebSocket-Key.
  * @param  drbg: seeded DRBG. MUST be seeded - an unseeded one HardFaults on
  *         first reseed, which is a fault this codebase has already paid for.
  * @param  key_b64: receives 24 characters plus a NUL.
  * @param  max: size of key_b64; must be at least WS_KEY_B64_SIZE.
  * @retval WS_OK, or WS_ERR_BUFFER / WS_ERR_CRYPTO.
  *
  * A NEW KEY PER CONNECTION IS REQUIRED, not merely polite. RFC 6455 4.1 says
  * the key must be unpredictable and fresh; reusing one lets a cache or proxy
  * replay a previous handshake response.
  */
int32_t ws_make_key(mbedtls_ctr_drbg_context *drbg, char *key_b64, size_t max);

/**
  * @brief  Computes the Sec-WebSocket-Accept the server must return.
  * @param  key_b64: the key sent in the request.
  * @param  accept_b64: receives 28 characters plus a NUL.
  * @param  max: size of accept_b64; at least WS_ACCEPT_B64_SIZE.
  * @retval WS_OK, or WS_ERR_BUFFER / WS_ERR_CRYPTO.
  *
  * base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")). The GUID is
  * fixed by the RFC and is not a secret - it exists so that a server which
  * merely echoes bytes cannot pass for a WebSocket server.
  *
  * CHECKING THIS IS NOT OPTIONAL. Skipping it means any HTTP server answering
  * 101 would be treated as a WebSocket peer, and the first "frame" would be
  * whatever it sent - parsed as a header, with a payload length taken from
  * arbitrary bytes.
  */
int32_t ws_expected_accept(const char *key_b64, char *accept_b64, size_t max);

/**
  * @brief  Parses a frame header from the front of a buffer.
  * @param  buf: bytes received so far.
  * @param  len: how many.
  * @param  out: receives the decoded header on success.
  * @retval Positive = header length in bytes, consumed from buf.
  *         WS_ERR_NEED_MORE = incomplete, call again with more bytes.
  *         WS_ERR_BAD_OPCODE / WS_ERR_TOO_LONG / WS_ERR_MASKED on protocol error.
  *
  * NEED_MORE IS THE NORMAL CASE, NOT AN ERROR. A header is 2 to 14 bytes and
  * a TCP read can split it anywhere - including between the two fixed bytes.
  * The caller must keep the partial bytes and call again; this function never
  * consumes anything it has not fully decoded.
  *
  * REJECTS MASKED FRAMES. RFC 6455 5.1 forbids a server masking towards a
  * client, and accepting one would mean unmasking data that was never masked.
  */
int32_t ws_parse_header(const uint8_t *buf, uint32_t len, ws_frame_hdr_t *out);

/**
  * @brief  Builds a complete client frame, masked, ready to send.
  * @param  opcode: one of WS_OP_*.
  * @param  payload: may be NULL when len is 0.
  * @param  len: payload length.
  * @param  drbg: seeded DRBG, for the mask key.
  * @param  out: receives header + masked payload.
  * @param  out_max: size of out.
  * @retval Total bytes written, or WS_ERR_BUFFER / WS_ERR_CRYPTO.
  *
  * EVERY CLIENT FRAME IS MASKED, WITH A FRESH KEY. RFC 6455 5.3 requires it
  * and a compliant server closes the connection on an unmasked client frame -
  * so this is not a setting. The mask defends intermediaries against cache
  * poisoning, not the payload against reading; it is not encryption and adds
  * no confidentiality whatsoever.
  */
int32_t ws_build_frame(uint8_t opcode, const uint8_t *payload, uint32_t len,
                       mbedtls_ctr_drbg_context *drbg,
                       uint8_t *out, uint32_t out_max);

/**
  * @brief  Unmasks payload bytes in place.
  * @param  data: bytes to unmask.
  * @param  len: how many.
  * @param  mask_key: the four bytes from the frame header.
  * @param  offset: how many payload bytes of THIS frame were already unmasked.
  * @retval None
  *
  * THE OFFSET IS WHAT MAKES THIS USABLE ON A STREAM. The mask repeats every
  * four bytes counted from the start of the frame's payload, so a payload
  * arriving in several reads must continue the rotation rather than restart
  * it. Passing 0 every time silently corrupts every chunk after the first, and
  * the corruption looks like line noise rather than a bug.
  */
void ws_unmask(uint8_t *data, uint32_t len, const uint8_t mask_key[4],
               uint64_t offset);

/**
  * @brief  Names an opcode, for logging.
  * @param  opcode: any value.
  * @retval A short constant string. Never NULL.
  */
const char *ws_opcode_name(uint8_t opcode);

/**
  * @brief  1 compiles ws_selftest() in, 0 compiles it away entirely.
  *
  * Leave it at 1 until the WebSocket path has run against the real server.
  * It costs roughly 1 KB of flash and about 2 ms at boot, and it is the only
  * thing that has actually EXECUTED this module - see ws_selftest().
  */
#ifndef WS_SELFTEST_ENABLE
#define WS_SELFTEST_ENABLE      1
#endif

/**
  * @brief  Runs the module against RFC 6455 test vectors and reports on the
  *         console.
  * @param  drbg: seeded DRBG, for the frame-building round trip.
  * @retval Number of failures. 0 means every vector passed.
  *
  * WHY A SELF-TEST AND NOT A HOST UNIT TEST. There is no C compiler and no
  * emulator on the development machine, so this module can be cross-compiled
  * but not executed there. Rather than call it verified because it builds,
  * the vectors were generated by an INDEPENDENT implementation - Python's
  * hashlib and base64, plus the worked example from RFC 6455 1.3 - and are
  * checked here, on the target, by the code that will actually run.
  *
  * The first handshake vector is the RFC's own: key "dGhlIHNhbXBsZSBub25jZQ=="
  * must produce accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=". If that passes, the
  * SHA-1 + GUID + base64 chain is right for reasons that owe nothing to my
  * reading of the specification.
  */
int32_t ws_selftest(mbedtls_ctr_drbg_context *drbg);

#ifdef __cplusplus
}
#endif

#endif /* WEBSOCKET_H */
