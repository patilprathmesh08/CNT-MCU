/**
  ******************************************************************************
  * @file    json_parser.h
  * @brief   Streaming extractor that pulls several named fields out of a
  *          continuous JSON object stream
  * @version 2.0 - 27-08-2026 (single field -> field table)
  *
  * Feed it whatever bytes arrive off the network, in whatever sizes they arrive.
  * For every complete JSON object it sees, it emits the value of each field in
  * the caller's table, as the EXACT characters that were on the wire,
  * terminated with CR LF. Each value is tagged with its field index so the
  * caller can route it:
  *
  *     in : {"message_type":"joystick_controller","sequence_id":18,
  *           "ntp_time":1787819915.843,
  *           "controller_to_base_station_received_ntp_time":1787819915.830,
  *           "joystick_x":0,"joystick_y":0}
  *
  *     out: field 0 -> "18,1787819915.843\r\n"
  *          field 1 -> "18,1787819915.830\r\n"
  *          field 2 -> "18,0\r\n"
  *          field 3 -> "18,0\r\n"
  *
  * THE LEADING 18 IS sequence_id, configured as the prefix key. Every emitted
  * line carries it, which is what lets a receiver correlate four separate UART
  * streams back into one sample. Without it the four are four independent
  * streams that merely happen to arrive at similar times - and if any one UART
  * ever drops a line, nothing downstream could detect the resulting skew.
  *
  * It is read ONCE per object and reused for all four fields, so the four
  * cannot disagree about which sample they describe.
  *
  * THIS MODULE KNOWS NOTHING ABOUT UARTs. It reports a field index; mapping
  * index to peripheral is the caller's business, and lives in stream_client.c.
  * Keeping that out of here is what lets the same parser serve a different
  * destination set without being touched.
  *
  * ===========================================================================
  * THE DECOY KEY - why every key in the table carries its own quotes
  * ===========================================================================
  * "controller_to_base_station_received_ntp_time" ENDS WITH the characters
  * "ntp_time". Searching for the bare word therefore matches the wrong field,
  * and because the two carry timestamps about 13 ms apart the output stays
  * perfectly well-formed - just wrong. Nothing downstream can tell.
  *
  * THE FIX IS ONE CHARACTER: search for the key WITH its opening quote. Inside
  * the decoy the character before ntp_time is an underscore, never a quote, so
  * the quoted form cannot match it.
  *
  * Verified 27-08-2026 against a reference model, including the case where the
  * server emits the two fields in the OPPOSITE order: matching is
  * order-independent, so the table needs no longest-key-first sorting.
  *
  * ===========================================================================
  * THE VALUE IS NEVER CONVERTED TO A NUMBER
  * ===========================================================================
  * 1787819915.843 needs 41 bits of mantissa. A 32-bit float has 24, so
  * strtof() returns 1787819904 - and the same for 1787819915.830, meaning the
  * two DIFFERENT timestamps both collapse to the SAME value, four digits gone.
  * Measured, not assumed, on 27-08-2026.
  *
  * So no conversion happens at all: value characters are COPIED from the
  * receive buffer to the output. What the server sent is what the UART carries,
  * to the digit. This also means a negative or exponent-form value passes
  * through untouched.
  *
  * ===========================================================================
  * NETWORK BOUNDARIES MEAN NOTHING
  * ===========================================================================
  * A TLS record, a WebSocket frame and a JSON object are three unrelated
  * framings sharing one byte stream. A single read can deliver half an object,
  * three objects, or two and a half. This module is therefore a byte-at-a-time
  * state machine holding a reassembly buffer ACROSS calls - see
  * json_parser_feed(). It never treats a call boundary as an object boundary.
  *
  * Object boundaries come from BRACE DEPTH, not newlines. The sample stream
  * happens to put one object per line but nothing guarantees it, and a newline
  * is not part of JSON's grammar. Depth counting is string-aware and
  * escape-aware, so a brace inside a quoted string - "text":"a{b" - does not
  * corrupt the count. Bytes before the first '{' are discarded, which is also
  * how the parser recovers from joining a stream mid-object.
  *
  * ===========================================================================
  * FAILURE BEHAVIOUR
  * ===========================================================================
  * An object longer than JSON_PARSER_OBJ_MAX cannot be buffered. Rather than
  * emit a truncated value - which would look like real data - the object is
  * dropped, json_parser_overflows is incremented, and the parser resynchronises
  * at the next '{'. A field absent from an object simply produces no output for
  * that field; the others are still emitted. Nothing wrong ever reaches a UART.
  ******************************************************************************
  */

#ifndef __JSON_PARSER_H__
#define __JSON_PARSER_H__

#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------- */

/* Most fields that may be extracted from one object. Four are used today. */
#define JSON_PARSER_FIELD_MAX    8U

/* Largest complete JSON object that can be reassembled. Costs exactly this many
   bytes of .bss, once - one stream means one parser instance.

   RAISED FROM 512 TO 1024 ON 10-09-2026, and this is worth reading before it is
   ever lowered again.

   The original 512 was chosen against a server message of about 170 bytes. The
   server has since added motor_1_pos..motor_4_insertion_pos, five button_*
   flags and several timing fields, taking the live object to 610 bytes. Every
   object therefore overflowed, was dropped by design, and NOTHING reached the
   four UARTs.

   WHAT THAT LOOKED LIKE FROM THE OUTSIDE, and why it cost a day: the WebSocket
   connected, the frames printed perfectly on the VCOM - that dump happens
   BEFORE the parser - and the only visible symptom was the PE9 scope trigger
   sitting permanently HIGH, because the pin is dropped by the object-complete
   hook that a dropped object never reaches. It was investigated twice as a GPIO
   fault. The parser was working exactly as specified; the buffer was simply too
   small, and it said so only in a counter nobody was reading.

   1024 gives 414 bytes of headroom on today's message. json_parser_obj_len_max
   reports the largest object actually seen, so the next resize is a measurement
   rather than a guess, and the overflow is now announced on the console. */
#define JSON_PARSER_OBJ_MAX      1024U

/* Longest value string accepted, generous against "1787819915.843" at 14. Also
   the guard that stops a malformed object with a long run of digits from
   overflowing the output buffer. */
#define JSON_PARSER_VALUE_MAX    48U

/* Character placed between the prefix value and the field value. A comma keeps
   each line trivially splittable by any receiver, including a spreadsheet. */
#define JSON_PARSER_PREFIX_SEP   ','

/* ===========================================================================
 * EMIT THE FIELD NAME AS A COLUMN.  Added 10-09-2026.
 * ===========================================================================
 * 1  "<sequence_id>,<field_name>,<value>" - self-describing, so a capture can
 *    be read without knowing which port it came from. This matters now that
 *    the four UARTs carry four MOTOR POSITIONS rather than two timestamps and
 *    two joystick axes: the four motor values are the same shape, in the same
 *    range, and updating together, so a line on the wrong port is no longer
 *    obvious by eye the way a timestamp on a joystick port was.
 *
 * 0  "<sequence_id>,<value>" - the format used up to 10-09-2026.
 *
 * THE NAME IS DERIVED FROM THE KEY, not stored separately. The key already
 * carries its own quotes - "\"motor_1_pos\"" - so the label is simply the key
 * with the outer quotes stripped. A second table column holding the same text
 * unquoted would be one more thing to keep in step, and a drift between the
 * two would mislabel a value while both halves stayed individually plausible.
 * A key without surrounding quotes is emitted verbatim rather than having its
 * first and last characters eaten.
 *
 * Costs the label plus one separator per line, per UART. The longest key here,
 * "motor_4_insertion_pos", is 21 characters, which keeps a realistic line
 * around 56 bytes against the 128-byte UART_DISPATCH_MAX_PAYLOAD ceiling.
 * ========================================================================= */
/* SET TO 0 ON 09-10-2026 - the UARTs now carry the bare value and nothing
   else. See JSON_PARSER_EMIT_PREFIX immediately below, which drops the other
   column; with both at 0 a line is "<value>" + CRLF. */
#ifndef JSON_PARSER_EMIT_LABEL
#define JSON_PARSER_EMIT_LABEL   0
#endif

/* ===========================================================================
 * EMIT THE SEQUENCE ID AS A COLUMN.  Added 09-10-2026.
 * ===========================================================================
 * 1  "<sequence_id>,<value>" - the format used from 27-08-2026 to 09-10-2026.
 * 0  "<value>" alone, which is what this build sends.
 *
 * WHY THIS EXISTS RATHER THAN JUST SETTING STREAM_JSON_PREFIX_KEY TO NULL.
 * Those two look interchangeable and are not. The prefix key is what makes the
 * parser READ sequence_id, and that value is used for two separate things:
 *
 *   a) the column on the wire                      - what we want to remove
 *   b) the id handed to the object-begin hook      - which must NOT be removed
 *
 * Route (b) reaches scope_trig_seq_begin(), which binds the id to the running
 * PE9 pulse, and scope_trig_seq_uart_done() then accepts a transmit-complete
 * only when it carries that same id - see the per-sequence guard at
 * scope_trig.c:631. Setting the prefix key to NULL makes json_parser_to_u32()
 * return 0 for every object, so EVERY object binds as 0 and every tracked
 * message reports 0. The guard still runs and now always matches, so a
 * completion left over from the PREVIOUS object is accepted against the
 * CURRENT one, ending the pulse early and reporting a latency for a sample
 * that has not finished. scope_trig_seq_mismatch sits at 0 throughout, which
 * reads as healthy.
 *
 * Untracked traffic is not at risk either way: the NTP epoch lines and HTTPS
 * POSTs carry UART_DISPATCH_SEQ_NONE, which is 0xFFFFFFFF and is refused
 * before the comparison.
 *
 * So this flag governs the COLUMN ONLY. The sequence id is still read once per
 * object and still handed to the hooks, and the measurement keeps working
 * exactly as before. Leave STREAM_JSON_PREFIX_KEY pointing at "sequence_id".
 * ========================================================================= */
#ifndef JSON_PARSER_EMIT_PREFIX
#define JSON_PARSER_EMIT_PREFIX  0
#endif

/* Longest field name emitted as a column. Names longer than this are truncated
   rather than allowed to overrun the line buffer.

   RAISED FROM 32 TO 48 ON 09-10-2026, to fix a self-test that had never passed.

   32 cleared the longest key in USE - "motor_4_insertion_pos" at 21 - but not
   the longest key the self-test EXERCISES. Check 9 feeds the original sample
   object and expects the decoy key to label itself in full:

       "controller_to_base_station_received_ntp_time"   44 characters

   At 32 the label was clamped to "controller_to_base_station_recei", so the
   comparison could never match and json_parser_selftest() returned 9 on every
   run. Both the check and the clamp were added on 10-09-2026, so it has been
   failing since the day it was written.

   THE SYMPTOM WAS WORSE THAN THE FAULT. main.c prints

       json: *** EXTRACTOR SELF-TEST FAILED at check 9 ***
       json:     Values on the UARTs from this run cannot be trusted.

   at every boot, for a parser that is extracting perfectly - and the legend
   printed underneath only listed checks 1 to 8, so there was nothing to look
   "check 9" up against. Confirmed by building the pre-change source on a PC
   and running it: json_parser.c needs no STM32 headers, so the self-test runs
   on the host unchanged.

   48 is the next value that clears 44 with room to spare, and matches
   JSON_PARSER_VALUE_MAX so the two limits are easy to reason about together.
   It widens JSON_PARSER_OUT_MAX from 133 to 149 bytes of stack in
   json_parser_emit_field(), which is the only cost.

   NO EMITTED LINE GETS LONGER. JSON_PARSER_EMIT_LABEL is 0 in this build, so
   nothing carries a label column at all; this limit now only governs what the
   self-test can check. Were the label column ever switched back on, a line
   using the 44-character key would reach about 64 bytes, still inside
   UART_DISPATCH_MAX_PAYLOAD of 128. */
#define JSON_PARSER_LABEL_MAX    48U

/* Worst-case emitted line:
   prefix + sep + label + sep + value + CR + LF + NUL. */
#define JSON_PARSER_OUT_MAX      ((JSON_PARSER_VALUE_MAX * 2U) +               \
                                  JSON_PARSER_LABEL_MAX + 5U)

/* ---------------------------------------------------------------------------
 * Types
 * ------------------------------------------------------------------------- */

/**
  * @brief One field to extract from every object.
  *
  * key MUST include its surrounding quotes - "\"ntp_time\"", not "ntp_time".
  * See the decoy-key note in the file header; the quotes are the entire
  * mechanism that keeps ntp_time and
  * controller_to_base_station_received_ntp_time apart.
  */
typedef struct
{
    const char *key;
} json_parser_field_t;

/**
  * @brief  Sink that receives each extracted value.
  * @return None
  * @param  field: index into the table passed to json_parser_init(), which is
  *         what the caller routes on
  * @param  text: the value with CR LF already appended, and NUL-terminated
  * @param  len: characters in text, excluding the NUL
  *
  * Value and CR LF arrive as ONE call so the caller can pass them to a UART in
  * a single message. Splitting them would put two frames on the queue per
  * value and split the PE9 scope pulse in two.
  */
typedef void (*json_parser_emit_fn)(uint8_t field, const char *text, uint16_t len);

/**
  * @brief  Called once per complete object, BEFORE any of its values are
  *         emitted.
  * @return None
  * @param  seq: prefix value parsed as an unsigned integer, or 0 if the object
  *         carried no prefix field
  *
  * Exists so a consumer can open a per-object transaction - the PE9 measurement
  * uses it to bind the sequence id to the running pulse. The value is a NUMBER
  * here only because it is used for matching; what reaches the UART is still
  * the verbatim character string, so no precision is at stake.
  */
typedef void (*json_parser_object_begin_fn)(uint32_t seq);

/**
  * @brief  Called once per complete object, AFTER all its values are emitted.
  * @return None
  * @param  None
  *
  * The consumer now knows the full set of values that went out for this object.
  * The PE9 measurement uses it to close the expected set: until this fires it
  * will not end the pulse, because a UART that finished before the remaining
  * sends were queued would otherwise end it early.
  */
typedef void (*json_parser_object_end_fn)(void);

/**
  * @brief  Installs optional per-object hooks.
  * @return None
  * @param  begin: called before an object's values are emitted, or NULL
  * @param  end: called after them, or NULL
  *
  * Separate from json_parser_init() so a consumer that does not need object
  * boundaries is not forced to pass two NULLs. Survives json_parser_reset().
  */
void json_parser_set_object_hooks(json_parser_object_begin_fn begin,
                                  json_parser_object_end_fn end);

/* ---------------------------------------------------------------------------
 * Counters - read in the debugger
 * ------------------------------------------------------------------------- */

extern volatile uint32_t json_parser_objects;    /**< complete objects parsed   */
extern volatile uint32_t json_parser_emitted;    /**< values emitted, all fields*/
extern volatile uint32_t json_parser_overflows;  /**< objects too big, dropped  */
extern volatile uint32_t json_parser_resyncs;    /**< bytes skipped seeking '{' */

/** Length of the LARGEST object seen, whether or not it fitted. This is the
    number to size JSON_PARSER_OBJ_MAX against - it is measured from the wire
    rather than assumed, which is precisely what was missing when the server's
    message grew from 170 to 610 bytes and every object was silently dropped.

    Counted for oversized objects too: the copy stops at the buffer limit but
    the brace tracking runs to the end, so the true length is always known. A
    value at or above JSON_PARSER_OBJ_MAX means data is being lost right now. */
extern volatile uint32_t json_parser_obj_len_max;

/** Values dropped because the assembled line would not fit JSON_PARSER_OUT_MAX.
    Should stay 0. Non-zero means JSON_PARSER_VALUE_MAX or JSON_PARSER_LABEL_MAX
    has been raised without raising JSON_PARSER_OUT_MAX to match. Counted and
    dropped rather than truncated, because a truncated numeric value is still a
    valid-looking number. */
extern volatile uint32_t json_parser_line_too_long;

/** Emissions that carried NO prefix because the object had no sequence id. It
    should stay 0. Climbing in step with json_parser_emitted means the prefix
    key is wrong or the server dropped the field - the UARTs keep working, and
    quietly stop being correlatable, which is the failure this counter names. */
extern volatile uint32_t json_parser_no_seq;

/** Per-field emitted count. A field stuck at 0 while json_parser_objects climbs
    means that key is not in the stream - a rename or a typo in the table, which
    is otherwise silent because the other three keep working. */
extern volatile uint32_t json_parser_field_hits[JSON_PARSER_FIELD_MAX];

/* ---------------------------------------------------------------------------
 * API
 * ------------------------------------------------------------------------- */

/**
  * @brief  Installs the field table, prefix key and output sink, and clears the
  *         parser.
  * @return None
  * @param  fields: table of keys, each WITH its quotes. Must stay valid for as
  *         long as the parser is used - a static const table is expected.
  * @param  count: entries in fields, clamped to JSON_PARSER_FIELD_MAX
  * @param  prefix_key: key WITH quotes whose value prefixes EVERY emitted
  *         value, "\"sequence_id\"" here. NULL emits bare values.
  * @param  emit: called once per extracted value. NULL parses and counts while
  *         emitting nothing, which the self-test uses to check counters alone.
  *
  * The prefix key is read ONCE per object and reused across all fields, so the
  * four UARTs cannot disagree about which sample a line belongs to.
  */
void json_parser_init(const json_parser_field_t *fields, uint8_t count,
                      const char *prefix_key, json_parser_emit_fn emit);

/**
  * @brief  Discards any partly-received object and zeroes the counters.
  * @return None
  * @param  None
  *
  * Call on every new connection. Without it, half an object left over from a
  * dropped stream would be joined to the first bytes of the next one, producing
  * one corrupt object at every reconnect. The field table and sink survive.
  */
void json_parser_reset(void);

/**
  * @brief  Feeds received bytes to the parser, emitting any values found.
  * @return Number of values emitted by THIS call, summed over all fields. 0 is
  *         normal and means no object completed inside these bytes.
  * @param  data: received bytes, not required to be NUL-terminated and allowed
  *         to contain any byte value
  * @param  len: number of bytes at data
  *
  * Safe with a partial object, several objects, or a single byte. State carries
  * over between calls, which is what makes fragmentation a non-event. Task
  * context only: not interrupt-safe, and does not need to be, since the stream
  * task is its only caller.
  */
uint32_t json_parser_feed(const uint8_t *data, uint32_t len);

/**
  * @brief  Verifies extraction against the real message format, including every
  *         trap this module exists to avoid.
  * @return 0 if all checks passed, otherwise the number of the first failing
  *         check (1..9)
  * @param  None
  *
  * WHY IT MATTERS MORE THAN USUAL HERE. The decoy-key bug does not crash and
  * does not look wrong: it routes a well-formed timestamp to the wrong UART.
  * Only a test that knows both values can tell them apart - check 2.
  *
  *   1  all four fields from the exact sample object, each tagged
  *   2  ntp_time and the decoy land on DIFFERENT fields, right way round
  *   3  the two timestamp fields in the OPPOSITE order still extract correctly
  *   4  one object split across three feeds, cutting a key AND a value
  *   5  two objects in one buffer with DIFFERENT sequence ids - the tag must be
  *      re-read per object, not cached from the first
  *   6  a brace inside a quoted string, and an object with NO sequence id,
  *      which must still emit its value bare and count it
  *   7  an oversized object is dropped AND the next one still parses
  *   8  the whole object fed one byte per call
  *
  * Destroys parser state and counters but preserves the installed table and
  * sink, so it is safe to call after json_parser_init() and before the stream
  * starts.
  */
int json_parser_selftest(void);

#endif /* __JSON_PARSER_H__ */
