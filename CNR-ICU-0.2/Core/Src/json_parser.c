/**
  ******************************************************************************
  * @file    json_parser.c
  * @brief   Streaming JSON multi-field extractor - implementation
  * @version 2.0 - 27-08-2026 (single field -> field table)
  *
  * See json_parser.h for what this solves and why. This file is the mechanism:
  * a byte-at-a-time state machine that reassembles objects across network
  * boundaries, then one length-bounded key search per field inside each
  * completed object.
  *
  * NO STANDARD STRING FUNCTIONS ARE USED ON THE RECEIVE BUFFER, deliberately.
  * strstr() and friends stop at the first NUL, and this buffer holds bytes that
  * came off a socket - a stray 0x00 in a malformed message would truncate the
  * search and hide a key that is really there. Every scan below is bounded by
  * an explicit length instead.
  *
  * COST PER OBJECT. One pass over the object per field, so four passes over
  * ~170 bytes. That is under 700 byte-compares against a stream delivering an
  * object every ~300 ms - immaterial. A single-pass tokeniser would be faster
  * and considerably harder to prove correct; the simple version is the right
  * trade here and would only need revisiting if the field count grew large.
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "json_parser.h"
#include <string.h>   /* memcmp, memcpy, strlen - all bounded or on literals */
#include <stdio.h>    /* printf - the ONE-TIME oversize warning only         */

/* Private types -------------------------------------------------------------*/

/**
  * @brief Reassembly state, carried across json_parser_feed() calls.
  *
  * A single static instance: one stream, one parser. Making it a struct rather
  * than loose statics keeps json_parser_reset() honest - it is one memset and
  * cannot forget a field.
  */
typedef struct
{
    char     obj[JSON_PARSER_OBJ_MAX];  /**< object being reassembled        */
    uint16_t len;                        /**< bytes valid in obj[]            */
    uint32_t full_len;                   /**< bytes SEEN, even past the buffer*/
    uint16_t depth;                      /**< brace nesting, 0 = between objs */
    uint8_t  in_object;                  /**< a '{' has been seen             */
    uint8_t  in_string;                  /**< inside a quoted string          */
    uint8_t  escaped;                    /**< previous char was a backslash   */
    uint8_t  dropping;                   /**< oversized: discard to next '{'  */
} json_parser_state_t;

/* Private variables ---------------------------------------------------------*/
static json_parser_state_t State;

/* Field table and sink live outside State so json_parser_reset() cannot lose
   them - a reset on reconnect must not silently stop the routing. */
static const json_parser_field_t *Fields;
static uint8_t                    FieldCount;
static const char                *PrefixKey;
static json_parser_emit_fn        Emit;
static json_parser_object_begin_fn ObjBegin;
static json_parser_object_end_fn   ObjEnd;

volatile uint32_t json_parser_objects;
volatile uint32_t json_parser_emitted;
volatile uint32_t json_parser_overflows;
volatile uint32_t json_parser_obj_len_max;
volatile uint32_t json_parser_line_too_long;

/* Emit the field name as a column. Initialised from the compile-time default
   and held as a variable, not a macro, for one reason: the self-test's 18
   expected strings were written against the two-column format, and the test
   clears this for its duration exactly as it already does for Fields, Emit and
   the object hooks. Rewriting all 18 to carry labels would have re-tested
   nothing and risked transcription errors in the one place that exists to
   catch them. Check 9 covers the label on its own. */
static uint8_t EmitLabel = (uint8_t)JSON_PARSER_EMIT_LABEL;

/* Governs the sequence-id COLUMN only; the id itself is still read once per
   object and still passed to the object-begin hook. Held in a variable rather
   than tested as a macro for the same reason as EmitLabel - the self-test has
   to force it on for checks written against the tagged format. */
static uint8_t EmitPrefix = (uint8_t)JSON_PARSER_EMIT_PREFIX;

/* Latches the console warning to ONE line for the life of the run. The stream
   delivers about ten objects a second, so an unlatched message would flood the
   VCOM and - worse - run the console transmit interrupt inside the very window
   the PE9 trigger is measuring, corrupting the reading it is meant to explain.
   Not part of State: a reconnect must not re-arm the warning. */
static uint8_t Overflow_reported;
volatile uint32_t json_parser_resyncs;
volatile uint32_t json_parser_no_seq;
volatile uint32_t json_parser_field_hits[JSON_PARSER_FIELD_MAX];

/* Private function prototypes -----------------------------------------------*/
static int      json_parser_find(const char *hay, uint16_t hay_len,
                                 const char *needle, uint16_t needle_len);
static uint8_t  json_parser_is_value_char(char c);
static uint16_t json_parser_read_value(const char *key, char *out);
static uint16_t json_parser_label_of(const char *key, const char **out_label);
static uint32_t json_parser_emit_field(uint8_t field, const char *seq,
                                       uint16_t seq_len);
static uint32_t json_parser_extract_all(void);
static void     json_parser_begin_object(void);

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Length-bounded substring search.
  * @return Index of the first occurrence, or -1 if absent.
  * @param  hay: buffer to search, may contain any byte including NUL
  * @param  hay_len: bytes valid at hay
  * @param  needle: pattern to find
  * @param  needle_len: length of needle
  *
  * Exists instead of strstr() because hay comes off a socket and may contain a
  * NUL that strstr() would treat as the end of the data.
  */
static int json_parser_find(const char *hay, uint16_t hay_len,
                            const char *needle, uint16_t needle_len)
{
    int result = -1;

    if ((needle_len != 0U) && (hay_len >= needle_len))
    {
        uint16_t last = (uint16_t)(hay_len - needle_len);
        uint16_t i;

        for (i = 0U; i <= last; i++)
        {
            if (memcmp(&hay[i], needle, (size_t)needle_len) == 0)
            {
                result = (int)i;
                break;
            }
            else
            {
                /* No match at this offset - keep scanning. */
            }
        }
    }
    else
    {
        /* Needle longer than the haystack, or empty - cannot match. */
    }

    return result;
}

/**
  * @brief  Reports whether a character can form part of a JSON number.
  * @return 1 if it belongs to the value, 0 if it terminates it.
  * @param  c: character to test
  *
  * Accepts digits, the decimal point, a leading or exponent sign, and the
  * exponent marker - so -32768 and 1.5e3 pass through as written. Everything
  * else, notably ',' and '}', ends the value. A quoted STRING value ends
  * immediately, which is correct: none of the four fields is a string, and
  * emitting the opening quote of one would be wrong.
  */
static uint8_t json_parser_is_value_char(char c)
{
    uint8_t result;

    if (((c >= '0') && (c <= '9')) ||
        (c == '.') || (c == '-') || (c == '+') || (c == 'e') || (c == 'E'))
    {
        result = 1U;
    }
    else
    {
        result = 0U;
    }

    return result;
}

/**
 * @brief  Reads a key's value from the JSON object.
 * @return Number of characters copied, or 0 if the value is missing or invalid.
 * @param  key: JSON key including quotes.
 * @param  out: Destination buffer of at least JSON_PARSER_VALUE_MAX bytes.
 *
 * Supports unquoted numbers and quoted strings without escape characters.
 * Copies values as text without conversion, preserving their precision.
 */
static uint16_t json_parser_read_value(const char *key, char *out)
{
    uint16_t n = 0U;
    uint16_t key_len;
    int      at;

    /* CHECKED BEFORE ANYTHING DEREFERENCES THEM. Until 09-10-2026 this test sat
       below the two initialisers, so strlen(key) and json_parser_find() had
       both already read through the pointer by the time it ran - a NULL key
       would have crashed several lines before the guard that exists to prevent
       it. Harmless in practice, because every caller passes either the static
       field table or a PrefixKey the caller has already tested, but a guard
       that cannot fire is worse than none: it reads as protection. */
    if ((key == NULL) || (out == NULL))
    {
        return 0U;
    }
    else
    {
        /* Both usable - safe to read through them below. */
    }

    key_len = (uint16_t)strlen(key);
    at      = json_parser_find(State.obj, State.len, key, key_len);

    if (at < 0)
    {
        /*
         * Key absent from this object.
         * Do not count it as an extraction error.
         */
    }
    else
    {
        uint16_t i = (uint16_t)((uint16_t)at + key_len);

        /*
         * Skip whitespace before the colon.
         */
        while ((i < State.len) &&
               ((State.obj[i] == ' ')  ||
                (State.obj[i] == '\t') ||
                (State.obj[i] == '\r') ||
                (State.obj[i] == '\n')))
        {
            i++;
        }

        if ((i < State.len) && (State.obj[i] == ':'))
        {
            i++;

            /*
             * Skip whitespace after the colon.
             */
            while ((i < State.len) &&
                   ((State.obj[i] == ' ')  ||
                    (State.obj[i] == '\t') ||
                    (State.obj[i] == '\r') ||
                    (State.obj[i] == '\n')))
            {
                i++;
            }

            /*
             * Handle quoted JSON string values:
             * "motor_1_pos":"M7.628417"
             * "motor_1_pos":"M-7.643015"
             *
             * Copy the contents without the quotation marks.
             */
            if ((i < State.len) && (State.obj[i] == '"'))
            {
                i++;

                while ((i < State.len) &&
                       (State.obj[i] != '"') &&
                       (n < (uint16_t)(JSON_PARSER_VALUE_MAX - 1U)))
                {
                    /*
                     * This implementation supports ordinary strings
                     * without escaped characters.
                     */
                    if (State.obj[i] == '\\')
                    {
                        n = 0U;
                        break;
                    }

                    out[n] = State.obj[i];
                    n++;
                    i++;
                }

                /*
                 * Reject an unterminated or oversized string.
                 */
                if ((i >= State.len) || (State.obj[i] != '"'))
                {
                    n = 0U;
                }
            }
            else
            {
                /*
                 * Handle unquoted numeric values:
                 * "motor_1_pos":7.678761
                 *
                 * Keep the existing value-character rules.
                 */
                while ((i < State.len) &&
                       (n < (uint16_t)(JSON_PARSER_VALUE_MAX - 1U)) &&
                       (json_parser_is_value_char(State.obj[i]) != 0U))
                {
                    out[n] = State.obj[i];
                    n++;
                    i++;
                }
            }
        }
        else
        {
            /*
             * The key was found, but no colon followed it.
             */
        }
    }

    out[n] = '\0';

    return n;
}

/**
  * @brief  Derives the printable field name from a key.
  * @return Characters at *out_label, clamped to JSON_PARSER_LABEL_MAX.
  * @param  key: field key, normally carrying its own surrounding quotes
  * @param  out_label: receives a pointer INTO key, not a copy
  *
  * The keys are stored quoted - "\"motor_1_pos\"" - because the opening quote
  * is what stops a short key matching inside a longer one. The label is that
  * same text with the outer quotes stripped, so the two can never disagree.
  *
  * A key that is NOT quoted is returned verbatim rather than having its first
  * and last characters removed. Silently eating them would produce "otor_1_po",
  * which is wrong in a way that still looks like a field name.
  */
static uint16_t json_parser_label_of(const char *key, const char **out_label)
{
    uint16_t key_len = (uint16_t)strlen(key);
    uint16_t n;

    if ((key_len >= 2U) && (key[0] == '"') && (key[key_len - 1U] == '"'))
    {
        *out_label = &key[1];
        n          = (uint16_t)(key_len - 2U);
    }
    else
    {
        *out_label = key;
        n          = key_len;
    }

    /* Limit-checked on the line after it is set, so a long key truncates the
       label instead of overrunning the line buffer. */
    if (n > (uint16_t)JSON_PARSER_LABEL_MAX)
    {
        n = (uint16_t)JSON_PARSER_LABEL_MAX;
    }
    else
    {
        /* Fits. */
    }

    return n;
}

/**
  * @brief  Emits one field's value, prefixed with the sequence id if there is
  *         one.
  * @return 1 if a value was emitted, 0 otherwise.
  * @param  field: index into Fields[]
  * @param  seq: sequence-id characters, or NULL if the object had none
  * @param  seq_len: characters at seq
  *
  * Output is "<seq><sep><label><sep><value>\r\n", with the label column present
  * only while JSON_PARSER_EMIT_LABEL is 1, and the sequence column only when
  * the object actually carried one. Both are independent, so all four
  * combinations are reachable and none of them is malformed.
  *
  * Emitting a bare value when the sequence id is missing, rather than dropping
  * the line, is deliberate: a server that stopped sending sequence_id would
  * otherwise silence all four UARTs at once, which looks exactly like the link
  * dying.
  *
  * A line that would not fit JSON_PARSER_OUT_MAX is DROPPED and counted in
  * json_parser_line_too_long, never truncated - a truncated number is still a
  * valid-looking number, and would be believed downstream.
  */
static uint32_t json_parser_emit_field(uint8_t field, const char *seq, uint16_t seq_len)
{
    uint32_t emitted = 0U;
    char     val[JSON_PARSER_VALUE_MAX];
    uint16_t val_len = json_parser_read_value(Fields[field].key, val);

    if (val_len == 0U)
    {
        /* Absent, or present with a non-numeric value - nothing safe to emit. */
    }
    else
    {
        char        out[JSON_PARSER_OUT_MAX];
        uint16_t    n         = 0U;
        const char *label     = NULL;
        uint16_t    label_len = 0U;
        uint16_t    seq_col   = 0U;
        uint16_t    need;

        /* PREFIX COLUMN. EmitPrefix governs the COLUMN, never the reading of
           the id: json_parser_extract_all() has already passed the real value
           to the object-begin hook by the time this runs, so the PE9
           per-sequence guard is unaffected by switching the column off. */
        if (EmitPrefix == 0U)
        {
            /* Column suppressed - the value goes out bare.

               json_parser_no_seq IS DELIBERATELY NOT TOUCHED HERE. That counter
               names an object that ARRIVED without a sequence id, which is a
               fault worth seeing. Bumping it for a column we chose to remove
               would make it climb in step with json_parser_emitted and stop
               distinguishing the two, which is the whole value of having it. */
            seq_col = 0U;
        }
        else if ((seq != NULL) && (seq_len != 0U))
        {
            seq_col = seq_len;
        }
        else
        {
            /* Column wanted, but this object carried no sequence id. */
            seq_col = 0U;
            json_parser_no_seq++;
        }

        if (EmitLabel != 0U)
        {
            label_len = json_parser_label_of(Fields[field].key, &label);
        }
        else
        {
            /* Label column switched off - two columns as before. */
        }

        /* CHECKED BEFORE THE FIRST BYTE IS WRITTEN, not after each memcpy.
           out[] is a fixed local and the three parts are all bounded, so this
           can only fire if the configured maxima are raised out of step with
           JSON_PARSER_OUT_MAX - which is exactly the mistake worth catching
           here rather than in the stack frame next door. */
        need = (uint16_t)(seq_col + 1U + label_len + 1U + val_len + 3U);

        if (need > (uint16_t)JSON_PARSER_OUT_MAX)
        {
            json_parser_line_too_long++;
            return 0U;
        }
        else
        {
            /* Fits. */
        }

        if (seq_col != 0U)
        {
            memcpy(out, seq, (size_t)seq_col);
            n = seq_col;
            out[n] = (char)JSON_PARSER_PREFIX_SEP;
            n++;
        }
        else
        {
            /* No prefix column on this line - either the object carried no
               sequence id, or the column is switched off. Both were already
               classified and counted above. */
        }

        if (label_len != 0U)
        {
            memcpy(&out[n], label, (size_t)label_len);
            n = (uint16_t)(n + label_len);
            out[n] = (char)JSON_PARSER_PREFIX_SEP;
            n++;
        }
        else
        {
            /* No label - value follows the sequence id directly. */
        }

        memcpy(&out[n], val, (size_t)val_len);
        n = (uint16_t)(n + val_len);

        out[n]      = '\r';
        out[n + 1U] = '\n';
        out[n + 2U] = '\0';
        n = (uint16_t)(n + 2U);

        json_parser_emitted++;
        json_parser_field_hits[field]++;
        emitted = 1U;

        if (Emit != NULL)
        {
            Emit(field, out, n);
        }
        else
        {
            /* No sink installed - parse and count only. */
        }
    }

    return emitted;
}

/**
  * @brief  Runs every configured field against the completed object.
  * @return Number of values emitted for this object.
  * @param  None
  *
  * The prefix is read ONCE per object and reused for all four fields, rather
  * than re-searched per field. That matters less for speed than for
  * consistency: one search cannot return two different sequence ids for the
  * same object, so the four UARTs are guaranteed to agree on which sample they
  * are describing. That guarantee is the entire reason for tagging them.
  */
/**
  * @brief  Converts the prefix characters to an unsigned integer for matching.
  * @return The value, or 0 if there are no usable digits.
  * @param  s: characters
  * @param  len: how many
  *
  * Hand-rolled rather than atoi()/strtoul(): the buffer is not NUL-terminated,
  * and the baremetal library rules exclude the ato* family anyway. Non-digits
  * simply stop the scan - a negative or fractional prefix is not meaningful as
  * a sequence id.
  *
  * ONLY EVER USED FOR MATCHING. The characters that reach the UART are the
  * verbatim ones from the wire, so this conversion cannot cost precision on the
  * transmitted value however large the id grows.
  */
static uint32_t json_parser_to_u32(const char *s, uint16_t len)
{
    uint32_t v = 0U;
    uint16_t i;

    for (i = 0U; i < len; i++)
    {
        if ((s[i] >= '0') && (s[i] <= '9'))
        {
            v = (v * 10U) + (uint32_t)(s[i] - '0');
        }
        else
        {
            break;
        }
    }

    return v;
}

static uint32_t json_parser_extract_all(void)
{
    uint32_t emitted = 0U;
    uint8_t  f;
    char     seq[JSON_PARSER_VALUE_MAX];
    uint16_t seq_len = 0U;

    json_parser_objects++;

    if (PrefixKey != NULL)
    {
        seq_len = json_parser_read_value(PrefixKey, seq);
    }
    else
    {
        /* No prefix configured - values go out bare. */
    }

    /* Announce the object BEFORE emitting, so a consumer can open a transaction
       that the emissions then join. Doing it afterwards would mean the first
       value was already queued - and possibly already transmitted - before
       anything knew which sequence it belonged to. */
    if (ObjBegin != NULL)
    {
        ObjBegin(json_parser_to_u32(seq, seq_len));
    }
    else
    {
        /* No hook installed. */
    }

    for (f = 0U; f < FieldCount; f++)
    {
        emitted += json_parser_emit_field(f, seq, seq_len);
    }

    /* And close it once the full set of emissions is known. */
    if (ObjEnd != NULL)
    {
        ObjEnd();
    }
    else
    {
        /* No hook installed. */
    }

    return emitted;
}

/**
  * @brief  Starts a fresh object at an opening brace.
  * @return None
  * @param  None
  */
static void json_parser_begin_object(void)
{
    State.in_object = 1U;
    State.in_string = 0U;
    State.escaped   = 0U;
    State.depth     = 1U;
    State.dropping  = 0U;
    State.obj[0]    = '{';
    State.len       = 1U;

    /* Counts every byte of the object as it goes past, buffered or not, so an
       oversized object can report how big it actually was. */
    State.full_len  = 1U;
}

/* Exported functions --------------------------------------------------------*/

void json_parser_init(const json_parser_field_t *fields, uint8_t count,
                      const char *prefix_key, json_parser_emit_fn emit)
{
    Fields     = fields;
    FieldCount = (count <= (uint8_t)JSON_PARSER_FIELD_MAX)
                 ? count : (uint8_t)JSON_PARSER_FIELD_MAX;
    PrefixKey  = prefix_key;
    Emit       = emit;

    if (fields == NULL)
    {
        /* No table means nothing can be extracted. Forced to zero so the
           extract loop cannot walk a NULL pointer. */
        FieldCount = 0U;
    }
    else
    {
        /* Table supplied. */
    }

    json_parser_reset();
}

void json_parser_set_object_hooks(json_parser_object_begin_fn begin,
                                  json_parser_object_end_fn end)
{
    ObjBegin = begin;
    ObjEnd   = end;
}

void json_parser_reset(void)
{
    uint8_t f;

    memset(&State, 0, sizeof(State));

    json_parser_objects       = 0U;
    json_parser_emitted       = 0U;
    json_parser_overflows     = 0U;
    json_parser_resyncs       = 0U;
    json_parser_no_seq        = 0U;
    json_parser_obj_len_max   = 0U;
    json_parser_line_too_long = 0U;

    for (f = 0U; f < (uint8_t)JSON_PARSER_FIELD_MAX; f++)
    {
        json_parser_field_hits[f] = 0U;
    }

    /* Fields, FieldCount, PrefixKey and Emit are deliberately NOT cleared - see
       the note on where they live. A reconnect must not stop the routing. */
}

uint32_t json_parser_feed(const uint8_t *data, uint32_t len)
{
    uint32_t emitted = 0U;
    uint32_t k;

    if ((data == NULL) || (len == 0U))
    {
        return 0U;
    }
    else
    {
        /* Normal case - fall through. */
    }

    for (k = 0U; k < len; k++)
    {
        char c = (char)data[k];

        if (State.in_object == 0U)
        {
            /* Between objects. Anything that is not an opening brace is noise:
               the newline separating the sample objects, whitespace, or the
               tail of an object we joined half way through. */
            if (c == '{')
            {
                json_parser_begin_object();
            }
            else
            {
                json_parser_resyncs++;
            }
        }
        else
        {
            /* ---- accumulate, unless this object already overflowed --------
               While dropping, the depth tracking below still runs so the end of
               the oversized object is found correctly; only the copy stops. */
            /* Counted before the buffer test, and for dropped objects too, so
               json_parser_obj_len_max reports the true size on the wire rather
               than the size that happened to fit. */
            State.full_len++;

            if (State.dropping == 0U)
            {
                if (State.len < (uint16_t)JSON_PARSER_OBJ_MAX)
                {
                    State.obj[State.len] = c;
                    State.len++;
                }
                else
                {
                    /* Too big to buffer. Emitting what we have would risk a
                       TRUNCATED value that looks exactly like a real one, so
                       the whole object is abandoned instead. */
                    State.dropping = 1U;
                    json_parser_overflows++;
                }
            }
            else
            {
                /* Already abandoned - still tracking depth to find the end. */
            }

            /* ---- string-aware, escape-aware depth tracking ---------------
               Order matters: an escaped character can never itself open or
               close a string, and a brace inside a string must not move the
               depth. Getting this wrong makes "text":"a{b" swallow the rest of
               the stream. */
            if (State.escaped != 0U)
            {
                State.escaped = 0U;
            }
            else if (State.in_string != 0U)
            {
                if (c == '\\')
                {
                    State.escaped = 1U;
                }
                else if (c == '"')
                {
                    State.in_string = 0U;
                }
                else
                {
                    /* Ordinary character inside a string. */
                }
            }
            else
            {
                if (c == '"')
                {
                    State.in_string = 1U;
                }
                else if (c == '{')
                {
                    State.depth++;
                }
                else if (c == '}')
                {
                    State.depth--;

                    if (State.depth == 0U)
                    {
                        /* ---- a complete object -------------------------
                           The full length is only known here, at the closing
                           brace, so the high-water mark is taken now. */
                        if (State.full_len > json_parser_obj_len_max)
                        {
                            json_parser_obj_len_max = State.full_len;
                        }
                        else
                        {
                            /* Not a new largest object. */
                        }

                        if (State.dropping == 0U)
                        {
                            emitted += json_parser_extract_all();
                        }
                        else
                        {
                            /* ---- OVERSIZED: SAY SO, ONCE -----------------
                               Silence here is what turned a buffer that was
                               214 bytes too small into a day spent hunting a
                               GPIO fault on 10-09-2026. The object is dropped,
                               so no field reaches any UART and the PE9 trigger
                               never gets its object-complete hook - the pin
                               stays HIGH and every other symptom is absent.
                               The frames still print on the VCOM, because that
                               dump happens upstream of the parser, so the link
                               looks perfectly healthy.

                               Printed once per run: at ten objects a second an
                               unlatched message would flood the console and run
                               the VCP transmit interrupt inside the window the
                               trigger is measuring. */
                            if (Overflow_reported == 0U)
                            {
                                Overflow_reported = 1U;

                                printf("json: *** OBJECT TOO BIG - %lu bytes, "
                                       "buffer is %lu ***\r\n",
                                       (unsigned long)State.full_len,
                                       (unsigned long)JSON_PARSER_OBJ_MAX);
                                printf("json:     the object is DROPPED, so all "
                                       "four UARTs get nothing and PE9 stays "
                                       "HIGH\r\n");
                                printf("json:     raise JSON_PARSER_OBJ_MAX in "
                                       "json_parser.h above %lu and rebuild\r\n",
                                       (unsigned long)State.full_len);
                            }
                            else
                            {
                                /* Already reported - stay quiet. */
                            }
                        }

                        State.in_object = 0U;
                        State.len       = 0U;
                        State.full_len  = 0U;
                        State.dropping  = 0U;
                    }
                    else
                    {
                        /* Closed a nested object, still inside the outer one. */
                    }
                }
                else
                {
                    /* Ordinary structural character. */
                }
            }
        }
    }

    return emitted;
}

/* ---------------------------------------------------------------------------
 * Self-test
 * ------------------------------------------------------------------------- */

/* Captures what each field emitted, so the checks can compare per field.

   SIZED AGAINST JSON_PARSER_OUT_MAX SINCE 09-10-2026, not against
   JSON_PARSER_VALUE_MAX. This row holds a whole EMITTED LINE - prefix, label,
   value and CR LF - so the only correct dimension is the one that bounds such a
   line. It was VALUE_MAX + 3, which pre-dates the label column entirely.

   WHAT THAT COST. At 51 bytes a row, the sink below clamped every captured line
   to 50 characters. Check 9 compares the decoy field, whose line is

       18,controller_to_base_station_received_ntp_time,1787819915.830 + CRLF

   at 64 characters. It arrived truncated to 50 -

       18,controller_to_base_station_received_ntp_time,17

   - so the comparison failed on a line the parser had emitted perfectly. The
   captured text even looked plausible: a sequence id, a full field name, and
   what reads as the start of a number. The PARSER was never at fault, and
   neither was the label clamp that was raised first in the same session; this
   buffer was the cause all along.

   Using OUT_MAX means it cannot be outgrown again: any line emit_field() can
   build fits by construction. Costs
   JSON_PARSER_FIELD_MAX * JSON_PARSER_OUT_MAX bytes of .bss, 8 * 149 = 1192,
   against 408 before. */
static char     test_val[JSON_PARSER_FIELD_MAX][JSON_PARSER_OUT_MAX];
static uint32_t test_calls;

/**
  * @brief  Emit sink used only by json_parser_selftest().
  * @return None
  * @param  field: field index
  * @param  text: emitted value with its CR LF
  * @param  len: length of text
  */
static void json_parser_test_emit(uint8_t field, const char *text, uint16_t len)
{
    if (field < (uint8_t)JSON_PARSER_FIELD_MAX)
    {
        /* Clamp to the ROW SIZE less the NUL, so the bound and the buffer can
           never disagree. Previously this clamped to VALUE_MAX + 2 while the
           row was VALUE_MAX + 3 - self-consistent, but both were sized for a
           bare value rather than a whole emitted line. */
        uint16_t n = (len < (uint16_t)(JSON_PARSER_OUT_MAX - 1U))
                     ? len : (uint16_t)(JSON_PARSER_OUT_MAX - 1U);

        memcpy(test_val[field], text, (size_t)n);
        test_val[field][n] = '\0';
        test_calls++;
    }
    else
    {
        /* Out of range - cannot happen with the table below. */
    }
}

/**
  * @brief  Compares one field's captured value against an expected string.
  * @return 1 if equal, 0 otherwise.
  * @param  field: field index
  * @param  expect: expected text, CR LF included
  */
static uint8_t json_parser_test_is(uint8_t field, const char *expect)
{
    return (uint8_t)((strcmp(test_val[field], expect) == 0) ? 1U : 0U);
}

/**
  * @brief  Clears captured values between checks.
  * @return None
  * @param  None
  */
static void json_parser_test_clear(void)
{
    memset(test_val, 0, sizeof(test_val));
    test_calls = 0U;
    json_parser_reset();
}

int json_parser_selftest(void)
{
    /* The four fields under test, in the order the application uses them. Held
       here rather than borrowed from the caller so the test proves the parser
       regardless of how the application happens to be configured. */
    static const json_parser_field_t test_fields[4] =
    {
        { "\"ntp_time\"" },
        { "\"controller_to_base_station_received_ntp_time\"" },
        { "\"joystick_x\"" },
        { "\"joystick_y\"" }
    };

    /* NAMED INDICES INTO test_fields, so the checks below read as "the ntp_time
       field" rather than "field 0".

       WHY THIS EXISTS. The table order was changed on 28-08-2026 without the
       expectations being changed with it, and every check that names a field
       started failing - correct parser, wrong test. Numeric literals scattered
       through eight checks made that coupling invisible. If the table is
       reordered again, ONLY these four lines need to follow it.

       Note this ordering is internal to the test and has nothing to do with
       which UART anything reaches; that is Stream_json_route[] in
       stream_client.c. */
    #define T_NTP   0U   /* "ntp_time"                                     */
    #define T_CTRL  1U   /* "controller_to_base_station_received_ntp_time" */
    #define T_JX    2U   /* "joystick_x"                                   */
    #define T_JY    3U   /* "joystick_y"                                   */

    /* The exact message format from the live stream. The two timestamps differ
       by 13 ms, which is what lets check 2 tell a correct extraction from the
       classic wrong one. */
    static const char sample[] =
        "{\"message_type\":\"joystick_controller\",\"sequence_id\":18,"
        "\"ntp_time\":1787819915.843,"
        "\"controller_to_base_station_received_ntp_time\":1787819915.830,"
        "\"joystick_x\":0,\"joystick_y\":0}";

    /* Same object with the two timestamp fields SWAPPED. If the quote-prefix
       trick only worked because the short key happened to come first, this is
       what would expose it. */
    static const char swapped[] =
        "{\"sequence_id\":18,"
        "\"controller_to_base_station_received_ntp_time\":1787819915.830,"
        "\"ntp_time\":1787819915.843,"
        "\"joystick_x\":-32768,\"joystick_y\":32767}";

    const json_parser_field_t *keep_fields = Fields;
    uint8_t                    keep_count  = FieldCount;
    const char                *keep_prefix = PrefixKey;
    json_parser_emit_fn        keep_emit   = Emit;

    /* HOOKS ARE DETACHED FOR THE DURATION. They are wired to the PE9 sequence
       tracker in the live build, and firing them with test sequence ids would
       bind 4242 to a real pulse and leave the pin held until a completion that
       will never come. Today the test runs before stream_client_init() installs
       them, so they are NULL anyway - this makes the test independent of that
       ordering rather than quietly dependent on it. */
    json_parser_object_begin_fn keep_begin = ObjBegin;
    json_parser_object_end_fn   keep_end   = ObjEnd;

    ObjBegin = NULL;
    ObjEnd   = NULL;

    /* CHECK 7 OVERFLOWS AN OBJECT ON PURPOSE. Latching the warning shut for the
       duration stops a passing self-test from printing three lines of alarm
       about a buffer that is fine. Cleared again at the end so a genuinely
       oversized object on the live stream is still announced. */
    Overflow_reported = 1U;

    /* CHECKS 1 TO 8 EXPECT THE TWO-COLUMN FORMAT. They were written before the
       label column existed and each names an exact output string. Clearing the
       flag here keeps all 18 of those expectations testing what they were
       written to test - reassembly, the decoy key, fragmentation, overflow -
       instead of turning them into 18 transcription exercises. Check 9 tests
       the label on its own, with the flag back on. */
    uint8_t keep_label = EmitLabel;

    EmitLabel = 0U;

    /* AND THE CHECKS ALL EXPECT THE SEQUENCE ID TO BE PRESENT. Every expected
       string from check 1 onwards is written as "18,...", "41,...", "7,..."
       and so on, and check 6 asserts specifically that an object with NO
       sequence id still emits its value bare and counts it in
       json_parser_no_seq. All of that tests the parser's own behaviour and
       none of it should change because this build happens to ship with the
       column switched off - so the flag is forced ON for the duration and
       restored afterwards, exactly as EmitLabel is.

       Without this the self-test fails at check 1 on every boot, and main.c
       prints "Values on the UARTs from this run cannot be trusted" for a
       parser that is working perfectly. */
    uint8_t keep_prefix_col = EmitPrefix;

    EmitPrefix = 1U;

    int    result     = 0;
    size_t sample_len = sizeof(sample) - 1U;

    json_parser_init(test_fields, 4U, "\"sequence_id\"", json_parser_test_emit);

    /* ---- 1. all four fields, each tagged with the sequence id ---------- */
    json_parser_test_clear();
    (void)json_parser_feed((const uint8_t *)sample, (uint32_t)sample_len);

    if ((test_calls != 4U) ||
        (json_parser_test_is(T_NTP,  "18,1787819915.843\r\n") == 0U) ||
        (json_parser_test_is(T_CTRL, "18,1787819915.830\r\n") == 0U) ||
        (json_parser_test_is(T_JX,   "18,0\r\n") == 0U) ||
        (json_parser_test_is(T_JY,   "18,0\r\n") == 0U) ||
        (json_parser_no_seq != 0U))
    {
        result = 1;
    }

    /* ---- 2. THE DECOY. ntp_time must NOT have taken the controller value
       Both are well-formed timestamps 13 ms apart, so this is the only check
       that separates a correct parser from the obvious broken one. */
    if ((result == 0) &&
        (json_parser_test_is(T_NTP, "18,1787819915.830\r\n") != 0U))
    {
        result = 2;
    }

    /* ---- 3. the two timestamps in the OPPOSITE order ------------------- */
    if (result == 0)
    {
        json_parser_test_clear();
        (void)json_parser_feed((const uint8_t *)swapped,
                               (uint32_t)(sizeof(swapped) - 1U));

        if ((json_parser_test_is(T_NTP,  "18,1787819915.843\r\n") == 0U) ||
            (json_parser_test_is(T_CTRL, "18,1787819915.830\r\n") == 0U) ||
            (json_parser_test_is(T_JX,   "18,-32768\r\n") == 0U) ||
            (json_parser_test_is(T_JY,   "18,32767\r\n") == 0U))
        {
            result = 3;
        }
    }

    /* ---- 4. split across three feeds, cutting a key AND a value --------
       Offsets verified against the sample on 27-08-2026: "ntp_time" occupies
       bytes 55..64 and its value starts at 66. So 59 cuts the key in half and
       71 cuts the digits in half - the two places a per-buffer strstr() can
       never recover from. The sequence id sits earlier still, at byte 52, so
       this also proves the prefix survives reassembly. */
    if (result == 0)
    {
        json_parser_test_clear();

        (void)json_parser_feed((const uint8_t *)sample, 59U);
        (void)json_parser_feed((const uint8_t *)&sample[59], 12U);
        (void)json_parser_feed((const uint8_t *)&sample[71],
                               (uint32_t)(sample_len - 71U));

        if ((test_calls != 4U) ||
            (json_parser_test_is(T_NTP,  "18,1787819915.843\r\n") == 0U) ||
            (json_parser_test_is(T_CTRL, "18,1787819915.830\r\n") == 0U))
        {
            result = 4;
        }
    }

    /* ---- 5. two objects in one buffer, DIFFERENT sequence ids ----------
       The second id must replace the first, not be remembered from it. A
       prefix cached across objects would tag every line with the first id
       ever seen and make the whole tagging useless - while still producing
       perfectly plausible output. */
    if (result == 0)
    {
        static const char two[] =
            "{\"sequence_id\":41,\"ntp_time\":1.5,\"joystick_x\":7}\n"
            "{\"sequence_id\":42,\"ntp_time\":2.25,\"joystick_x\":9}";

        json_parser_test_clear();
        (void)json_parser_feed((const uint8_t *)two, (uint32_t)(sizeof(two) - 1U));

        if ((json_parser_objects != 2U) ||
            (json_parser_test_is(T_NTP, "42,2.25\r\n") == 0U) ||
            (json_parser_test_is(T_JX,  "42,9\r\n") == 0U))
        {
            result = 5;
        }
    }

    /* ---- 6. brace inside a string, and NO sequence id ------------------
       Two things at once: depth tracking must survive "a{b}c", and an object
       with no sequence id must still emit its value - bare, and counted. A
       server that dropped sequence_id would otherwise silence every UART, an
       outage indistinguishable from the link dying. */
    if (result == 0)
    {
        static const char braces[] = "{\"text\":\"a{b}c\",\"ntp_time\":9.75}";

        json_parser_test_clear();
        (void)json_parser_feed((const uint8_t *)braces,
                               (uint32_t)(sizeof(braces) - 1U));

        if ((json_parser_objects != 1U) ||
            (json_parser_test_is(T_NTP, "9.75\r\n") == 0U) ||
            (json_parser_no_seq != 1U))
        {
            result = 6;
        }
    }

    /* ---- 7. oversized object dropped, and the NEXT one still works -----
       The recovery half matters more than the drop: a parser that survives one
       bad object but never parses again would pass a test checking only the
       drop. */
    if (result == 0)
    {
        static const char tail[] =
            "{\"sequence_id\":7,\"ntp_time\":3.125,\"joystick_y\":4}";
        uint32_t i;
        uint8_t  filler = (uint8_t)'x';

        json_parser_test_clear();

        (void)json_parser_feed((const uint8_t *)"{", 1U);
        for (i = 0U; i < ((uint32_t)JSON_PARSER_OBJ_MAX + 64U); i++)
        {
            (void)json_parser_feed(&filler, 1U);
        }
        (void)json_parser_feed((const uint8_t *)"}", 1U);
        (void)json_parser_feed((const uint8_t *)tail, (uint32_t)(sizeof(tail) - 1U));

        if ((json_parser_overflows != 1U) ||
            (json_parser_test_is(T_NTP, "7,3.125\r\n") == 0U) ||
            (json_parser_test_is(T_JY,  "7,4\r\n") == 0U))
        {
            result = 7;
        }
    }

    /* ---- 8. one byte per call - the worst case for reassembly ---------- */
    if (result == 0)
    {
        uint32_t i;

        json_parser_test_clear();

        for (i = 0U; i < (uint32_t)sample_len; i++)
        {
            (void)json_parser_feed((const uint8_t *)&sample[i], 1U);
        }

        if ((test_calls != 4U) ||
            (json_parser_test_is(T_NTP,  "18,1787819915.843\r\n") == 0U) ||
            (json_parser_test_is(T_CTRL, "18,1787819915.830\r\n") == 0U))
        {
            result = 8;
        }
    }

    /* ---- 9. THE LABEL COLUMN.  Added 10-09-2026. ----------------------
       Three things at once, and each has a distinct wrong answer that still
       looks like a field name:

         a) the outer quotes are stripped, so the label is "ntp_time" and not
            "\"ntp_time\"" - a line carrying its own quote characters would
            break any receiver splitting on commas;
         b) the quote-stripping does NOT eat real characters, so the decoy key
            still labels itself in full rather than as "ontroller_..._tim";
         c) the label is derived from the SAME key the value was found under,
            so a value can never be emitted under a neighbour's name.

       Run with EmitLabel back ON, which is the shipping configuration. */
    if (result == 0)
    {
        EmitLabel = 1U;

        json_parser_test_clear();
        (void)json_parser_feed((const uint8_t *)sample, (uint32_t)sample_len);

        if ((json_parser_test_is(T_NTP,
                 "18,ntp_time,1787819915.843\r\n") == 0U) ||
            (json_parser_test_is(T_CTRL,
                 "18,controller_to_base_station_received_ntp_time,"
                 "1787819915.830\r\n") == 0U) ||
            (json_parser_line_too_long != 0U))
        {
            result = 9;
        }
        else
        {
            /* ---- 9b. AN UNQUOTED KEY.  Rewritten 09-10-2026. -----------
               Still the guard against silently removing the first and last
               real characters of a key that never had quotes - but testing it
               where that actually happens, which is json_parser_label_of().

               WHAT THIS CHECK USED TO ASSERT, AND WHY IT COULD NEVER PASS.
               It fed {"sequence_id":5,"ntp_time":1.5} with the table key
               written bare as "ntp_time", and expected "5,ntp_time,1.5". That
               extraction has never worked, and should not: json_parser_find()
               matches the bare word INSIDE the JSON's own quoted key, so the
               index lands on the key's CLOSING QUOTE. The code then skips
               whitespace, requires a colon, finds that quote instead, and
               correctly concludes the key text was not a field.

               Proved by probe on 09-10-2026 - the same bare table key against
               an object whose key is also unquoted, ntp_time:1.5, extracts
               1.5 perfectly. The blocking character is the quote, nothing else.

               So the old expectation contradicted this module's own rule that
               a key MUST carry its quotes, and check 9 therefore failed on
               every boot from 10-09-2026 onward. Teaching the matcher to skip
               that quote was rejected deliberately: it would let a bare
               "ntp_time" match inside
               "controller_to_base_station_received_ntp_time" and route a
               wrong-but-entirely-plausible timestamp - the exact fault the
               quote rule exists to prevent, and the one check 2 guards.

               Both halves of the real behaviour are now asserted: the matcher
               REFUSES an unquoted table key, and label_of() still returns such
               a key whole. */
            static const json_parser_field_t bare[] = { { "ntp_time" } };
            static const char one[] = "{\"sequence_id\":5,\"ntp_time\":1.5}";
            const char *lbl = NULL;
            uint16_t    lbl_len;

            json_parser_init(bare, 1U, "\"sequence_id\"",
                             json_parser_test_emit);
            json_parser_test_clear();
            (void)json_parser_feed((const uint8_t *)one,
                                   (uint32_t)(sizeof(one) - 1U));

            /* The matcher must emit NOTHING for a key missing its quotes. */
            if (json_parser_test_is(0U, "") == 0U)
            {
                result = 9;
            }
            else
            {
                /* And the label must survive whole - "ntp_time", not
                   "tp_tim". Called directly because this is the only place the
                   unquoted branch is reachable now that the matcher refuses
                   such a key end to end. */
                lbl_len = json_parser_label_of("ntp_time", &lbl);

                if ((lbl_len != 8U) || (memcmp(lbl, "ntp_time", 8U) != 0))
                {
                    result = 9;
                }
                else
                {
                    /* And a QUOTED key still loses exactly its two quotes. */
                    lbl_len = json_parser_label_of("\"ntp_time\"", &lbl);

                    if ((lbl_len != 8U) || (memcmp(lbl, "ntp_time", 8U) != 0))
                    {
                        result = 9;
                    }
                    else
                    {
                        /* All nine checks passed. */
                    }
                }
            }
        }

        EmitLabel = 0U;
    }

    /* Restore whatever the application had installed and leave no test state.
       json_parser_init() calls json_parser_reset(), which also clears the
       obj_len_max high-water mark that check 7's deliberately oversized object
       would otherwise leave behind. */
    json_parser_init(keep_fields, keep_count, keep_prefix, keep_emit);
    json_parser_set_object_hooks(keep_begin, keep_end);

    /* Re-arm the oversize warning for the live stream. */
    Overflow_reported = 0U;

    /* Put the label column back to whatever the build configured. Restoring
       the SAVED value rather than assigning 1 keeps a build with
       JSON_PARSER_EMIT_LABEL 0 genuinely label-free after the test. */
    EmitLabel = keep_label;

    /* Same for the sequence-id column, and for the same reason: restoring the
       saved value is what lets this build go back to emitting bare values once
       the test has finished exercising the tagged format. */
    EmitPrefix = keep_prefix_col;

    #undef T_NTP
    #undef T_CTRL
    #undef T_JX
    #undef T_JY

    return result;
}
