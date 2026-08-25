import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()


# ============================================================
# CONSTANTS
# ============================================================

SAFE_INTEGER_MAX = 9007199254740991

CRC32C_POLYNOMIAL = 0x82F63B78

REQUIRED_ROW_FIELDS = {
    "id",
    "entity",
    "eventTime",
    "revision",
    "text",
}

GENERATION_PATTERN = re.compile(
    r"^[0-9]+$"
)

CRC32C_PATTERN = re.compile(
    r"^[0-9a-f]{8}$"
)

TIME_PATTERN = re.compile(
    r"^"
    r"(\d{4})-"
    r"(\d{2})-"
    r"(\d{2})"
    r"T"
    r"(\d{2}):"
    r"(\d{2}):"
    r"(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})"
    r"$"
)


# ============================================================
# UTF-8 SORTING
# ============================================================

def utf8_bytes(value):
    return value.encode("utf-8")


# ============================================================
# CRC32C
# ============================================================

def calculate_crc32c(data):
    crc = 0xFFFFFFFF

    for byte in data:
        crc ^= byte

        for _ in range(8):
            if crc & 1:
                crc = (
                    crc >> 1
                ) ^ CRC32C_POLYNOMIAL
            else:
                crc >>= 1

    return crc ^ 0xFFFFFFFF


def crc32c_hex(data):
    return format(
        calculate_crc32c(data),
        "08x"
    )


# ============================================================
# COMPACT JSON
# ============================================================

def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    )


# ============================================================
# CANONICALIZE TEXT
# ============================================================

def canonicalize_text(value):

    value = unicodedata.normalize(
        "NFKC",
        value
    )

    value = value.lower()

    characters = []

    for character in value:

        if character.isspace():
            characters.append(" ")
        else:
            characters.append(character)

    value = "".join(characters)

    value = value.strip()

    value = re.sub(
        r" +",
        " ",
        value
    )

    return value


# ============================================================
# EVENT TIME
# ============================================================

def normalize_event_time(value):

    if not isinstance(value, str):
        return None

    match = TIME_PATTERN.fullmatch(value)

    if match is None:
        return None

    (
        year,
        month,
        day,
        hour,
        minute,
        second,
        fraction,
        offset
    ) = match.groups()

    year = int(year)
    month = int(month)
    day = int(day)
    hour = int(hour)
    minute = int(minute)
    second = int(second)

    # Validate clock
    if hour > 23:
        return None

    if minute > 59:
        return None

    if second > 59:
        return None

    # Time zone
    if offset == "Z":

        timezone_value = timezone.utc

    else:

        offset_hours = int(
            offset[1:3]
        )

        offset_minutes = int(
            offset[4:6]
        )

        if offset_hours > 14:
            return None

        if offset_minutes > 59:
            return None

        # If hour is 14, minutes must be 00.
        if (
            offset_hours == 14
            and offset_minutes != 0
        ):
            return None

        sign = 1 if offset[0] == "+" else -1

        timezone_value = timezone(
            sign * timedelta(
                hours=offset_hours,
                minutes=offset_minutes
            )
        )

    # Fractional seconds
    milliseconds = 0

    if fraction is not None:

        milliseconds = int(
            fraction.ljust(3, "0")
        )

    try:

        date_time = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            milliseconds * 1000,
            tzinfo=timezone_value
        )

    except ValueError:

        return None

    # Convert to UTC
    date_time = date_time.astimezone(
        timezone.utc
    )

    return (
        date_time.strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        + "."
        + f"{date_time.microsecond // 1000:03d}"
        + "Z"
    )


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(
        policy,
        dict
    ):
        return False

    required_fields = [
        "minTime",
        "maxTime",
        "contaminationThreshold"
    ]

    for field in required_fields:

        if field not in policy:
            return False

    minimum = normalize_event_time(
        policy["minTime"]
    )

    maximum = normalize_event_time(
        policy["maxTime"]
    )

    if minimum is None:
        return False

    if maximum is None:
        return False

    threshold = policy[
        "contaminationThreshold"
    ]

    if isinstance(
        threshold,
        bool
    ):
        return False

    if not isinstance(
        threshold,
        (int, float)
    ):
        return False

    if not math.isfinite(
        threshold
    ):
        return False

    if threshold < 0:
        return False

    if threshold > 1:
        return False

    if minimum > maximum:
        return False

    return True


# ============================================================
# STRICT JSON PARSER
# ============================================================

class DuplicateJSONKey(Exception):
    pass


def strict_object(pairs):

    result = {}

    for key, value in pairs:

        if key in result:
            raise DuplicateJSONKey()

        result[key] = value

    return result


def parse_json_line(line):

    try:

        return json.loads(
            line,
            object_pairs_hook=strict_object
        )

    except Exception:

        return None


# ============================================================
# JSONL VALIDATION
# ============================================================

def parse_jsonl(content):

    if not isinstance(
        content,
        str
    ):
        return (
            None,
            "SCHEMA_INVALID"
        )

    lines = content.split("\n")

    rows = []

    for line in lines:

        # Blank lines are ignored
        if not line.strip():
            continue

        parsed = parse_json_line(
            line
        )

        # JSON parsing failed
        if parsed is None:

            return (
                None,
                "JSONL_INVALID"
            )

        # Must be an object
        if not isinstance(
            parsed,
            dict
        ):

            return (
                None,
                "SCHEMA_INVALID"
            )

        # Must contain exactly:
        # id, entity, eventTime, revision, text
        if set(parsed.keys()) != REQUIRED_ROW_FIELDS:

            return (
                None,
                "SCHEMA_INVALID"
            )

        # Four string fields
        if not isinstance(
            parsed["id"],
            str
        ):

            return (
                None,
                "SCHEMA_INVALID"
            )

        if not isinstance(
            parsed["entity"],
            str
        ):

            return (
                None,
                "SCHEMA_INVALID"
            )

        if not isinstance(
            parsed["eventTime"],
            str
        ):

            return (
                None,
                "SCHEMA_INVALID"
            )

        if not isinstance(
            parsed["text"],
            str
        ):

            return (
                None,
                "SCHEMA_INVALID"
            )

        # Revision
        revision = parsed[
            "revision"
        ]

        if isinstance(
            revision,
            bool
        ):

            return (
                None,
                "SCHEMA_INVALID"
            )

        if not isinstance(
            revision,
            int
        ):

            return (
                None,
                "SCHEMA_INVALID"
            )

        if revision < 0:

            return (
                None,
                "SCHEMA_INVALID"
            )

        if revision > SAFE_INTEGER_MAX:

            return (
                None,
                "SCHEMA_INVALID"
            )

        # Validate eventTime
        if normalize_event_time(
            parsed["eventTime"]
        ) is None:

            return (
                None,
                "SCHEMA_INVALID"
            )

        rows.append(parsed)

    # File must contain at least one row
    if len(rows) == 0:

        return (
            None,
            "SCHEMA_INVALID"
        )

    return (
        rows,
        None
    )


# ============================================================
# OBJECT VALIDATION
# ============================================================

def validate_object(obj):

    reasons = []

    # Object itself must be an object
    if not isinstance(
        obj,
        dict
    ):

        return (
            None,
            ["SCHEMA_INVALID"],
            None
        )

    # --------------------------------------------------------
    # URI
    # --------------------------------------------------------

    uri = obj.get("uri")

    if uri != "gs://bucket/object":

        reasons.append(
            "URI_INVALID"
        )

    # --------------------------------------------------------
    # GENERATION
    # --------------------------------------------------------

    generation = obj.get(
        "generation"
    )

    fetched_generation = obj.get(
        "fetchGeneration"
    )

    generation_valid = (
        isinstance(
            generation,
            str
        )
        and GENERATION_PATTERN.fullmatch(
            generation
        ) is not None
    )

    fetched_generation_valid = (
        isinstance(
            fetched_generation,
            str
        )
        and GENERATION_PATTERN.fullmatch(
            fetched_generation
        ) is not None
    )

    if not generation_valid:

        reasons.append(
            "GENERATION_INVALID"
        )

    if not fetched_generation_valid:

        reasons.append(
            "GENERATION_INVALID"
        )

    if (
        generation_valid
        and fetched_generation_valid
        and generation != fetched_generation
    ):

        reasons.append(
            "GENERATION_MISMATCH"
        )

    # --------------------------------------------------------
    # CRC32C
    # --------------------------------------------------------

    crc_value = obj.get(
        "crc32c"
    )

    crc_valid = (
        isinstance(
            crc_value,
            str
        )
        and CRC32C_PATTERN.fullmatch(
            crc_value
        ) is not None
    )

    if not crc_valid:

        reasons.append(
            "CRC32C_INVALID"
        )

    # --------------------------------------------------------
    # SCHEMA
    # --------------------------------------------------------

    if obj.get(
        "schemaId"
    ) != "training-v1":

        reasons.append(
            "SCHEMA_INVALID"
        )

    # --------------------------------------------------------
    # CONTENT
    # --------------------------------------------------------

    content = obj.get(
        "content"
    )

    if not isinstance(
        content,
        str
    ):

        reasons.append(
            "SCHEMA_INVALID"
        )

        return (
            uri,
            sorted(
                set(reasons),
                key=utf8_bytes
            ),
            None
        )

    # --------------------------------------------------------
    # CRC MATCH
    # --------------------------------------------------------

    if crc_valid:

        calculated_crc = crc32c_hex(
            content.encode("utf-8")
        )

        if calculated_crc != crc_value:

            reasons.append(
                "CRC32C_MISMATCH"
            )

    # --------------------------------------------------------
    # JSONL
    # --------------------------------------------------------

    rows, jsonl_error = parse_jsonl(
        content
    )

    if jsonl_error is not None:

        reasons.append(
            jsonl_error
        )

    return (
        uri,
        sorted(
            set(reasons),
            key=utf8_bytes
        ),
        rows
    )


# ============================================================
# WORD SET FOR CONTAMINATION
# ============================================================

def unicode_word_set(text):

    result = []

    current = []

    for character in text.lower():

        category = unicodedata.category(
            character
        )

        is_letter_or_number = (
            category.startswith("L")
            or category.startswith("N")
        )

        if is_letter_or_number:

            current.append(
                character
            )

        else:

            if current:

                result.append(
                    "".join(current)
                )

                current = []

    if current:

        result.append(
            "".join(current)
        )

    return set(result)


# ============================================================
# JACCARD
# ============================================================

def jaccard_similarity(
    first,
    second
):

    first_set = unicode_word_set(
        first
    )

    second_set = unicode_word_set(
        second
    )

    # Empty / empty = 1
    if (
        not first_set
        and not second_set
    ):

        return 1.0

    union = (
        first_set
        | second_set
    )

    if not union:
        return 1.0

    intersection = (
        first_set
        & second_set
    )

    return (
        len(intersection)
        / len(union)
    )


# ============================================================
# SPLIT
# ============================================================

def determine_split(entity):

    digest = hashlib.sha256(
        entity.encode("utf-8")
    ).digest()

    bucket = digest[0] % 10

    if bucket <= 5:

        return "train"

    if bucket <= 7:

        return "validation"

    return "test"


# ============================================================
# OUTPUT ROW
# ============================================================

def output_row(row):

    return {
        "id": row["id"],
        "entity": row["entity"],
        "eventTime": row["eventTime"],
        "revision": row["revision"],
        "text": row["text"]
    }


# ============================================================
# ADD REJECTION
# ============================================================

def add_rejection(
    rejected_rows,
    row_id,
    code
):

    rejected_rows.append({
        "id": row_id,
        "reasonCodes": [
            code
        ]
    })


# ============================================================
# API ENDPOINT
# ============================================================

@app.post(
    "/build-corpus"
)
async def build_corpus(
    request: Request
):

    # ========================================================
    # REQUEST PARSING
    # ========================================================

    try:

        request_data = (
            await request.json()
        )

    except Exception:

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            }
        )

    # ========================================================
    # TOP LEVEL
    # ========================================================

    if not isinstance(
        request_data,
        dict
    ):

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            }
        )

    if "policy" not in request_data:

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            }
        )

    if "objects" not in request_data:

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            }
        )

    if not isinstance(
        request_data["objects"],
        list
    ):

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            }
        )

    policy = request_data[
        "policy"
    ]

    objects = request_data[
        "objects"
    ]

    # ========================================================
    # POLICY
    # ========================================================

    policy_valid = validate_policy(
        policy
    )

    # ========================================================
    # OBJECTS
    # ========================================================

    rejected_objects = []

    valid_objects = []

    for obj in objects:

        (
            uri,
            reason_codes,
            rows
        ) = validate_object(
            obj
        )

        if reason_codes:

            rejected_objects.append({
                "uri": (
                    uri
                    if isinstance(
                        uri,
                        str
                    )
                    else None
                ),
                "reasonCodes":
                    sorted(
                        set(reason_codes),
                        key=utf8_bytes
                    )
            })

        else:

            valid_objects.append({
                "object": obj,
                "rows": rows
            })

    # ========================================================
    # LINEAGE
    # ========================================================

    lineage = []

    for item in valid_objects:

        obj = item[
            "object"
        ]

        lineage.append({
            "uri": obj["uri"],
            "generation": obj["generation"],
            "crc32c": obj["crc32c"].lower(),
            "schemaId": obj["schemaId"]
        })

    # ========================================================
    # CANONICALIZATION
    # ========================================================

    candidates = []

    for item in valid_objects:

        rows = item["rows"]

        for row in rows:

            candidates.append({

                "id":
                    row["id"],

                "entity":
                    canonicalize_text(
                        row["entity"]
                    ),

                "eventTime":
                    normalize_event_time(
                        row["eventTime"]
                    ),

                "revision":
                    row["revision"],

                "text":
                    canonicalize_text(
                        row["text"]
                    )
            })

    # ========================================================
    # DEDUPLICATION
    # ========================================================

    duplicate_groups = {}

    for row in candidates:

        key = (
            row["entity"],
            row["eventTime"],
            row["text"]
        )

        if key not in duplicate_groups:

            duplicate_groups[key] = []

        duplicate_groups[key].append(
            row
        )

    retained_rows = []

    rejected_rows = []

    for group in duplicate_groups.values():

        # Highest revision first.
        # Smallest UTF-8 ID wins if revisions tie.
        winner = sorted(
            group,
            key=lambda row: (
                -row["revision"],
                utf8_bytes(
                    row["id"]
                )
            )
        )[0]

        retained_rows.append(
            winner
        )

        for row in group:

            if row is not winner:

                add_rejection(
                    rejected_rows,
                    row["id"],
                    "DUPLICATE"
                )

    # ========================================================
    # POLICY
    # ========================================================

    if not policy_valid:

        for row in retained_rows:

            add_rejection(
                rejected_rows,
                row["id"],
                "POLICY_INVALID"
            )

        retained_rows = []

    else:

        minimum_time = normalize_event_time(
            policy["minTime"]
        )

        maximum_time = normalize_event_time(
            policy["maxTime"]
        )

        inside_window = []

        for row in retained_rows:

            if (
                row["eventTime"]
                < minimum_time
                or
                row["eventTime"]
                > maximum_time
            ):

                add_rejection(
                    rejected_rows,
                    row["id"],
                    "OUT_OF_WINDOW"
                )

            else:

                inside_window.append(
                    row
                )

        retained_rows = inside_window

    # ========================================================
    # SPLIT
    # ========================================================

    splits = {
        "train": [],
        "validation": [],
        "test": []
    }

    for row in retained_rows:

        split = determine_split(
            row["entity"]
        )

        splits[split].append(
            row
        )

    # ========================================================
    # CONTAMINATION
    # ========================================================

    if policy_valid:

        threshold = policy[
            "contaminationThreshold"
        ]

        train_rows = splits[
            "train"
        ]

        for split_name in (
            "validation",
            "test"
        ):

            clean_rows = []

            for row in splits[
                split_name
            ]:

                contaminated = False

                for train_row in train_rows:

                    similarity = (
                        jaccard_similarity(
                            row["text"],
                            train_row["text"]
                        )
                    )

                    if similarity >= threshold:

                        contaminated = True

                        break

                if contaminated:

                    add_rejection(
                        rejected_rows,
                        row["id"],
                        "TRAIN_CONTAMINATION"
                    )

                else:

                    clean_rows.append(
                        row
                    )

            splits[
                split_name
            ] = clean_rows

    # ========================================================
    # SORT SPLITS
    # ========================================================

    for split_name in (
        "train",
        "validation",
        "test"
    ):

        splits[
            split_name
        ].sort(
            key=lambda row:
                utf8_bytes(
                    row["id"]
                )
        )

    # ========================================================
    # DIGESTS
    # ========================================================

    digests = {}

    for split_name in (
        "train",
        "validation",
        "test"
    ):

        jsonl_lines = []

        for row in splits[
            split_name
        ]:

            jsonl_lines.append(
                compact_json(
                    output_row(row)
                )
            )

        exact_jsonl = ""

        for line in jsonl_lines:

            exact_jsonl += (
                line
                + "\n"
            )

        digest = hashlib.sha256(
            exact_jsonl.encode(
                "utf-8"
            )
        ).hexdigest()

        digests[
            split_name
        ] = digest

    # ========================================================
    # MERGE REJECTED ROW REASONS
    # ========================================================

    rejected_by_id = {}

    for item in rejected_rows:

        row_id = item["id"]

        if row_id not in rejected_by_id:

            rejected_by_id[row_id] = set()

        for code in item[
            "reasonCodes"
        ]:

            rejected_by_id[
                row_id
            ].add(code)

    rejected_rows = []

    for row_id in rejected_by_id:

        codes = sorted(
            rejected_by_id[row_id],
            key=utf8_bytes
        )

        rejected_rows.append({
            "id": row_id,
            "reasonCodes": codes
        })

    # ========================================================
    # SORT REJECTED ROWS
    # ========================================================

    rejected_rows.sort(
        key=lambda item:
            utf8_bytes(
                item["id"]
            )
    )

    # ========================================================
    # SORT REJECTED OBJECTS
    # ========================================================

    rejected_objects.sort(
        key=lambda item:
            utf8_bytes(
                item["uri"]
                if isinstance(
                    item["uri"],
                    str
                )
                else ""
            )
    )

    # ========================================================
    # SORT LINEAGE
    # ========================================================

    lineage.sort(
        key=lambda item:
            utf8_bytes(
                item["uri"]
            )
    )

    # ========================================================
    # RESPONSE
    # ========================================================

    return {

        "splits": {

            "train": [
                output_row(row)
                for row in splits["train"]
            ],

            "validation": [
                output_row(row)
                for row in splits["validation"]
            ],

            "test": [
                output_row(row)
                for row in splits["test"]
            ]
        },

        "rejectedObjects":
            rejected_objects,

        "rejectedRows":
            rejected_rows,

        "digests":
            digests,

        "lineage":
            lineage
    }


# ============================================================
# ROOT TEST
# ============================================================

@app.get("/")
def root():

    return {
        "status": "ok",
        "endpoint": "/build-corpus"
    }


# ============================================================
# LOCAL RUN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000
    )