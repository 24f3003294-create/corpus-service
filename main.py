import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

SAFE_INT_MAX = 9007199254740991
CRC32C_POLY = 0x82F63B78

TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T"
    r"(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)

GENERATION_RE = re.compile(r"^[0-9]+$")
CRC_RE = re.compile(r"^[0-9a-fA-F]{8}$")

REQUIRED_ROW_KEYS = {
    "id",
    "entity",
    "eventTime",
    "revision",
    "text"
}


# =========================================================
# CRC32C
# =========================================================

def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF

    for byte in data:
        crc ^= byte

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ CRC32C_POLY
            else:
                crc >>= 1

    return crc ^ 0xFFFFFFFF


def crc32c_hex(data: bytes) -> str:
    return f"{crc32c(data):08x}"


# =========================================================
# UTF-8 SORTING
# =========================================================

def utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


# =========================================================
# COMPACT JSON
# =========================================================

def compact_json(obj) -> str:
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    )


# =========================================================
# CANONICALIZATION
# =========================================================

def canonical_text(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = value.lower()

    # Unicode whitespace -> ASCII space
    value = "".join(
        " " if ch.isspace() else ch
        for ch in value
    )

    # Trim and collapse whitespace
    return " ".join(value.strip().split(" "))


# =========================================================
# EVENT TIME
# =========================================================

def normalize_time(value):
    if not isinstance(value, str):
        return None

    match = TIME_RE.fullmatch(value)

    if not match:
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

    if hour > 23:
        return None

    if minute > 59:
        return None

    if second > 59:
        return None

    # Time zone
    if offset == "Z":
        tz = timezone.utc

    else:
        offset_hour = int(offset[1:3])
        offset_minute = int(offset[4:6])

        if offset_hour > 14:
            return None

        if offset_minute > 59:
            return None

        # +14:00 / -14:00 only
        if offset_hour == 14 and offset_minute != 0:
            return None

        sign = 1 if offset[0] == "+" else -1

        tz = timezone(
            sign * timedelta(
                hours=offset_hour,
                minutes=offset_minute
            )
        )

    milliseconds = 0

    if fraction:
        milliseconds = int(
            fraction.ljust(3, "0")
        )

    try:
        dt = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            milliseconds * 1000,
            tzinfo=tz
        )

    except ValueError:
        return None

    dt = dt.astimezone(timezone.utc)

    return (
        dt.strftime("%Y-%m-%dT%H:%M:%S")
        + f".{dt.microsecond // 1000:03d}Z"
    )


# =========================================================
# POLICY VALIDATION
# =========================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    required = [
        "minTime",
        "maxTime",
        "contaminationThreshold"
    ]

    for key in required:
        if key not in policy:
            return False

    min_time = normalize_time(
        policy["minTime"]
    )

    max_time = normalize_time(
        policy["maxTime"]
    )

    if min_time is None:
        return False

    if max_time is None:
        return False

    threshold = policy[
        "contaminationThreshold"
    ]

    if isinstance(threshold, bool):
        return False

    if not isinstance(
        threshold,
        (int, float)
    ):
        return False

    if not math.isfinite(threshold):
        return False

    if threshold < 0 or threshold > 1:
        return False

    return True


# =========================================================
# STRICT JSON OBJECT PARSING
# =========================================================

class DuplicateKeyError(Exception):
    pass


def strict_object(pairs):

    obj = {}

    for key, value in pairs:

        if key in obj:
            raise DuplicateKeyError()

        obj[key] = value

    return obj


# =========================================================
# JSONL PARSING
# =========================================================

def parse_json_line(line):

    try:
        return json.loads(
            line,
            object_pairs_hook=strict_object
        )

    except Exception:
        return None


def parse_jsonl(content):

    if not isinstance(content, str):
        return None, "SCHEMA_INVALID"

    # Empty file is invalid
    if not any(
        line.strip()
        for line in content.split("\n")
    ):
        return None, "SCHEMA_INVALID"

    rows = []

    for line in content.split("\n"):

        # Blank lines ignored
        if not line.strip():
            continue

        obj = parse_json_line(line)

        # JSON syntax error
        if obj is None:
            return None, "JSONL_INVALID"

        if not isinstance(obj, dict):
            return None, "SCHEMA_INVALID"

        # Exactly these keys
        if set(obj.keys()) != REQUIRED_ROW_KEYS:
            return None, "SCHEMA_INVALID"

        # id
        if not isinstance(
            obj["id"],
            str
        ):
            return None, "SCHEMA_INVALID"

        # entity
        if not isinstance(
            obj["entity"],
            str
        ):
            return None, "SCHEMA_INVALID"

        # eventTime
        if not isinstance(
            obj["eventTime"],
            str
        ):
            return None, "SCHEMA_INVALID"

        # text
        if not isinstance(
            obj["text"],
            str
        ):
            return None, "SCHEMA_INVALID"

        # revision
        revision = obj["revision"]

        if isinstance(
            revision,
            bool
        ):
            return None, "SCHEMA_INVALID"

        if not isinstance(
            revision,
            int
        ):
            return None, "SCHEMA_INVALID"

        if revision < 0:
            return None, "SCHEMA_INVALID"

        if revision > SAFE_INT_MAX:
            return None, "SCHEMA_INVALID"

        # eventTime must be valid
        if normalize_time(
            obj["eventTime"]
        ) is None:
            return None, "JSONL_INVALID"

        rows.append(obj)

    if not rows:
        return None, "SCHEMA_INVALID"

    return rows, None


# =========================================================
# OBJECT VALIDATION
# =========================================================

def validate_object(obj):

    reasons = []

    if not isinstance(obj, dict):
        return (
            None,
            ["SCHEMA_INVALID"],
            None
        )

    uri = obj.get("uri")

    # URI
    if uri != "gs://bucket/object":
        reasons.append(
            "URI_INVALID"
        )

    # Generation
    generation = obj.get(
        "generation"
    )

    fetched_generation = obj.get(
        "fetchedGeneration"
    )

    generation_valid = (
        isinstance(
            generation,
            str
        )
        and GENERATION_RE.fullmatch(
            generation
        ) is not None
    )

    fetched_valid = (
        isinstance(
            fetched_generation,
            str
        )
        and GENERATION_RE.fullmatch(
            fetched_generation
        ) is not None
    )

    if not generation_valid:
        reasons.append(
            "GENERATION_INVALID"
        )

    if not fetched_valid:
        reasons.append(
            "GENERATION_INVALID"
        )

    if (
        generation_valid
        and fetched_valid
        and generation != fetched_generation
    ):
        reasons.append(
            "GENERATION_MISMATCH"
        )

    # CRC32C
    crc = obj.get("crc32c")

    crc_valid = (
        isinstance(crc, str)
        and CRC_RE.fullmatch(crc)
        is not None
    )

    if not crc_valid:
        reasons.append(
            "CRC32C_INVALID"
        )

    # Schema
    if obj.get(
        "schemaId"
    ) != "training-v1":

        reasons.append(
            "SCHEMA_INVALID"
        )

    # Content
    content = obj.get("content")

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
                key=utf8_key
            ),
            None
        )

    # CRC mismatch is checked only
    # when CRC syntax itself is valid
    if crc_valid:

        actual_crc = crc32c_hex(
            content.encode("utf-8")
        )

        if actual_crc.lower() != crc.lower():
            reasons.append(
                "CRC32C_MISMATCH"
            )

    rows, parse_error = parse_jsonl(
        content
    )

    if parse_error:
        reasons.append(
            parse_error
        )

    return (
        uri,
        sorted(
            set(reasons),
            key=utf8_key
        ),
        rows
    )


# =========================================================
# WORD SET
# =========================================================

def word_set(value):

    words = []
    current = []

    for ch in value.lower():

        category = unicodedata.category(
            ch
        )

        if (
            category.startswith("L")
            or category.startswith("N")
        ):

            current.append(ch)

        else:

            if current:
                words.append(
                    "".join(current)
                )

                current = []

    if current:
        words.append(
            "".join(current)
        )

    return set(words)


# =========================================================
# JACCARD SIMILARITY
# =========================================================

def jaccard(a, b):

    set_a = word_set(a)
    set_b = word_set(b)

    if not set_a and not set_b:
        return 1.0

    union = set_a | set_b

    if not union:
        return 1.0

    return len(
        set_a & set_b
    ) / len(union)


# =========================================================
# TRAIN / VALIDATION / TEST
# =========================================================

def get_split(entity):

    digest = hashlib.sha256(
        entity.encode("utf-8")
    ).digest()

    bucket = digest[0] % 10

    if bucket <= 5:
        return "train"

    if bucket <= 7:
        return "validation"

    return "test"


# =========================================================
# OUTPUT ROW
# =========================================================

def row_output(row):

    return {
        "id": row["id"],
        "entity": row["entity"],
        "eventTime": row["eventTime"],
        "revision": row["revision"],
        "text": row["text"]
    }


# =========================================================
# REJECTION HELPERS
# =========================================================

def add_rejected_row(
    rejected_rows,
    row_id,
    *codes
):

    rejected_rows.append({
        "id": row_id,
        "reasonCodes": sorted(
            set(codes),
            key=utf8_key
        )
    })


# =========================================================
# MAIN API
# =========================================================

@app.post("/build-corpus")
async def build_corpus(
    request: Request
):

    # -----------------------------------------------------
    # Request parsing
    # -----------------------------------------------------

    try:

        data = await request.json()

    except Exception:

        return JSONResponse(
            content={
                "error": "INVALID_INPUT"
            },
            status_code=400
        )

    # -----------------------------------------------------
    # Top-level validation
    # -----------------------------------------------------

    if (
        not isinstance(data, dict)
        or "policy" not in data
        or "objects" not in data
        or not isinstance(
            data["objects"],
            list
        )
    ):

        return JSONResponse(
            content={
                "error": "INVALID_INPUT"
            },
            status_code=400
        )

    policy = data["policy"]
    objects = data["objects"]

    # -----------------------------------------------------
    # Policy
    # -----------------------------------------------------

    policy_valid = validate_policy(
        policy
    )

    # -----------------------------------------------------
    # Objects
    # -----------------------------------------------------

    rejected_objects = []
    accepted_objects = []

    for obj in objects:

        uri, reasons, rows = validate_object(
            obj
        )

        if reasons:

            rejected_objects.append({
                "uri": (
                    uri
                    if isinstance(uri, str)
                    else None
                ),
                "reasonCodes": sorted(
                    set(reasons),
                    key=utf8_key
                )
            })

            continue

        accepted_objects.append({
            "obj": obj,
            "rows": rows
        })

    # -----------------------------------------------------
    # Lineage
    # -----------------------------------------------------

    lineage = []

    for item in accepted_objects:

        obj = item["obj"]

        lineage.append({
            "uri": obj["uri"],
            "generation": obj["generation"],
            "crc32c": obj["crc32c"].lower(),
            "schemaId": obj["schemaId"]
        })

    # -----------------------------------------------------
    # Canonicalize rows
    # -----------------------------------------------------

    candidates = []

    for item in accepted_objects:

        for row in item["rows"]:

            candidates.append({

                "id": row["id"],

                "entity": canonical_text(
                    row["entity"]
                ),

                "eventTime": normalize_time(
                    row["eventTime"]
                ),

                "revision": row["revision"],

                "text": canonical_text(
                    row["text"]
                )
            })

    # -----------------------------------------------------
    # Deduplication
    # -----------------------------------------------------

    groups = {}

    for row in candidates:

        key = (
            row["entity"],
            row["eventTime"],
            row["text"]
        )

        groups.setdefault(
            key,
            []
        ).append(row)

    retained = []
    rejected_rows = []

    for rows in groups.values():

        # Highest revision wins.
        # If tied, smallest UTF-8 ID wins.
        winner = min(
            rows,
            key=lambda r: (
                -r["revision"],
                utf8_key(r["id"])
            )
        )

        retained.append(
            winner
        )

        for row in rows:

            if row is not winner:

                add_rejected_row(
                    rejected_rows,
                    row["id"],
                    "DUPLICATE"
                )

    # -----------------------------------------------------
    # Policy processing
    # -----------------------------------------------------

    if not policy_valid:

        for row in retained:

            add_rejected_row(
                rejected_rows,
                row["id"],
                "POLICY_INVALID"
            )

        retained = []

    else:

        min_time = normalize_time(
            policy["minTime"]
        )

        max_time = normalize_time(
            policy["maxTime"]
        )

        kept = []

        for row in retained:

            if (
                row["eventTime"] < min_time
                or row["eventTime"] > max_time
            ):

                add_rejected_row(
                    rejected_rows,
                    row["id"],
                    "OUT_OF_WINDOW"
                )

            else:

                kept.append(row)

        retained = kept

    # -----------------------------------------------------
    # Split
    # -----------------------------------------------------

    splits = {
        "train": [],
        "validation": [],
        "test": []
    }

    for row in retained:

        split = get_split(
            row["entity"]
        )

        splits[split].append(
            row
        )

    # -----------------------------------------------------
    # Contamination
    # -----------------------------------------------------

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

            kept = []

            for row in splits[
                split_name
            ]:

                contaminated = any(

                    jaccard(
                        row["text"],
                        train_row["text"]
                    ) >= threshold

                    for train_row
                    in train_rows
                )

                if contaminated:

                    add_rejected_row(
                        rejected_rows,
                        row["id"],
                        "TRAIN_CONTAMINATION"
                    )

                else:

                    kept.append(
                        row
                    )

            splits[
                split_name
            ] = kept

    # -----------------------------------------------------
    # Sort split rows
    # -----------------------------------------------------

    for split_name in splits:

        splits[split_name].sort(
            key=lambda r:
                utf8_key(r["id"])
        )

    # -----------------------------------------------------
    # Digests
    # -----------------------------------------------------

    digests = {}

    for split_name in (
        "train",
        "validation",
        "test"
    ):

        lines = []

        for row in splits[
            split_name
        ]:

            lines.append(
                compact_json(
                    row_output(row)
                )
            )

        # One newline per row
        exact_jsonl = "".join(
            line + "\n"
            for line in lines
        )

        digests[split_name] = (
            hashlib.sha256(
                exact_jsonl.encode(
                    "utf-8"
                )
            ).hexdigest()
        )

    # -----------------------------------------------------
    # Merge rejected row codes
    # -----------------------------------------------------

    merged = {}

    for item in rejected_rows:

        row_id = item["id"]

        if row_id not in merged:
            merged[row_id] = set()

        merged[row_id].update(
            item["reasonCodes"]
        )

    rejected_rows = []

    for row_id, codes in merged.items():

        rejected_rows.append({
            "id": row_id,
            "reasonCodes": sorted(
                codes,
                key=utf8_key
            )
        })

    # -----------------------------------------------------
    # Sort rejected rows
    # -----------------------------------------------------

    rejected_rows.sort(
        key=lambda x:
            utf8_key(x["id"])
    )

    # -----------------------------------------------------
    # Sort rejected objects
    # -----------------------------------------------------

    rejected_objects.sort(
        key=lambda x:
            utf8_key(
                x["uri"]
                if isinstance(
                    x["uri"],
                    str
                )
                else ""
            )
    )

    # -----------------------------------------------------
    # Sort lineage
    # -----------------------------------------------------

    lineage.sort(
        key=lambda x:
            utf8_key(x["uri"])
    )

    # -----------------------------------------------------
    # Final response
    # -----------------------------------------------------

    return {

        "splits": {

            "train": [
                row_output(row)
                for row
                in splits["train"]
            ],

            "validation": [
                row_output(row)
                for row
                in splits["validation"]
            ],

            "test": [
                row_output(row)
                for row
                in splits["test"]
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


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "status": "ok",
        "endpoint": "/build-corpus"
    }


# =========================================================
# LOCAL RUN
# =========================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000
    )