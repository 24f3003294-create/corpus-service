import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

SAFE_INTEGER_MAX = 9007199254740991
CRC32C_POLYNOMIAL = 0x82F63B78

REQUIRED_ROW_FIELDS = {
    "id",
    "entity",
    "eventTime",
    "revision",
    "text"
}

GENERATION_PATTERN = re.compile(r"^[0-9]+$")
CRC32C_PATTERN = re.compile(r"^[0-9a-fA-F]{8}$")

TIME_PATTERN = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)


# ============================================================
# UTF-8
# ============================================================

def utf8_key(value):
    return value.encode("utf-8")


# ============================================================
# CRC32C
# ============================================================

def crc32c(data):
    crc = 0xFFFFFFFF

    for byte in data:
        crc ^= byte

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ CRC32C_POLYNOMIAL
            else:
                crc >>= 1

    return crc ^ 0xFFFFFFFF


def crc32c_hex(data):
    return f"{crc32c(data):08x}"


# ============================================================
# JSON
# ============================================================

def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    )


# ============================================================
# CANONICALIZATION
# ============================================================

def canonicalize(value):
    value = unicodedata.normalize("NFKC", value)
    value = value.lower()

    result = []

    for ch in value:
        if ch.isspace():
            result.append(" ")
        else:
            result.append(ch)

    value = "".join(result)

    return re.sub(r" +", " ", value.strip())


# ============================================================
# TIME
# ============================================================

def normalize_time(value):

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

    if hour > 23 or minute > 59 or second > 59:
        return None

    if offset == "Z":

        tz = timezone.utc

    else:

        off_hour = int(offset[1:3])
        off_minute = int(offset[4:6])

        if off_hour > 14:
            return None

        if off_minute > 59:
            return None

        if off_hour == 14 and off_minute != 0:
            return None

        sign = 1 if offset[0] == "+" else -1

        tz = timezone(
            sign * timedelta(
                hours=off_hour,
                minutes=off_minute
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


# ============================================================
# POLICY
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    required = [
        "minTime",
        "maxTime",
        "contaminationThreshold"
    ]

    if any(key not in policy for key in required):
        return False

    min_time = normalize_time(policy["minTime"])
    max_time = normalize_time(policy["maxTime"])

    if min_time is None or max_time is None:
        return False

    threshold = policy["contaminationThreshold"]

    if isinstance(threshold, bool):
        return False

    if not isinstance(threshold, (int, float)):
        return False

    if not math.isfinite(threshold):
        return False

    if threshold < 0 or threshold > 1:
        return False

    return True


# ============================================================
# STRICT JSON OBJECT
# ============================================================

class DuplicateKeyError(Exception):
    pass


def strict_object(pairs):

    result = {}

    for key, value in pairs:

        if key in result:
            raise DuplicateKeyError()

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
# JSONL
# ============================================================

def parse_jsonl(content):

    if not isinstance(content, str):
        return None, "SCHEMA_INVALID"

    rows = []

    for line in content.split("\n"):

        if not line.strip():
            continue

        obj = parse_json_line(line)

        if obj is None:
            return None, "JSONL_INVALID"

        if not isinstance(obj, dict):
            return None, "SCHEMA_INVALID"

        if set(obj.keys()) != REQUIRED_ROW_FIELDS:
            return None, "SCHEMA_INVALID"

        if not isinstance(obj["id"], str):
            return None, "SCHEMA_INVALID"

        if not isinstance(obj["entity"], str):
            return None, "SCHEMA_INVALID"

        if not isinstance(obj["eventTime"], str):
            return None, "SCHEMA_INVALID"

        if not isinstance(obj["text"], str):
            return None, "SCHEMA_INVALID"

        revision = obj["revision"]

        if isinstance(revision, bool):
            return None, "SCHEMA_INVALID"

        if not isinstance(revision, int):
            return None, "SCHEMA_INVALID"

        if revision < 0 or revision > SAFE_INTEGER_MAX:
            return None, "SCHEMA_INVALID"

        if normalize_time(obj["eventTime"]) is None:
            return None, "SCHEMA_INVALID"

        rows.append(obj)

    if not rows:
        return None, "SCHEMA_INVALID"

    return rows, None


# ============================================================
# OBJECT VALIDATION
# ============================================================

def validate_object(obj):

    reasons = []

    if not isinstance(obj, dict):
        return None, ["SCHEMA_INVALID"], None

    uri = obj.get("uri")

    if uri != "gs://bucket/object":
        reasons.append("URI_INVALID")

    generation = obj.get("generation")
    fetched = obj.get("fetchedGeneration")

    generation_valid = (
        isinstance(generation, str)
        and GENERATION_PATTERN.fullmatch(generation)
    )

    fetched_valid = (
        isinstance(fetched, str)
        and GENERATION_PATTERN.fullmatch(fetched)
    )

    if not generation_valid:
        reasons.append("GENERATION_INVALID")

    if not fetched_valid:
        reasons.append("GENERATION_INVALID")

    if (
        generation_valid
        and fetched_valid
        and generation != fetched
    ):
        reasons.append("GENERATION_MISMATCH")

    crc = obj.get("crc32c")

    crc_valid = (
        isinstance(crc, str)
        and CRC32C_PATTERN.fullmatch(crc)
    )

    if not crc_valid:
        reasons.append("CRC32C_INVALID")

    if obj.get("schemaId") != "training-v1":
        reasons.append("SCHEMA_INVALID")

    content = obj.get("content")

    if not isinstance(content, str):
        reasons.append("SCHEMA_INVALID")

        return (
            uri,
            sorted(set(reasons), key=utf8_key),
            None
        )

    if crc_valid:

        actual_crc = crc32c_hex(
            content.encode("utf-8")
        )

        if actual_crc.lower() != crc.lower():
            reasons.append("CRC32C_MISMATCH")

    rows, error = parse_jsonl(content)

    if error:
        reasons.append(error)

    return (
        uri,
        sorted(set(reasons), key=utf8_key),
        rows
    )


# ============================================================
# WORD SET
# ============================================================

def word_set(text):

    words = []
    current = []

    for ch in text.lower():

        category = unicodedata.category(ch)

        if (
            category.startswith("L")
            or category.startswith("N")
        ):

            current.append(ch)

        else:

            if current:
                words.append("".join(current))
                current = []

    if current:
        words.append("".join(current))

    return set(words)


# ============================================================
# JACCARD
# ============================================================

def jaccard(a, b):

    a_set = word_set(a)
    b_set = word_set(b)

    if not a_set and not b_set:
        return 1.0

    union = a_set | b_set

    if not union:
        return 1.0

    return len(a_set & b_set) / len(union)


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
# API
# ============================================================

@app.post("/build-corpus")
async def build_corpus(request: Request):

    # --------------------------------------------------------
    # Request parsing
    # --------------------------------------------------------

    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    # --------------------------------------------------------
    # Top level
    # --------------------------------------------------------

    if not isinstance(data, dict):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    if "policy" not in data:
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    if "objects" not in data:
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    if not isinstance(data["objects"], list):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    policy = data["policy"]
    objects = data["objects"]

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    policy_valid = validate_policy(policy)

    # --------------------------------------------------------
    # Object validation
    # --------------------------------------------------------

    rejected_objects = []
    accepted_objects = []

    for obj in objects:

        uri, reasons, rows = validate_object(obj)

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

        else:

            accepted_objects.append({
                "object": obj,
                "rows": rows
            })

    # --------------------------------------------------------
    # Lineage
    # --------------------------------------------------------

    lineage = []

    for item in accepted_objects:

        obj = item["object"]

        lineage.append({
            "uri": obj["uri"],
            "generation": obj["generation"],
            "crc32c": obj["crc32c"].lower(),
            "schemaId": obj["schemaId"]
        })

    # --------------------------------------------------------
    # Canonicalize
    # --------------------------------------------------------

    candidates = []

    for item in accepted_objects:

        for row in item["rows"]:

            candidates.append({
                "id": row["id"],
                "entity": canonicalize(row["entity"]),
                "eventTime": normalize_time(
                    row["eventTime"]
                ),
                "revision": row["revision"],
                "text": canonicalize(row["text"])
            })

    # --------------------------------------------------------
    # Deduplication
    # --------------------------------------------------------

    groups = {}

    for row in candidates:

        key = (
            row["entity"],
            row["eventTime"],
            row["text"]
        )

        groups.setdefault(key, []).append(row)

    retained = []
    rejected_rows = []

    for group in groups.values():

        winner = sorted(
            group,
            key=lambda row: (
                -row["revision"],
                utf8_key(row["id"])
            )
        )[0]

        retained.append(winner)

        for row in group:

            if row is not winner:

                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": [
                        "DUPLICATE"
                    ]
                })

    # --------------------------------------------------------
    # Policy / time window
    # --------------------------------------------------------

    if not policy_valid:

        for row in retained:

            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": [
                    "POLICY_INVALID"
                ]
            })

        retained = []

    else:

        minimum = normalize_time(
            policy["minTime"]
        )

        maximum = normalize_time(
            policy["maxTime"]
        )

        inside = []

        for row in retained:

            if (
                row["eventTime"] < minimum
                or row["eventTime"] > maximum
            ):

                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": [
                        "OUT_OF_WINDOW"
                    ]
                })

            else:

                inside.append(row)

        retained = inside

    # --------------------------------------------------------
    # Split
    # --------------------------------------------------------

    splits = {
        "train": [],
        "validation": [],
        "test": []
    }

    for row in retained:

        split = determine_split(
            row["entity"]
        )

        splits[split].append(row)

    # --------------------------------------------------------
    # Contamination
    # --------------------------------------------------------

    if policy_valid:

        threshold = policy[
            "contaminationThreshold"
        ]

        train_rows = splits["train"]

        for split_name in (
            "validation",
            "test"
        ):

            clean = []

            for row in splits[split_name]:

                contaminated = False

                for train_row in train_rows:

                    if (
                        jaccard(
                            row["text"],
                            train_row["text"]
                        )
                        >= threshold
                    ):

                        contaminated = True
                        break

                if contaminated:

                    rejected_rows.append({
                        "id": row["id"],
                        "reasonCodes": [
                            "TRAIN_CONTAMINATION"
                        ]
                    })

                else:

                    clean.append(row)

            splits[split_name] = clean

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    for split_name in splits:

        splits[split_name].sort(
            key=lambda row:
                utf8_key(row["id"])
        )

    # --------------------------------------------------------
    # Digests
    # --------------------------------------------------------

    digests = {}

    for split_name in (
        "train",
        "validation",
        "test"
    ):

        content = ""

        for row in splits[split_name]:

            content += (
                compact_json(
                    output_row(row)
                )
                + "\n"
            )

        digests[split_name] = hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()

    # --------------------------------------------------------
    # Merge rejection codes
    # --------------------------------------------------------

    merged = {}

    for item in rejected_rows:

        row_id = item["id"]

        if row_id not in merged:
            merged[row_id] = set()

        merged[row_id].update(
            item["reasonCodes"]
        )

    rejected_rows = [
        {
            "id": row_id,
            "reasonCodes": sorted(
                codes,
                key=utf8_key
            )
        }
        for row_id, codes
        in merged.items()
    ]

    # --------------------------------------------------------
    # Sort rejected rows
    # --------------------------------------------------------

    rejected_rows.sort(
        key=lambda item:
            utf8_key(item["id"])
    )

    # --------------------------------------------------------
    # Sort rejected objects
    # --------------------------------------------------------

    rejected_objects.sort(
        key=lambda item:
            utf8_key(
                item["uri"]
                if isinstance(
                    item["uri"],
                    str
                )
                else ""
            )
    )

    # --------------------------------------------------------
    # Sort lineage
    # --------------------------------------------------------

    lineage.sort(
        key=lambda item:
            utf8_key(item["uri"])
    )

    # --------------------------------------------------------
    # Final response
    # --------------------------------------------------------

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
        "rejectedObjects": rejected_objects,
        "rejectedRows": rejected_rows,
        "digests": digests,
        "lineage": lineage
    }


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "endpoint": "/build-corpus"
    }


# ============================================================
# LOCAL
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000
    )