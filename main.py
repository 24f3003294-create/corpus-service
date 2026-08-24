import json
import hashlib
import math
import re
import unicodedata
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()


# ---------------------------------------------------------
# CRC32C - Castagnoli
# ---------------------------------------------------------

CRC32C_POLY = 0x82F63B78


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


# ---------------------------------------------------------
# UTF-8 byte sorting
# ---------------------------------------------------------

def utf8_key(value):
    return value.encode("utf-8")


# ---------------------------------------------------------
# Unicode canonicalization
# ---------------------------------------------------------

def canonical_text(value):
    value = unicodedata.normalize("NFKC", value)
    value = value.lower()
    value = value.strip()

    # Unicode whitespace -> ASCII space
    result = []

    for ch in value:
        if ch.isspace():
            result.append(" ")
        else:
            result.append(ch)

    value = "".join(result)

    # Collapse multiple spaces
    value = re.sub(r" +", " ", value)

    return value


# ---------------------------------------------------------
# Event time validation and normalization
# ---------------------------------------------------------

TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)


def normalize_time(value):
    if not isinstance(value, str):
        return None

    match = TIME_RE.fullmatch(value)

    if not match:
        return None

    year, month, day, hour, minute, second, fraction, offset = match.groups()

    year = int(year)
    month = int(month)
    day = int(day)
    hour = int(hour)
    minute = int(minute)
    second = int(second)

    # Validate clock values
    if hour > 23 or minute > 59 or second > 59:
        return None

    # Validate offset
    if offset == "Z":
        tz = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        off_hour = int(offset[1:3])
        off_min = int(offset[4:6])

        if off_hour > 14 or off_min > 59:
            return None

        # Hour 14 requires minute 00
        if off_hour == 14 and off_min != 0:
            return None

        tz = timezone(sign * timedelta(hours=off_hour,
                                       minutes=off_min))

    # Convert fraction to milliseconds
    millis = 0

    if fraction:
        millis = int(fraction.ljust(3, "0"))

    try:
        dt = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            millis * 1000,
            tzinfo=tz
        )
    except ValueError:
        return None

    dt = dt.astimezone(timezone.utc)

    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"


# ---------------------------------------------------------
# Policy validation
# ---------------------------------------------------------

def validate_policy(policy):
    if not isinstance(policy, dict):
        return False

    required = ["minTime", "maxTime", "contaminationThreshold"]

    for key in required:
        if key not in policy:
            return False

    min_time = normalize_time(policy["minTime"])
    max_time = normalize_time(policy["maxTime"])

    if min_time is None or max_time is None:
        return False

    threshold = policy["contaminationThreshold"]

    if not isinstance(threshold, (int, float)):
        return False

    if isinstance(threshold, bool):
        return False

    if not math.isfinite(threshold):
        return False

    if threshold < 0 or threshold > 1:
        return False

    return True


# ---------------------------------------------------------
# JSONL parsing
# ---------------------------------------------------------

REQUIRED_ROW_KEYS = {
    "id",
    "entity",
    "eventTime",
    "revision",
    "text"
}


def parse_jsonl(content):
    if not isinstance(content, str):
        return None

    rows = []

    for line in content.splitlines():

        # Blank lines are ignored
        if not line.strip():
            continue

        try:
            obj = json.loads(line)
        except Exception:
            return None

        if not isinstance(obj, dict):
            return None

        # Exactly these five keys
        if set(obj.keys()) != REQUIRED_ROW_KEYS:
            return None

        # Four text fields must be strings
        if not isinstance(obj["id"], str):
            return None

        if not isinstance(obj["entity"], str):
            return None

        if not isinstance(obj["eventTime"], str):
            return None

        if not isinstance(obj["text"], str):
            return None

        # Revision must be non-negative safe integer
        revision = obj["revision"]

        if isinstance(revision, bool):
            return None

        if not isinstance(revision, int):
            return None

        if revision < 0:
            return None

        # JavaScript safe integer range
        if revision > 9007199254740991:
            return None

        rows.append(obj)

    if len(rows) == 0:
        return None

    return rows


# ---------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------

def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":")
    )


# ---------------------------------------------------------
# Unicode letter/number word set
# ---------------------------------------------------------

def word_set(value):
    words = []
    current = []

    for ch in value.lower():
        category = unicodedata.category(ch)

        if category.startswith("L") or category.startswith("N"):
            current.append(ch)
        else:
            if current:
                words.append("".join(current))
                current = []

    if current:
        words.append("".join(current))

    return set(words)


def jaccard(a, b):
    sa = word_set(a)
    sb = word_set(b)

    if not sa and not sb:
        return 1.0

    union = sa | sb

    if not union:
        return 1.0

    return len(sa & sb) / len(union)


# ---------------------------------------------------------
# Split calculation
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# Object validation
# ---------------------------------------------------------

def validate_object(obj):
    reasons = []

    uri = obj.get("uri") if isinstance(obj, dict) else None

    if not isinstance(obj, dict):
        return uri, ["URI_INVALID"]

    # URI
    if obj.get("uri") != "gs://bucket/object":
        reasons.append("URI_INVALID")

    # Generation
    generation = obj.get("generation")

    if not isinstance(generation, str) or not generation.isdecimal():
        reasons.append("GENERATION_INVALID")

    fetched = obj.get("fetchedGeneration")

    if not isinstance(fetched, str) or not fetched.isdecimal():
        reasons.append("GENERATION_INVALID")

    if (
        isinstance(generation, str)
        and isinstance(fetched, str)
        and generation.isdecimal()
        and fetched.isdecimal()
        and generation != fetched
    ):
        reasons.append("GENERATION_MISMATCH")

    # CRC32C
    crc = obj.get("crc32c")

    crc_valid = (
        isinstance(crc, str)
        and re.fullmatch(r"[0-9a-fA-F]{8}", crc) is not None
    )

    if not crc_valid:
        reasons.append("CRC32C_INVALID")

    # Schema
    if obj.get("schemaId") != "training-v1":
        reasons.append("SCHEMA_INVALID")

    # Content / JSONL
    content = obj.get("content")

    rows = None

    if not isinstance(content, str):
        reasons.append("SCHEMA_INVALID")
    else:
        content_bytes = content.encode("utf-8")

        if crc_valid:
            actual_crc = crc32c_hex(content_bytes)

            if actual_crc.lower() != crc.lower():
                reasons.append("CRC32C_MISMATCH")

        rows = parse_jsonl(content)

        if rows is None:
            reasons.append("JSONL_INVALID")

    # If JSONL parsed, its row schema is valid by parse_jsonl
    return uri, sorted(
        set(reasons),
        key=utf8_key
    ), rows


# ---------------------------------------------------------
# Main endpoint
# ---------------------------------------------------------

@app.post("/build-corpus")
async def build_corpus(request: Request):

    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    # Required top-level fields
    if (
        not isinstance(data, dict)
        or "policy" not in data
        or "objects" not in data
        or not isinstance(data["objects"], list)
    ):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    policy = data["policy"]
    objects = data["objects"]

    policy_valid = validate_policy(policy)

    # -----------------------------------------------------
    # Validate objects
    # -----------------------------------------------------

    rejected_objects = []
    rejected_rows = []

    valid_objects = []

    for obj in objects:

        result = validate_object(obj)

        uri, reasons, rows = result

        if reasons:
            rejected_objects.append({
                "uri": uri if isinstance(uri, str) else None,
                "reasonCodes": reasons
            })
            continue

        valid_objects.append({
            "obj": obj,
            "rows": rows
        })

    # -----------------------------------------------------
    # Lineage
    # -----------------------------------------------------

    lineage = []

    for item in valid_objects:
        obj = item["obj"]

        lineage.append({
            "uri": obj["uri"],
            "generation": obj["generation"],
            "crc32c": obj["crc32c"].lower(),
            "schemaId": obj["schemaId"]
        })

    # -----------------------------------------------------
    # Collect rows
    # -----------------------------------------------------

    candidates = []

    for item in valid_objects:

        for row in item["rows"]:

            entity = canonical_text(row["entity"])
            text = canonical_text(row["text"])
            event_time = normalize_time(row["eventTime"])

            # Event time should already be valid because row
            # validation is part of the object schema.
            if event_time is None:
                continue

            canonical_row = {
                "id": row["id"],
                "entity": entity,
                "eventTime": event_time,
                "revision": row["revision"],
                "text": text
            }

            candidates.append(canonical_row)

    # -----------------------------------------------------
    # Deduplicate
    # -----------------------------------------------------

    groups = {}

    for row in candidates:

        key = (
            row["entity"],
            row["eventTime"],
            row["text"]
        )

        groups.setdefault(key, []).append(row)

    retained = []

    for key, rows in groups.items():

        # Highest revision
        # Then smallest UTF-8 ID
        winner = sorted(
            rows,
            key=lambda r: (
                -r["revision"],
                utf8_key(r["id"])
            )
        )[0]

        retained.append(winner)

        for row in rows:
            if row is not winner:
                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": ["DUPLICATE"]
                })

    # -----------------------------------------------------
    # Policy
    # -----------------------------------------------------

    if not policy_valid:

        for row in retained:
            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": ["POLICY_INVALID"]
            })

        retained = []

    else:

        min_time = normalize_time(policy["minTime"])
        max_time = normalize_time(policy["maxTime"])

        for row in retained:

            if (
                row["eventTime"] < min_time
                or row["eventTime"] > max_time
            ):
                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": ["OUT_OF_WINDOW"]
                })

        retained = [
            row for row in retained
            if row["eventTime"] >= min_time
            and row["eventTime"] <= max_time
        ]

    # -----------------------------------------------------
    # Split
    # -----------------------------------------------------

    splits = {
        "train": [],
        "validation": [],
        "test": []
    }

    for row in retained:

        split = get_split(row["entity"])

        splits[split].append(row)

    # -----------------------------------------------------
    # Contamination detection
    # -----------------------------------------------------

    threshold = (
        policy["contaminationThreshold"]
        if policy_valid
        else None
    )

    if threshold is not None:

        train_rows = splits["train"]

        for split_name in ["validation", "test"]:

            kept = []

            for row in splits[split_name]:

                contaminated = False

                for train_row in train_rows:

                    similarity = jaccard(
                        row["text"],
                        train_row["text"]
                    )

                    if similarity >= threshold:
                        contaminated = True
                        break

                if contaminated:

                    rejected_rows.append({
                        "id": row["id"],
                        "reasonCodes": ["TRAIN_CONTAMINATION"]
                    })

                else:
                    kept.append(row)

            splits[split_name] = kept

    # -----------------------------------------------------
    # Sort rows
    # -----------------------------------------------------

    for split_name in splits:

        splits[split_name].sort(
            key=lambda row: utf8_key(row["id"])
        )

    # -----------------------------------------------------
    # Serialize JSONL and calculate SHA-256
    # -----------------------------------------------------

    digests = {}

    for split_name in ["train", "validation", "test"]:

        lines = []

        for row in splits[split_name]:

            line = compact_json({
                "id": row["id"],
                "entity": row["entity"],
                "eventTime": row["eventTime"],
                "revision": row["revision"],
                "text": row["text"]
            })

            lines.append(line)

        content = "\n".join(lines)

        if lines:
            content += "\n"

        content_bytes = content.encode("utf-8")

        digests[split_name] = hashlib.sha256(
            content_bytes
        ).hexdigest()

    # -----------------------------------------------------
    # Sort rejected rows
    # -----------------------------------------------------

    for item in rejected_rows:
        item["reasonCodes"] = sorted(
            set(item["reasonCodes"]),
            key=utf8_key
        )

    rejected_rows.sort(
        key=lambda x: utf8_key(x["id"])
    )

    # -----------------------------------------------------
    # Sort rejected objects
    # -----------------------------------------------------

    rejected_objects.sort(
        key=lambda x: utf8_key(
            x["uri"] if isinstance(x["uri"], str) else ""
        )
    )

    # -----------------------------------------------------
    # Sort lineage
    # -----------------------------------------------------

    lineage.sort(
        key=lambda x: utf8_key(x["uri"])
    )

    # -----------------------------------------------------
    # Final response
    # -----------------------------------------------------

    return {
        "splits": {
            "train": splits["train"],
            "validation": splits["validation"],
            "test": splits["test"]
        },
        "rejectedObjects": rejected_objects,
        "rejectedRows": rejected_rows,
        "digests": digests,
        "lineage": lineage
    }


# ---------------------------------------------------------
# Local execution
# ---------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000
    )