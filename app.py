from flask import Flask, request, jsonify
import hashlib
import json
import os
import threading

app = Flask(__name__)

STATE_FILE = "state.json"
LOCK = threading.Lock()

NODES = [
    "verify_data",
    "prepare",
    "train",
    "evaluate",
    "register",
    "publish"
]

REQUIRED_INPUTS = [
    "generation",
    "checksum",
    "canonicalData",
    "prepareCode",
    "prepareConfig",
    "trainCode",
    "trainConfig",
    "runtime",
    "evaluateCode",
    "evaluateConfig",
    "schemaDigest",
    "publishConfig"
]

STATUSES = {
    "started",
    "succeeded",
    "retryable_failed",
    "terminal_failed"
}

EVENT_FIELDS = {
    "eventId",
    "revision",
    "node",
    "attempt",
    "status",
    "key",
    "artifactDigest",
    "receiptId"
}


def compact_json(value):
    return json.dumps(
        value,
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=True
    )


def sha256_array(value):
    return hashlib.sha256(
        json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def is_safe_positive_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= 9007199254740991
    )


def load_state():
    if not os.path.exists(STATE_FILE):
        return {"sessions": {}}

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return {"sessions": {}}

        if not isinstance(data.get("sessions"), dict):
            data["sessions"] = {}

        return data

    except Exception:
        return {"sessions": {}}


def save_state(state):
    temp_file = STATE_FILE + ".tmp"

    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(
            state,
            f,
            separators=(",", ":"),
            ensure_ascii=False
        )

    os.replace(temp_file, STATE_FILE)


def input_signature(inputs):
    return compact_json(inputs)


def initial_session(revision, inputs):
    return {
        "revision": revision,
        "inputs": inputs,
        "inputSignature": input_signature(inputs),
        "events": {},
        "eventIds": {},
        "nodes": {},
        "cache": {}
    }


def cache_get(session, node, key):
    if key is None:
        return None

    node_cache = session["cache"].get(node, {})
    return node_cache.get(key)


def cache_put(session, node, key, artifact, event_id):
    if node not in session["cache"]:
        session["cache"][node] = {}

    session["cache"][node][key] = {
        "artifactDigest": artifact,
        "eventId": event_id
    }


def reusable_artifact(session, node, key):
    state = session["nodes"].get(node)

    if state and state.get("status") == "succeeded":
        if state.get("key") == key:
            return state.get("artifactDigest"), state.get("successEventId")

    cached = cache_get(session, node, key)

    if cached:
        return cached["artifactDigest"], cached["eventId"]

    return None, None


def resolve_reusable_artifacts(session):
    inputs = session["inputs"]
    artifacts = {}
    keys = {}

    keys["verify_data"] = sha256_array([
        inputs["generation"],
        inputs["checksum"]
    ])

    artifact, _ = reusable_artifact(
        session,
        "verify_data",
        keys["verify_data"]
    )

    if artifact is None:
        return artifacts, keys

    artifacts["verify_data"] = artifact

    keys["prepare"] = sha256_array([
        inputs["canonicalData"],
        inputs["prepareCode"],
        inputs["prepareConfig"]
    ])

    artifact, _ = reusable_artifact(
        session,
        "prepare",
        keys["prepare"]
    )

    if artifact is None:
        return artifacts, keys

    artifacts["prepare"] = artifact

    keys["train"] = sha256_array([
        artifacts["prepare"],
        inputs["trainCode"],
        inputs["trainConfig"],
        inputs["runtime"]
    ])

    artifact, _ = reusable_artifact(
        session,
        "train",
        keys["train"]
    )

    if artifact is None:
        return artifacts, keys

    artifacts["train"] = artifact

    keys["evaluate"] = sha256_array([
        artifacts["train"],
        inputs["canonicalData"],
        inputs["evaluateCode"],
        inputs["evaluateConfig"]
    ])

    artifact, _ = reusable_artifact(
        session,
        "evaluate",
        keys["evaluate"]
    )

    if artifact is None:
        return artifacts, keys

    artifacts["evaluate"] = artifact

    keys["register"] = sha256_array([
        artifacts["evaluate"],
        inputs["schemaDigest"]
    ])

    artifact, _ = reusable_artifact(
        session,
        "register",
        keys["register"]
    )

    if artifact is None:
        return artifacts, keys

    artifacts["register"] = artifact

    keys["publish"] = sha256_array([
        artifacts["register"],
        inputs["publishConfig"]
    ])

    return artifacts, keys


def dependency_digests(inputs, node, key, artifacts):
    if node == "verify_data":
        data = {
            "generation": inputs["generation"],
            "checksum": inputs["checksum"]
        }

    elif node == "prepare":
        data = {
            "canonicalData": inputs["canonicalData"],
            "prepareCode": inputs["prepareCode"],
            "prepareConfig": inputs["prepareConfig"]
        }

    elif node == "train":
        data = {
            "prepareArtifact": artifacts.get("prepare"),
            "trainCode": inputs["trainCode"],
            "trainConfig": inputs["trainConfig"],
            "runtime": inputs["runtime"]
        }

    elif node == "evaluate":
        data = {
            "trainArtifact": artifacts.get("train"),
            "canonicalData": inputs["canonicalData"],
            "evaluateCode": inputs["evaluateCode"],
            "evaluateConfig": inputs["evaluateConfig"]
        }

    elif node == "register":
        data = {
            "evaluateArtifact": artifacts.get("evaluate"),
            "schemaDigest": inputs["schemaDigest"]
        }

    else:
        data = {
            "registerArtifact": artifacts.get("register"),
            "publishConfig": inputs["publishConfig"]
        }

    data["cacheKey"] = key
    return data


def calculate_nodes(session):
    inputs = session["inputs"]

    output = []

    artifacts = {}
    blocked_reason = None

    for node in NODES:

        if node == "verify_data":
            key = sha256_array([
                inputs["generation"],
                inputs["checksum"]
            ])

        elif node == "prepare":
            if "verify_data" not in artifacts:
                key = None
            else:
                key = sha256_array([
                    inputs["canonicalData"],
                    inputs["prepareCode"],
                    inputs["prepareConfig"]
                ])

        elif node == "train":
            if "prepare" not in artifacts:
                key = None
            else:
                key = sha256_array([
                    artifacts["prepare"],
                    inputs["trainCode"],
                    inputs["trainConfig"],
                    inputs["runtime"]
                ])

        elif node == "evaluate":
            if "train" not in artifacts:
                key = None
            else:
                key = sha256_array([
                    artifacts["train"],
                    inputs["canonicalData"],
                    inputs["evaluateCode"],
                    inputs["evaluateConfig"]
                ])

        elif node == "register":
            if "evaluate" not in artifacts:
                key = None
            else:
                key = sha256_array([
                    artifacts["evaluate"],
                    inputs["schemaDigest"]
                ])

        else:
            if "register" not in artifacts:
                key = None
            else:
                key = sha256_array([
                    artifacts["register"],
                    inputs["publishConfig"]
                ])

        state = session["nodes"].get(node)

        triggering = []

        if blocked_reason is not None:
            reason = (
                "UPSTREAM_TERMINAL"
                if blocked_reason == "terminal"
                else "UPSTREAM_PENDING"
            )

            output.append({
                "node": node,
                "action": "block",
                "reasonCodes": [reason],
                "dependencyDigests": dependency_digests(
                    inputs,
                    node,
                    key,
                    artifacts
                ),
                "triggeringEventIds": []
            })

            continue

        if key is None:
            output.append({
                "node": node,
                "action": "block",
                "reasonCodes": ["UPSTREAM_PENDING"],
                "dependencyDigests": dependency_digests(
                    inputs,
                    node,
                    key,
                    artifacts
                ),
                "triggeringEventIds": []
            })

            blocked_reason = "pending"
            continue

        if state:
            status = state.get("status")

            if status == "succeeded" and state.get("key") == key:
                artifact = state["artifactDigest"]
                artifacts[node] = artifact
                triggering = [state["successEventId"]]

                output.append({
                    "node": node,
                    "action": "reuse",
                    "reasonCodes": ["CACHE_HIT"],
                    "dependencyDigests": dependency_digests(
                        inputs,
                        node,
                        key,
                        artifacts
                    ),
                    "triggeringEventIds": triggering
                })

                continue

            if status == "started":
                output.append({
                    "node": node,
                    "action": "block",
                    "reasonCodes": ["RUNNING"],
                    "dependencyDigests": dependency_digests(
                        inputs,
                        node,
                        key,
                        artifacts
                    ),
                    "triggeringEventIds": [state["eventId"]]
                })

                blocked_reason = "pending"
                continue

            if status == "terminal_failed":
                output.append({
                    "node": node,
                    "action": "block",
                    "reasonCodes": ["TERMINAL_FAILURE"],
                    "dependencyDigests": dependency_digests(
                        inputs,
                        node,
                        key,
                        artifacts
                    ),
                    "triggeringEventIds": [state["eventId"]]
                })

                blocked_reason = "terminal"
                continue

            if status == "retryable_failed":
                output.append({
                    "node": node,
                    "action": "rerun",
                    "reasonCodes": ["RETRYABLE_FAILURE"],
                    "dependencyDigests": dependency_digests(
                        inputs,
                        node,
                        key,
                        artifacts
                    ),
                    "triggeringEventIds": [state["eventId"]]
                })

                blocked_reason = "pending"
                continue

        cached = cache_get(session, node, key)

        if cached:
            artifact = cached["artifactDigest"]
            artifacts[node] = artifact

            output.append({
                "node": node,
                "action": "reuse",
                "reasonCodes": ["CACHE_HIT"],
                "dependencyDigests": dependency_digests(
                    inputs,
                    node,
                    key,
                    artifacts
                ),
                "triggeringEventIds": [cached["eventId"]]
            })

            continue

        output.append({
            "node": node,
            "action": "rerun",
            "reasonCodes": ["CACHE_MISS"],
            "dependencyDigests": dependency_digests(
                inputs,
                node,
                key,
                artifacts
            ),
            "triggeringEventIds": []
        })

        blocked_reason = "pending"

    return output


def validate_request(body):
    if not isinstance(body, dict):
        return False

    session = body.get("session")
    revision = body.get("revision")
    inputs = body.get("inputs")
    events = body.get("events")

    if not isinstance(session, str) or not session:
        return False

    if not is_safe_positive_integer(revision):
        return False

    if not isinstance(inputs, dict):
        return False

    for name in REQUIRED_INPUTS:
        if (
            name not in inputs
            or not isinstance(inputs[name], str)
            or not inputs[name]
        ):
            return False

    if not isinstance(events, list):
        return False

    return True


def validate_event_structure(event):
    if not isinstance(event, dict):
        return False

    if set(event.keys()) != EVENT_FIELDS:
        return False

    if not isinstance(event["eventId"], str) or not event["eventId"]:
        return False

    if not is_safe_positive_integer(event["revision"]):
        return False

    return True


def event_semantically_valid(event):
    if event["node"] not in NODES:
        return False

    if not is_safe_positive_integer(event["attempt"]):
        return False

    if event["status"] not in STATUSES:
        return False

    if not isinstance(event["key"], str) or not event["key"]:
        return False

    if event["status"] == "succeeded":
        if (
            not isinstance(event["artifactDigest"], str)
            or not event["artifactDigest"]
        ):
            return False
    else:
        if event["artifactDigest"] is not None:
            return False

    if event["node"] in ("register", "publish"):
        if event["status"] == "succeeded":
            expected = (
                "receipt:"
                + event["node"]
                + ":"
                + event["key"]
            )

            if event["receiptId"] != expected:
                return False
        else:
            if event["receiptId"] is not None:
                return False
    else:
        if event["receiptId"] is not None:
            return False

    return True


def current_key_for_node(session, node):
    inputs = session["inputs"]

    artifacts, keys = resolve_reusable_artifacts(session)

    return keys.get(node)


def process_event(session, event):
    event_id = event["eventId"]

    if event_id in session["eventIds"]:
        old = session["eventIds"][event_id]

        if old == compact_json(event):
            return "ignored", None

        return "conflict", "EVENT_ID_CONFLICT"

    if event["revision"] != session["revision"]:
        return "ignored", None

    if not event_semantically_valid(event):
        return "ignored", None

    node = event["node"]

    current_key = current_key_for_node(session, node)

    if current_key is None:
        return "ignored", None

    if event["key"] != current_key:
        return "ignored", None

    state = session["nodes"].get(node)

    if state is None:

        if event["status"] == "started" and event["attempt"] == 1:

            session["nodes"][node] = {
                "status": "started",
                "attempt": 1,
                "eventId": event_id,
                "key": current_key
            }

            session["events"][event_id] = event
            session["eventIds"][event_id] = compact_json(event)

            return "accepted", None

        return "ignored", None

    previous_status = state["status"]
    previous_attempt = state["attempt"]

    if previous_status == "started":

        if (
            event["attempt"] == previous_attempt
            and event["status"] in {
                "succeeded",
                "retryable_failed",
                "terminal_failed"
            }
        ):

            if event["status"] == "succeeded":

                artifact = event["artifactDigest"]

                cache = cache_get(
                    session,
                    node,
                    current_key
                )

                if cache:
                    if cache["artifactDigest"] != artifact:
                        return "conflict", "EVIDENCE_CONFLICT"
                else:
                    cache_put(
                        session,
                        node,
                        current_key,
                        artifact,
                        event_id
                    )

                session["nodes"][node] = {
                    "status": "succeeded",
                    "attempt": previous_attempt,
                    "artifactDigest": artifact,
                    "successEventId": (
                        cache["eventId"]
                        if cache
                        else event_id
                    ),
                    "key": current_key
                }

            else:

                session["nodes"][node] = {
                    "status": event["status"],
                    "attempt": previous_attempt,
                    "eventId": event_id,
                    "key": current_key
                }

            session["events"][event_id] = event
            session["eventIds"][event_id] = compact_json(event)

            return "accepted", None

        if event["attempt"] < previous_attempt:
            return "ignored", None

        return "conflict", "STATUS_CONFLICT"

    if previous_status == "retryable_failed":

        if (
            event["status"] == "started"
            and event["attempt"] == previous_attempt + 1
        ):

            session["nodes"][node] = {
                "status": "started",
                "attempt": event["attempt"],
                "eventId": event_id,
                "key": current_key
            }

            session["events"][event_id] = event
            session["eventIds"][event_id] = compact_json(event)

            return "accepted", None

        if event["attempt"] < previous_attempt:
            return "ignored", None

        return "conflict", "STATUS_CONFLICT"

    if previous_status == "terminal_failed":
        return "conflict", "STATUS_CONFLICT"

    if previous_status == "succeeded":

        if event["status"] == "succeeded":

            if (
                event["artifactDigest"]
                != state["artifactDigest"]
            ):
                return "conflict", "EVIDENCE_CONFLICT"

        return "conflict", "STATUS_CONFLICT"

    return "conflict", "STATUS_CONFLICT"


@app.route("/pipeline", methods=["POST"])
def pipeline():

    body = request.get_json(silent=True)

    if not validate_request(body):
        return jsonify({
            "error": "INVALID_REQUEST"
        }), 409

    session_id = body["session"]
    revision = body["revision"]
    inputs = body["inputs"]
    events = body["events"]

    with LOCK:

        state = load_state()

        if session_id not in state["sessions"]:
            state["sessions"][session_id] = initial_session(
                revision,
                inputs
            )

        session = state["sessions"][session_id]

        if revision < session["revision"]:

            accepted = []
            ignored = []

            for event in events:

                if validate_event_structure(event):
                    ignored.append(event["eventId"])

            return jsonify({
                "revision": session["revision"],
                "acceptedEventIds": accepted,
                "ignoredEventIds": ignored,
                "nodes": calculate_nodes(session)
            })

        if revision > session["revision"]:

            session["revision"] = revision
            session["inputs"] = inputs
            session["inputSignature"] = input_signature(inputs)

            session["nodes"] = {}

        else:

            if (
                session["inputSignature"]
                != input_signature(inputs)
            ):
                return jsonify({
                    "error": "REVISION_CONFLICT"
                }), 409

        snapshot = json.loads(
            json.dumps(state)
        )

        accepted = []
        ignored = []

        for event in events:

            if not validate_event_structure(event):
                state = snapshot

                return jsonify({
                    "error": "INVALID_EVENT"
                }), 409

            result, error = process_event(
                session,
                event
            )

            if result == "conflict":

                state = snapshot

                return jsonify({
                    "error": error
                }), 409

            if result == "accepted":
                accepted.append(event["eventId"])
            else:
                ignored.append(event["eventId"])

        save_state(state)

        return jsonify({
            "revision": session["revision"],
            "acceptedEventIds": accepted,
            "ignoredEventIds": ignored,
            "nodes": calculate_nodes(session)
        })


if __name__ == "__main__":
    port = int(
        os.environ.get("PORT", 5000)
    )

    app.run(
        host="0.0.0.0",
        port=port
    )