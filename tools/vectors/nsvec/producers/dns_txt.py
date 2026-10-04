"""Public DNS discovery of NodeRecords: the TXT `r` field, character-string splitting and
the client checks against the queried node ID and the companion AAAA (quick-v2 §11.2)."""

import base64

from .. import derive
from . import node_records
from .node_records import Signer, sign

CRATE = "nsshared-proto"
GROUP = "dns_txt"
TITLE = "NS v2 NodeRecord DNS TXT answers, valid and rejected"
SECTIONS = "ns/quick-v2.md §2.2, §3.2, §11.2"

PREFIX = "v=ns2 r="
MAX_STRING = 255

# The §11.2 example, printed verbatim in the specification.
SPEC_TXT = (
    "v=ns2 r=iAJYIMfcKgbeGSnTMYuN6HO_EnAww-4AB_IOBuoPxUBWdFr7WCA1mQwcvVcQmGtwbrxcjN5RmS25H9T"
    "VpHZ7q7Z1xEzMOQMaaVW5ABppXvOAgXgYaGtnLWExLnJlbGF5Lm5zLmlvOjUxODIyWECkn2HAyOlMQSYLsKZwSQXVg3BG"
    "BKW08g9tslS3ReFfQodZ6hsaJEyCKYY6XCmiAkWY8mXZYSrHunEBmpQfdccP"
)
SPEC_NAME = "5kemem6slxrgyd63rcqa"
SPEC_AAAA = "fda6:72ac:58cb:cc8d:1e39:e507:bda:5052"


def txt_text(encoded):
    """`v=ns2 r=` followed by the unpadded base64url of the whole record (§11.2)."""
    return PREFIX + base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")


def split(text):
    """Character-strings of at most 255 bytes, in order; the client concatenates them."""
    return [text[i : i + MAX_STRING] for i in range(0, len(text), MAX_STRING)]


def answer(name, encoded, identity, now, strings=None, aaaa=None, queried=None):
    strings = split(txt_text(encoded)) if strings is None else strings
    vector = [
        ("name", name),
        ("now", now),
        ("node_id", derive.node_id_text(derive.node_id(identity if queried is None else queried))),
        ("aaaa", derive.ipv6_text(derive.node_addr(identity, 0)) if aaaa is None else aaaa),
        ("txt_count", len(strings)),
    ]
    vector += [(f"txt_{i}", s) for i, s in enumerate(strings)]
    return vector


def vectors():
    demo = Signer("ns-demo-node-v2", "ns-demo-wg-v2")
    other = Signer("ns-test-node-b", "ns-test-wg-b")
    *_, spec_record = sign(demo, 3, 1767225600, 1767830400, ["hkg-a1.relay.ns.io:51822"])
    if txt_text(spec_record) != SPEC_TXT or len(spec_record) != 174 or len(SPEC_TXT) != 240:
        raise AssertionError("quick-v2 §11.2 example TXT does not match the derived record")
    if derive.node_id_text(derive.node_id(demo.identity)) != SPEC_NAME:
        raise AssertionError("quick-v2 §11.2 example name does not match")
    if derive.ipv6_text(derive.node_addr(demo.identity, 0)) != SPEC_AAAA:
        raise AssertionError("quick-v2 §11.2 example AAAA does not match")

    now = 1767225600 + 60
    out = []
    v = answer("spec-example", spec_record, demo.identity, now)
    out.append(v + [("record", spec_record)])

    long_relays = [node_records.relay_of_length(100, t) for t in ("a", "b", "c", "d")]
    *_, big = sign(demo, 4, 1767225600, 1767830400, long_relays)
    assert node_records.validate(big) is None
    strings = split(txt_text(big))
    assert len(strings) >= 3
    out.append(answer("split-strings", big, demo.identity, now) + [("record", big)])
    uneven = [txt_text(big)[:10], txt_text(big)[10:]]
    uneven = [uneven[0]] + split(uneven[1])
    out.append(answer("uneven-split", big, demo.identity, now, strings=uneven) + [("record", big)])

    def reject(name, reason, **kw):
        record = kw.pop("record", spec_record)
        identity = kw.pop("identity", demo.identity)
        return answer(name, record, identity, kw.pop("now", now), **kw) + [
            ("expect", "reject"),
            ("reason", reason),
        ]

    out.append(reject("expired-at-expires", "expired", now=1767830400))
    out.append(reject("wrong-queried-id", "node_id", queried=other.identity))
    out.append(
        reject("aaaa-is-n4", "address", aaaa=derive.ipv6_text(derive.node_addr(demo.identity, 1)))
    )
    out.append(reject("missing-prefix", "prefix", strings=[SPEC_TXT[len(PREFIX) :]]))
    out.append(reject("prefix-v1", "prefix", strings=["v=ns1 r=" + SPEC_TXT[len(PREFIX) :]]))
    out.append(reject("padded-base64url", "encoding", strings=[SPEC_TXT + "=="]))
    out.append(reject("standard-alphabet", "encoding", strings=[SPEC_TXT.replace("_", "/")]))
    out.append(reject("record-tampered", "record", strings=[SPEC_TXT[:-2] + "cQ"]))
    too_long = PREFIX + "A" * (((600 + 2) // 3) * 4 + 1)
    out.append(reject("too-long", "too_long", strings=split(too_long)))
    out.append(reject("string-over-255", "string_length", strings=[SPEC_TXT + "A" * 20]))
    return out
