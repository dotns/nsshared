"""Independent Exit installation observations, hashes and strict codec vectors."""
import copy
import hashlib
import ipaddress
from nsvec import cbor, ed25519
from nsvec.producers.control.account.subnet.selection import prefix

CRATE = "nsshared-control"
GROUP = "account/subnet/readiness"
TITLE = "Provider-confirmed Exit observations"
SPEC = "docs/spec/account/exit-readiness.md"
EXTERNAL = None
GRANT_DOMAIN = b"ns-exit-grant-v1\0"
CONTEXT_DOMAIN = b"ns-exit-context-v1\0"
OBSERVATION_DOMAIN = b"ns-exit-observation-v1\0"


def return_host(identity, mapped):
    for index in range(16):
        digest = hashlib.blake2s(identity + bytes([4, index]), key=b"ns-alias4-v2", digest_size=3).digest()
        alias = 0x64400000 | ((int.from_bytes(digest, "big") >> 2) % 2**21)
        if alias != 0x64400001:
            return mapped[:6] + b"\x00\x02" + bytes(4) + alias.to_bytes(4, "big")
    raise ValueError("return alias exhausted")


def example(default=False, selection_byte=11, resource_byte=7, challenge_byte=13):
    nsd_seed = bytes([2])*32
    nsd, consumer, provider = [ed25519.public_key(bytes([i])*32) for i in (2, 1, 3)]
    network = bytes([4])*16
    realm = "040G2081040G2081040G208104"
    source = [1, nsd, consumer, realm, "nodes", "explicit-gateway-profile", consumer, bytes([5])*16, 1, 1]
    source_bytes = cbor.encode(source)
    signed = cbor.encode([source_bytes, ed25519.sign(nsd_seed, b"ns.account.source-binding.v1\0" + source_bytes)])
    resource = cbor.encode([bytes([6])*16, network, bytes([resource_byte])*16])
    real = prefix("0.0.0.0/0" if default else "10.0.0.0/8")
    mapped = prefix("fd00:1122:3344:1::/96" if default else "fd00:1122:3344:1::a00:0/104")
    selection = [0, []] if default else [1, [real]]
    route = [resource, real, mapped, provider, consumer, [], [], selection]
    subnet = [1, 4, bytes([6])*16, network, consumer, 1, [route]]
    grant = [resource, consumer, provider, [[network, bytes([8])*16]], bytes([9])*16, 10000, [1, cbor.encode(subnet)]]
    command = [1, signed, bytes([10])*16, bytes([selection_byte])*16, [0, provider, resource, selection]]
    receipt = [1, cbor.encode(command), 17, 0]
    psource = copy.deepcopy(source)
    psource[2] = psource[6] = provider
    psource[7] = bytes([12])*16
    host = return_host(consumer, mapped[1])
    context = [1, bytes([challenge_byte])*16, bytes([14])*16, cbor.encode(receipt), [1, consumer, bytes([15])*32, 1], bytes([16])*16,
               cbor.encode(psource), [1, provider, bytes([17])*32, 1], bytes([18])*16, cbor.encode(grant), 1,
               hashlib.sha256(cbor.encode([1, 4, nsd, provider, 1, [grant]])).digest(), [host], 10000]
    peer = [1, bytes([19])*16, bytes([17])*32, bytes([15])*32, [host]]
    binding = [1, 1, resource, real, 2, "exit0", ipaddress.IPv4Address("192.0.2.1").packed, 10000]
    observation = [1, context[1], hashlib.sha256(CONTEXT_DOMAIN + cbor.encode(context)).digest(), context[8], 1,
                   [1, cbor.encode(peer), cbor.encode(binding)]]
    confirmation = [1, cbor.encode(context), cbor.encode(observation), 10000]
    publication = [1, 4, bytes([6])*16, network, consumer, 1, [cbor.encode(confirmation)]]
    return dict(context=context, peer=peer, binding=binding, observation=observation,
                confirmation=confirmation, publication=publication, grant=grant)


def vectors():
    out = []

    def emit(name, kind, value, accepted=True, raw=None, **extra):
        out.append([("name", name), ("kind", kind), ("bytes", cbor.encode(value) if raw is None else raw),
                    ("decision", "accept" if accepted else "refuse"), *extra.items()])

    for default in (False, True):
        values = example(default)
        suffix = "default" if default else "explicit"
        for kind, value in values.items():
            domain = dict(grant=GRANT_DOMAIN, context=CONTEXT_DOMAIN, observation=OBSERVATION_DOMAIN).get(kind)
            extra = {"digest": hashlib.sha256(domain + cbor.encode(value)).digest()} if domain else {}
            emit(kind + "-" + suffix, kind, value, **extra)
        emit("return-" + suffix, "return", values["context"][12][0], identity=values["context"][4][1],
             mapped=cbor.encode(cbor.decode(values["grant"][6][1])[6][0][2]))
    values = example()
    for kind, value in values.items():
        emit(kind + "-arity", kind, value + [0], False)
        raw = cbor.encode(value)
        emit(kind + "-trailing", kind, None, False, raw=raw + b"\0")
        if kind != "grant":
            emit(kind + "-nonminimal", kind, None, False, raw=raw[:1] + b"\x18\x01" + raw[2:])
    for index, replacement in [(1, bytes(16)), (2, bytes(16)), (5, bytes(16)), (8, bytes(16)), (10, 0), (12, []), (12, values["context"][12]*2), (13, 10001)]:
        bad = copy.deepcopy(values["context"]); bad[index] = replacement
        emit(f"context-invalid-{index}-{len(out)}", "context", bad, False)
    for index, replacement in [(1, bytes(16)), (2, bytes(32)), (3, bytes(32)), (4, [])]:
        bad = copy.deepcopy(values["peer"]); bad[index] = replacement
        emit(f"peer-invalid-{index}", "peer", bad, False)
    for index, replacement in [(1, 0), (4, 0), (4, 2**32), (5, ""), (6, bytes(4)), (7, 0)]:
        bad = copy.deepcopy(values["binding"]); bad[index] = replacement
        emit(f"binding-invalid-{index}-{len(out)}", "binding", bad, False)
    for index, replacement in [(1, bytes(16)), (3, bytes(16)), (4, 0), (5, [2]), (5, [0, None])]:
        bad = copy.deepcopy(values["observation"]); bad[index] = replacement
        emit(f"observation-invalid-{index}-{len(out)}", "observation", bad, False)
    negative = copy.deepcopy(values["observation"]); negative[-1] = [0]
    emit("not-installed", "observation", negative)
    bad = copy.deepcopy(values["confirmation"]); bad[2] = cbor.encode(negative)
    emit("negative-confirmation", "confirmation", bad, False)
    empty = copy.deepcopy(values["publication"]); empty[-1] = []
    emit("empty-replacement", "publication", empty)
    bad = copy.deepcopy(values["publication"]); bad[-1] *= 2
    emit("duplicate-selection", "publication", bad, False)
    bad[-1] *= 17
    emit("oversized-set", "publication", bad, False)
    for field in (2, 3, 4):
        bad = copy.deepcopy(values["publication"]); bad[field] = bytes([99])*len(bad[field])
        emit(f"publication-scope-{field}", "publication", bad, False)
    # A high h22 bit distinguishes the fixed /11 pool from an incorrect /10.
    identity = ed25519.public_key(bytes([2])*32)
    mapping = prefix("fd00:1122:3344:1::a00:0/104")
    host = return_host(identity, mapping[1])
    assert identity.hex() == "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
    assert ipaddress.IPv6Address(host) == ipaddress.IPv6Address("fd00:1122:3344:2::644f:a080")
    emit("return-high-bit", "return", host, identity=identity, mapped=cbor.encode(mapping))
    # Keep the expected context digest fixed while changing nonzero observation fields.
    for field, name in [(1, "challenge"), (3, "provider")]:
        foreign = copy.deepcopy(values["observation"])
        foreign[field] = bytes([99])*16
        emit("foreign-observation-" + name, "observation-match", foreign, False,
             context=cbor.encode(values["context"]), now=1)
    shorter = copy.deepcopy(values["confirmation"]); shorter[3] = 5000
    for name, now, accepted in [("before", 4999, True), ("at", 5000, False)]:
        emit("short-confirmation-" + name, "confirmation-match", shorter, accepted,
             context=cbor.encode(values["context"]), now=now)
    second = example(selection_byte=12, resource_byte=8, challenge_byte=30)
    pair = copy.deepcopy(values["publication"])
    pair[-1].append(cbor.encode(second["confirmation"]))
    emit("two-selections", "publication", pair)
    reversed_pair = copy.deepcopy(pair); reversed_pair[-1].reverse()
    emit("reversed-selections", "publication", reversed_pair, False)
    mixed = copy.deepcopy(second)
    mixed["context"][5] = bytes([77])*16
    mixed["observation"][2] = hashlib.sha256(CONTEXT_DOMAIN + cbor.encode(mixed["context"])).digest()
    mixed["confirmation"][1:3] = [cbor.encode(mixed["context"]), cbor.encode(mixed["observation"])]
    mixed_pair = copy.deepcopy(pair); mixed_pair[-1][1] = cbor.encode(mixed["confirmation"])
    emit("mixed-consumer-lifetimes", "publication", mixed_pair, False)
    # Authenticated publications remain observational and source-fenced.
    context = values["context"]
    source = cbor.decode(cbor.decode(cbor.decode(context[3])[1])[1])[0]
    source = cbor.decode(source)
    for name, family, kind, channel, outcome, payload, version, realm, issuer_seed in [
        ("event-positive", 4, "exit-readiness", 1, 0, cbor.encode(values["publication"]), 1, source[3], bytes([2])*32),
        ("event-empty", 4, "exit-readiness", 1, 0, cbor.encode(empty), 1, source[3], bytes([2])*32),
        ("event-withdraw", 4, "exit-readiness", 1, 0, b"", 2, source[3], bytes([2])*32),
        ("event-failed", 4, "exit-readiness", 1, 1, cbor.encode(empty), 1, source[3], bytes([2])*32),
        ("event-failed-positive", 4, "exit-readiness", 1, 1, cbor.encode(values["publication"]), 1, source[3], bytes([2])*32),
        ("event-stream", 4, "exit-readiness", 0, 0, cbor.encode(values["publication"]), 1, source[3], bytes([2])*32),
        ("event-version", 4, "exit-readiness", 1, 0, cbor.encode(values["publication"]), 2, source[3], bytes([2])*32),
        ("event-network", 4, "exit-readiness", 1, 0, cbor.encode(values["publication"]), 1, "030C1G60R30C1G60R30C1G60R3", bytes([2])*32),
        ("event-issuer", 4, "exit-readiness", 1, 0, cbor.encode(values["publication"]), 1, source[3], bytes([3])*32),
    ]:
        issuer = ed25519.public_key(issuer_seed)
        content = cbor.encode([1, issuer, source[2], realm, "nodes", family, kind, channel, True, version, 0, 20, outcome, payload])
        event = cbor.encode([content, ed25519.sign(issuer_seed, b"ns.account.publication.v1\0" + content)])
        emit(name, "event", None, name in ("event-positive", "event-empty", "event-withdraw", "event-failed"), raw=event)
    return out
