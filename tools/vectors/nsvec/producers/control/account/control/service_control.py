"""Independent M6 maps and signed carrier fixtures; no Rust output."""
import base64
import copy
import hashlib
from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope as bootstrap_envelope

CRATE = "nsshared-control"
GROUP = "account/control/service-control"
TITLE = "M6 service control carrier"
SPEC = "docs/spec/account/control.md"
EXTERNAL = None


def vectors():
    node = ed25519.public_key(bytes([1])*32)
    authority = ed25519.public_key(bytes([2])*32)
    ident = lambda n: bytes([n])*16
    digest = bytes([8])*32
    out = []

    def message(kind, body, network=4, session=3, runtime=True, epoch=2):
        return dict(schema=1, kind=kind, nsd_id=ident(3), network_id=ident(network), subject_identity=node,
                    runtime_generation=1 if runtime else None, runtime_id=ident(6) if runtime else None,
                    authority_epoch=epoch, request_id=ident(7), session_seq=session, body=body)

    def envelope(payload, response=True, nonce=9, **changes):
        value = [1, int(response), authority if response else node, node if response else authority,
                 "service.control.v1", 100, ident(nonce), payload]
        indices = dict(signer=2, recipient=3, kind=4, timestamp=5)
        for k, v in changes.items():
            value[indices[k]] = v
        content = cbor.encode(value)
        domain = bootstrap_envelope.RESPONSE if response else bootstrap_envelope.REQUEST
        seed = bytes([2 if response else 1])*32
        return cbor.encode([content, ed25519.sign(seed, domain+content)])

    def emit(name, mode, raw, accepted=True, **fields):
        out.append([("name", name), ("mode", mode), ("bytes", raw),
                    ("decision", "accepted" if accepted else "refused"),
                    ("node", node), ("authority", authority),
                    ("node_pin", bootstrap_envelope.pin(node)),
                    ("authority_pin", bootstrap_envelope.pin(authority)), *fields.items()])

    def pair(name, request, reply, accepted=True, empty=False, **changes):
        nonce = changes.pop('request_nonce', 20 + request['network_id'][0])
        changes.setdefault('nonce', nonce)
        raw_request = cbor.encode_value(request)
        raw_reply = b"" if empty else cbor.encode_value(reply)
        emit(name, "reply", envelope(raw_reply, **changes), accepted,
             request=envelope(raw_request, False, nonce=nonce), outcome="receipt" if empty else "failure" if reply['kind'] == 'error' else "message")

    for network in (4, 5):
        binding = [ident(3), ident(network), 1, ident(6), 2, 3, ident(7)]
        subscription = cbor.encode([1, node, [], [], [], ident(10), 1, binding])
        emit(f"subscription-{network}", "subscription", subscription)
        ref = [ident(3), ident(network), ident(11)]
        proposal = dict(service_ref=ref, listener_revision=1, intent_digest=digest,
                        allocation_round=1, proposal_seq=1, proposal_id=ident(12), port=40001)
        service = {k: proposal[k] for k in ('service_ref', 'listener_revision', 'intent_digest')}
        result = dict(**service, grant_id=ident(13), refresh_seq=None, consumer_seq=1, remaining_ms=20000,
                      result='ok', snapshot_revision=1, snapshot_digest=digest)
        acquire = message('lease.acquire', dict(consumer_seq=1, snapshot_revision=1, snapshot_digest=digest, services=[service]), network)
        lease = message('lease.result', result, network)
        pair(f"lease-{network}", acquire, lease)
        pair(f"lease-retry-{network}", acquire, lease, request_nonce=30+network)
        emit(f'lease-null-reply-{network}', 'reply', envelope(cbor.encode(None), nonce=20+network), False,
             request=envelope(cbor.encode_value(acquire), False, nonce=20+network), outcome='message')
        pair(f"lease-empty-receipt-{network}", acquire, None, False, empty=True)
        for count in (0, 2):
            bad = copy.deepcopy(acquire)
            other = copy.deepcopy(service); other['service_ref'][2] = ident(12)
            bad['body']['services'] = [] if count == 0 else [service, other]
            emit(f"lease-count-{network}-{count}", "request", envelope(cbor.encode_value(bad), False), False, message_valid='yes' if count == 2 else 'no')
        if network == 4:
            wrong = copy.deepcopy(lease); wrong['network_id'] = ident(5)
            pair('wrong-network-reply', acquire, wrong, False)
            wrong = copy.deepcopy(lease); wrong['body']['consumer_seq'] = 2
            pair('wrong-consumer-seq', acquire, wrong, False)
            pair('wrong-nonce', acquire, lease, False, nonce=10)
            pair('wrong-recipient', acquire, lease, False, recipient=authority)
            pair('missing-recipient', acquire, lease, False, recipient=None)
            pair('wrong-operation', acquire, lease, False, kind='config.stream')
            for field, value in [('nsd_id', ident(15)), ('request_id', ident(15)),
                                 ('subject_identity', authority), ('runtime_generation', 2),
                                 ('runtime_id', ident(15)), ('authority_epoch', 3), ('session_seq', 4)]:
                wrong = copy.deepcopy(lease); wrong[field] = value
                pair('reply-mismatch-' + field, acquire, wrong, False)
            for field, value in [('listener_revision', 2), ('intent_digest', bytes([9])*32),
                                 ('snapshot_revision', 2), ('snapshot_digest', bytes([9])*32)]:
                wrong = copy.deepcopy(lease)
                wrong['body'][field] = value
                pair('lease-mismatch-' + field, acquire, wrong, False)
        # Snapshot content uses its own unchanged M6 map and domain-separated digest.
        snapshot = dict(scope=[node, ident(3), ident(network)],
                        snapshot_revision=1, resources=[], routes=[], listeners=[], grants=[], withdrawals=[])
        content = cbor.encode_value(snapshot)
        push = message('snapshot.push', dict(snapshot_revision=1,
            snapshot_digest=hashlib.sha256(b'ns.service.snapshot.v1\0'+content).digest(), content=content), network)
        for kind, body in [('snapshot.push', push['body']), ('port.cancel', proposal), ('port.query', proposal)]:
            event = message(kind, body, network)
            raw = envelope(cbor.encode_value(event), nonce=15)
            emit(f"event-{kind}-{network}", "event", raw, binding=subscription,
                 data=base64.urlsafe_b64encode(raw).rstrip(b'=').decode())
            if network == 4:
                for name, key, value in [('other-network', 'network_id', ident(5)), ('old-session', 'session_seq', 2)]:
                    bad = copy.deepcopy(event); bad[key] = value
                    emit(f"event-{kind}-{name}", "event", envelope(cbor.encode_value(bad), nonce=15), False, binding=subscription)
                for field, value in [('runtime_generation', 2), ('runtime_id', ident(14)), ('authority_epoch', 3), ('nsd_id', ident(14)), ('subject_identity', authority)]:
                    bad = copy.deepcopy(event); bad[field] = value
                    emit(f'event-{kind}-mismatch-{field}', 'event', envelope(cbor.encode_value(bad), nonce=15), False, binding=subscription)
            if kind != 'snapshot.push':
                answer_body = dict(**proposal, result='terminated-pure' if kind == 'port.cancel' else 'installed',
                                   terminal_floor=1 if kind == 'port.cancel' else None)
                answer = message('port.result' if kind == 'port.cancel' else 'port.query.result', answer_body, network)
                emit(f"reverse-{kind}-{network}", "reverse", cbor.encode_value(answer), operation=cbor.encode_value(event))
                bad = copy.deepcopy(answer); bad['body']['proposal_id'] = ident(14)
                emit(f"reverse-{kind}-mismatch-{network}", "reverse", cbor.encode_value(bad), False, operation=cbor.encode_value(event))
                pair(f"receipt-{answer['kind']}-{network}", answer, None, empty=True)
                if network == 4:
                    for field, value in [('request_id', ident(14)), ('runtime_generation', 2), ('runtime_id', ident(14)), ('authority_epoch', 3), ('session_seq', 4)]:
                        bad = copy.deepcopy(answer); bad[field] = value
                        emit(f'reverse-{kind}-context-{field}', 'reverse', cbor.encode_value(bad), False, operation=cbor.encode_value(event))
                    for field, value in [('port', 40002), ('listener_revision', 2), ('intent_digest', bytes([9])*32), ('allocation_round', 2), ('proposal_seq', 2)]:
                        bad = copy.deepcopy(answer); bad['body'][field] = value
                        emit(f'reverse-{kind}-proposal-{field}', 'reverse', cbor.encode_value(bad), False, operation=cbor.encode_value(event))
        emit(f"receipt-as-event-{network}", "event", envelope(b''), False, binding=subscription)
        emit(f"rpc-as-event-{network}", "event", envelope(cbor.encode_value(lease)), False, binding=subscription)
        ack = message('snapshot.ack', dict(snapshot_revision=1, snapshot_digest=digest, accepted=True,
                      enforcement_applied=True, dns_applied=True, error=None), network)
        retry = message('service.retry-port', dict(service_ref=ref), network, None)
        for req in (ack, retry):
            pair(f"receipt-{req['kind']}-{network}", req, None, empty=True)
            pair(f"receipt-wrong-nonce-{req['kind']}-{network}", req, None, False, empty=True, nonce=16)
            err = message('error', dict(code='recovery-required'), network, None)
            pair(f"error-{req['kind']}-{network}", req, err)
        for kind in ('listener.ready', 'lease.refresh'):
            ready_body = dict(**proposal, refresh_seq=1, snapshot_revision=1, snapshot_digest=digest,
                              enforcement_policy_digest=digest)
            request = message(kind, ready_body, network)
            publisher = dict(**result); publisher.update(refresh_seq=1, consumer_seq=None, snapshot_revision=None, snapshot_digest=None)
            reply = message('lease.result', publisher, network)
            pair(f'{kind}-{network}', request, reply)
            bad = copy.deepcopy(reply); bad['body']['refresh_seq'] = 2
            pair(f'{kind}-wrong-sequence-{network}', request, bad, False)
        report_content = cbor.encode_value(dict(scope=[node, ident(3), ident(network)], strict_mode=False, declarations=[]))
        report_digest = hashlib.sha256(b'ns.service.report.v1\0'+report_content).digest()
        report = message('report.replace', dict(report_revision=1, report_digest=report_digest, report_content=report_content), network, None)
        accepted = message('report.accepted', dict(accepted_revision=1, report_digest=report_digest, bindings=[]), network, None)
        pair(f'report.replace-{network}', report, accepted)
        bad = copy.deepcopy(accepted); bad['body']['accepted_revision'] = 2
        pair(f'report.replace-wrong-revision-{network}', report, bad, False)
        for kind, reply_kind, reqbody, repbody in [
            ('session.open', 'session.open.result', {}, dict(session_seq=3)),
            ('report.head', 'report.head.result', {}, dict(accepted_revision=0, report_digest=None, bindings=[])),
            ('runtime.floor', 'runtime.floor.result', {}, dict(current_generation=1, current_runtime_id=ident(6), active=True, authority_epoch=2)),
            ('runtime.bind', 'runtime.bind.result', dict(recovery=False, observed_generation=None, observed_runtime_id=None, owner_recovery=False), dict(authority_epoch=2)),
        ]:
            bootstrap = kind.startswith('runtime.')
            req = message(kind, reqbody, network, None if kind != 'session.open' else 3, epoch=None if bootstrap else 2)
            rep = message(reply_kind, repbody, network, None if kind != 'session.open' else 3)
            pair(f"{kind}-{network}", req, rep)
            err = message('error', dict(code='unauthorized'), network, None)
            pair(f"error-{kind}-{network}", req, err)
            if kind == 'runtime.floor':
                req['runtime_generation'] = req['runtime_id'] = None
                rep['runtime_generation'] = rep['runtime_id'] = None
                pair(f"floor-unbound-{network}", req, rep)
                pair(f"floor-unbound-error-{network}", req, err, False)
        error = message('error', dict(code='stale-session'), network, None)
        pair(f"error-session-bound-{network}", acquire, error)
        error['session_seq'] = 3
        pair(f"error-with-session-{network}", acquire, error, False)
    base = message('session.open', {})
    for field in ('runtime_id', 'request_id', 'nsd_id', 'network_id'):
        changed = copy.deepcopy(base); changed[field] = bytes(16)
        emit('zero-request-' + field, 'request', envelope(cbor.encode_value(changed), False),
             field in ('nsd_id', 'network_id'))
    raw = cbor.encode_value(base)
    emit('nonminimal-message', 'request', envelope(b'\xb8\x0b'+raw[1:], False), False)
    bad = dict(base, extra=1)
    emit('unknown-message-field', 'request', envelope(cbor.encode_value(bad), False), False)
    for kind, body in [('runtime.bind.result', dict(authority_epoch=2)), ('report.accepted', dict(accepted_revision=0, report_digest=None, bindings=[])), ('error', dict(code='unauthorized'))]:
        emit('illegal-node-request-' + kind, 'request', envelope(cbor.encode_value(message(kind, body, session=None)), False), False)
    emit('oversized-envelope', 'request', b'\x82'+cbor.head(cbor.BYTES, 8388609), False)
    return out
