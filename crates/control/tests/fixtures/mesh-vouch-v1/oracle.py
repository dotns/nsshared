"""Independent CBOR/OpenSSL oracle; fixed seeds are synthetic test identities."""
import hashlib
import json
import pathlib
import subprocess
import tempfile


def head(major, value):
    for bound, width, tag in ((24, 0, 0), (256, 1, 24), (65536, 2, 25), (2**32, 4, 26), (2**64, 8, 27)):
        if value < bound:
            return bytes([(major << 5) | (value if not width else tag)]) + value.to_bytes(width, 'big') if width else bytes([(major << 5) | value])
    raise ValueError('integer overflow')


def cbor(value):
    if value is None:
        return b'\xf6'
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return head(3, len(data)) + data
    if isinstance(value, dict):
        return head(5, len(value)) + b''.join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


def payload(*values):
    return cbor(dict(enumerate((1, *values))))


def command(args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, timeout=10).stdout


with tempfile.TemporaryDirectory(prefix='mesh-vouch-oracle-') as directory:
    root = pathlib.Path(directory)
    public = {}
    for seed in (11, 12, 14):
        secret = root / str(seed)
        secret.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + bytes([seed]) * 32)
        secret.chmod(0o600)
        der = command(['openssl', 'pkey', '-inform', 'DER', '-in', str(secret), '-pubout', '-outform', 'DER'])
        assert der[:12] == bytes.fromhex('302a300506032b6570032100')
        public[seed] = der[12:]

    def sign(seed, value):
        message = root / 'message'
        message.write_bytes(value)
        return command(['openssl', 'pkeyutl', '-sign', '-rawin', '-keyform', 'DER', '-inkey', str(root / str(seed)), '-in', str(message)])

    def envelope(api, seed, value, nonce):
        text = api.encode()
        signing = b'nsio-ctrl-v1\0' + b'\x01' + len(text).to_bytes(4, 'big') + text
        signing += (1000).to_bytes(8, 'big') + nonce + b'\x00' + public[seed] + hashlib.sha256(value).digest()
        return cbor({'v': 1, 'api': api, 'ts': 1000, 'nonce': nonce, 'machine_id': None,
                     'machine_key_pub': public[seed], 'payload': value, 'signature': sign(seed, signing)})

    target_id = hashlib.blake2s(public[14], digest_size=20).digest()
    inner_input = b'nsmesh-vouch-v1\0' + public[12] + target_id + bytes([6]) * 32
    inner_input += (3).to_bytes(8, 'big') + bytes([2]) * 16 + (1000).to_bytes(8, 'big') + (1060).to_bytes(8, 'big')
    inner_payload = payload(public[12], target_id, bytes([6]) * 32, 3, bytes([2]) * 16, 1000, 1060, sign(11, inner_input))
    credential = envelope('mesh.vouch', 11, inner_payload, bytes([3]) * 16)
    register = payload(public[12], bytes([6]) * 32, 3, None, None, credential)
    original = envelope('mesh.register', 14, register, bytes([2]) * 16)
    canonical = (1).to_bytes(2, 'big') + public[12] + (9).to_bytes(8, 'big') + (2).to_bytes(4, 'big')
    for signer, wg, incarnation in sorted([(public[11], bytes([4]) * 32, 1), (public[14], bytes([6]) * 32, 3)]):
        canonical += signer + wg + incarnation.to_bytes(8, 'big')
    canonical += (2).to_bytes(8, 'big') + (1).to_bytes(4, 'big') + public[11]
    canonical += (1).to_bytes(4, 'big') + public[14] + (2).to_bytes(8, 'big')
    print(json.dumps({'version': 1, 'canonical_hex': canonical.hex(),
                      'state_digest_hex': hashlib.sha256(b'nsmesh-membership-state-v1\0' + canonical).hexdigest(),
                      'register_hex': original.hex(), 'udp_hex': (b'NSGWMSH1' + original).hex(),
                      'wss_hex': (b'\x01\x01' + original).hex()}, indent=2))
