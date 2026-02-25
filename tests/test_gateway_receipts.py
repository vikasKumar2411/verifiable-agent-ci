from __future__ import annotations

import base64

from vaci.gateway import LocalGateway, verify_receipt


def test_gateway_produces_verifiable_receipt():
    gw = LocalGateway.ephemeral()
    r = gw.run(["python", "-c", "print('hello')"])
    assert r.exit_code == 0
    assert verify_receipt(gw.public_key, r) is True


def test_tampering_stdout_breaks_verification():
    gw = LocalGateway.ephemeral()
    r = gw.run(["python", "-c", "print('hello')"])
    assert verify_receipt(gw.public_key, r) is True

    # tamper the stdout but keep hashes/signature unchanged => should fail
    tampered = r.__class__(
        **{**r.__dict__, "stdout_b64": base64.urlsafe_b64encode(b"FAKE\n").decode("ascii").rstrip("=")}
    )
    assert verify_receipt(gw.public_key, tampered) is False


def test_tampering_signature_breaks_verification():
    gw = LocalGateway.ephemeral()
    r = gw.run(["python", "-c", "print('hello')"])
    assert verify_receipt(gw.public_key, r) is True

    bad_sig = r.signature.model_copy(update={"sig_b64": r.signature.sig_b64[::-1]})
    tampered = r.__class__(**{**r.__dict__, "signature": bad_sig})
    assert verify_receipt(gw.public_key, tampered) is False