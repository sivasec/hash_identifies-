import pytest

from hash_identifier import PREFIX_RULES, HashCandidate, identify


def test_bcrypt_prefix_is_recognized() -> None:
    sample = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G"
    candidates = identify(sample)
    assert candidates
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].confidence == "high"


def test_argon2id_prefix_is_recognized() -> None:
    sample = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA"
    candidates = identify(sample)
    assert any(c.algorithm == "Argon2id" for c in candidates)


def test_sha512_crypt_prefix_is_recognized() -> None:
    sample = "$6$rounds=10000$salt$hashedpasswordhere"
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-512 crypt"


def test_django_pbkdf2_prefix_is_recognized() -> None:
    sample = "pbkdf2_sha256$260000$salt$hash"
    candidates = identify(sample)
    assert candidates[0].algorithm == "Django PBKDF2-SHA256"


def test_apr1_prefix_is_recognized() -> None:
    sample = "$apr1$rsalt$mp7TYYDvbgvNCJN3JTd6q1"
    candidates = identify(sample)
    assert candidates[0].algorithm == "Apache MD5-crypt"
    assert candidates[0].confidence == "high"


def test_mysql5_format_is_recognized() -> None:
    sample = "*23AE809DDACAF96AF0FD78ED04B6A265E05AA257"
    candidates = identify(sample)
    assert candidates[0].algorithm == "MySQL5"
    assert candidates[0].confidence == "high"


def test_mysql5_rejects_lowercase_body() -> None:
    lowercase_body = "23ae809ddacaf96af0fd78ed04b6a265e05aa257"
    candidates = identify("*" + lowercase_body)
    if candidates:
        assert candidates[0].algorithm != "MySQL5"


def test_netntlmv2_format_is_recognized() -> None:
    sample = "alice::CORP:1122334455667788:" + "a" * 32 + ":" + "b" * 64
    candidates = identify(sample)
    assert candidates[0].algorithm == "NetNTLMv2"
    assert candidates[0].confidence == "high"


def test_netntlmv1_format_is_recognized() -> None:
    sample = "alice::CORP:" + "a" * 48 + ":" + "b" * 48 + ":1122334455667788"
    candidates = identify(sample)
    assert candidates[0].algorithm == "NetNTLMv1"
    assert candidates[0].confidence == "high"


def test_descrypt_format_is_recognized() -> None:
    sample = "kRq14pmccuMOA"
    candidates = identify(sample)
    assert candidates[0].algorithm == "DES crypt"
    assert candidates[0].confidence == "medium"


def test_mysql323_length_returns_mysql323_first() -> None:
    sample = "5d2e19393cc5ef67"
    candidates = identify(sample)
    assert candidates[0].algorithm == "MySQL323"
    assert candidates[0].confidence == "medium"


def test_md5_length_returns_md5_first() -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"
    candidates = identify(sample)
    assert candidates[0].algorithm == "MD5"
    assert candidates[0].confidence == "medium"
    algorithms = [c.algorithm for c in candidates]
    assert "NTLM" in algorithms


def test_sha256_length_returns_sha256_first() -> None:
    sample = "a" * 64
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-256"


def test_sha1_length_returns_sha1_first() -> None:
    sample = "a" * 40
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-1"


def test_empty_input_returns_no_candidates() -> None:
    assert identify("") == []
    assert identify("   ") == []


def test_garbage_returns_no_candidates() -> None:
    assert identify("hello, this is not a hash") == []


def test_input_is_trimmed_of_whitespace() -> None:
    sample = "   5f4dcc3b5aa765d61d8327deb882cf99\n"
    candidates = identify(sample)
    assert candidates[0].algorithm == "MD5"


def test_unknown_phc_string_falls_back_to_generic() -> None:
    sample = "$pbkdf2-sha512$25000$cnNhbHQ$aGFzaA"
    candidates = identify(sample)
    assert candidates
    assert "PHC" in candidates[0].algorithm
    assert "pbkdf2-sha512" in candidates[0].algorithm
    assert candidates[0].confidence == "low"


def test_jwt_input_is_called_out_as_not_a_hash() -> None:
    sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"
    candidates = identify(sample)
    assert candidates
    assert "JWT" in candidates[0].algorithm
    assert candidates[0].confidence == "low"


def test_base64_blob_is_called_out_as_not_a_hash() -> None:
    sample = "VGhpcyBpcyBub3QgYSBoYXNoLCBpdHMgYmFzZTY0Lg=="
    candidates = identify(sample)
    assert candidates
    assert "Base64" in candidates[0].algorithm


def test_hash_candidate_is_frozen() -> None:
    candidate = HashCandidate(
        algorithm="MD5",
        confidence="medium",
        reason="test",
    )

    try:
        candidate.algorithm = "SHA-1"
    except (AttributeError, TypeError):
        return

    raise AssertionError(
        "HashCandidate should be frozen; assignment should have raised"
    )


@pytest.mark.parametrize("prefix,algorithm,_note", PREFIX_RULES)
def test_every_prefix_rule_is_recognized_with_high_confidence(
    prefix: str,
    algorithm: str,
    _note: str,
) -> None:
    sample = prefix + "fakebodydoesntmatter"
    candidates = identify(sample)
    assert candidates
    assert candidates[0].algorithm == algorithm
    assert candidates[0].confidence == "high"