from collections import List
from testing import assert_equal, assert_true

import emberjson

# ===----------------------------------------------------------------------=== #
# ValidationStatus: Represented as a struct with compile-time constants.
# Note: In Mojo 0.25.6.1, 'alias' is the keyword for comptime constants.
# ===----------------------------------------------------------------------=== #


@register_passable("trivial")
struct ValidationStatus(EqualityComparable, Stringable):
    var value: Int

    fn __init__(out self, value: Int):
        self.value = value

    fn __eq__(self, other: ValidationStatus) -> Bool:
        return self.value == other.value

    fn __ne__(self, other: ValidationStatus) -> Bool:
        return self.value != other.value

    fn __str__(self) -> String:
        if self == Self.PENDING:
            return "Pending"
        if self == Self.VALID:
            return "Valid"
        if self == Self.UNTRUSTED_ROOT:
            return "Untrusted_Root"
        if self == Self.SUBJECT_ISSUER_MISMATCH:
            return "Subject_Issuer_Mismatch"
        if self == Self.SIGNATURE_FAILURE:
            return "Signature_Failure"
        if self == Self.NOT_A_CA:
            return "Not_A_CA"
        if self == Self.EXPIRED:
            return "Expired"
        return "Unknown(" + String(self.value) + ")"

    alias PENDING = ValidationStatus(0)
    alias VALID = ValidationStatus(1)
    alias UNTRUSTED_ROOT = ValidationStatus(2)
    alias SUBJECT_ISSUER_MISMATCH = ValidationStatus(3)
    alias SIGNATURE_FAILURE = ValidationStatus(4)
    alias NOT_A_CA = ValidationStatus(5)
    alias EXPIRED = ValidationStatus(6)

    @staticmethod
    fn from_string(s: String) -> ValidationStatus:
        if s == "Pending":
            return Self.PENDING
        if s == "Valid":
            return Self.VALID
        if s == "Untrusted_Root":
            return Self.UNTRUSTED_ROOT
        if s == "Subject_Issuer_Mismatch":
            return Self.SUBJECT_ISSUER_MISMATCH
        if s == "Signature_Failure":
            return Self.SIGNATURE_FAILURE
        if s == "Not_A_CA":
            return Self.NOT_A_CA
        if s == "Expired":
            return Self.EXPIRED
        return ValidationStatus(-1)


# ===----------------------------------------------------------------------=== #
# MockCertificate: Metadata for validation logic.
# ===----------------------------------------------------------------------=== #


@register_passable("trivial")
struct MockCertificate:
    var id: Int
    var subject: Int
    var issuer: Int
    var public_key_id: Int
    var authority_key_id: Int
    var is_ca: Bool
    var not_before: Int
    var not_after: Int

    fn __init__(
        out self,
        id: Int,
        subject: Int,
        issuer: Int,
        public_key_id: Int,
        authority_key_id: Int,
        is_ca: Bool,
        not_before: Int,
        not_after: Int,
    ):
        self.id = id
        self.subject = subject
        self.issuer = issuer
        self.public_key_id = public_key_id
        self.authority_key_id = authority_key_id
        self.is_ca = is_ca
        self.not_before = not_before
        self.not_after = not_after

    fn copy(self) -> MockCertificate:
        return self


# ===----------------------------------------------------------------------=== #
# PKIValidator: Implements the state machine from pki_path_validation.qnt
# ===----------------------------------------------------------------------=== #

struct PKIValidator:
    var trust_store: List[MockCertificate]
    var current_chain: List[MockCertificate]
    var status: ValidationStatus
    var step: Int
    var current_time: Int

    fn __init__(
        out self,
        var trust_store: List[MockCertificate],
        var chain: List[MockCertificate],
        current_time: Int,
    ):
        self.trust_store = trust_store^
        self.current_chain = chain^
        self.status = ValidationStatus.PENDING
        self.step = 0
        self.current_time = current_time

    @always_inline
    fn dispatch[action_id: Int](mut self) -> Bool:
        """
        Compile-time dispatcher specialized for each action ID.
        This mirrors the 'any' block in Quint.
        """
        @parameter
        if action_id == 0:
            return self.handle_already_finished()
        elif action_id == 1:
            return self.handle_root_success()
        elif action_id == 2:
            return self.handle_root_expired()
        elif action_id == 3:
            return self.handle_root_signature_failure()
        elif action_id == 4:
            return self.handle_intermediate_success()
        elif action_id == 5:
            return self.handle_intermediate_expired()
        elif action_id == 6:
            return self.handle_subject_issuer_mismatch()
        elif action_id == 7:
            return self.handle_intermediate_signature_failure()
        elif action_id == 8:
            return self.handle_not_a_ca_failure()
        elif action_id == 9:
            return self.handle_untrusted_root()
        return False

    fn validate_step(mut self):
        """
        Automatic dispatcher: specialized at compile-time to iterate over all actions.
        """
        @parameter
        for i in range(10):
            if self.dispatch[i]():
                return

    # --- Atomic Actions (Mirroring Quint Spec) ---

    fn handle_already_finished(mut self) -> Bool:
        if self.status != ValidationStatus.PENDING or self.step >= len(
            self.current_chain
        ):
            return True
        return False

    fn handle_root_success(mut self) -> Bool:
        var cert = self.current_chain[self.step]
        for i in range(len(self.trust_store)):
            var root = self.trust_store[i]
            if cert.issuer == root.subject:
                if cert.authority_key_id == root.public_key_id:
                    if (
                        self.current_time >= cert.not_before
                        and self.current_time <= cert.not_after
                    ):
                        self.status = ValidationStatus.VALID
                        self.step += 1
                        return True
        return False

    fn handle_root_expired(mut self) -> Bool:
        var cert = self.current_chain[self.step]
        for i in range(len(self.trust_store)):
            var root = self.trust_store[i]
            if cert.issuer == root.subject:
                if cert.authority_key_id == root.public_key_id:
                    if (
                        self.current_time < cert.not_before
                        or self.current_time > cert.not_after
                    ):
                        self.status = ValidationStatus.EXPIRED
                        self.step += 1
                        return True
        return False

    fn handle_root_signature_failure(mut self) -> Bool:
        var cert = self.current_chain[self.step]
        var found_matching_subject = False
        for i in range(len(self.trust_store)):
            var root = self.trust_store[i]
            if cert.issuer == root.subject:
                found_matching_subject = True
                if cert.authority_key_id == root.public_key_id:
                    # If ANY matches, it's not a signature failure
                    return False

        if found_matching_subject:
            self.status = ValidationStatus.SIGNATURE_FAILURE
            self.step += 1
            return True
        return False

    fn handle_intermediate_success(mut self) -> Bool:
        if self.step + 1 >= len(self.current_chain):
            return False

        var cert = self.current_chain[self.step]
        var next_cert = self.current_chain[self.step + 1]

        if (
            cert.issuer == next_cert.subject
            and cert.authority_key_id == next_cert.public_key_id
            and next_cert.is_ca
        ):
            if (
                self.current_time >= cert.not_before
                and self.current_time <= cert.not_after
            ):
                self.step += 1
                return True
        return False

    fn handle_intermediate_expired(mut self) -> Bool:
        if self.step + 1 >= len(self.current_chain):
            return False

        var cert = self.current_chain[self.step]
        var next_cert = self.current_chain[self.step + 1]

        if (
            cert.issuer == next_cert.subject
            and cert.authority_key_id == next_cert.public_key_id
            and next_cert.is_ca
        ):
            if (
                self.current_time < cert.not_before
                or self.current_time > cert.not_after
            ):
                self.status = ValidationStatus.EXPIRED
                self.step += 1
                return True
        return False

    fn handle_subject_issuer_mismatch(mut self) -> Bool:
        if self.step + 1 >= len(self.current_chain):
            return False

        var cert = self.current_chain[self.step]
        var next_cert = self.current_chain[self.step + 1]

        if cert.issuer != next_cert.subject:
            self.status = ValidationStatus.SUBJECT_ISSUER_MISMATCH
            self.step += 1
            return True
        return False

    fn handle_intermediate_signature_failure(mut self) -> Bool:
        if self.step + 1 >= len(self.current_chain):
            return False

        var cert = self.current_chain[self.step]
        var next_cert = self.current_chain[self.step + 1]

        if (
            cert.issuer == next_cert.subject
            and cert.authority_key_id != next_cert.public_key_id
        ):
            self.status = ValidationStatus.SIGNATURE_FAILURE
            self.step += 1
            return True
        return False

    fn handle_not_a_ca_failure(mut self) -> Bool:
        if self.step + 1 >= len(self.current_chain):
            return False

        var cert = self.current_chain[self.step]
        var next_cert = self.current_chain[self.step + 1]

        if (
            cert.issuer == next_cert.subject
            and cert.authority_key_id == next_cert.public_key_id
            and not next_cert.is_ca
        ):
            self.status = ValidationStatus.NOT_A_CA
            self.step += 1
            return True
        return False

    fn handle_untrusted_root(mut self) -> Bool:
        if self.step + 1 >= len(self.current_chain):
            self.status = ValidationStatus.UNTRUSTED_ROOT
            self.step += 1
            return True
        return False


# ===----------------------------------------------------------------------=== #
# Trace Replay Harness
# ===----------------------------------------------------------------------=== #


fn mock_hash(s: String) -> Int:
    var h = 0
    for i in range(len(s)):
        h = h * 31 + ord(s[i])
    return h


fn parse_cert_json(val: emberjson.Value) raises -> MockCertificate:
    var obj = val.object().copy()
    var authority_key_id = Int(
        obj["authority_key_id"].copy()["#bigint"].copy().string()
    )
    var public_key_id = Int(
        obj["public_key_id"].copy()["#bigint"].copy().string()
    )
    var id = Int(obj["id"].copy()["#bigint"].copy().string())
    var is_ca = obj["is_ca"].copy().bool()
    var issuer = mock_hash(obj["issuer"].copy().string())
    var subject = mock_hash(obj["subject"].copy().string())
    var not_before = Int(obj["not_before"].copy()["#bigint"].copy().string())
    var not_after = Int(obj["not_after"].copy()["#bigint"].copy().string())
    return MockCertificate(
        id,
        subject,
        issuer,
        public_key_id,
        authority_key_id,
        is_ca,
        not_before,
        not_after,
    )


fn test_with_trace(path: String) raises:
    print("Testing with trace: " + path)
    var f = open(path, "r")
    var data = f.read()
    f.close()

    var trace = emberjson.parse(data)
    var states = trace["states"].copy().array().copy()

    var s0 = states[0].copy()

    var trust_store = List[MockCertificate]()
    var ts_json = s0["trust_store"].copy()["#set"].copy().array().copy()
    for i in range(len(ts_json)):
        trust_store.append(parse_cert_json(ts_json[i].copy()))

    var chain = List[MockCertificate]()
    var chain_json = s0["current_chain"].copy().array().copy()
    for i in range(len(chain_json)):
        chain.append(parse_cert_json(chain_json[i].copy()))

    var current_time = Int(s0["current_time"].copy()["#bigint"].copy().string())

    var validator = PKIValidator(trust_store^, chain^, current_time)

    for i in range(len(states)):
        var current_state = states[i].copy()
        var expected_status = ValidationStatus.from_string(
            current_state["validation_status"].copy()["tag"].copy().string()
        )
        var expected_step = Int(
            current_state["current_step"].copy()["#bigint"].copy().string()
        )

        assert_equal(validator.status, expected_status)
        assert_equal(validator.step, expected_step)

        if i < len(states) - 1:
            validator.validate_step()

    print("  OK")


# ===----------------------------------------------------------------------=== #
# Main
# ===----------------------------------------------------------------------=== #


fn main() raises:
    test_with_trace("poc/valid.itf.json")
    test_with_trace("poc/untrusted.itf.json")
    test_with_trace("poc/mismatch.itf.json")
    test_with_trace("poc/expired.itf.json")

    print("All Declarative POC tests passed!")