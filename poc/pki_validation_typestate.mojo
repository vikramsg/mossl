from collections import List, Optional
from testing import assert_equal, assert_true

from utils import Variant
import emberjson

# ===----------------------------------------------------------------------=== #
# ValidationStatus: Error tags and status indicators.
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

    # Can be made comptime?
    fn __str__(self) -> String:
        if self == Self.PENDING: return "Pending"
        if self == Self.VALID: return "Valid"
        if self == Self.UNTRUSTED_ROOT: return "Untrusted_Root"
        if self == Self.SUBJECT_ISSUER_MISMATCH: return "Subject_Issuer_Mismatch"
        if self == Self.SIGNATURE_FAILURE: return "Signature_Failure"
        if self == Self.NOT_A_CA: return "Not_A_CA"
        if self == Self.EXPIRED: return "Expired"
        return "Unknown(" + String(self.value) + ")"

    alias PENDING = ValidationStatus(0)
    alias VALID = ValidationStatus(1)
    alias UNTRUSTED_ROOT = ValidationStatus(2)
    alias SUBJECT_ISSUER_MISMATCH = ValidationStatus(3)
    alias SIGNATURE_FAILURE = ValidationStatus(4)
    alias NOT_A_CA = ValidationStatus(5)
    alias EXPIRED = ValidationStatus(6)

    # Can be made comptime?
    @staticmethod
    fn from_string(s: String) -> ValidationStatus:
        if s == "Pending": return Self.PENDING
        if s == "Valid": return Self.VALID
        if s == "Untrusted_Root": return Self.UNTRUSTED_ROOT
        if s == "Subject_Issuer_Mismatch": return Self.SUBJECT_ISSUER_MISMATCH
        if s == "Signature_Failure": return Self.SIGNATURE_FAILURE
        if s == "Not_A_CA": return Self.NOT_A_CA
        if s == "Expired": return Self.EXPIRED
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
# Typestate Definitions
#
# NOTE: Boilerplate manual implementations of __copyinit__ and __moveinit__ 
# are required here because:
# 1. The structs contain a List[MockCertificate], which is not ImplicitlyCopyable.
# 2. The Mojo compiler cannot synthesize __copyinit__ for structs with non-copyable fields.
# 3. utils.Variant requires its member types to be both Copyable and Movable.
# 4. We use 'Movable, Copyable' instead of 'ImplicitlyCopyable' for safety,
#    forcing explicit moves (^) or copies (.copy()) of the certificate chain.
# ===----------------------------------------------------------------------=== #

struct ValidationInProgress(Movable, Copyable):
    var step: Int
    var chain: List[MockCertificate]

    fn __init__(out self, step: Int, var chain: List[MockCertificate]):
        self.step = step
        self.chain = chain^

    fn __copyinit__(out self, read other: Self):
        self.step = other.step
        self.chain = other.chain.copy()

    fn __moveinit__(out self, deinit other: Self):
        self.step = other.step
        self.chain = other.chain^

struct ValidationSuccess(Movable, Copyable):
    var step: Int
    var chain: List[MockCertificate]

    fn __init__(out self, step: Int, var chain: List[MockCertificate]):
        self.step = step
        self.chain = chain^

    fn __copyinit__(out self, read other: Self):
        self.step = other.step
        self.chain = other.chain.copy()

    fn __moveinit__(out self, deinit other: Self):
        self.step = other.step
        self.chain = other.chain^

struct ValidationFailure(Movable, Copyable):
    var status: ValidationStatus
    var step: Int

    fn __init__(out self, status: ValidationStatus, step: Int):
        self.status = status
        self.step = step

    fn __copyinit__(out self, read other: Self):
        self.status = other.status
        self.step = other.step

    fn __moveinit__(out self, deinit other: Self):
        self.status = other.status
        self.step = other.step

alias ValidatorState = Variant[
    ValidationInProgress,
    ValidationSuccess,
    ValidationFailure
]

# ===----------------------------------------------------------------------=== #
# Action Implementations (Atomic Transitions)
# ===----------------------------------------------------------------------=== #

@always_inline
fn handle_root_success(read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    var cert = current.chain[current.step]
    for i in range(len(trust_store)):
        var root = trust_store[i]
        if cert.issuer == root.subject:
            if cert.authority_key_id == root.public_key_id:
                if (current_time >= cert.not_before and current_time <= cert.not_after):
                    return ValidatorState(ValidationSuccess(current.step + 1, current.chain.copy()))
    return None

@always_inline
fn handle_root_expired(read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    var cert = current.chain[current.step]
    for i in range(len(trust_store)):
        var root = trust_store[i]
        if cert.issuer == root.subject:
            if cert.authority_key_id == root.public_key_id:
                if (current_time < cert.not_before or current_time > cert.not_after):
                    return ValidatorState(ValidationFailure(ValidationStatus.EXPIRED, current.step + 1))
    return None

@always_inline
fn handle_root_signature_failure(read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    var cert = current.chain[current.step]
    var found_matching_subject = False
    for i in range(len(trust_store)):
        var root = trust_store[i]
        if cert.issuer == root.subject:
            found_matching_subject = True
            if cert.authority_key_id == root.public_key_id:
                return None # Matches, so not a signature failure
    
    if found_matching_subject:
        return ValidatorState(ValidationFailure(ValidationStatus.SIGNATURE_FAILURE, current.step + 1))
    return None

@always_inline
fn handle_intermediate_success(read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    if current.step + 1 >= len(current.chain):
        return None

    var cert = current.chain[current.step]
    var next_cert = current.chain[current.step + 1]

    if (cert.issuer == next_cert.subject and cert.authority_key_id == next_cert.public_key_id and next_cert.is_ca):
        if (current_time >= cert.not_before and current_time <= cert.not_after):
            return ValidatorState(ValidationInProgress(current.step + 1, current.chain.copy()))
    return None

@always_inline
fn handle_intermediate_expired(read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    if current.step + 1 >= len(current.chain):
        return None

    var cert = current.chain[current.step]
    var next_cert = current.chain[current.step + 1]

    if (cert.issuer == next_cert.subject and cert.authority_key_id == next_cert.public_key_id and next_cert.is_ca):
        if (current_time < cert.not_before or current_time > cert.not_after):
            return ValidatorState(ValidationFailure(ValidationStatus.EXPIRED, current.step + 1))
    return None

@always_inline
fn handle_subject_issuer_mismatch(read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    if current.step + 1 >= len(current.chain):
        return None

    var cert = current.chain[current.step]
    var next_cert = current.chain[current.step + 1]

    if cert.issuer != next_cert.subject:
        return ValidatorState(ValidationFailure(ValidationStatus.SUBJECT_ISSUER_MISMATCH, current.step + 1))
    return None

@always_inline
fn handle_intermediate_signature_failure(read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    if current.step + 1 >= len(current.chain):
        return None

    var cert = current.chain[current.step]
    var next_cert = current.chain[current.step + 1]

    if (cert.issuer == next_cert.subject and cert.authority_key_id != next_cert.public_key_id):
        return ValidatorState(ValidationFailure(ValidationStatus.SIGNATURE_FAILURE, current.step + 1))
    return None

@always_inline
fn handle_not_a_ca_failure(read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    if current.step + 1 >= len(current.chain):
        return None

    var cert = current.chain[current.step]
    var next_cert = current.chain[current.step + 1]

    if (cert.issuer == next_cert.subject and cert.authority_key_id == next_cert.public_key_id and not next_cert.is_ca):
        return ValidatorState(ValidationFailure(ValidationStatus.NOT_A_CA, current.step + 1))
    return None

@always_inline
fn handle_untrusted_root(read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    if current.step + 1 >= len(current.chain):
        return ValidatorState(ValidationFailure(ValidationStatus.UNTRUSTED_ROOT, current.step + 1))
    return None

@always_inline
fn dispatch_action[action_id: Int](read current: ValidationInProgress, read trust_store: List[MockCertificate], current_time: Int) -> Optional[ValidatorState]:
    @parameter
    if action_id == 1: return handle_root_success(current, trust_store, current_time)
    elif action_id == 2: return handle_root_expired(current, trust_store, current_time)
    elif action_id == 3: return handle_root_signature_failure(current, trust_store, current_time)
    elif action_id == 4: return handle_intermediate_success(current, trust_store, current_time)
    elif action_id == 5: return handle_intermediate_expired(current, trust_store, current_time)
    elif action_id == 6: return handle_subject_issuer_mismatch(current, trust_store, current_time)
    elif action_id == 7: return handle_intermediate_signature_failure(current, trust_store, current_time)
    elif action_id == 8: return handle_not_a_ca_failure(current, trust_store, current_time)
    elif action_id == 9: return handle_untrusted_root(current, trust_store, current_time)
    return None

# ===----------------------------------------------------------------------=== #
# State Machine Wrapper
# ===----------------------------------------------------------------------=== #

struct TypestatePKIValidator:
    var trust_store: List[MockCertificate]
    var state: ValidatorState
    var current_time: Int

    fn __init__(out self, var trust_store: List[MockCertificate], var chain: List[MockCertificate], current_time: Int):
        self.trust_store = trust_store^
        self.state = ValidatorState(ValidationInProgress(0, chain^))
        self.current_time = current_time

    fn validate_step(mut self):
        if not self.state.isa[ValidationInProgress]():
            return

        # Use var to take ownership of the in-progress state
        var current = self.state.unsafe_take[ValidationInProgress]()
        
        @parameter
        for i in range(1, 10):
            var maybe_next = dispatch_action[i](current, self.trust_store, self.current_time)
            if maybe_next:
                self.state = maybe_next.take()
                return
        
        # If no action matched, we put it back (should not happen based on spec)
        self.state = ValidatorState(current^)

    fn get_status(mut self) -> ValidationStatus:
        if self.state.isa[ValidationInProgress]():
            return ValidationStatus.PENDING
        if self.state.isa[ValidationSuccess]():
            return ValidationStatus.VALID
        if self.state.isa[ValidationFailure]():
            return self.state[ValidationFailure].status
        return ValidationStatus(-1)

    fn get_step(mut self) -> Int:
        if self.state.isa[ValidationInProgress]():
            return self.state[ValidationInProgress].step
        if self.state.isa[ValidationSuccess]():
            return self.state[ValidationSuccess].step
        if self.state.isa[ValidationFailure]():
            return self.state[ValidationFailure].step
        return -1

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
    var authority_key_id = Int(obj["authority_key_id"].copy()["#bigint"].copy().string())
    var public_key_id = Int(obj["public_key_id"].copy()["#bigint"].copy().string())
    var id = Int(obj["id"].copy()["#bigint"].copy().string())
    var is_ca = obj["is_ca"].copy().bool()
    var issuer = mock_hash(obj["issuer"].copy().string())
    var subject = mock_hash(obj["subject"].copy().string())
    var not_before = Int(obj["not_before"].copy()["#bigint"].copy().string())
    var not_after = Int(obj["not_after"].copy()["#bigint"].copy().string())
    return MockCertificate(id, subject, issuer, public_key_id, authority_key_id, is_ca, not_before, not_after)

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

    var validator = TypestatePKIValidator(trust_store^, chain^, current_time)

    for i in range(len(states)):
        var current_state = states[i].copy()
        var expected_status = ValidationStatus.from_string(
            current_state["validation_status"].copy()["tag"].copy().string()
        )
        var expected_step = Int(
            current_state["current_step"].copy()["#bigint"].copy().string()
        )

        assert_equal(validator.get_status(), expected_status)
        assert_equal(validator.get_step(), expected_step)

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

    print("All Typestate POC tests passed!")
