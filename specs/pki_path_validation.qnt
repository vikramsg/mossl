// -*- mode: quint; -*-

/**
 * PKI Path Validation Specification
 *
 * OVERVIEW:
 * This specification models the core logic of X.509 certificate path validation.
 * It defines a state machine that processes a chain of certificates (from leaf 
 * to intermediate) and attempts to link them to a trusted anchor in the trust store.
 * 
 * The algorithm verifies:
 * 1. Trust Anchors: If the current certificate's issuer is in the trust store.
 * 2. Chain Continuity: If each certificate correctly identifies the next as its issuer.
 * 3. CA Constraints: If intermediate certificates are authorized to sign others (is_ca).
 * 4. Key Integrity: If the public keys match across the signing boundary (simplified signature).
 *
 * USAGE:
 * 1. Simulation: `quint run specs/pki_path_validation.qnt`
 *    Used to explore random paths and verify basic logic.
 * 2. Trace Generation: `quint run --run <run_name> --out-itf trace.json specs/pki_path_validation.qnt`
 *    Examples:
 *    - `quint run --run valid_chain_trace ...`
 *    - `quint run --run untrusted_root_trace ...`
 *    - `quint run --run mismatch_issuer_trace ...`
 *    The `run` blocks generate deterministic ITF traces used by Mojo tests.
 * 3. Model Checking: `quint check specs/pki_path_validation.qnt`
 *    Verifies that the invariants hold true for ALL possible execution paths.
 * 4. Temporal Checking: `quint check --temporal EventuallyTerminates specs/pki_path_validation.qnt`
 *    Verifies liveness properties (e.g., that validation always finishes).
 */
module pki_path_validation {
  // Types
  type Certificate = {
    id: int,
    subject: str,
    issuer: str,
    public_key_id: int,
    // basic constraint
    is_ca: bool,
    not_before: int,
    not_after: int
  }

  // All valid states for verification
  type ValidationStatus = 
    | Pending
    | Valid
    | Invalid_Chain
    | Untrusted_Root
    | Subject_Issuer_Mismatch
    | Signature_Failure
    | Not_A_CA

  // State
  // The current state in the chain
  var current_chain: List[Certificate]
  var trust_store: Set[Certificate]
  var validation_status: ValidationStatus
  var current_step: int
  var current_time: int

  // Constants/Parameters for testing
  // 5 is a reasonable limit for real-world hierarchies (Leaf -> Inter1 -> Inter2 -> Root)
  // We use 10 to let quint find more fuzzy paths.
  val MAX_CHAIN_LEN = 10

  // Pure functions
  pure def is_signed_by(cert: Certificate, issuer: Certificate): bool = {
    cert.issuer == issuer.subject and cert.public_key_id == issuer.public_key_id
  }

  pure def is_valid_at(cert: Certificate, time: int): bool = {
    time >= cert.not_before and time <= cert.not_after
  }

  // --- Invariants (Safety Properties) ---

  // 1. The validation status should only be 'Valid' if we have found a trust anchor
  val ValidImpliesTrustedRoot = 
    (validation_status == Valid) implies 
      trust_store.exists(root => 
        val last_cert = current_chain[current_step - 1]
        last_cert.issuer == root.subject and last_cert.public_key_id == root.public_key_id
      )

  // 2. Every certificate in a valid chain (except the leaf) MUST be a CA
  val IntermediatesMustBeCA = 
    (current_step > 0 and current_step < current_chain.length()) implies 
      current_chain[current_step].is_ca

  // 3. Step counter safety
  val StepWithinBounds = current_step <= current_chain.length()

  // --- Temporal Properties (Liveness) ---

  // 1. Eventually, the validation process must reach a terminal state (not Pending)
  // This ensures the algorithm doesn't get stuck in an infinite loop.
  temporal EventuallyTerminates = eventually(validation_status != Pending)

  // Actions
  action init: bool = all {
    current_chain' = [],
    trust_store' = Set(),
    validation_status' = Pending,
    current_step' = 0,
    current_time' = 0,
  }

  action setup(trusted_roots: Set[Certificate], chain: List[Certificate], time: int): bool = all {
    trust_store' = trusted_roots,
    current_chain' = chain,
    current_time' = time,
    validation_status' = Pending,
    current_step' = 0,
  }

  action validate_step: bool = {
    val chain_len = current_chain.length()
    if (validation_status == Pending and current_step < chain_len) {
      val cert = current_chain[current_step]
      
      // 1. Check if we reached a trusted root
      val matching_roots = trust_store.filter(r => r.subject == cert.issuer)
      if (matching_roots.size() > 0) {
        // Verify signature by root
        // For simplicity, we assume one matching root for now or pick one
        val root = matching_roots.chooseSome()
        if (cert.public_key_id == root.public_key_id) {
          all {
            validation_status' = Valid,
            current_step' = current_step + 1,
            current_chain' = current_chain,
            trust_store' = trust_store,
            current_time' = current_time,
          }
        } else {
          all {
            validation_status' = Signature_Failure,
            current_step' = current_step + 1,
            current_chain' = current_chain,
            trust_store' = trust_store,
            current_time' = current_time,
          }
        }
      } else {
        // 2. Not a root, check if there's a next intermediate
        if (current_step + 1 < chain_len) {
          val next_cert = current_chain[current_step + 1]
          
          if (cert.issuer != next_cert.subject) {
            all {
              validation_status' = Subject_Issuer_Mismatch,
              current_step' = current_step + 1,
              current_chain' = current_chain,
              trust_store' = trust_store,
              current_time' = current_time,
            }
          } else if (cert.public_key_id != next_cert.public_key_id) {
             all {
              validation_status' = Signature_Failure,
              current_step' = current_step + 1,
              current_chain' = current_chain,
              trust_store' = trust_store,
              current_time' = current_time,
            }
          } else if (not(next_cert.is_ca)) {
             all {
              validation_status' = Not_A_CA,
              current_step' = current_step + 1,
              current_chain' = current_chain,
              trust_store' = trust_store,
              current_time' = current_time,
            }
          } else {
            // Step successful, move to next
            all {
              current_step' = current_step + 1,
              validation_status' = validation_status,
              current_chain' = current_chain,
              trust_store' = trust_store,
              current_time' = current_time,
            }
          }
        } else {
          // No more certs and not found in trust store
          all {
            validation_status' = Untrusted_Root,
            current_step' = current_step + 1,
            current_chain' = current_chain,
            trust_store' = trust_store,
            current_time' = current_time,
          }
        }
      }
    } else {
      all {
        validation_status' = validation_status,
        current_step' = current_step,
        current_chain' = current_chain,
        trust_store' = trust_store,
        current_time' = current_time,
      }
    }
  }

  // Helpers for trace generation
  val example_root = { id: 0, subject: "Root", issuer: "Root", public_key_id: 100, is_ca: true, not_before: 0, not_after: 1000 }
  val example_inter = { id: 1, subject: "Inter", issuer: "Root", public_key_id: 101, is_ca: true, not_before: 0, not_after: 1000 }
  val example_leaf = { id: 2, subject: "Leaf", issuer: "Inter", public_key_id: 102, is_ca: false, not_before: 0, not_after: 1000 }

  run valid_chain_trace = {
    setup(Set(example_root), [example_leaf, example_inter], 500)
    .then(validate_step) // Validates leaf signed by inter
    .then(validate_step) // Validates inter signed by root
  }

  run untrusted_root_trace = {
    setup(Set(), [example_leaf, example_inter], 500)
    .then(validate_step)
    .then(validate_step)
  }

  run mismatch_issuer_trace = {
    val bad_inter = { id: 1, subject: "WrongSubject", issuer: "Root", public_key_id: 101, is_ca: true, not_before: 0, not_after: 1000 }
    setup(Set(example_root), [example_leaf, bad_inter], 500)
    .then(validate_step)
  }
}
