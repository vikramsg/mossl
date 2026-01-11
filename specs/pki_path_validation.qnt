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
 * 1. Simulation: `npx quint run specs/pki_path_validation.qnt`
 *    Explores random paths non-deterministically starting from different scenarios.
 * 2. Trace Generation: `npx quint test --match <run_name> --out-itf trace.json specs/pki_path_validation.qnt`
 *    Examples:
 *    - `npx quint test --match valid_chain_trace ...`
 *    - `npx quint test --match untrusted_root_trace ...`
 *    - `npx quint test --match mismatch_issuer_trace ...`
 * 3. Model Checking: `npx quint run --invariant ValidImpliesTrustedRoot specs/pki_path_validation.qnt`
 *    Checks safety properties via random simulation.
 * 4. Formal Verification: `npx quint verify --temporal EventuallyTerminates specs/pki_path_validation.qnt`
 *    Requires Java/Apalache. Verifies liveness properties for ALL paths.
 */
module pki_path_validation {
  // Types
  type Certificate = {
    id: int,
    subject: str,
    issuer: str,
    public_key_id: int,
    /**
     * Basic Constraints: represents whether the certificate is a CA.
     * - is_ca: true  => Intermediate/Root; authorized to sign other certificates.
     * - is_ca: false => Leaf/End-Entity; identifies a server but forbidden from signing.
     * This prevents 'Leaf-as-CA' attacks where a site cert tries to issue new certs.
     */
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
  // Monitor variable to track liveness (termination)
  var timeout_steps: int

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

  // 3. Step counter safety: prevents out-of-bounds access to the chain
  val StepWithinBounds = current_step <= current_chain.length()

  // 4. Liveness monitor: Validation must terminate within a bounded number of steps
  // We expect termination in at most MAX_CHAIN_LEN + 1 steps.
  val MustTerminateInvariant = (validation_status == Pending) implies (timeout_steps <= MAX_CHAIN_LEN)

  // --- Temporal Properties (Liveness) ---

  // 1. Eventually, the validation process must reach a terminal state (not Pending)
  // This ensures the algorithm doesn't get stuck in an infinite loop.
  temporal EventuallyTerminates = eventually(validation_status != Pending)

  // Standard transition action for the simulator
  action step = validate_step

  // Actions
  action init: bool = all {
    nondet scenario = Set("valid", "untrusted", "mismatch").oneOf()
    all {
      if (scenario == "valid") {
        all {
          trust_store' = Set(example_root),
          current_chain' = [example_leaf, example_inter],
        }
      } else if (scenario == "untrusted") {
        all {
          trust_store' = Set(),
          current_chain' = [example_leaf, example_inter],
        }
      } else {
        all {
          trust_store' = Set(example_root),
          current_chain' = [example_leaf, { id: 1, subject: "WrongSubject", issuer: "Root", public_key_id: 101, is_ca: true, not_before: 0, not_after: 1000 }],
        }
      },
      validation_status' = Pending,
      current_step' = 0,
      current_time' = 500,
      timeout_steps' = 0,
    }
  }

  action setup(trusted_roots: Set[Certificate], chain: List[Certificate], time: int): bool = all {
    trust_store' = trusted_roots,
    current_chain' = chain,
    current_time' = time,
    validation_status' = Pending,
    current_step' = 0,
    timeout_steps' = 0,
  }

  // --- Transition Logic ---

  // Helper to maintain state for variables that don't change in a step
  action keep_state: bool = all {
    current_chain' = current_chain,
    trust_store' = trust_store,
    current_time' = current_time,
  }

  // TERMINAL: Process already finished or chain exhausted
  action handle_already_finished: bool = all {
    or {
      validation_status != Pending,
      current_step >= current_chain.length(),
    },
    validation_status' = validation_status,
    current_step' = current_step,
    timeout_steps' = timeout_steps,
    keep_state,
  }

  // SUCCESS: Found a trusted root with matching signature
  action handle_root_success: bool = {
    val cert = current_chain[current_step]
    val matching_roots = trust_store.filter(r => r.subject == cert.issuer)
    all {
      validation_status == Pending,
      current_step < current_chain.length(),
      matching_roots.size() > 0,
      cert.public_key_id == matching_roots.chooseSome().public_key_id,
      validation_status' = Valid,
      current_step' = current_step + 1,
      timeout_steps' = timeout_steps + 1,
      keep_state,
    }
  }

  // FAILURE: Found matching root but signature (public key) fails
  action handle_root_signature_failure: bool = {
    val cert = current_chain[current_step]
    val matching_roots = trust_store.filter(r => r.subject == cert.issuer)
    all {
      validation_status == Pending,
      current_step < current_chain.length(),
      matching_roots.size() > 0,
      cert.public_key_id != matching_roots.chooseSome().public_key_id,
      validation_status' = Signature_Failure,
      current_step' = current_step + 1,
      timeout_steps' = timeout_steps + 1,
      keep_state,
    }
  }

  // PROGRESS: Successfully validated link to next intermediate
  action handle_intermediate_success: bool = {
    val cert = current_chain[current_step]
    all {
      validation_status == Pending,
      current_step < current_chain.length(),
      trust_store.filter(r => r.subject == cert.issuer).size() == 0,
      current_step + 1 < current_chain.length(),
      val next_cert = current_chain[current_step + 1]
      all {
        cert.issuer == next_cert.subject,
        cert.public_key_id == next_cert.public_key_id,
        next_cert.is_ca,
        validation_status' = Pending,
        current_step' = current_step + 1,
        timeout_steps' = timeout_steps + 1,
        keep_state,
      }
    }
  }

  // FAILURE: Current cert's issuer does not match next cert's subject
  action handle_subject_issuer_mismatch: bool = {
    val cert = current_chain[current_step]
    all {
      validation_status == Pending,
      current_step < current_chain.length(),
      trust_store.filter(r => r.subject == cert.issuer).size() == 0,
      current_step + 1 < current_chain.length(),
      cert.issuer != current_chain[current_step + 1].subject,
      validation_status' = Subject_Issuer_Mismatch,
      current_step' = current_step + 1,
      timeout_steps' = timeout_steps + 1,
      keep_state,
    }
  }

  // FAILURE: Intermediate signature check fails
  action handle_intermediate_signature_failure: bool = {
    val cert = current_chain[current_step]
    all {
      validation_status == Pending,
      current_step < current_chain.length(),
      trust_store.filter(r => r.subject == cert.issuer).size() == 0,
      current_step + 1 < current_chain.length(),
      val next_cert = current_chain[current_step + 1]
      all {
        cert.issuer == next_cert.subject,
        cert.public_key_id != next_cert.public_key_id,
        validation_status' = Signature_Failure,
        current_step' = current_step + 1,
        timeout_steps' = timeout_steps + 1,
        keep_state,
      }
    }
  }

  // FAILURE: Next certificate in chain is not a CA
  action handle_not_a_ca_failure: bool = {
    val cert = current_chain[current_step]
    all {
      validation_status == Pending,
      current_step < current_chain.length(),
      trust_store.filter(r => r.subject == cert.issuer).size() == 0,
      current_step + 1 < current_chain.length(),
      val next_cert = current_chain[current_step + 1]
      all {
        cert.issuer == next_cert.subject,
        cert.public_key_id == next_cert.public_key_id,
        not(next_cert.is_ca),
        validation_status' = Not_A_CA,
        current_step' = current_step + 1,
        timeout_steps' = timeout_steps + 1,
        keep_state,
      }
    }
  }

  // FAILURE: Reached end of chain without finding a trusted root
  action handle_untrusted_root: bool = {
    val cert = current_chain[current_step]
    all {
      validation_status == Pending,
      current_step < current_chain.length(),
      trust_store.filter(r => r.subject == cert.issuer).size() == 0,
      current_step + 1 >= current_chain.length(),
      validation_status' = Untrusted_Root,
      current_step' = current_step + 1,
      timeout_steps' = timeout_steps + 1,
      keep_state,
    }
  }

  action validate_step: bool = any {
    handle_root_success,
    handle_root_signature_failure,
    handle_intermediate_success,
    handle_subject_issuer_mismatch,
    handle_intermediate_signature_failure,
    handle_not_a_ca_failure,
    handle_untrusted_root,
    handle_already_finished,
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