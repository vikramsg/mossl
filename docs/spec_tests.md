# Spec-Based Testing Architecture

This document describes how we bridge Quint formal specifications with Mojo implementations using Trace-Based Testing (TBT).

## Overview

The goal is to ensure that the Mojo implementation behaves exactly as the Quint model dictates by using the model as a "Golden Test Vector" generator.

## Components

1.  **Formal Specification (`.qnt`)**: 
    A stateful model of the component (e.g., TLS Record Layer). It defines states (variables) and transitions (actions).

2.  **ITF Trace Generation**:
    We use the Quint CLI to generate traces in the **Interchange Trace Format (ITF)**. An ITF trace is a JSON file representing a sequence of states.
    ```bash
    quint run --out-itf trace.json --max-steps 10 specs/component.qnt
    ```

3.  **Mojo Trace Driver**:
    A Mojo test that:
    - Loads the ITF JSON using `emberjson`.
    - Iterates through each state in the `states` array.
    - For each state, it extracts the variables (e.g., `sequence_number`).
    - Compares the expected state from the trace with the actual state of the Mojo implementation.
    - Executes the action described in the transition to reach the next state.

## Workflow

1.  **Model**: Define logic in Quint.
2.  **Simulate**: Generate a `trace.json` representing a valid execution path.
3.  **Verify**: The Mojo test reads `trace.json`, injects inputs into the Mojo code, and asserts the outputs/state match the JSON.

## Target Component: TLS Record Layer
We will start by testing the sequence number progression and nonce derivation in the `RecordSealer`.
