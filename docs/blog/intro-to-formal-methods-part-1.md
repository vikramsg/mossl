# Introduction to Formal Methods (Part 1): Why Spec First?

Formal methods, sounds very... formal!
But I have been trying to dive a bit into what they are and so I decided to write down my learnings.
Hopefully this proves a good starting point for someone else who was curious about the idea but didn't have a good starting point.
This is going to be part 1 of 2. 
In part 1, I will try to give a more conceptual understanding, while also introducing tooling using `Quint`.
In part 2, I will try to show how it can be wired up so that we make sure software implementations actually benefit from formal methods.

## The Problem with English (and AI)

First a warning, and then if you stick around, we can get into it.
My dive into formal methods was motivated by posts like [this](https://martin.kleppmann.com/2025/12/08/ai-formal-verification.html).
I have been increasingly using AI/Agents and I believe something is required to make the use of AI more productive. 
And if the word AI is triggering, then this would be a good time to stop reading.
If you are still here, let's talk about AI a little bit, and the programming language for AI - English.

## What are Formal Methods?

Formal methods are mathematically based techniques for the specification, development, and verification of software and hardware systems. Ideally, they allow us to prove that a system behaves exactly as intended.

Historically, formal methods had a reputation for being:
1.  **Hard**: Requiring a PhD in mathematics to understand.
2.  **Slow**: Taking years to write a spec for a small system.
3.  **Disconnected**: The spec sits in a PDF while the code evolves separately.

## Enter Quint

[Quint](https://github.com/informalsystems/quint) is a modern specification language designed to bridge the gap between engineers and formal methods. It is developed by Informal Systems (the folks behind the Cosmos ecosystem).

Quint is special because **it looks like code**. If you can read TypeScript or Python, you can likely read Quint. However, under the hood, it is backed by the rigorous semantics of TLA+ (Temporal Logic of Actions).

### What can we do with Quint?

Unlike a static design document, a Quint spec is **executable**.

#### 1. Modeling State and Transitions

In Quint, we model our system as a state machine. We define **variables** (the state) and **actions** (transitions).

```quint
module circuit_breaker {
  var state: str // "CLOSED", "OPEN", "HALF_OPEN"
  var failures: int

  action Init = all {
    state' = "CLOSED",
    failures' = 0,
  }

  action Fail = all {
    state == "CLOSED",
    failures' = failures + 1,
    if (failures' >= 3) {
      state' = "OPEN"
    } else {
      state' = state
    }
  }
}
```

This looks like code, but it describes *logic*, not implementation details like memory management or network sockets.

#### 2. Simulation

We can run the spec! Quint has a built-in simulator that can explore the state space.

```bash
quint run --max-steps=10 circuit_breaker.qnt
```

This randomly executes actions to generate "traces" (sequences of states). It's like fuzzing your logic before you've written a single line of real code.

#### 3. Invariants (Safety Properties)

This is the superpower of formal methods. We can define properties that must **always** be true, no matter what happens.

```quint
val Safety = not (state == "CLOSED" and failures >= 3)
```

If the simulator (or a model checker) finds a sequence of actions where `failures` is 3 but the state is still `CLOSED`, it will report a violation and show you exactly how it happened. This catches "design bugs"—logical flaws that unit tests often miss.

## Why this matters for `ssl.mojo`

For `ssl.mojo`, we aim to implement TLS 1.3. The protocol is complex, with specific state transitions, key derivations, and security properties.

Instead of guessing, we write a Quint spec for the handshake. We verify that:
1.  Keys are not used before they are established.
2.  The handshake proceeds in the correct order.
3.  Deadlocks don't occur.

Once the spec is verified, it becomes the **Golden Model**.

## What's Next?

Writing a spec is great, but how do we ensure our Mojo code actually matches the Quint spec?

In **Part 2**, we will look at how to wire this up. We will explore:
- Generating execution traces from Quint.
- Converting those traces into test vectors.
- Using those vectors to drive unit tests in Mojo.

Stay tuned!
