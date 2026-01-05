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

We prompt agents in English. We write requirements documents in English.
- "The user is authenticated after a successful handshake."
- "The program is crashing. Fix it."

But English is inherently ambiguous. What "program"? What exactly constitutes a "successful handshake"? Are we talking about a human handshake? 

When we jump straight to code based on English prompts, the *implementation* becomes the specification. 
If the Agent guesses wrong, that guess becomes the hard-coded behavior of the system. 
And cue the inevitable conversation, 

```json
{
  "user": "This isn't what I meant",
  "agent": "You are absoloutely right. You are God. I will fix it....."
  ... 
  ...
  "agent": "Here's the updated code."
  "user": "That's still wrong".
}
```
Right now, the only mechanisms I use are code review and unit tests.
But I keep feeling that relying on these mechanisms inevitably makes me the bottleneck to more output.
We need a way to describe *intent* that is as rigorous as code, but abstract enough to be a specification.

## The Scary Part: TLA+

This isn't a new problem. Decades ago, Leslie Lamport (the creator of LaTeX and distributed systems legend) gave us **TLA+** (Temporal Logic of Actions).
It is the gold standard for formal verification. It is used by AWS to design DynamoDB and S3. It is used by Azure. It works.

But have you ever looked at TLA+?

```tla
Total ==
  LET S == { r[type] : r \in Records }
  IN  Cardinality(S)

Inv == \A r \in Records : r.amount >= 0
```

It is grounded in set theory and temporal logic. It uses symbols like `/\`, `\/`, `[]`, and `<>`.
For a software engineer, this is a friction point.
If I have to learn a completely new paradigm that looks like advanced calculus just to write a spec, I'm probably not going to do it. And more importantly, I'm not going to maintain it.
If the spec is harder to read than the code, the spec dies.

## Enter Quint

This is where [Quint](https://github.com/informalsystems/quint) comes in.
Quint is a modern specification language developed by Informal Systems.
It is based on the same rigorous semantics as TLA+, but with a syntax designed for software engineers.

It looks like TypeScript or Python.
If you can read code, you can read Quint.
This is crucial. I need to be able to look at the spec and immediately understand the logic without mentally translating mathematical symbols.

### A Concrete Example: The TCP Handshake

To understand what we can do with this, let's look at something we all know: the TCP 3-way handshake.
We want to verify that a client and server can establish a connection correctly.

In code, we'd worry about packets, sequence numbers, buffers, and timeouts.
In a spec, we worry about **State** and **Transitions**.

#### 1. Modeling State

We define the universe of our protocol.

```quint
module tcp_simple {
  // Types
  type State = INIT | SYN_SENT | SYN_RCVD | ESTABLISHED

  // State Variables
  var client_state: State
  var server_state: State

  // Initial State
  action Init = all {
    client_state' = INIT,
    server_state' = INIT,
  }
}
```

#### 2. Defining Actions (Transitions)

Next, we define what *can* happen. These are the rules of the road.

```quint
  // Client sends SYN
  action SendSyn = all {
    client_state == INIT,        // Precondition: Client must be INIT
    client_state' = SYN_SENT,    // Transition: Client moves to SYN_SENT
    server_state' = server_state // Server state doesn't change yet
  }

  // Server receives SYN, sends SYN-ACK
  action ReceiveSyn = all {
    server_state == INIT,
    // In a real spec, we'd check if a SYN message is in the network
    server_state' = SYN_RCVD,
    client_state' = client_state
  }

  // Client receives SYN-ACK, sends ACK
  action ReceiveSynAck = all {
    client_state == SYN_SENT,
    client_state' = ESTABLISHED,
    server_state' = server_state
  }
  
  // ... and so on
```

This is readable. It describes the logical flow.

#### 3. Simulation

Unlike a static diagram, we can **run** this.
Quint has a built-in simulator. We can ask it: "Run this logic for 10 steps and see what happens."

```bash
quint run --max-steps=10 tcp_simple.qnt
```

It will execute the actions randomly, effectively "fuzzing" our design logic. It produces a trace:
`Init -> SendSyn -> ReceiveSyn -> ReceiveSynAck ...`

#### 4. Invariants (The Guardrails)

This is the superpower. We can define properties that must **always** be true.

For example, we might want to assert that the Server never thinks the connection is established before the Client has at least initiated it.

```quint
val Safety = not (server_state == ESTABLISHED and client_state == INIT)
```

If we run the simulator (or the model checker), and it finds a sequence of events that leads to this invalid state, it reports a **Violation**.
It gives us the exact trace of steps that caused the bug.
We fix the logic in the spec, long before we've written a single line of C or Rust or Mojo.

## What's Next?

So we have a verified spec. We know our logic is sound. We know that our state machine doesn't deadlock and respects our safety properties.

But a spec in a file is just a piece of paper (or digital text). How do we ensure our *actual* code implements this logic correctly?

In **Part 2**, we will explore **Model-Based Testing**. We will look at:
1.  Generating execution traces from the Quint spec.
2.  Parsing those traces.
3.  Feeding them into our unit tests to ensure our implementation behaves exactly as the spec dictates.

Stay tuned.
