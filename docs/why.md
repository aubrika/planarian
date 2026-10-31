# Why Planarian

Imagine a computer that knows what it’s supposed to be. It notices when something breaks and puts itself back together, the way a body can heal a cut. Anyone can use it safely, even an AI agent, because whatever they do is checked and undone if it breaks something.

That’s the idea behind Planarian: a living, self-repairing layer woven into the operating system, and a single trustworthy gatekeeper for every change made to the machine, whether made by a human or an agent. It starts on NixOS, and the goal is an operating system that is itself a harness for agents working inside it.

## Computers that look after themselves

This dream is older than AI agents. In 2001 IBM launched **autonomic computing**, named after the autonomic nervous system, the part of you that keeps your heart beating without conscious effort. The goal was machines that configure, heal, optimize and protect themselves.

The [classic picture](https://doi.org/10.1109/MC.2003.1160055) (Kephart and Chess, 2003) is a loop called **MAPE-K**:

- **Monitor** what’s happening.
- **Analyze** whether it’s what should be happening.
- **Plan** a fix.
- **Execute** it.
- All four steps share **Knowledge** of what the system is supposed to be.

This idea lived on mostly in data centers. Cloud tools like Kubernetes run loops like this all day. Your laptop doesn’t. A NixOS update activates cleanly and Wi-Fi stops working, and the system calls that a success. A service dies at 3 a.m. and stays dead until someone notices. A machine you set up for a relative breaks, and the fix starts with a phone call from grandma.

## Why now: agents

AI agents now commonly get real access to real machines. Ask a coding agent to fix a failing build, and it may decide the fix is a system package, a service setting, or a firewall rule, and just make the change. As with a human operator, it may or may not be the right call.

Today, the only things standing between an agent and your machine often live inside the agent’s own wrapper: permission prompts, instructions, and the model’s judgment. A capable or prompt-injected agent can talk its way past all three. The operating system won’t stop it. Linux lets any process with enough permission do anything, and nothing records who changed what, checks whether it worked, or undoes it if it didn’t.

A computer that can heal itself and a computer that’s safe to hand to an agent turn out to need the same thing: a system that knows what it’s supposed to be, checks every change against that, and puts itself back when something goes wrong.

## How Planarian does it

Planarian runs that loop on your own machine, with three additions.

**The target is written down.** NixOS already describes the whole machine in one configuration, so Planarian’s “Knowledge” isn’t a guess. It checks the machine against the configuration, notices when the two drift apart (a crashed service, a lost driver), and repairs in a fixed order: restart, rebind, re-apply, roll back. It’s honest about uncertainty: when it can’t tell what’s happening, it says “unknown” instead of guessing.

**Every change goes through one checker, including Planarian’s own.** The loop’s “Execute” step is a **reference monitor**, a security idea from 1972: a single gate that every change must pass, that nothing can tamper with, and that’s small enough to prove correct. Planarian’s core decisions carry mathematical proofs, written in Rust and checked with the Verus verifier. Every change, whether it comes from you, an app, an AI agent, or Planarian’s own repair loop, is checked, recorded with who asked for it, tried, tested, and undone automatically if it breaks something.

**Agents are just another kind of user.** An agent can do only what the person who started it could do. Anything risky waits for a person with the authority to say yes, and everything an agent does is recorded under its name. That’s what “the operating system as the agent harness” means: the limits live in the system, which knows who’s really asking, instead of in a prompt that a clever agent can argue with.

The system also doesn’t fight you. Stop a service on purpose and it stays stopped: Planarian only needs the choice to have your name on it, so it can tell a decision from a crash. Its own overhead is measured at every milestone and isn’t allowed to grow.

## Where the name comes from

Planarians are flatworms that can regrow a whole body from a small piece. Somehow every fragment knows the shape it belongs to. Michael Levin studies how they do it, and in [Growing Neural Cellular Automata](https://distill.pub/2020/growing-ca/) (2020) he and his colleagues built a small model of the same trick: a grid of cells, each following one simple rule, that regrows its shape when you cut part of it away. Planarian borrows that idea of a shape the whole system keeps returning to, with one difference: its shape is written down, so it never has to guess.

Mark Burgess made the case for [“Computer Immunology”](https://www.usenix.org/legacy/publications/library/proceedings/lisa98/full_papers/burgess/burgess_html/burgess.html) back in 1998. What Planarian adds is undoing changes that made things worse, an honest “unknown,” and a formally verified core.

## What it doesn’t promise (yet)

- Until Phase E, root can go around it. Planarian can detect and repair that, but it can’t prevent it.
- If you start an AI agent yourself, instead of through Planarian's launcher, the system can't tell it apart from you: everything it does is recorded as yours, and it can do anything you can.
- It doesn’t catch malicious software that works perfectly, and it doesn’t protect your files, only the system.
- It doesn’t make agents smarter or more honest. It limits what they can do and records what they did.

Every known way around a guarantee is listed in [bypasses.md](./bypasses.md), and everything the proofs take on trust is listed in [assumptions.md](./assumptions.md).

## Where it’s going

- **Phase A, now:** the verified core, self-repair, automatic undo, and an agent launcher, as a NixOS module.
- **Phase B:** a small local model for the problems plain rules can’t solve, plus disposable test machines that try each change before it reaches the real one.
- **Phase C:** PlanarianOS, a distribution Planarian governs from the first boot, with profiles for agent hosts, servers and personal computers.
- **Phase D:** Rust replacements for the machinery underneath.
- **Phase E:** the [Asterinas](https://github.com/asterinas/asterinas) kernel, written in memory-safe Rust.

The long-term picture: **Asterinas makes the bottom of the stack trustworthy; Planarian makes the top of it safe to hand to an agent.**

## Follow along

Phase A is nearing completion. The code and the full spec are in this repository. Open an issue, or find me on Bluesky at [@aub.bsky.social](https://bsky.app/profile/aub.bsky.social). Whether you run NixOS, build agents, or just want a computer that looks after itself, I’d like to hear from you.
