# COE576 Problem 11 — Terrapin Replication

My name is Safianu Umar. For COE576 Problem 11, I was assigned the paper *Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation* by Fabian Bäumer, Marcus Brinkmann and Jörg Schwenk (USENIX Security 2024, pp. 7463–7480). This repository presents my work to understand the paper and independently reproduce selected results using an offline implementation.

## Overview

SSH stands for **Secure Shell**, a protocol used for secure remote access and file transfer. Terrapin is a prefix-truncation attack: in vulnerable SSH configurations, an active on-path attacker can manipulate packet counters during the handshake and then remove initial encrypted packets without causing the remaining packets to fail authentication.
This project has two complementary components:

| Component | Purpose | How to run |
| --- | --- | --- |
| Python reproduction | Run controlled experiments, save results and generate figures. | `python run_experiments.py` |
| Browser demonstration | Explain the handshake, packet counters, attack and safeguards interactively. | Open `Terrapin_demonstration/Terrapin_Demonstrator.html` in a browser. |

**Scope:** this is an offline packet/state model with real cryptographic operations. The harness builds SSH ChaCha20-Poly1305 encrypted packets. It is not a full SSH implementation or a live OpenSSH replication. Neither component connects to an SSH server or uses production secrets.

## What the Python reproduction demonstrates

The reproduction investigates the sequence-manipulation and prefix-truncation mechanism discussed in Sections 4.2 and 4.4.2 of the paper. It also models deletion of the initial `SSH_MSG_EXT_INFO` packet, as discussed in Section 5.2.

Each trial:

1. Creates fresh shared test key material and initial packet counters.
2. Models the injection of optional `SSH_MSG_IGNORE` messages during the handshake.
3. Processes the transition represented by `SSH_MSG_NEWKEYS`.
4. Constructs 12 encrypted packets using the SSH ChaCha20–Poly1305 packet construction: `EXT_INFO`, `SERVICE_ACCEPT` and ten filler packets.
5. Removes the selected number of initial encrypted packets.
6. Verifies authentication tags, decrypts retained packets, checks packet framing and compares the recovered payloads with the expected suffix.

The filler packets represent later traffic; they are encrypted and authenticated like the other test packets. They allow the experiment to check whether subsequent messages remain intact after a deletion.

The `cryptography` library supplies the cryptographic primitives. Packet assembly, sequence-state handling, experiment logic and plotting are implemented in this repository. The reproduction does not copy or execute the authors' exploit implementation.




## Setup (Ubuntu / Python 3.12 recommended)

Run these commands in the directory containing this README:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python run_experiments.py
```

If Ubuntu reports that venv/ensurepip is missing, install your distribution's `python3-venv` package and retry. Python 3.12 was used in the recorded run. Network access is needed only to install dependencies; the experiment itself runs offline. It has no Tkinter or GUI dependency. Figures are saved to disk; there is no `plt.show()` requirement.

Optional explicit reproduction parameters:

```bash
python run_experiments.py --seed 57611 --trials 1000 --grid-trials 100
```

Changing these parameters regenerates the CSVs and plots; 

## Recorded results

The preparation-environment run completed 17,100 sessions: nine cases with 1,000 trials each, plus 81 grid cells with 100 trials each. Each session contains 12 encrypted packets. All eight unit tests passed.

| Case | Remaining stream accepted | Undetected prefix removed |
|---|---:|---:|
| Clean legacy | 1000/1000 | 0/1000 |
| Drop only | 0/1000 | 0/1000 |
| Inject only | 0/1000 | 0/1000 |
| Matched truncation | 1000/1000 | 1000/1000 |
| Reset only | 0/1000 | 0/1000 |
| Reject optional only | 0/1000 | 0/1000 |
| Strict KEX model | 0/1000 | 0/1000 |
| Tampered ciphertext | 0/1000 | 0/1000 |
| Clean strict KEX | 1000/1000 | 0/1000 |

For matched single-packet truncation, EXT_INFO is absent and all 11 remaining payloads are intact in every trial. This demonstrates packet loss, not the actual behavior of a live client's keystroke protection.

### Sensitivity analysis

The sensitivity sweep varies both the injected count and the deleted count from 0 through 8:

- All nine diagonal cells, where the counts match, accepted **100/100** trials.
- All 72 off-diagonal cells accepted **0/100** trials.
- The `(0,0)` cell is the clean baseline, with no injection or deletion.

This sweep provides an additional visualization of the alignment mechanism beyond the paper's original figures. Acceptance after deleting multiple packets does not imply that a real SSH login would complete.

## Interactive Terrapin demonstration

The browser demonstration makes the same packet-level mechanism visible during a presentation. It includes a step-by-step handshake, client and server counters, attack controls, authentication-tag inspection and an injection/deletion grid.

### Open the demonstration

After downloading or cloning the repository, open [Terrapin_Demonstrator.html](Terrapin_demonstration/Terrapin_Demonstrator.html) in Firefox, Chrome or Edge.

On Ubuntu, run this command from the repository root:

```bash
xdg-open Terrapin_demonstration/Terrapin_Demonstrator.html
```

Alternatively, locate the HTML file in your file manager and choose **Open With → Web Browser**. Opening it in VS Code shows its source code. The GitHub file view also shows the source; download the file or repository and open it locally to run the demonstration.

**No Python environment, local server or internet connection is required to use the standalone HTML file.**

### What the demonstration shows

- **Handshake walkthrough:** step forward or backward, play the exchange automatically, or jump to the outcome.
- **Packet counters:** follow the client's and server's `Snd` and `Rcv` values. These represent the next packet numbers after each event. For server-to-client traffic, compare server `Snd` with client `Rcv`.
- **Attack controls:** vary the injected `IGNORE` count and deleted encrypted-prefix length from 0 to 8.
- **Control scenarios:** compare clean traffic, unmatched manipulation, matched truncation, safeguards and ciphertext tampering.
- **Real packet checks:** inspect computed and received authentication tags; acceptance is not hard-coded from counter equality.
- **Count grid:** explore all 81 injection/deletion combinations.
- **JSON export:** save a configured trial's settings, trace, packet evidence and outcome.

### Relationship to the recorded experiments

The demonstration supplements the Python results. Its browser engine performs actual ChaCha20 and Poly1305 operations, tag verification, decryption, framing checks and expected-payload comparison on the modeled protected packets.

| Property | Python reproduction | Browser demonstration |
| --- | --- | --- |
| Primary purpose | Record repeatable experimental evidence. | Explain the mechanism interactively. |
| Trials per control | 1,000 in the recorded run | One per comparison run |
| Trials per grid cell | 100 in the recorded run | One per grid run |
| Outputs | CSV records, metadata and Matplotlib figures | Interactive displays and JSON trial export |

The browser uses a different deterministic teaching random generator from Python. The same seed therefore does not produce identical packet bytes across the two implementations. The browser engine was checked against Python's cryptographic library using 36 fixed-input packet cases; its validation record is in `Terrapin_demonstration/VALIDATION.txt`.

The displayed handshake and reverse-direction request are schematic. The demonstration does not perform a full key exchange, authenticate a real host or measure a live feature downgrade.


## Files and evidence

- `src/terrapin.py`: packet construction, authenticated decryption, receiver state, scenario.
- `run_experiments.py`: experiment runner and original Matplotlib charts.
- `tests/test_terrapin.py`: primitive known vectors, framing, state, attack and defense controls.
- `requirements.txt`: pinned experiment dependencies.
- `results/trials.csv`: per-trial records for all nine cases.
- `results/summary.csv`
- `results/grid_trials.csv`, `results/grid.csv`: raw sensitivity trials and aggregates.
- `results/metadata.json`: seed, versions and configuration.
- `results/validation.txt`: captured test output.
- `figures/control_results.png`, `figures/count_sensitivity.png`: original, code-generated figures.

- `Terrapin_demonstration/Terrapin_Demonstrator.html`: Standalone offline browser demonstration. 
- `Terrapin_demonstration/source/engine.js`: Browser packet cryptography and scenario model. 
- `Terrapin_demonstration/source/interface.js`: Interactive controls and displays. 
- `Terrapin_demonstration/source/template.html`: Page structure and styling. 
- `Terrapin_demonstration/source/build.py`: Standalone HTML build script. 
- `Terrapin_demonstration/source/verify.py`: Independent Python/JavaScript packet checks. 
- `Terrapin_demonstration/VALIDATION.txt`: Browser demonstration validation record. 


## Interpretation and limits

Let s be the first encrypted sender number, i the injected count, and d the dropped prefix length. The receiver expects s+i while the first retained ciphertext was authenticated under s+d. For the tested bounds, alignment occurs when i=d. The code does **not** return success by comparing i with d; it verifies actual tags, parses packets, decrypts, and compares plaintext payloads.

### Assumptions

- Both peers already share valid test key material; the legitimate key exchange and server authentication are assumed rather than implemented.
- The attacker can identify exact packet boundaries and remove the intended encrypted prefix.
- The modeled strict-KEX safeguards are assumed to have been negotiated by both endpoints.
- Deterministic randomness supports repeatability and is not suitable for production secrets.
- Each Python trial uses a fresh test key. The harness does not implement rekeying or a sequence-number rollover policy.


### What is outside this reproduction

- TCP parsing and encrypted-packet length inference.
- Diffie–Hellman exchange, signatures and host authentication.
- Algorithm negotiation and strict-KEX negotiation.
- Full SSH application state and live endpoint interoperability.
- CBC, CTR and GCM experiments.
- AsyncSSH-specific exploits and internet prevalence scans.
- Measurement of actual security-feature downgrades following `EXT_INFO` removal.


The repeated trials check correctness across varied test inputs under fixed assumptions. They do not estimate the probability of a successful attack against internet hosts. The modeled safeguards show how this attack route can be blocked; they do not establish that every real implementation enforces the safeguards correctly.