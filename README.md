# COE 576 Problem 11 - Terrapin replication
My name is  Safianu Umar.I am give Assign an assigned a paper by the the authors: Fabian Bäumer, Marcus Brinkmann and Jörg Schwenk, *Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation*, USENIX Security 2024, pp. 7463-7480. to read, understand, and replicate the results in the paper.

## What this repository demonstrates

I independently replicate the , ** offline implementation** of the central prefix-truncation claim in sections 4.2 and 4.4.2. The harness builds SSH ChaCha20-Poly1305 encrypted packets, injects optional-message events into a modeled handshake, removes ciphertext packets, then verifies and decrypts the surviving packets. It also models removal of the initial EXT_INFO (§5.2). It does not copy or execute the authors' exploit implementation.

This is a packet/state simulation with real ChaCha20 and Poly1305 operations, **not a full SSH implementation or a live OpenSSH replication**. It opens no sockets. Primitive algorithms are supplied by `cryptography`; packet assembly, sequence-state handling, experiments and plots are in this repository. No production secrets are used.

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

The sensitivity sweep covers injected and deleted counts 0 through 8. Every diagonal cell accepts 100/100; every off-diagonal cell accepts 0/100. The (0,0) cell is a clean baseline. This is the **additional visualization beyond the paper's original figures**. Acceptance with more than one dropped packet does not imply that SSH user authentication could complete.

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


## Interpretation and limits

Let s be the first encrypted sender number, i the injected count, and d the dropped prefix length. The receiver expects s+i while the first retained ciphertext was authenticated under s+d. For the tested bounds, alignment occurs when i=d. The code does **not** return success by comparing i with d; it verifies actual tags, parses packets, decrypts, and compares plaintext payloads.

Assumptions: both peers already share valid key material; the common pre-NEWKEYS count represents an authenticated legitimate handshake; an on-path attacker can identify exact packet boundaries; the modeled strict safeguards are already bilaterally negotiated. The random generator is deterministic for repeatability, not suitable for production keys. Each session uses a new test key; the test harness does not implement rekeying or sequence-number rollover policy.

Omissions: TCP parsing and length inference, Diffie-Hellman and signatures, algorithm/strict-KEX negotiation, full application state, live endpoint interoperability, CBC/CTR/GCM experiments, AsyncSSH-specific exploits, and internet prevalence scans. No confidence interval is claimed for internet attack probability. The repeated trials are a correctness check across varied test inputs under fixed assumptions.

