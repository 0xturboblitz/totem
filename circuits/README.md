# Totem

Totem circuits check invariants across multiple identity sources.

#### Requirements

Install `circom` and `nodejs v18`

#### Installation

```bash
yarn
```

#### Build circuits (dev only, not secure)

```bash
./scripts/build_circuit.sh
```

#### Run tests

```bash
yarn test
```

To run with your own passport data, extract your `passportData.json` using the proof of passport app (available soon) and place it in `inputs/`