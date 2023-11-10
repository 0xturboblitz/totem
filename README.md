# 🗿Totem

Zero-knowledge identity tools like [zk-email](https://github.com/zkemail/) and [proof of passport](https://github.com/zk-passport/proof-of-passport) allow users to prove aspects of their identity while only selectively disclosing private information.

However, taken separately, most of them aren't very convincing.

Wouldn't it be cool if we could combine them together ?

Totem allows users to prove invariants like their name or their email address across multiple identity sources.
For instance, without ever disclosing my name publicly I can prove that:
- I received an email from the government calling me by my name
- I own a valid passport
- Both attest to the same name

In this proof of concept, we extract data from a french passport and an email from the french Ministry of Public Finances and prove they refer to the same name without disclosing it.

### Architecture.

Totem uses [zk-regex](https://github.com/zkemail/zk-regex) to look for substrings in data.
Then, it uses Poseidon to commit to the data, adding a salt as a blinding factor.
If the results of the regex searches match, the commitments should match.

<img width="100%" src="https://i.imgur.com/zMxnbSN.png" alt="Diagram">

### Run it

Install packages
```
cd circuits
yarn
```
Build the circuits. This might take a long time.
```
./scripts/build_passport_circuit.sh
./scripts/build_email_circuit.sh
```
Check each circuit flow:
```
ts-node scripts/passport.ts
ts-node scripts/email.ts
```
Check the end-to-end verification flow:
```
ts-node scripts/totem.ts
```

This runs using a true email and a sample passport data file generated on the fly that imitates the true one.

Regex circuits can also be tested individually.
