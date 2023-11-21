# 🗿Totem🗿

Zero-knowledge identity tools like [zk-email](https://github.com/zkemail/) and [proof of passport](https://github.com/zk-passport/proof-of-passport) allow users to prove aspects of their identity while only selectively disclosing private information.

However, on their own, most of these tools aren't convincing. One can steal someone else's passport or hack their email to impersonate them.

Wouldn't it be cool to combine multiple sources of identity together?

Totem allows users to prove invariants like their name or email address across multiple sources.
For instance, without disclosing my name I can prove that:
- I received an email from the government calling me by my name
- I own a valid passport
- Both attest to the same name

In this proof of concept, we extract data from a French passport and an email from the French Ministry of Public Finances and prove they refer to the same name without disclosing it.

### Architecture

Totem uses [zk-regex](https://github.com/zkemail/zk-regex) to look for substrings in data.
Then, it uses Poseidon to commit to the data, adding a secret salt as a blinding factor.
If the results of the regex searches match, the commitments should match too.

<img width="100%" alt="Diagram" src="https://github.com/0xturboblitz/totem/assets/62038140/1f768d59-42d7-4edc-bafe-2fdadfd00a59">

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
