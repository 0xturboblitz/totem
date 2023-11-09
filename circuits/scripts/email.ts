import { hash, toUnsignedByte } from '../utils/computeEContent'
import { DataHash, PassportData } from '../utils/types'
import { genSampleData } from '../utils/sampleData'
import { arraysAreEqual, bytesToBigDecimal, formatAndConcatenateDataHashes, formatMrz, splitToWords } from '../utils/utils'
import { groth16 } from 'snarkjs'
import fs from 'fs';
import path from 'path';


async function main() {
  const rawEmail = fs.readFileSync(
    path.join(__dirname, "../inputs/gov_email.eml"),
    "utf8"
  );

  let dkimResult: import("@zk-email/helpers/src/dkim").DKIMVerificationResult;

  const govEmailVerifierInputs = generateTwitterVerifierCircuitInputs({
    rsaSignature: dkimResult.signature,
    rsaPublicKey: dkimResult.publicKey,
    body: dkimResult.body,
    bodyHash: dkimResult.bodyHash,
    message: dkimResult.message,
    ethereumAddress: "0x00000000000000000000",
  });




  console.log('gov email circuit inputs: ', govEmailVerifierInputs)

  const { proof, publicSignals } = await groth16.fullProve(
    govEmailVerifierInputs,
    "build/regex_js/regex.wasm",
    "build/regex_final.zkey"
  )

  console.log('proof generated');
  console.log('proof:', proof);
  console.log('public signals:', publicSignals);

  const revealChars = publicSignals.map((byte: string) => String.fromCharCode(parseInt(byte, 10))).join('');
  console.log('reveal chars', revealChars);

  const vKey = JSON.parse(fs.readFileSync("build/regex_vk.json").toString());
  const verified = await groth16.verify(
    vKey,
    publicSignals,
    proof
  )

  if (verified) {
    console.log('Proof is verified');
    fs.writeFileSync('outputs/proof.json', JSON.stringify(proof));
    fs.writeFileSync('outputs/publicSignals.json', JSON.stringify(publicSignals));
  } else {
    console.log('Proof is not verified');
  }

  process.exit();
}

main()