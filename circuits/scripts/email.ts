import { groth16 } from 'snarkjs'
import fs from 'fs';
import path from 'path';
import { Uint8ArrayToCharArray, bytesToBigInt, fromHex } from "@zk-email/helpers/dist/binaryFormat";
import { generateCircuitInputs } from "@zk-email/helpers/dist/input-helpers";
import { verifyDKIMSignature, DKIMVerificationResult } from "@zk-email/helpers/dist/dkim";
const wasm_tester = require("../node_modules/circom_tester").wasm;

export const STRING_PRESELECTOR = "Bonjour ";
export const MAX_HEADER_PADDED_BYTES = 1024; // NOTE: this must be the same as the first arg in the email in main args circom
export const MAX_BODY_PADDED_BYTES = 2176; // NOTE: this must be the same as the arg to sha the remainder number of bytes in the email in main args circom

export function generateGovEmailVerifierCircuitInputs({
  rsaSignature,
  rsaPublicKey,
  body,
  bodyHash,
  message, // the message that was signed (header + bodyHash)
  ethereumAddress,
}: {
  body: Buffer;
  message: Buffer;
  bodyHash: string;
  rsaSignature: BigInt;
  rsaPublicKey: BigInt;
  ethereumAddress: string;
}) {
  const emailVerifierInputs = generateCircuitInputs({
    rsaSignature,
    rsaPublicKey,
    body,
    bodyHash,
    message,
    shaPrecomputeSelector: STRING_PRESELECTOR,
    maxMessageLength: MAX_HEADER_PADDED_BYTES,
    maxBodyLength: MAX_BODY_PADDED_BYTES,
  });

  // const bodyRemaining = emailVerifierInputs.in_body_padded.map(c => Number(c)); // Char array to Uint8Array
  // const selectorBuffer = Buffer.from(STRING_PRESELECTOR);
  // const nameIndex = Buffer.from(bodyRemaining).indexOf(selectorBuffer) + selectorBuffer.length;
  // console.log('nameIndex', nameIndex)
  const address = bytesToBigInt(fromHex(ethereumAddress)).toString();

  const string = emailVerifierInputs.in_body_padded.map((byte: string) => String.fromCharCode(parseInt(byte, 10))).join('');
  const LAST_NAME_REGEX = "Bonjour [A-Za-z]+ ([A-Za-z]+)+";
  const lastName = new RegExp(LAST_NAME_REGEX).exec(string);
  console.log('lastName', lastName)
  const indexOfNameInString = lastName[0].indexOf(lastName[1]);
  console.log('lastName.index', lastName.index)
  console.log('indexOfNameInString', indexOfNameInString)
  const finalIndex = lastName.index + indexOfNameInString;
  console.log('finalIndex', finalIndex)

  // content=3D'telephone=3Dno'/></head><bod=rny>Bonjour FLORENT TAVERNIER&nbsp;(num=C3=A9ro fiscal : 302*******241),<br/>=rn<p>Pour activer votre nouvel acc=C3=A

  return {
    ...emailVerifierInputs,
    name_idx: finalIndex.toString(),
    address,
  };
}

async function main() {
  const rawEmail = fs.readFileSync(
    path.join(__dirname, "../inputs/short_signed_email.eml"),
    "utf8"
  );

  const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));
  
  const govEmailVerifierInputs = generateGovEmailVerifierCircuitInputs({
    rsaSignature: dkimResult.signature,
    rsaPublicKey: dkimResult.publicKey,
    body: dkimResult.body,
    bodyHash: dkimResult.bodyHash,
    message: dkimResult.message,
    ethereumAddress: "0x00000000000000000000",
  });

  console.log('gov email circuit inputs: ', govEmailVerifierInputs)


  // const circuit = await wasm_tester(path.join(__dirname, "../circuits/email/french_gov_email.circom"), {include: ["node_modules"]});  
  // const w = await circuit.calculateWitness(govEmailVerifierInputs);
  // console.log('witness calculated', w);
  // await circuit.checkConstraints(w);
  // console.log('finished checking constraints');
  // fs.writeFileSync('outputs/govEmailVerifierInputs.json', JSON.stringify(govEmailVerifierInputs));

  const { proof, publicSignals } = await groth16.fullProve(
    govEmailVerifierInputs,
    "build/french_gov_email_js/french_gov_email.wasm",
    "build/french_gov_email_final.zkey"
  )

  console.log('proof generated');
  console.log('proof:', proof);
  console.log('public signals:', publicSignals);

  const revealChars = publicSignals.map((byte: string) => String.fromCharCode(parseInt(byte, 10))).join('');
  console.log('reveal chars', revealChars);

  const vKey = JSON.parse(fs.readFileSync("build/french_gov_email_vk.json").toString());
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