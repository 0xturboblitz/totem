import { groth16 } from 'snarkjs'
import fs from 'fs';
import path from 'path';
import { Uint8ArrayToCharArray, bytesToBigInt, fromHex } from "@zk-email/helpers/dist/binaryFormat";
import { generateCircuitInputs } from "@zk-email/helpers/dist/input-helpers";
import { verifyDKIMSignature, DKIMVerificationResult } from "@zk-email/helpers/dist/dkim";

export const STRING_PRESELECTOR = "Bonjour ";
export const MAX_HEADER_PADDED_BYTES = 1024; // NOTE: this must be the same as the first arg in the email in main args circom
export const MAX_BODY_PADDED_BYTES = 1536; // NOTE: this must be the same as the arg to sha the remainder number of bytes in the email in main args circom

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

  const bodyRemaining = emailVerifierInputs.in_body_padded.map(c => Number(c)); // Char array to Uint8Array
  const selectorBuffer = Buffer.from(STRING_PRESELECTOR);
  const nameIndex = Buffer.from(bodyRemaining).indexOf(selectorBuffer) + selectorBuffer.length;
  console.log('nameIndex', nameIndex)
  const address = bytesToBigInt(fromHex(ethereumAddress)).toString();

  return {
    ...emailVerifierInputs,
    name_idx: nameIndex.toString(),
    address,
  };
}

async function main() {
  const rawEmail = fs.readFileSync(
    path.join(__dirname, "../inputs/short_signed_email.eml"),
    "utf8"
  );

  const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));
  
  console.log('dkimResult.body', dkimResult.body)
  const body = Array.from(dkimResult.body).map((x) => x.toString());
  console.log('body.length', body.length)
  const inputs = {
    msg: body
  }
  console.log('Regex circuit inputs: ', inputs)
  console.log('inputs.msg.length', inputs.msg.length)

  const { proof, publicSignals } = await groth16.fullProve(
    inputs,
    "build/email_regex_only_js/email_regex_only.wasm",
    "build/email_regex_only_final.zkey"
  )

  console.log('proof generated');
  console.log('proof:', proof);
  console.log('public signals:', publicSignals);

  const revealChars = publicSignals.map((byte: string) => String.fromCharCode(parseInt(byte, 10))).join('');
  console.log('reveal chars', revealChars);

  const vKey = JSON.parse(fs.readFileSync("build/email_regex_only_vk.json").toString());
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