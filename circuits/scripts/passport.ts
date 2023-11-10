import { hash, toUnsignedByte } from '../utils/computeEContent'
import { DataHash, PassportData } from '../utils/types'
import { genSampleData } from '../utils/sampleData'
import { arraysAreEqual, bytesToBigDecimal, formatAndConcatenateDataHashes, formatMrz, splitToWords } from '../utils/utils'
import { groth16 } from 'snarkjs'
import fs from 'fs';
// import passportData from '../inputs/passportData.json'

async function main() {
  let passportData;

  if (fs.existsSync('inputs/passportData.json')) {
    passportData = require('../inputs/passportData.json');
  } else {
    passportData = (await genSampleData()) as PassportData;
    if (!fs.existsSync("inputs/")) {
      fs.mkdirSync("inputs/");
    }
    fs.writeFileSync('inputs/passportData.json', JSON.stringify(passportData));
  }

  const formattedMrz = formatMrz(passportData.mrz);
  const concatenatedDataHashes = formatAndConcatenateDataHashes(
    hash(formattedMrz),
    passportData.dataGroupHashes as DataHash[],
  );

  const inputs = {
    mrz: formattedMrz.map(byte => String(byte)),
    dataHashes: concatenatedDataHashes.map(toUnsignedByte).map(byte => String(byte)),
    eContentBytes: passportData.eContent.map(toUnsignedByte).map(byte => String(byte)),
    pubkey: splitToWords(
      BigInt(passportData.modulus),
      BigInt(64),
      BigInt(32)
    ),
    signature: splitToWords(
      BigInt(bytesToBigDecimal(passportData.encryptedDigest)),
      BigInt(64),
      BigInt(32)
    ),
    address: "0x9D392187c08fc28A86e1354aD63C70897165b982",
    salt: "0x13bb9dbfe6f8a52eb0850e3ccbaba7281b463db1a7583676a6e8247d8ab3a47c"
  }

  console.log('Passport circuit inputs: ', inputs)

  const { proof, publicSignals } = await groth16.fullProve(
    inputs,
    "build/passportTotem_js/passportTotem.wasm",
    "build/passportTotem_final.zkey"
  )

  console.log('proof generated');
  console.log('proof:', proof);
  console.log('public signals:', publicSignals);
  console.log('commitment', publicSignals[0]);

  const vKey = JSON.parse(fs.readFileSync("build/passportTotem_vk.json").toString());
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