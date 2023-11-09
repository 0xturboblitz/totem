import { hash, toUnsignedByte } from '../utils/computeEContent'
import { DataHash, PassportData } from '../utils/types'
import { genSampleData } from '../utils/sampleData'
import { arraysAreEqual, bytesToBigDecimal, formatAndConcatenateDataHashes, formatMrz, splitToWords } from '../utils/utils'
import { groth16 } from 'snarkjs'
import fs from 'fs';

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

  const inputs = {
    msg: formattedMrz.slice(10).map(byte => String(byte)),
  }

  console.log('Regex circuit inputs: ', inputs)
  console.log('Inputs as chars: ', inputs.msg.map((byte: string) => String.fromCharCode(parseInt(byte, 10))))

  const { proof, publicSignals } = await groth16.fullProve(
    inputs,
    "build/passport_regex_only_js/passport_regex_only.wasm",
    "build/passport_regex_only_final.zkey"
  )

  console.log('proof generated');
  console.log('proof:', proof);
  console.log('public signals:', publicSignals);

  const revealChars = publicSignals.map((byte: string) => String.fromCharCode(parseInt(byte, 10))).join('');
  console.log('reveal chars', revealChars);

  const vKey = JSON.parse(fs.readFileSync("build/passport_regex_only_vk.json").toString());
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