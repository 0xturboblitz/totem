import { provePassport } from "./passport";
import { proveEmail } from "./email";

async function totemEndToEnd() {
  const passportCommitment = await provePassport();
  const emailCommitment = await proveEmail();

  if (passportCommitment === emailCommitment) {
    console.log('Passport and email commitments match');
  } else {
    console.log('Passport and email commitments do not match');
  }
}

totemEndToEnd().then(() => {
  process.exit();
})