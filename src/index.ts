import { verifyDKIMSignature } from "@zk-email/helpers/dist/dkim";
import { generateCircuitInputs, sha256Pad } from "@zk-email/helpers/";
// import { bytesToBigInt, fromHex } from "@zk-email/helpers/src/binaryFormat";
import fs from "fs";
import path from "path";

const rawEmail = fs.readFileSync(
  path.join(__dirname, "./emls/credit_score.eml"),
  "utf-8",
);

const MAP_HEX = {
  0: 0,
  1: 1,
  2: 2,
  3: 3,
  4: 4,
  5: 5,
  6: 6,
  7: 7,
  8: 8,
  9: 9,
  a: 10,
  b: 11,
  c: 12,
  d: 13,
  e: 14,
  f: 15,
  A: 10,
  B: 11,
  C: 12,
  D: 13,
  E: 14,
  F: 15,
} as const;

const MAX_BODY_PADDED_BYTES = 512;

async function findSelector(
  a: Uint8Array,
  selector: number[],
): Promise<number> {
  let i = 0;
  let j = 0;
  while (i < a.length) {
    if (a[i] === selector[j]) {
      j++;
      if (j === selector.length) {
        return i - j + 1;
      }
    } else {
      j = 0;
    }
    i++;
  }
  return -1;
}

export function bytesToBigInt(bytes: Uint8Array) {
  let res = 0n;
  for (let i = 0; i < bytes.length; ++i) {
    res = (res << 8n) + BigInt(bytes[i]);
  }
  return res;
}

export function fromHex(hexString: string): Uint8Array {
  let hexStringTrimmed: string = hexString;
  if (hexString[0] === "0" && hexString[1] === "x") {
    hexStringTrimmed = hexString.slice(2);
  }
  const bytes = new Uint8Array(Math.floor((hexStringTrimmed || "").length / 2));
  let i;
  for (i = 0; i < bytes.length; i++) {
    const a = MAP_HEX[hexStringTrimmed[i * 2] as keyof typeof MAP_HEX];
    const b = MAP_HEX[hexStringTrimmed[i * 2 + 1] as keyof typeof MAP_HEX];
    if (a === undefined || b === undefined) {
      break;
    }
    bytes[i] = (a << 4) | b;
  }
  return i === bytes.length ? bytes : bytes.slice(0, i);
}

const main = async () => {
  try {
    const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));
    console.log("🚀 ~ main ~ dkimResult:", dkimResult);
    const STRING_PRESELECTOR = "Your credit score is: ";
    const circuitInputs = generateCircuitInputs({
      rsaSignature: dkimResult.signature,
      rsaPublicKey: dkimResult.publicKey,
      body: dkimResult.body,
      bodyHash: dkimResult.bodyHash,
      message: dkimResult.message,
      maxMessageLength: 576,
      maxBodyLength: 512,
      shaPrecomputeSelector: STRING_PRESELECTOR,
    });
    const eth_address = process.env.ETH_ADDRESS || "";
    const address = bytesToBigInt(fromHex(eth_address)).toString();

    //@ts-ignore
    circuitInputs.address = address;

    const selector = STRING_PRESELECTOR.split("").map((char) =>
      char.charCodeAt(0),
    );
    const calc_length =
      Math.floor((dkimResult.body.length + 63 + 65) / 64) * 64;

    const [bodyPadded] = await sha256Pad(
      dkimResult.body,
      Math.max(MAX_BODY_PADDED_BYTES, calc_length),
    );

    const shaCutoffIndex =
      Math.floor((await findSelector(bodyPadded, selector)) / 64) * 64;

    const bodyRemaining = bodyPadded.slice(shaCutoffIndex);

    const CREDIT_SCORE_SELECTOR = Buffer.from(STRING_PRESELECTOR);

    const credit_score_idx = (
      Buffer.from(bodyRemaining).indexOf(CREDIT_SCORE_SELECTOR) +
      CREDIT_SCORE_SELECTOR.length
    ).toString();

    //@ts-ignore
    circuitInputs.credit_score_idx = credit_score_idx;

    console.log("In_padded length", circuitInputs.in_padded.length);
    console.log("Message length", dkimResult.message.length);
    console.log("Body length", dkimResult.body.length);
    console.log("In_body_padded length", circuitInputs.in_body_padded?.length);
    if (!circuitInputs.in_body_padded?.length) throw new Error("No body");
    fs.writeFileSync("./input.json", JSON.stringify(circuitInputs));
  } catch (error) {
    console.error(error);
  }
};

main().catch(console.error);
