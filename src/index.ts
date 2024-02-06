import { verifyDKIMSignature } from "@zk-email/helpers/dist/dkim";
import { generateCircuitInputs } from "@zk-email/helpers/";
import fs from "fs";
import path from "path";

const rawEmail = fs.readFileSync(
  path.join(__dirname, "./emls/HelloWorld.eml"),
  "utf-8",
);

const main = async () => {
  try {
    const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));
    console.log("🚀 ~ main ~ dkimResult:", dkimResult);
    const preselector = "Sent from my ";
    const circuitInputs = generateCircuitInputs({
      rsaSignature: dkimResult.signature,
      rsaPublicKey: dkimResult.publicKey,
      body: dkimResult.body,
      bodyHash: dkimResult.bodyHash,
      message: dkimResult.message,
      maxMessageLength: 576,
      maxBodyLength: 270,
      shaPrecomputeSelector: preselector,
    });
    console.log("circutInputs", circuitInputs);
    fs.writeFileSync("./input.json", JSON.stringify(circuitInputs));
  } catch (error) {
    console.error(error);
  }
};

main().catch(console.error);
