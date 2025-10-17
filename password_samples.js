import path from "path";
import fs from "fs";
import csv from "csv-parser";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const filepath = path.join(__dirname, "samples", "1millionPasswords.csv");

/**
 * @type {Array<{rank: string, password: string}>}
 */
const password_samples = [];

fs.createReadStream(filepath)
  .pipe(csv())
  .on("data", (data) => password_samples.push(data));

  /**
   * @type {string[]}
   */
const passwords_array = [];
for (const sample of password_samples) {
  passwords_array.push(sample.password);
}
export {passwords_array};
export default password_samples;