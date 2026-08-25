#!/usr/bin/env node
import { extractPatchText, finishFromScan, readHookInput, runScan } from "./hook-utils.mjs";

const input = await readHookInput();
const patch = extractPatchText(input);
if (!patch) {
  process.exit(0);
}

finishFromScan(runScan(patch));
