#!/usr/bin/env node
import { currentPracticeDiff, finishFromScan, runScan } from "./hook-utils.mjs";

const diff = currentPracticeDiff();
if (!diff.trim()) {
  process.exit(0);
}

finishFromScan(runScan(diff));
