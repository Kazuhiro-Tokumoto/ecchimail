import { Ed25519 } from "./eddsa.js";
import { PointPairSchnorrP256 } from "./server/cryptos/ecdsa.js";

const message = new TextEncoder().encode("Hello, World!");
const N = 1000;

function stats(times: number[]): { min: number; p25: number; median: number; mean: number; p75: number; p95: number; p99: number; max: number; stddev: number } {
  times.sort((a, b) => a - b);
  const mean = times.reduce((a, b) => a + b, 0) / times.length;
  const stddev = Math.sqrt(times.reduce((a, b) => a + (b - mean) ** 2, 0) / times.length);
  return {
    min:    times[0],
    p25:    times[Math.floor(N * 0.25)],
    median: times[Math.floor(N * 0.50)],
    mean,
    p75:    times[Math.floor(N * 0.75)],
    p95:    times[Math.floor(N * 0.95)],
    p99:    times[Math.floor(N * 0.99)],
    max:    times[N - 1],
    stddev,
  };
}

function printStats(label: string, s: ReturnType<typeof stats>): void {
  console.log(`── ${label} ──`);
  console.log(`  min   : ${s.min.toFixed(3)}ms`);
  console.log(`  p25   : ${s.p25.toFixed(3)}ms`);
  console.log(`  median: ${s.median.toFixed(3)}ms`);
  console.log(`  mean  : ${s.mean.toFixed(3)}ms`);
  console.log(`  p75   : ${s.p75.toFixed(3)}ms`);
  console.log(`  p95   : ${s.p95.toFixed(3)}ms`);
  console.log(`  p99   : ${s.p99.toFixed(3)}ms`);
  console.log(`  max   : ${s.max.toFixed(3)}ms`);
  console.log(`  stddev: ${s.stddev.toFixed(4)}ms`);
}

function printRatio(label: string, a: ReturnType<typeof stats>, b: ReturnType<typeof stats>, aName: string, bName: string): void {
  console.log(`── ${label} 比率 (${aName} vs ${bName}, meanベース) ──`);
  console.log(`  ${aName} mean: ${a.mean.toFixed(3)}ms`);
  console.log(`  ${bName} mean: ${b.mean.toFixed(3)}ms`);
  console.log(`  ${aName} は ${bName} の ${(a.mean / b.mean).toFixed(2)}倍`);
}

// ── Ed25519 ──
const ed_privateKey = crypto.getRandomValues(new Uint8Array(32));
const ed_publicKey = await Ed25519.getPublicKey(ed_privateKey);

const edSignTimes: number[] = [];
const edSigs: Uint8Array[] = [];
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  const sig = await Ed25519.sign(message, ed_privateKey);
  edSignTimes.push(performance.now() - t0);
  edSigs.push(sig);
}

const edVerifyTimes: number[] = [];
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  await Ed25519.verify(edSigs[i], message, ed_publicKey);
  edVerifyTimes.push(performance.now() - t0);
}

// ── P-256 Schnorr ──
const ec = new PointPairSchnorrP256();
const { privateKey: ecPriv, publicKey: ecPub } = ec.generateKeyPair();

const ecSignTimes: number[] = [];
const ecSigs: ReturnType<typeof ec.sign>[] = [];
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  const sig = ec.sign(message, ecPriv);
  ecSignTimes.push(performance.now() - t0);
  ecSigs.push(sig);
}

const ecVerifyTimes: number[] = [];
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  ec.verify(message, ecPub, ecSigs[i]);
  ecVerifyTimes.push(performance.now() - t0);
}

// ── 結果表示 ──
const edSign   = stats(edSignTimes);
const edVerify = stats(edVerifyTimes);
const ecSign   = stats(ecSignTimes);
const ecVerify = stats(ecVerifyTimes);

console.log(`\n${"=".repeat(50)}`);
console.log(`  Ed25519  (n=${N})`);
console.log("=".repeat(50));
printStats("署名", edSign);
printStats("検証", edVerify);
console.log("valid:", await Ed25519.verify(edSigs[0], message, ed_publicKey));

console.log(`\n${"=".repeat(50)}`);
console.log(`  P-256 Schnorr  (n=${N})`);
console.log("=".repeat(50));
printStats("署名", ecSign);
printStats("検証", ecVerify);
console.log("valid:", ec.verify(message, ecPub, ecSigs[0]));

console.log(`\n${"=".repeat(50)}`);
console.log(`  比率サマリ`);
console.log("=".repeat(50));
printRatio("署名",   ecSign,   edSign,   "P256", "Ed25519");
printRatio("検証",   ecVerify, edVerify, "P256", "Ed25519");