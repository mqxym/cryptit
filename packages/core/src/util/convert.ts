// packages/core/src/util/convert.ts
export async function ensureUint8Array(
  src: Uint8Array | ArrayBuffer | Blob,
): Promise<Uint8Array> {
  if (src instanceof Uint8Array)  return src;
  if (src instanceof ArrayBuffer) return new Uint8Array(src);
  return new Uint8Array(await src.arrayBuffer());
}