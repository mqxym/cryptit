export async function collectStream(
  rs: ReadableStream<Uint8Array>,
  prefix?: Uint8Array,
): Promise<Uint8Array> {
  const reader = rs.getReader();
  const chunks: Uint8Array[] = prefix && prefix.length ? [prefix] : [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return out;
}