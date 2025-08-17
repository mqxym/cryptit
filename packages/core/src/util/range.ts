export function assertSliceBounds(
  total: number,
  offset: number,
  len: number,
): void {
  if (offset < 0 || len < 0 || offset + len > total) {
    throw new RangeError('read() slice exceeds data bounds');
  }
}