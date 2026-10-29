/** Persist a complete byte slice, including when FileHandle.write makes short progress. */
export async function writeAll(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes.subarray(offset));
    if (!Number.isInteger(bytesWritten) || bytesWritten <= 0 || bytesWritten > bytes.length - offset) {
      throw new Error('File write made no progress or returned an invalid byte count');
    }
    offset += bytesWritten;
  }
}
