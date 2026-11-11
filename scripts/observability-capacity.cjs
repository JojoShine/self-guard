const fs = require('node:fs');

const fields = [
  'dailyAccessCount', 'recordBytesPerAccess', 'requestBytesPerAccess',
  'responseBytesPerAccess', 'retentionDays', 'dailyPinnedPacketBytes',
  'evidenceCopies', 'dailyIndexBytes', 'indexRetentionDays', 'indexCopies', 'bufferBytes',
];
const positiveFields = new Set(['retentionDays', 'evidenceCopies', 'indexRetentionDays', 'indexCopies']);

function checked(value) {
  if (!Number.isSafeInteger(value)) throw new RangeError('Capacity exceeds the safe integer byte range');
  return value;
}

function calculateCapacity(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).length !== fields.length || Object.keys(input).some(key => !fields.includes(key))) {
    throw new TypeError('Provide exactly the required capacity fields');
  }
  for (const field of fields) {
    if (!Object.hasOwn(input, field) || !Number.isSafeInteger(input[field]) || input[field] < (positiveFields.has(field) ? 1 : 0)) {
      throw new TypeError(`${field} must be a ${positiveFields.has(field) ? 'positive' : 'non-negative'} safe integer`);
    }
  }
  const bytesPerAccess = checked(checked(input.recordBytesPerAccess + input.requestBytesPerAccess) + input.responseBytesPerAccess);
  const dailyBusinessBytes = checked(input.dailyAccessCount * bytesPerAccess);
  const retainedBusinessBytes = checked(dailyBusinessBytes * input.retentionDays);
  const retainedPinnedPacketBytes = checked(input.dailyPinnedPacketBytes * input.retentionDays);
  const evidenceBytesWithCopies = checked(checked(retainedBusinessBytes + retainedPinnedPacketBytes) * input.evidenceCopies);
  const indexBytesWithCopies = checked(checked(input.dailyIndexBytes * input.indexRetentionDays) * input.indexCopies);
  const totalBytes = checked(checked(evidenceBytesWithCopies + indexBytesWithCopies) + input.bufferBytes);
  return {dailyBusinessBytes, retainedBusinessBytes, retainedPinnedPacketBytes,
    evidenceBytesWithCopies, indexBytesWithCopies, bufferBytes: input.bufferBytes, totalBytes};
}

if (require.main === module) {
  try {
    if (process.argv.length !== 3) throw new Error('Usage: node observability-capacity.cjs <input.json>');
    let input;
    try {
      const fd = fs.openSync(process.argv[2], fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
      try {
        if (!fs.fstatSync(fd).isFile()) throw new Error('Not a regular file');
        const buffer = Buffer.alloc(65537);
        const length = fs.readSync(fd, buffer, 0, buffer.length, 0);
        if (length > 65536) throw new Error('Input too large');
        input = JSON.parse(buffer.toString('utf8', 0, length));
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      // JSON parser errors can include source snippets containing sensitive values.
      throw new Error('Unable to read a valid capacity JSON file (maximum 64 KiB)');
    }
    process.stdout.write(JSON.stringify(calculateCapacity(input), null, 2) + '\n');
  } catch (error) {
    process.stderr.write(error.message + '\n');
    process.exitCode = 1;
  }
}

module.exports = {calculateCapacity};
