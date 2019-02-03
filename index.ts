import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';


async function crack(ciphertext: Buffer, blocksizeBytes: number, paddingOracle: (ciphertext: Buffer) => Promise<boolean>): Promise<Buffer> {
  if (ciphertext.length === 0 || ciphertext.length % blocksizeBytes !== 0) {
    throw new Error('Invalid ciphertext');
  }

  const allButLastTwoBlocks = ciphertext.slice(
    0,
    ciphertext.length - blocksizeBytes * 2
  );

  const secondToLastBlock = ciphertext.slice(
    ciphertext.length - blocksizeBytes * 2,
    ciphertext.length - blocksizeBytes
  );

  const lastBlock = ciphertext.slice(ciphertext.length - blocksizeBytes);

  const decryptedLastBlock: number[] = [];

  for (let offset = 15; offset >= 0; offset--) {
    const paddingValue = 16 - offset;

    const testCiphertext = Buffer.concat([
      allButLastTwoBlocks,
      secondToLastBlock.slice(0, offset),
      Buffer.from([0]), // The current target value that we're going to change
      // XOR with each decrypted byte so that the next decryption byte results in 0, then XOR with desired padding value
      Buffer.from(decryptedLastBlock.map((bte, i) => secondToLastBlock[i + offset + 1] ^ bte ^ paddingValue)),
      lastBlock
    ]);

    const testIndex = allButLastTwoBlocks.length + offset;
    const originalValue = secondToLastBlock[offset];

    let found = false;
    // Zero should always decrypt as expected
    for (let test = 1; test < 256; test++) {
      testCiphertext[testIndex] = originalValue ^ test;

      if (await paddingOracle(testCiphertext)) {
        decryptedLastBlock.unshift(test ^ paddingValue);
        found = true;
        break;
      }
    }

    if (!found) {
      // This occurs when we hit the last padding byte of the decrypted data
      decryptedLastBlock.unshift(paddingValue);
    }
  }

  if (allButLastTwoBlocks.length >= blocksizeBytes) {
    const preceedingBytes = await crack(Buffer.concat([allButLastTwoBlocks, secondToLastBlock]), blocksizeBytes, paddingOracle);

    return Buffer.concat([preceedingBytes, Buffer.from(decryptedLastBlock)]);
  } else {
    return Buffer.from(decryptedLastBlock);
  }
}


function removePadding(data: Buffer): Buffer {
  const paddingLength = data[data.length - 1];

  for (let i = data.length - 1; i >= data.length - paddingLength; i--) {
    if (data[i] !== paddingLength) {
      throw new Error('Invalid padding');
    }
  }

  return data.slice(0, data.length - paddingLength);
}


(async function demo() {
  const plaintext = Buffer.from('The quick brown fox jumped over the lazy dog. This is a sample message to decrypt.');
  const key = randomBytes(32);
  const iv = randomBytes(16);

  const cipher = createCipheriv('aes-256-cbc', key, iv);

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  // Async, because padding oracle implementation could be via a network request
  const paddingOracle = async (testCiphertext: Buffer): Promise<boolean> => {
    const decipher = createDecipheriv('aes-256-cbc', key, iv);

    decipher.update(testCiphertext);

    try {
      decipher.final();
      return true;
    } catch (err) {
      return false;
    }
  };

  const decrypted = await crack(ciphertext, 16, paddingOracle);
  console.log('Plaintext: ' + plaintext.toString());
  console.log('Decrypted: ' + ' '.repeat(16) + removePadding(decrypted).toString());
})().catch(err => console.log(err));
