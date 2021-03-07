/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import * as env from './env.js';
import * as forge from 'node-forge';

export function createJwsFactory() {
  if(env.nodejs) {
    return ({encodedHeader, verifyData}) => {
      const buffer = Buffer.concat([
        Buffer.from(encodedHeader + '.', 'utf8'),
        Buffer.from(verifyData.buffer, verifyData.byteOffset, verifyData.length)
      ]);
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.length);
    };
  }

  return ({encodedHeader, verifyData}) => {
    const buffer = new forge.util.ByteBuffer(encodedHeader + '.', 'utf8');
    const binaryString = forge.util.binary.raw.encode(verifyData);
    buffer.putBytes(binaryString);
    return forge.util.binary.raw.decode(buffer.getBytes());
  };
}
