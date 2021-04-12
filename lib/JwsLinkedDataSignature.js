/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import jsigs from 'jsonld-signatures';
const {LinkedDataSignature} = jsigs.suites;
import {encode, decode} from 'base64url-universal';

export class JwsLinkedDataSignature extends LinkedDataSignature {
  /**
   * @param {object} options - Options hashmap.
   * @param {string} options.type - Provided by subclass.
   * @param {string} options.alg - JWS alg provided by subclass.
   * @param {object} [options.LDKeyClass] - Provided by subclass or subclass
   *   overrides `getVerificationMethod`.
   *
   * Either a `key` OR at least one of `signer`/`verifier` is required.
   *
   * @param {object} [options.key] - An optional key object (containing an
   *   `id` property, and either `signer` or `verifier`, depending on the
   *   intended operation. Useful for when the application is managing keys
   *   itself (when using a KMS, you never have access to the private key,
   *   and so should use the `signer` param instead).
   * @param {Function} [options.signer] - Signer function that returns an
   *   object with an async sign() method. This is useful when interfacing
   *   with a KMS (since you don't get access to the private key and its
   *   `signer()`, the KMS client gives you only the signer function to use).
   * @param {Function} [options.verifier] - Verifier function that returns
   *   an object with an async `verify()` method. Useful when working with a
   *   KMS-provided verifier function.
   *
   * Advanced optional parameters and overrides.
   *
   * @param {object} [options.proof] - A JSON-LD document with options to use
   *   for the `proof` node. Any other custom fields can be provided here
   *   using a context different from `security-v2`.
   * @param {string|Date} [options.date] - Signing date to use if not passed.
   * @param {string} options.contextUrl - JSON-LD context url that corresponds
   *   to this signature suite. Used for enforcing suite context during the
   *   `sign()` operation.
   * @param {boolean} [options.useNativeCanonize] - Whether to use a native
   *   canonize algorithm.
   */
  constructor({
    type, alg, LDKeyClass, key, signer, verifier, proof, date, contextUrl,
    useNativeCanonize
  } = {}) {
    super({
      type, LDKeyClass, contextUrl, key, signer, verifier, proof, date,
      useNativeCanonize
    });
    this.alg = alg;
  }

  /**
   * @param {object} options - Options hashmap.
   * @param {Uint8Array} options.verifyData - The data to sign.
   * @param {object} options.proof - A JSON-LD document with options to use
   *   for the `proof` node. Any other custom fields can be provided here
   *   using a context different from `security-v2`.
   *
   * @returns {Promise<{object}>} The proof containing the signature value.
   */
  async sign({verifyData, proof}) {
    if(!(this.signer && typeof this.signer.sign === 'function')) {
      throw new Error('A signer API has not been specified.');
    }
    // JWS header
    const header = {
      alg: this.alg,
      b64: false,
      crit: ['b64']
    };

    /*
    +-------+-----------------------------------------------------------+
    | "b64" | JWS Signing Input Formula                                 |
    +-------+-----------------------------------------------------------+
    | true  | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||     |
    |       | BASE64URL(JWS Payload))                                   |
    |       |                                                           |
    | false | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.') ||    |
    |       | JWS Payload                                               |
    +-------+-----------------------------------------------------------+
    */

    // create JWS data and sign
    const encodedHeader = encode(JSON.stringify(header));

    const data = _createJws({encodedHeader, verifyData});

    const signature = await this.signer.sign({data});

    // create detached content signature
    const encodedSignature = encode(signature);
    proof.jws = encodedHeader + '..' + encodedSignature;
    return proof;
  }

  /**
   * @param {object} options - Options hashmap.
   * @param {Uint8Array} options.verifyData - The data to verify.
   * @param {object} options.verificationMethod - A verification method.
   * @param {object} options.proof - The proof to be verified.
   *
   * @returns {Promise<{boolean}>} Resolves with the verification result.
   */
  async verifySignature({verifyData, verificationMethod, proof}) {
    if(!(proof.jws && typeof proof.jws === 'string' &&
      proof.jws.includes('.'))) {
      throw new TypeError('The proof does not include a valid "jws" property.');
    }
    // add payload into detached content signature
    const [encodedHeader, /*payload*/, encodedSignature] = proof.jws.split('.');

    let header;
    try {
      const utf8decoder = new TextDecoder();
      header = JSON.parse(utf8decoder.decode(decode(encodedHeader)));
    } catch(e) {
      throw new Error('Could not parse JWS header; ' + e);
    }
    if(!(header && typeof header === 'object')) {
      throw new Error('Invalid JWS header.');
    }

    // confirm header matches all expectations
    if(!(header.alg === this.alg && header.b64 === false &&
      Array.isArray(header.crit) && header.crit.length === 1 &&
      header.crit[0] === 'b64') && Object.keys(header).length === 3) {
      throw new Error(
        `Invalid JWS header parameters for ${this.type}.`);
    }

    // do signature verification
    const signature = decode(encodedSignature);

    const data = _createJws({encodedHeader, verifyData});

    let {verifier} = this;
    if(!verifier) {
      const key = await this.LDKeyClass.from(verificationMethod);
      verifier = key.verifier();
    }
    return verifier.verify({data, signature});
  }

  async getVerificationMethod({proof, documentLoader}) {
    if(this.key) {
      // This happens most often during sign() operations. For verify(),
      // the expectation is that the verification method will be fetched
      // by the documentLoader (below), not provided as a `key` parameter.
      return this.key.export({publicKey: true});
    }

    let {verificationMethod} = proof;

    if(typeof verificationMethod === 'object') {
      verificationMethod = verificationMethod.id;
    }

    if(!verificationMethod) {
      throw new Error('No "verificationMethod" found in proof.');
    }

    const {document} = await documentLoader(verificationMethod);

    verificationMethod = typeof document === 'string' ?
      JSON.parse(document) : document;

    await this.assertVerificationMethod({verificationMethod});
    return verificationMethod;
  }

  /**
   * Checks whether a given proof exists in the document.
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.proof - A proof.
   * @param {object} options.document - A JSON-LD document.
   * @param {object} options.purpose - A jsonld-signatures ProofPurpose
   *  instance (e.g. AssertionProofPurpose, AuthenticationProofPurpose, etc).
   * @param {Function} options.documentLoader  - A secure document loader (it is
   *   recommended to use one that provides static known documents, instead of
   *   fetching from the web) for returning contexts, controller documents,
   *   keys, and other relevant URLs needed for the proof.
   * @param {Function} [options.expansionMap] - A custom expansion map that is
   *   passed to the JSON-LD processor; by default a function that will throw
   *   an error when unmapped properties are detected in the input, use `false`
   *   to turn this off and allow unmapped properties to be dropped or use a
   *   custom function.
   *
   * @returns {Promise<boolean>} Whether a match for the proof was found.
   */
  async matchProof({proof, document, purpose, documentLoader, expansionMap}) {
    if(!await super.matchProof(
      {proof, document, purpose, documentLoader, expansionMap})) {
      return false;
    }
    // NOTE: When subclassing this suite: Extending suites will need to check
    // for the presence their contexts here and in sign()

    if(!this.key) {
      // no key specified, so assume this suite matches and it can be retrieved
      return true;
    }

    const {verificationMethod} = proof;

    // only match if the key specified matches the one in the proof
    if(typeof verificationMethod === 'object') {
      return verificationMethod.id === this.key.id;
    }
    return verificationMethod === this.key.id;
  }
}

/**
 * Creates the bytes ready for signing.
 *
 * @param {object} options -  Options hashmap.
 * @param {string} options.encodedHeader - A base64url encoded JWT header.
 * @param {Uint8Array} options.verifyData - Payload to sign/verify.
 * @returns {Uint8Array} A combined byte array for signing.
 */
function _createJws({encodedHeader, verifyData}) {
  const encodedHeaderBytes = new TextEncoder().encode(encodedHeader + '.');

  // concatenate the two uint8arrays
  const data = new Uint8Array(encodedHeaderBytes.length + verifyData.length);
  data.set(encodedHeaderBytes, 0);
  data.set(verifyData, encodedHeaderBytes.length);
  return data;
}
