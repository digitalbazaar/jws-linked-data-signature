/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import jsonld from 'jsonld';
import jsigs from 'jsonld-signatures';
const {LinkedDataSignature} = jsigs.suites;
import {encode, decode} from 'base64url-universal';

export class JwsLinkedDataSignature extends LinkedDataSignature {
  /**
   * @param {object} options - Options hashmap.
   * @param {string} type - Provided by subclass.
   * @param {string} alg - JWS alg provided by subclass.
   * @param [LDKeyClass] {LDKeyClass} provided by subclass or subclass
   *   overrides `getVerificationMethod`.
   *
   * Either a `key` OR at least one of `signer`/`verifier` is required:
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
   * Advanced optional parameters and overrides:
   *
   * @param {object} [options.proof] - A JSON-LD document with options to use
   *   for the `proof` node (e.g. any other custom fields can be provided here
   *   using a context different from security-v2).
   * @param {string|Date} [options.date] - Signing date to use if not passed.
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
   * @param verifyData {Uint8Array}.
   * @param proof {object}
   *
   * @returns {Promise<{object}>} the proof containing the signature value.
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
   * @param verifyData {Uint8Array}.
   * @param verificationMethod {object}.
   * @param document {object} the document the proof applies to.
   * @param proof {object} the proof to be verified.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
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

  async assertVerificationMethod({verificationMethod}) {
    if(!_includesContext({
      document: verificationMethod, contextUrl: this.contextUrl
    })) {
      // For DID Documents, since keys do not have their own contexts,
      // the suite context is usually provided by the documentLoader logic
      throw new TypeError(
        `The verification method (key) must contain "${this.contextUrl}".`
      );
    }

    if(!jsonld.hasValue(verificationMethod, 'type', this.requiredKeyType)) {
      throw new Error(
        `Invalid key type. Key type must be "${this.requiredKeyType}".`);
    }

    // ensure verification method has not been revoked
    if(verificationMethod.revoked !== undefined) {
      throw new Error('The verification method has been revoked.');
    }
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

  async matchProof({proof, document, purpose, documentLoader, expansionMap}) {
    if(!_includesContext({document, contextUrl: this.contextUrl})) {
      return false;
    }

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
 * @param {string} encodedHeader - base64url encoded JWT header.
 * @param {Uint8Array} verifyData - Payload to sign/verify.
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

/**
 * Tests whether a provided JSON-LD document includes a context url in its
 * `@context` property.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.document - A JSON-LD document.
 * @param {string} options.contextUrl - A context url.
 *
 * @returns {boolean} Returns true if document includes context.
 */
function _includesContext({document, contextUrl}) {
  const context = document['@context'];
  return context === contextUrl ||
    (Array.isArray(context) && context.includes(contextUrl));
}
