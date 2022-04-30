/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
chai.should();
const {expect} = chai;

import {JwsLinkedDataSignature} from '../../lib/index.js';

/**
 * NOTE: Test coverage of this package currently depends on indirect testing
 * through other signature package test suites.
 */
describe('JwsLinkedDataSignature', () => {
  describe('constructor', () => {
    it('should exist', async () => {
      const ex = new JwsLinkedDataSignature({type: 'ExampleType'});

      expect(ex).to.exist;
    });
  });
});
