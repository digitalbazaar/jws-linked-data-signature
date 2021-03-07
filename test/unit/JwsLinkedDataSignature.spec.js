/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
chai.should();
const {expect} = chai;

import {JwsLinkedDataSignature} from '../../';

describe('JwsLinkedDataSignature', () => {
  describe('constructor', () => {
    it('should exist', async () => {
      const ex = new JwsLinkedDataSignature({type: 'ExampleType'});

      expect(ex).to.exist;
    });
  });
});
