/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import dirtyChai from 'dirty-chai';
chai.use(dirtyChai);
chai.should();
const {expect} = chai;

import {JwsLinkedDataSignature} from '../../';

describe('JwsLinkedDataSignature', () => {
  describe('constructor', () => {
    it('should exist', async () => {
      const ex = new JwsLinkedDataSignature({type: 'ExampleType'});

      expect(ex).to.exist();
    });
  });
});
