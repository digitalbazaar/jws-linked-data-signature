# @digitalbazaar/jws-linked-data-signature Changelog

## 3.0.0 - 2022-10-25

### Changed
- **BREAKING**: Use `jsonld-signatures@11` to get better safe mode
  protections.

## 2.0.0 - 2022-06-07

### Changed
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- Update dependencies.
- Lint module.

## 1.0.1 - 2021-04-12

### Fixed
- Fix passing `signer` and `verifier` to parent class constructor. 
- Enable the `Ed25519Signature2018` suite to enforce its own compatible context. 

## 1.0.0 - 2021-03-18

### Added
- Initial files extracted from https://github.com/digitalbazaar/jsonld-signatures.
