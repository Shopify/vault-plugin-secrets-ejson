# CHANGELOG

## 1.0.0

- Updated dependencies
- Migrated to go modules
- BREAKING CHANGE: All key values prefixed with an underscore will now be stored with that underscore removed in its decrypted path. Any existing secrets with underscore key values will not be changed until re-written.

## 0.1.0

- Initial release
