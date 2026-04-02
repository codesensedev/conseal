# Contributing to Conseal

## CLA Required

Before any pull request can be merged, you must sign the [Contributor License Agreement](./CLA.md).

When you open a PR, CLA Assistant will prompt you to sign via GitHub OAuth. The merge is blocked until you do.

This is required because `conseal` is dual-licensed — see [COMMERCIAL-LICENSE.md](./COMMERCIAL-LICENSE.md) for details.

## Getting Started

```bash
npm install
npm test         # run all tests
npm run build    # build to dist/
```

## Guidelines

- Every new function needs a test in `test/`.
- Tests go in the same module grouping as the source file — `src/aes.ts` → `test/aes.test.ts`.
- Keep each source file focused on one responsibility.
- Do not add dependencies outside of `@scure/bip39`. All other crypto uses SubtleCrypto.

## Questions

Open an issue or email **dev@conseal.dev**.
