## Description

Clearly describe the changes proposed in this pull request and the problem they solve.

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Security enhancement (hardens protocol, path safety, or token verification)
- [ ] Documentation update
- [ ] Refactoring / Test improvement

## Security Checklist

- [ ] **Approval Invariant Preserved**: Mutating operations still strictly require human operator decision via `npm run approve`. No bypass or automatic approval added.
- [ ] **Workspace Isolation**: No file operations can escape the authorized workspace boundaries. Symlinks and junctions are blocked.
- [ ] **Credential Protection**: Credential files (`.env`, private keys, secrets) cannot be read, listed, or altered.
- [ ] **No Hardcoded Secrets**: No developer credentials, tokens, or environment paths are committed.
- [ ] **Network Isolation**: The VS Code IPC service remains bound exclusively to `127.0.0.1`.

## Verification Steps

1. `npm run typecheck` passes with zero errors.
2. `npm run build` and `npm run build:extension` succeed.
3. `npm test` passes all tests (94+ passing).
4. `npm run test:mcpb` passes stdio verification.

