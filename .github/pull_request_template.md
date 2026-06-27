## Summary

Describe the change and why it is needed.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security hardening
- [ ] Documentation
- [ ] Refactoring or maintenance
- [ ] Breaking change

## Security impact

- [ ] No security-relevant behavior changed
- [ ] Authentication or session handling changed
- [ ] Authorization or tenant isolation changed
- [ ] Evidence, audit, or incident data handling changed
- [ ] Import, parser, SBOM, CSAF, VEX, or CVE handling changed
- [ ] Dependencies or software supply-chain behavior changed

Explain relevant risks, assumptions, and mitigations:

## Validation

- [ ] `make rust-build`
- [ ] `make rust-test`
- [ ] `make rust-smoke`
- [ ] `make team-test`
- [ ] Additional checks described below

Tests and checks performed:

## Documentation and compatibility

- [ ] Documentation was updated where required
- [ ] Database migrations were added where required
- [ ] Backward compatibility was considered
- [ ] UI screenshots are attached where relevant

## AI assistance

- [ ] No substantial AI assistance was used
- [ ] Substantial AI assistance was used and reviewed

Describe substantial AI assistance, if applicable:

## Checklist

- [ ] The change is focused and does not include unrelated modifications
- [ ] New or changed behavior is covered by tests
- [ ] Negative authorization or tenant-boundary tests were added where relevant
- [ ] No confidential information or credentials are included
- [ ] I have read `CONTRIBUTING.md` and `SECURITY.md`
