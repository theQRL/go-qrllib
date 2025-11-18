# Release Process

This project uses [go-semantic-release](https://github.com/go-semantic-release/semantic-release) to automate version management and package releases.

## How It Works

When commits are pushed to the `main` branch, the GitHub Actions workflow automatically:

1. Analyzes commit messages since the last release
2. Determines the next version number based on the changes
3. Generates release notes from commit messages
4. Creates a new Git tag
5. Publishes a GitHub release with generated changelog

## Commit Message Format

Semantic release uses the **Conventional Commits** specification to determine version bumps:

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types and Version Bumps

- **`fix:`** - Patches a bug (PATCH version bump: 1.0.0 → 1.0.1)
- **`feat:`** - Introduces a new feature (MINOR version bump: 1.0.0 → 1.1.0)
- **`BREAKING CHANGE:`** in footer or `!` after type - Breaking change (MAJOR version bump: 1.0.0 → 2.0.0)
- **`docs:`** - Documentation changes only (no version bump)
- **`chore:`** - Maintenance tasks (no version bump)
- **`test:`** - Adding or updating tests (no version bump)
- **`refactor:`** - Code changes that neither fix bugs nor add features (no version bump)
- **`perf:`** - Performance improvements (PATCH version bump)
- **`ci:`** - CI/CD changes (no version bump)
- **`build:`** - Build system changes (no version bump)
- **`style:`** - Code style changes (no version bump)

### Examples

#### Patch Release (1.0.0 → 1.0.1)

```
fix: resolve nil pointer in dilithium signature verification

The cryptoSignVerify function was not properly handling nil public keys,
causing a panic. This change adds proper validation.
```

```
fix(crypto): correct byte order in key serialization
```

```
perf(xmss): optimize hash computation for large trees
```

#### Minor Release (1.0.0 → 1.1.0)

```
feat: add NewDilithiumFromSecretKey function

This allows creating a Dilithium instance directly from a secret key
without requiring the original seed.
```

```
feat(wallet): support for ML-DSA-87 wallet generation
```

#### Major Release (1.0.0 → 2.0.0)

Using `BREAKING CHANGE:` in the footer:

```
feat: update to FIPS 204 final standard

BREAKING CHANGE: The Dilithium algorithm has been updated to comply
with the final FIPS 204 standard. Key formats and signatures from
previous versions are incompatible.
```

Using `!` after the type:

```
feat!: rename package from qrllib to go-qrllib

The main package has been renamed to align with Go module naming
conventions. All import paths must be updated.
```

#### No Release

```
docs: update README with installation instructions
```

```
chore: update dependencies
```

```
test: add integration tests for sphincsplus
```

```
ci: add code coverage reporting
```

## Release Workflow

### Automatic Releases

1. **Develop your changes** in a feature branch
2. **Create commits** following the conventional commit format
3. **Open a pull request** to `main`
4. **Merge the PR** - The release workflow triggers automatically
5. **New release is published** if there are releasable commits

### Manual Releases

If you need to create a release manually:

```bash
# Tag the commit
git tag v1.2.3

# Push the tag
git push origin v1.2.3
```

## Version Numbers

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version: Incompatible API changes
- **MINOR** version: New functionality in a backward compatible manner  
- **PATCH** version: Backward compatible bug fixes

### Pre-1.0.0 Versions

During initial development (0.x.y versions):

- **MINOR** version: Breaking changes
- **PATCH** version: New features and bug fixes

The workflow is configured with `allow-initial-development-versions: true` to handle this correctly.

## Changelog

The changelog is automatically generated in the GitHub release notes based on commit messages. To get well-formatted release notes:

- Write clear, descriptive commit messages
- Use the appropriate commit type
- Include relevant details in the commit body
- Reference issues with `#123` or `fixes #123`

## Configuration Files

- **`.github/workflows/release.yml`** - GitHub Actions workflow
- **`.releaserc.json`** - Semantic release configuration

## Skipping Releases

To skip the release process for a commit, add `[skip ci]` or `[ci skip]` to the commit message:

```
docs: update contributing guidelines [skip ci]
```

## Best Practices

1. **Atomic commits**: Each commit should represent a single logical change
2. **Descriptive subjects**: Keep under 72 characters, use imperative mood
3. **Detailed bodies**: Explain the what and why, not the how
4. **Reference issues**: Link to relevant GitHub issues
5. **Breaking changes**: Always document in the footer with `BREAKING CHANGE:`
6. **Scope usage**: Use consistent scopes like `(crypto)`, `(wallet)`, `(xmss)` for clarity

## Troubleshooting

### No release was created

- Check that commits follow the conventional format
- Verify that commit types warrant a release (`fix:`, `feat:`, or `BREAKING CHANGE:`)
- Review the GitHub Actions logs for errors

### Wrong version bump

- Review commit messages - ensure types are correct
- For breaking changes, verify `BREAKING CHANGE:` is in the footer or `!` is used
- Check that the base branch is correct

### Release failed

- Verify the `GITHUB_TOKEN` has sufficient permissions
- Check that the workflow has write access to contents
- Review the Actions logs for specific error messages

## Resources

- [Conventional Commits Specification](https://www.conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)
- [go-semantic-release Documentation](https://go-semantic-release.xyz/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
