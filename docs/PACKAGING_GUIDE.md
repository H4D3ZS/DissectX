# Packaging and Distribution Guide

This guide explains how to use the packaging and distribution infrastructure for DissectX.

## Table of Contents

- [Building Packages](#building-packages)
- [Testing Locally](#testing-locally)
- [Release Process](#release-process)
- [Docker Usage](#docker-usage)
- [CI/CD Pipeline](#cicd-pipeline)

---

## Building Packages

### Building Source Distribution and Wheel

```bash
# Install build tools
pip install build twine

# Build package
python -m build

# This creates:
# - dist/dissectx-X.Y.Z.tar.gz (source distribution)
# - dist/dissectx-X.Y.Z-py3-none-any.whl (wheel)
```

### Checking Package

```bash
# Check package for common issues
twine check dist/*

# Check package contents
tar -tzf dist/dissectx-*.tar.gz | head -20
unzip -l dist/dissectx-*.whl | head -20
```

---

## Testing Locally

### Installing from Local Build

```bash
# Build package
python -m build

# Install in a virtual environment
python -m venv test-env
source test-env/bin/activate  # On Windows: test-env\Scripts\activate

# Install from wheel
pip install dist/dissectx-*.whl

# Or install from source distribution
pip install dist/dissectx-*.tar.gz

# Test installation
dissectx --help
python -c "import src; print(src.__version__.__version__)"
```

### Installing in Development Mode

```bash
# Install in editable mode (for development)
pip install -e .

# With development dependencies
pip install -e ".[dev]"

# With all optional dependencies
pip install -e ".[dev,docs]"
```

---

## Release Process

### Automated Release (Recommended)

The release process is automated via GitHub Actions:

1. **Update CHANGELOG.md**:
   ```markdown
   ## [1.2.3] - 2025-11-25
   
   ### Added
   - New feature X
   
   ### Fixed
   - Bug fix Y
   ```

2. **Bump Version**:
   ```bash
   # Patch release (1.0.0 -> 1.0.1)
   python scripts/bump_version.py patch
   
   # Minor release (1.0.0 -> 1.1.0)
   python scripts/bump_version.py minor
   
   # Major release (1.0.0 -> 2.0.0)
   python scripts/bump_version.py major
   
   # Specific version
   python scripts/bump_version.py --version 1.2.3
   ```

3. **Review Changes**:
   ```bash
   git diff
   ```

4. **Commit and Tag**:
   ```bash
   git add .
   git commit -m "Bump version to 1.2.3"
   git tag -a v1.2.3 -m "Release v1.2.3"
   ```

5. **Push**:
   ```bash
   git push origin main
   git push origin v1.2.3
   ```

6. **GitHub Actions will automatically**:
   - Run tests
   - Build packages
   - Create GitHub release
   - Upload to PyPI
   - Build and push Docker image

### Manual Release

If you need to release manually:

```bash
# 1. Build package
python -m build

# 2. Check package
twine check dist/*

# 3. Upload to TestPyPI (optional, for testing)
twine upload --repository testpypi dist/*

# 4. Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ dissectx

# 5. Upload to PyPI
twine upload dist/*
```

### PyPI Credentials

For manual uploads, you need PyPI credentials:

```bash
# Create ~/.pypirc
cat > ~/.pypirc << EOF
[pypi]
username = __token__
password = pypi-YOUR-API-TOKEN-HERE

[testpypi]
username = __token__
password = pypi-YOUR-TEST-API-TOKEN-HERE
EOF

chmod 600 ~/.pypirc
```

Or use environment variables:
```bash
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-YOUR-API-TOKEN-HERE
twine upload dist/*
```

---

## Docker Usage

### Building Docker Image

```bash
# Build image
docker build -t dissectx:latest .

# Build with specific tag
docker build -t dissectx:1.2.3 .

# Build with build args
docker build --build-arg PYTHON_VERSION=3.11 -t dissectx:latest .
```

### Testing Docker Image

```bash
# Test help
docker run --rm dissectx:latest --help

# Test with a binary
docker run --rm -v $(pwd):/workspace dissectx:latest /workspace/binary.exe

# Interactive shell
docker run --rm -it --entrypoint /bin/bash dissectx:latest
```

### Using Docker Compose

```bash
# Run analysis
docker-compose run dissectx binary.exe

# Run web UI
docker-compose --profile web up dissectx-web

# Build and run
docker-compose build
docker-compose run dissectx --help
```

### Publishing Docker Image

```bash
# Tag for Docker Hub
docker tag dissectx:latest yourusername/dissectx:latest
docker tag dissectx:latest yourusername/dissectx:1.2.3

# Push to Docker Hub
docker push yourusername/dissectx:latest
docker push yourusername/dissectx:1.2.3

# Tag for GitHub Container Registry
docker tag dissectx:latest ghcr.io/yourusername/dissectx:latest
docker tag dissectx:latest ghcr.io/yourusername/dissectx:1.2.3

# Push to GHCR
docker push ghcr.io/yourusername/dissectx:latest
docker push ghcr.io/yourusername/dissectx:1.2.3
```

---

## CI/CD Pipeline

### GitHub Actions Workflows

#### CI Workflow (`.github/workflows/ci.yml`)

Runs on every push and pull request:

- **Test Matrix**: Tests on multiple Python versions (3.7-3.12) and OS (Linux, macOS, Windows)
- **Linting**: Runs flake8, black, and mypy
- **Build**: Builds distribution packages
- **Docker**: Builds Docker image

**Triggering**:
- Automatic on push to `main` or `develop`
- Automatic on pull requests
- Manual via GitHub Actions UI

#### Release Workflow (`.github/workflows/release.yml`)

Runs when a version tag is pushed:

- **Build**: Creates source and wheel distributions
- **Test**: Validates packages
- **Release**: Creates GitHub release with artifacts
- **PyPI**: Uploads to PyPI
- **Docker**: Builds and pushes Docker image

**Triggering**:
```bash
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

### Required GitHub Secrets

For the release workflow to work, configure these secrets in GitHub:

1. **PYPI_API_TOKEN**: PyPI API token for uploading packages
   - Get from: https://pypi.org/manage/account/token/
   - Scope: Upload packages

2. **DOCKERHUB_USERNAME** (optional): Docker Hub username
3. **DOCKERHUB_TOKEN** (optional): Docker Hub access token

To add secrets:
1. Go to repository Settings
2. Navigate to Secrets and variables → Actions
3. Click "New repository secret"
4. Add each secret

### Monitoring CI/CD

- **View workflow runs**: https://github.com/yourusername/dissectx/actions
- **Check test results**: Click on any workflow run
- **Download artifacts**: Available in workflow run details
- **View logs**: Click on individual jobs for detailed logs

---

## Version Management

### Version File

Version is stored in `src/__version__.py`:

```python
__version__ = "1.2.3"
__version_info__ = tuple(int(i) for i in __version__.split("."))
```

### Version Bumping Script

The `scripts/bump_version.py` script automates version updates:

```bash
# Dry run (see what would change)
python scripts/bump_version.py patch --dry-run

# Bump patch version (1.0.0 -> 1.0.1)
python scripts/bump_version.py patch

# Bump minor version (1.0.0 -> 1.1.0)
python scripts/bump_version.py minor

# Bump major version (1.0.0 -> 2.0.0)
python scripts/bump_version.py major

# Set specific version
python scripts/bump_version.py --version 2.0.0
```

### Semantic Versioning

DissectX follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Incompatible API changes
- **MINOR** (0.X.0): New features, backward compatible
- **PATCH** (0.0.X): Bug fixes, backward compatible

Examples:
- `1.0.0` → `1.0.1`: Bug fix
- `1.0.0` → `1.1.0`: New feature
- `1.0.0` → `2.0.0`: Breaking change

---

## Platform-Specific Builds

### Platform-Specific Requirements

```bash
# Linux
pip install -r requirements-linux.txt

# macOS
pip install -r requirements-macos.txt

# Windows
pip install -r requirements-windows.txt
```

### Building for Specific Platforms

The wheel built by `python -m build` is platform-independent (pure Python).

For platform-specific wheels (if needed in the future):

```bash
# Build for current platform
python -m build --wheel

# Build for specific platform (requires cross-compilation setup)
# This is typically not needed for DissectX
```

---

## Troubleshooting

### Build Fails

**Issue**: `ModuleNotFoundError: No module named 'setuptools'`

**Solution**:
```bash
pip install --upgrade pip setuptools wheel build
```

### Upload Fails

**Issue**: `403 Forbidden` when uploading to PyPI

**Solution**:
- Check PyPI API token is correct
- Ensure token has upload permissions
- Verify package name is not taken

### Docker Build Fails

**Issue**: Dependencies fail to install in Docker

**Solution**:
- Check Dockerfile for syntax errors
- Ensure all dependencies are in requirements.txt
- Try building with `--no-cache`: `docker build --no-cache -t dissectx:latest .`

### Version Conflicts

**Issue**: Version in package doesn't match expected

**Solution**:
```bash
# Clean build artifacts
rm -rf build/ dist/ *.egg-info/

# Rebuild
python -m build
```

---

## Best Practices

1. **Always test locally** before releasing
2. **Update CHANGELOG.md** for every release
3. **Use semantic versioning** consistently
4. **Test on multiple platforms** via CI/CD
5. **Keep dependencies up to date** but test thoroughly
6. **Document breaking changes** clearly
7. **Tag releases** in git for traceability
8. **Use virtual environments** for testing

---

## Additional Resources

- [Python Packaging Guide](https://packaging.python.org/)
- [Semantic Versioning](https://semver.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker Documentation](https://docs.docker.com/)
- [PyPI Help](https://pypi.org/help/)

---

**Last Updated**: 2025-11-25
**Maintained By**: DissectX Contributors
