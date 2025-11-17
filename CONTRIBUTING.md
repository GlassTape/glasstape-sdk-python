# Contributing to GlassTape SDK

Thank you for your interest in contributing to GlassTape! This document provides guidelines for contributing to the project.

## 🚀 Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/glasstape-sdk-python.git
   cd glasstape-sdk-python
   ```
3. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. **Install development dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

## 🛠️ Development Setup

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=glasstape --cov-report=html

# Run specific test file
pytest tests/test_decorators.py

# Run with verbose output
pytest -v
```

### Code Quality

We use several tools to maintain code quality:

```bash
# Format code
black glasstape/ tests/

# Sort imports
isort glasstape/ tests/

# Lint code
flake8 glasstape/ tests/

# Type checking
mypy glasstape/
```

### Pre-commit Hooks

Install pre-commit hooks to automatically run checks:

```bash
pip install pre-commit
pre-commit install
```

## 📝 Contribution Guidelines

### Code Style

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use [Black](https://black.readthedocs.io/) for code formatting
- Use [isort](https://pycqa.github.io/isort/) for import sorting
- Add type hints for all public functions
- Write docstrings for all public classes and functions

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes

Examples:
```
feat(decorators): add support for async functions
fix(config): handle missing environment variables
docs(readme): update installation instructions
```

### Pull Request Process

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the guidelines above

3. **Add tests** for new functionality

4. **Update documentation** if needed

5. **Run the test suite** and ensure all tests pass

6. **Submit a pull request** with:
   - Clear description of changes
   - Reference to any related issues
   - Screenshots/examples if applicable

### Testing Guidelines

- Write tests for all new features
- Maintain or improve test coverage
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies

Example test structure:
```python
def test_govern_decorator_allows_valid_request():
    """Test that @govern allows requests that pass policy validation."""
    # Arrange
    configure(policy_dir="./test_policies")
    
    @govern("test.policy.v1")
    def test_function(amount: float):
        return f"Processed ${amount}"
    
    # Act
    result = test_function(50.0)
    
    # Assert
    assert result == "Processed $50.0"
```

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Clear description** of the issue
2. **Steps to reproduce** the problem
3. **Expected behavior** vs actual behavior
4. **Environment details**:
   - Python version
   - GlassTape version
   - Operating system
   - Relevant dependencies
5. **Code examples** or minimal reproduction case

## 💡 Feature Requests

For feature requests, please:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** and problem you're solving
3. **Propose a solution** if you have ideas
4. **Consider backward compatibility**

## 📚 Documentation

Documentation improvements are always welcome:

- Fix typos or unclear explanations
- Add examples and use cases
- Improve API documentation
- Update README or guides

## 🏗️ Architecture Guidelines

### Core Principles

1. **Simplicity**: Keep the API minimal and intuitive
2. **Extensibility**: Design for future modes (platform, web3)
3. **Performance**: Sub-10ms policy evaluation
4. **Security**: Fail-closed, cryptographic receipts
5. **Offline-first**: Work without network dependencies

### Module Structure

```
glasstape/
├── __init__.py          # Public API exports
├── config.py            # Configuration management
├── decorators.py        # @govern and @monitor decorators
├── context.py           # Request context management
├── router.py            # Mode routing (local/platform/web3)
├── errors.py            # Exception definitions
├── policy_engine.py     # Policy evaluation engine
├── cerbos_evaluator.py  # CEL evaluation (Cerbos-compatible)
├── crypto.py            # Cryptographic operations
└── modes/
    ├── __init__.py
    └── local.py         # Local file-based mode
```

### Adding New Features

When adding features:

1. **Start with tests** - write failing tests first
2. **Keep it minimal** - add only what's necessary
3. **Maintain backward compatibility**
4. **Update documentation**
5. **Consider all modes** (local, platform, web3)

## 🤝 Community

- **GitHub Discussions**: Ask questions and share ideas
- **Issues**: Report bugs and request features
- **Discord**: Join our community chat (link in README)

## 📄 License

By contributing to GlassTape, you agree that your contributions will be licensed under the Apache 2.0 License.

## 🙏 Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes for significant contributions
- GitHub contributor graphs

Thank you for helping make GlassTape better! 🎉