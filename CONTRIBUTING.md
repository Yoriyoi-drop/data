# Contributing to Infinite AI Security

Terima kasih atas minat Anda untuk berkontribusi pada Infinite AI Security! 🎉

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)

## 📜 Code of Conduct

Project ini mengadopsi Code of Conduct. Dengan berpartisipasi, Anda diharapkan untuk mematuhi kode ini.

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- Go 1.21+
- Rust 1.70+
- Docker & Docker Compose
- Git

### Setup Development Environment

```bash
# Fork dan clone repository
git clone https://github.com/your-username/infinite_ai_security.git
cd infinite_ai_security

# Install dependencies
make install

# Setup environment
cp .env.example .env
# Edit .env sesuai kebutuhan

# Run database migrations
make migrate

# Start development server
make dev
```

## 🔄 Development Workflow

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   # atau
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes**
   - Write clean, readable code
   - Follow coding standards
   - Add tests for new features
   - Update documentation

3. **Test your changes**
   ```bash
   make test
   make lint
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request**

## 📝 Coding Standards

### Python

- Follow [PEP 8](https://pep8.org/)
- Use [Black](https://black.readthedocs.io/) for formatting
- Use [Ruff](https://github.com/astral-sh/ruff) for linting
- Type hints are required
- Docstrings for all public functions/classes

```python
def calculate_risk_score(threat_level: str, severity: int) -> float:
    """
    Calculate risk score based on threat level and severity.
    
    Args:
        threat_level: The threat level (low, medium, high, critical)
        severity: Severity score from 1-10
        
    Returns:
        Risk score as a float between 0-100
        
    Raises:
        ValueError: If severity is out of range
    """
    # Implementation
    pass
```

### TypeScript/JavaScript

- Follow [Airbnb Style Guide](https://github.com/airbnb/javascript)
- Use [Prettier](https://prettier.io/) for formatting
- Use [ESLint](https://eslint.org/) for linting
- TypeScript strict mode enabled
- Functional components with hooks

```typescript
interface AgentProps {
  id: string;
  name: string;
  status: 'active' | 'inactive';
}

export const AgentCard: React.FC<AgentProps> = ({ id, name, status }) => {
  // Implementation
  return <div>...</div>;
};
```

### Go

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Use `golangci-lint` for linting
- Error handling is mandatory

```go
func ScanCode(path string) (*ScanResult, error) {
    if path == "" {
        return nil, fmt.Errorf("path cannot be empty")
    }
    
    // Implementation
    
    return result, nil
}
```

### Rust

- Follow [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
- Use `rustfmt` for formatting
- Use `clippy` for linting
- Handle all `Result` and `Option` types

```rust
pub fn detect_anomaly(data: &[u8]) -> Result<AnomalyReport, Error> {
    if data.is_empty() {
        return Err(Error::EmptyData);
    }
    
    // Implementation
    
    Ok(report)
}
```

## 💬 Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/).

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `ci`: CI/CD changes

### Examples

```bash
feat(api): add user authentication endpoint

Implement JWT-based authentication with refresh tokens.
Includes rate limiting and brute force protection.

Closes #123

---

fix(dashboard): resolve memory leak in agent list

The agent list component was not properly cleaning up
WebSocket connections on unmount.

Fixes #456

---

docs(readme): update installation instructions

Add troubleshooting section for common setup issues.
```

## 🔀 Pull Request Process

1. **Update documentation** if needed
2. **Add tests** for new features
3. **Ensure all tests pass**
   ```bash
   make test
   ```
4. **Run linters**
   ```bash
   make lint
   ```
5. **Update CHANGELOG.md** with your changes
6. **Fill out the PR template** completely
7. **Request review** from maintainers
8. **Address review comments** promptly

### PR Title Format

Use the same format as commit messages:

```
feat(api): add user authentication endpoint
fix(dashboard): resolve memory leak in agent list
docs(readme): update installation instructions
```

## 🧪 Testing

### Python Tests

```bash
# Run all tests
cd apps/api
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_services.py

# Run specific test
pytest tests/unit/test_services.py::test_auth_service
```

### TypeScript Tests

```bash
# Run all tests
cd apps/dashboard
npm test

# Run with coverage
npm test -- --coverage

# Run in watch mode
npm test -- --watch
```

### Go Tests

```bash
# Run all tests
cd packages/security-engine/scanner_go
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/scanner
```

### Rust Tests

```bash
# Run all tests
cd packages/security-engine/labyrinth_rust
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_anomaly_detection
```

## 📊 Code Coverage

We aim for **80%+ code coverage** for all new code.

- Python: Use `pytest-cov`
- TypeScript: Use Jest coverage
- Go: Use built-in coverage tools
- Rust: Use `cargo-tarpaulin`

## 🐛 Reporting Bugs

Use the [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md)

Include:
- Clear description
- Steps to reproduce
- Expected vs actual behavior
- Environment details
- Screenshots if applicable

## 💡 Suggesting Features

Use the [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md)

Include:
- Clear use case
- Proposed solution
- Alternatives considered
- Additional context

## 🔒 Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead, email: security@example.com

See [SECURITY.md](SECURITY.md) for details.

## 📞 Getting Help

- 💬 [Discord Community](https://discord.gg/example)
- 📧 [Mailing List](mailto:dev@example.com)
- 📖 [Documentation](docs/)
- ❓ [FAQ](docs/guides/faq.md)

## 🎓 Learning Resources

- [Architecture Overview](docs/architecture/overview.md)
- [API Documentation](docs/api/endpoints.md)
- [Development Guide](docs/guides/development.md)
- [Best Practices](docs/guides/best-practices.md)

## 🏆 Recognition

Contributors will be:
- Listed in [CONTRIBUTORS.md](CONTRIBUTORS.md)
- Mentioned in release notes
- Eligible for contributor swag

Thank you for contributing! 🙏
