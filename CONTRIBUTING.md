# Contributing to PrivateLine

This guide explains how to set up a local development environment and the coding standards used for the project. Following these steps ensures a consistent workflow for all contributors.

## Prerequisites

- **Python 3.11**
- **Node.js 18**
- **Xcode 15** if building the iOS client
- `git` and `Docker` for optional containerized workflows

## Setup

1. Install Python dependencies:

   ```bash
   pip install -r backend/requirements.txt
   ```

2. Install frontend dependencies:

   ```bash
   cd frontend
   npm install
   ```

3. (Optional) Build the iOS project in `ios/` with Xcode.

4. Run the unit tests to verify your environment:

   ```bash
   pytest
   npm test --if-present --prefix frontend
   ```

## Code Style

Python code follows **PEP8** using `flake8` for linting. JavaScript code follows the default ESLint rules created by `create-react-app`. Swift code follows standard Apple conventions. Please run formatters or linters when available.

## Updating the OpenAPI Specification

API changes require regenerating `docs/openapi.yaml`:

```bash
python backend/generate_openapi.py
```

The CI workflow runs this script and fails if the generated file differs from what is committed. Be sure to run the command and commit the updated file whenever you modify backend endpoints.

