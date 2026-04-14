---
name: naming-conventions
applyTo: '**/*'
---

# Naming Conventions for Workflows and Files

## Purpose
This instruction enforces consistent naming conventions for workflows and other files in the project. It ensures clarity, maintainability, and adherence to project standards.

## Rules
1. **Workflows**:
   - Use `snake_case` for workflow file names.
   - Include a clear description of the workflow purpose (e.g., `build_and_test.yml`).

2. **Other Files**:
   - Use `kebab-case` for general files (e.g., `project-readme.md`).
   - Use `PascalCase` for class files (e.g., `MyClass.java`).

3. **General Guidelines**:
   - Avoid spaces in file names.
   - Use descriptive and concise names.
   - Include file extensions appropriate to the content.

## Examples
- Workflows: `deploy_to_production.yml`, `run_tests.yml`
- General Files: `user-guide.md`, `api-documentation.md`
- Class Files: `UserService.java`, `OrderProcessor.java`

## Quality Checks
- Ensure all new files follow the naming conventions.
- Review existing files periodically to maintain consistency.