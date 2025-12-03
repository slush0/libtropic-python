# Task Completion Checklist

When a development task is completed, follow this checklist to ensure code quality:

## 1. Type Checking
```bash
mypy src/libtropic
```
- All type hints must be present
- No mypy errors allowed
- Fix any type issues before proceeding

## 2. Linting
```bash
ruff check src tests
```
- Code must pass all ruff checks
- Fix any linting errors
- Use `ruff check --fix` for auto-fixable issues

## 3. Testing
```bash
# Run unit tests (always required)
pytest tests/unit/ tests/test_imports.py -v

# Or use the script
./tests/run_unit_tests.sh
```
- All existing tests must pass
- **NEVER modify existing tests unless explicitly requested by user**
- If tests fail, the code is wrong (not the tests)

## 4. Test Coverage (if new code added)
After implementing new features, **propose** test additions to the user:
- List what new tests would be needed
- Wait for user approval before adding tests
- Never add tests proactively without request

## 5. Code Review Self-Check
Before marking task complete:
- [ ] Changes are minimal (only what was requested)
- [ ] No unrelated refactoring was done
- [ ] Code has comments explaining WHY (not just what)
- [ ] All public APIs have docstrings
- [ ] Variable names are descriptive
- [ ] No duplication unless it improves readability
- [ ] Follows C library API conventions
- [ ] No feature creep (nothing beyond request)

## 6. Git Commit (if requested)
```bash
git add <files>
git commit -m "Brief description

- Bullet point of change if needed

🤖 Generated with Claude Code"
```
- Keep commit messages concise
- Focus on WHY, not just WHAT
- Use bullet points for multiple changes

## Important Notes

### DO NOT (unless explicitly requested):
- ❌ Modify existing tests
- ❌ Refactor unrelated code
- ❌ Add "improvements" beyond the request
- ❌ Change code style of existing code
- ❌ Add features not in the C library

### ALWAYS:
- ✅ Run mypy and ruff before completing
- ✅ Ensure all tests pass
- ✅ Propose test updates separately
- ✅ Add meaningful code comments
- ✅ Keep changes minimal and focused
- ✅ Match C library API behavior exactly

### Remember:
1. **Minimal Change Principle** - Only change what's needed
2. **Scope Discipline** - Don't touch unrelated code
3. **Tests Are Guards** - Never modify without explicit request
4. **Propose, Don't Assume** - Ask before adding tests or features
