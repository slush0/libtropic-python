# Critical Development Rules

These rules from CLAUDE.md MUST be followed strictly:

## 1. Minimal Change Principle
- **NEVER implement more functionality than explicitly requested**
- Bug fix = fix only that bug (no surrounding improvements)
- Feature request = implement only that feature (no extras)
- Resist urge to refactor, optimize, or enhance unrequested code

## 2. Scope Discipline
- **NEVER change or refactor code not directly related to request**
- Before modifying any function, ask: "Is this directly involved in the request?"
- Found unrelated issues? Note them but DON'T fix unless asked
- Keep pull requests focused and reviewable

## 3. Code Readability Over Cleverness
- **Keep source code well-documented with intentions**
- Every non-trivial block needs comment explaining PURPOSE (why, not what)
- Prefer explicit, verbose code over clever one-liners
- Use descriptive variable names revealing intent

## 4. Avoid Premature Abstraction
- **Avoid duplicating code, but NOT at cost of branching/limiting readability**
- Similar code serving different purposes may be intentionally duplicated
- Don't create abstractions used only once or twice
- Don't abstract if it makes debugging harder
- Threshold for extracting function: 3+ uses AND improves understanding

## 5. Tests Are Immutable Guards
- **NEVER modify tests unless explicitly requested by user**
- Tests detect breaking changes - they must remain stable
- If tests fail after changes, the CODE is wrong, not tests

## 6. Propose Test Coverage Separately
- **After implementing, propose test updates and ask for approval**
- List what new tests/modifications needed
- Wait for explicit confirmation before touching test files

## 7. Concise Git Commits
- **Keep commit messages short - use bullet points if needed**
- Focus on WHY, less on WHAT/HOW

## 8. 1:1 C Library Parity
- **API must mirror libtropic C library** - same functions, same behavior
- **Test coverage must mirror C tests** - port all C unit tests
- **No feature creep** - if not in C library, don't implement here
- Reference: `libtropic-upstream/` for API and test specs

## Workflow Summary

When user requests a change:

1. **Understand exact scope** - what specifically was requested?
2. **Make minimal changes** - touch only directly related code
3. **Document intentions** - add comments explaining WHY
4. **Run quality checks** - mypy, ruff, pytest
5. **Propose tests** - list needed test changes, wait for approval
6. **Commit if requested** - brief message focusing on why

## Red Flags to Avoid

- "While I'm here, let me also..."
- "This could be improved by..."
- "I'll just refactor this quickly..."
- "Let me update these tests to match..."
- "I'll add some extra error handling..."

If you catch yourself thinking these thoughts, STOP and refocus on the exact request.
