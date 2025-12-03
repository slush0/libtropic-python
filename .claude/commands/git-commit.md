---
allowed-tools: Bash(git add:*), Bash(git status:*), Bash(git commit:*)
description: Create a git commit
---

## Context

- Current git status: !`git status`
- Current git diff (staged and unstaged changes): !`git diff HEAD`
- Current branch: !`git branch --show-current`
- Recent commits: !`git log --oneline -3`

## Your task

Based on the above changes, compose concise commit message focused on features and functionality and create a single git commit. Avoid describtion of HOW, focus on WHAT. Add $1 as first line of commit message if provided by user.
