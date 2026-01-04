# Makefile for ssl.mojo

# Test commands
TEST_SPECS := pixi run test-specs
TEST_CRYPTO := pixi run test-crypto
TEST_TLS := pixi run test-tls
TEST_ALL := pixi run test-all

.PHONY: test-specs test-crypto test-tls test-all

test-specs:
	$(TEST_SPECS)

test-crypto:
	$(TEST_CRYPTO)

test-tls:
	$(TEST_TLS)

test-all:
	$(TEST_ALL)

# Git worktree commands
# Usage:
#   make worktree-add <branch>
#   make worktree-list
#   make worktree-remove <branch>

.PHONY: worktree-add worktree-list worktree-remove

# Extract the branch name from the command line arguments
ifeq ($(firstword $(MAKECMDGOALS)),$(filter $(firstword $(MAKECMDGOALS)),worktree-add worktree-remove))
  BRANCH_ARG := $(word 2,$(MAKECMDGOALS))
  # This prevents make from complaining about the branch being a missing target
  $(eval $(BRANCH_ARG):;@:)
endif

worktree-add:
	@if [ -z "$(BRANCH_ARG)" ]; then \
		echo "Usage: make worktree-add <branch>"; \
		exit 1; \
	fi
	@if git rev-parse --verify $(BRANCH_ARG) >/dev/null 2>&1; then \
		git worktree add worktrees/$(BRANCH_ARG) $(BRANCH_ARG); \
	else \
		git worktree add -b $(BRANCH_ARG) worktrees/$(BRANCH_ARG) main; \
	fi

worktree-list:
	git worktree list

worktree-remove:
	@if [ -z "$(BRANCH_ARG)" ]; then \
		echo "Usage: make worktree-remove <branch>"; \
		exit 1; \
	fi
	git worktree remove worktrees/$(BRANCH_ARG)

