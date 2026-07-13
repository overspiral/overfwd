# Convenience targets for the shared GreenMail e2e mail server.
# Default to podman-compose (the working tool in this env). On a Docker host:
#   make mail-up COMPOSE="docker compose"
COMPOSE ?= podman-compose
PROJECT ?= overfwd-mail
API     ?= http://localhost:8080

# -p pins the project name so every worktree targets the SAME stack (idempotent).
DC = $(COMPOSE) -p $(PROJECT)

.PHONY: mail-up mail-down mail-reset mail-logs mail-status

mail-up:      ## Start the shared GreenMail stack (idempotent across worktrees)
	$(DC) up -d

mail-down:    ## Stop and remove the shared GreenMail stack
	$(DC) down

mail-reset:   ## Wipe all mailboxes/state without restarting the container
	@command -v curl >/dev/null && curl -fsS -XPOST $(API)/api/service/reset && echo \
		|| $(DC) restart greenmail

mail-status:  ## Show container + readiness
	$(DC) ps
	@command -v curl >/dev/null && curl -fsS $(API)/api/service/readiness && echo || true

mail-logs:    ## Follow GreenMail logs
	$(DC) logs -f greenmail
