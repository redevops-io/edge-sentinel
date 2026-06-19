.PHONY: up down logs lint test

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

lint:
	ruff check .
	prettier --check .

test:
	pytest
