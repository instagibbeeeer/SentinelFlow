.PHONY: up down attack normal status logs test
up:
	docker compose up -d --build kafka-1 kafka-2 kafka-3 cassandra-1 cassandra-2 cassandra-3 kafka-init cassandra-init event-writer spark-master spark-worker-1 spark-worker-2 spark-job api agent
normal:
	docker compose --profile demo run --rm simulator python simulator.py normal
attack:
	docker compose --profile demo run --rm simulator python simulator.py attack
status:
	docker compose ps
	docker compose exec cassandra-1 nodetool status
logs:
	docker compose logs -f --tail=100 agent spark-job event-writer
down:
	docker compose down
test:
	python -m pytest -q
