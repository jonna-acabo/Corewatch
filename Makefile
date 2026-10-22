.PHONY: install dev demo test lint docker up monitoring lab

install:
	cd backend && pip install -r requirements-dev.txt

dev:
	cd backend && uvicorn app.main:app --reload

demo:   ## fast escalations, no random faults: drive it from the Simulate menu
	cd backend && SIM_FAULT_CHANCE=0 ESCALATION_MINUTE_SECONDS=5 uvicorn app.main:app

test:
	cd backend && SIM_ENABLED=false pytest --cov=app

lint:
	cd backend && ruff check .

docker:
	docker build -t corewatch:local .

up:
	docker compose up --build

monitoring:
	docker compose --profile monitoring up --build

lab:    ## poll real/virtual Junos devices: set LAB_DEVICES, LAB_USERNAME, LAB_PASSWORD first
	cd backend && pip install -r requirements-lab.txt && python -m app.lab
