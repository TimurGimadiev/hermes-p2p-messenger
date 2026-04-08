# Hermes P2P Messenger — Makefile

.PHONY: run test clean setup

# Run the P2P CLI chat
run:
	python3 cli.py

# Run as server (bootstrap node)
serve:
	python3 cli.py --serve

# Run with custom identity
identity:
	python3 cli.py --identity $(id)

# Run tests
test:
	python3 -m pytest tests/ -v

# Setup environment
setup:
	pip3 install -r requirements.txt

# Clean
clean:
	rm -rf build/ dist/ *.egg-info __pycache__ hermes_p2p/__pycache__
