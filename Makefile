PYTHON ?= python
.PHONY: test demo evaluate
test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s adversarial -v
demo:
	PYTHONPATH=src $(PYTHON) -m capability_guard demo --output artifacts/demo.json
evaluate:
	PYTHONPATH=src $(PYTHON) -m capability_guard evaluate --output artifacts/evaluation.json
