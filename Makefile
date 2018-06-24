PYTHON=python
ALGOS=$(shell $(PYTHON) pqcalgos.py all)

all: $(ALGOS) test

%/pqc_cli: %
	make -C $<

test:
	$(PYTHON) pqc.py test
