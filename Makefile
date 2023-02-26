clean:
	@rm -rf build __pycache__ powerhub.egg-info docs/_build .docvenv .tox

docs:
	@find .docvenv -maxdepth 0 -type d || python3 -m venv .docvenv ; \
	. .docvenv/bin/activate ; \
	cd docs ; \
	python3 -m pip install -r requirements.txt ; \
	sphinx-build . _build

test:
	tox

.PHONY: clean docs
