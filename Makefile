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

# \n in sed only works in GNU sed
release:
	@read -p "Enter version string (Format: x.y.z): " version; \
    echo "Version Bump: $$version"; \
	date=$$(date +%F); \
	sed -i "s/^version = \".*\"/version = \"$$version\"/" pyproject.toml && \
	sed -i "s/^## \[Unreleased\]/## [Unreleased]\n\n## [$$version] - $$date/" CHANGELOG.md && \
	git add CHANGELOG.md pyproject.toml && \
	git commit -m "Version bump: $$version" && \
	read -p "Committed. Do you want to tag and push the new version? [y/n] " ans && \
	if [ $$ans = 'y' ] ; then git tag $$version && git push && git push origin tag $$version && echo "Tagged and pushed." ; else echo "Tag it and push it yourself then." ; fi

.PHONY: clean docs test release
