install: clean update
	python setup.py install

test:
	docker build -f Dockerfile.test --tag=wapiti_test .
	docker run --rm wapiti_test:latest

update:
	curl -# -z wapitiCore/wappalyzer/data/apps.json -C - https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/apps.json > wapitiCore/wappalyzer/data/apps.json

clean:
	rm -rf dist/ build/
