install: clean
	pip3 install .

test:
	docker build -f Dockerfile.test --tag=wapiti_test .
	docker run --rm wapiti_test:latest

integration-test:
	./tests/integration/run.sh

integration-clean:
	rm -rf ./tests/integration/.test/* .dump_diff_file.txt 

wapiti-endpoint:
	docker build -f Dockerfile.endpoint -t wapiti-endpoint .
	docker run --rm -dit --name wapiti-running-endpoint -p 80:80 wapiti-endpoint

clean:
	rm -rf dist/ build/ wapiti3.egg-info/

release: clean
	python -m build --sdist --wheel