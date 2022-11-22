install: clean
	pip3 install .

test:
	docker build -f Dockerfile.test --tag=wapiti_test .
	docker run --rm wapiti_test:latest

clean:
	rm -rf dist/ build/ wapiti3.egg-info/
