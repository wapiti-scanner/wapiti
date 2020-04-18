install:
	python setup.py install

test:
	docker build -f Dockerfile.test --tag=wapiti_test .
	docker run --rm wapiti_test:latest
