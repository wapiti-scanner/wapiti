install: clean
	pip3 install --no-deps -r requirements.txt 
	pip3 install --no-deps .

test:
	docker build -f Dockerfile.test --tag=wapiti_test .
	docker run --rm wapiti_test:latest

clean:
	rm -rf dist/ build/ wapiti3.egg-info/
