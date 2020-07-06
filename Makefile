install: clean update
	python setup.py install

test:
	docker build -f Dockerfile.test --tag=wapiti_test .
	docker run --rm wapiti_test:latest

update:
	@if [ ! -d "wapitiCore/nikto/data" ]; then mkdir wapitiCore/nikto; mkdir wapitiCore/nikto/data; fi
	curl -# -C - https://raw.githubusercontent.com/sullo/nikto/master/program/databases/db_tests > wapitiCore/nikto/data/nikto_db

clean:
	rm -rf dist/ build/
