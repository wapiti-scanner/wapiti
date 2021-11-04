install: clean
	python setup.py install

test:
	docker-compose -f docker-compose.yaml build
	docker-compose -f docker-compose.yaml up -d mysqldb postgresdb
	docker-compose -f docker-compose.yaml up tests
	docker-compose -f docker-compose.yaml down

clean:
	rm -rf dist/ build/ wapiti3.egg-info/
