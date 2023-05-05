set -e
#$(cd ../../ && docker build wapiti .);
#$(cd wp_enum && docker build wordpress .);
for file in $(find . -name "docker*")
do
	docker compose --verbose -f "$file" up -d
done
