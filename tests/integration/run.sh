set -e

# gerer les params

# charger les tests dans wapiti

for file in $(find . -name "docker*")
do
	docker compose --verbose -f "$file" up -d
done

#boucle sur les params
	# requetes sur les modules
	# tests des requetes
	# si test fail, casse la boucle
# fin boucle

# cleanup process
