docker stop $(docker ps -a -q)
docker container prune -f 
