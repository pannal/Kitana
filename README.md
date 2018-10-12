# Kitana
A Plex plugin web frontend

# building
docker build --rm --pull -t kitana . && docker tag kitana pannal/kitana:latest && docker push pannal/kitana:latest

# running
docker run --name kitana -v kitana_data:/app/data -d -p 127.0.0.1:31337:31337 pannal/kitana:latest -B 0.0.0.0:31337 -p /kitana -P

# upgrading
docker stop kitana && docker rm kitana && docker pull pannal/kitana:latest

re-run