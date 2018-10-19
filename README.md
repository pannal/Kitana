# <img src="https://github.com/pannal/Kitana/raw/master/static/img/android-icon-36x36.png" align="left" height="36" style="vertical-align: center">Kitana
A responsive Plex plugin web frontend

# building
docker build --rm --pull -t kitana . && docker tag kitana pannal/kitana:latest && docker push pannal/kitana:latest

# running
docker run --name kitana -v kitana_data:/app/data -d -p 127.0.0.1:31337:31337 pannal/kitana:latest -B 0.0.0.0:31337 -p /kitana -P

# upgrading
docker stop kitana && docker rm kitana && docker pull pannal/kitana:latest

re-run
