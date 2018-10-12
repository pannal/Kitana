# Kitana
A Plex plugin web frontend


docker build --rm --pull -t kitana .
docker run --name kitana -d -p 127.0.0.1:31337:31337 pannal/kitana:latest -B 0.0.0.0:31337 -p /kitana -P