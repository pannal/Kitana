# <img src="https://github.com/pannal/Kitana/raw/master/static/img/android-icon-36x36.png" align="left" height="36" style="vertical-align: center">Kitana
[![](https://img.shields.io/github/release/pannal/Kitana.svg?style=flat&label=current)](https://github.com/pannal/Kitana/releases/latest) [![Maintenance](https://img.shields.io/maintenance/yes/2021.svg)]() [![Slack Status](https://szslack.fragstore.net/badge.svg)](https://szslack.fragstore.net) [![master](https://img.shields.io/badge/master-stable-green.svg?maxAge=2592000)]()

A responsive Plex plugin web frontend


If you like this, buy me a beer: <br>[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=G9VKR2B8PMNKG) <br>or become a Patreon starting at **1 $ / month** <br><a href="https://www.patreon.com/subzero_plex" target="_blank"><img src="https://cdn.iconscout.com/icon/free/png-256/patreon-282262.png" height="54" /></a>



## Introduction
#### What is Kitana?
Kitana exposes your Plex plugin interfaces "to the outside world". It does that by authenticating against Plex.TV, then connecting to the Plex Media Server you tell it to, and essentially proxying the plugin UI.
It has full PMS connection awareness and allows you to connect locally, remotely, or even via relay.

It does that in a responsive way, so your Plugins are easily managable from your mobile phones for example, as well.

***Running one instance of Kitana can serve infinite amounts of servers and plugins*** - you can even expose your Kitana instance to your friends, so they can manage their plugins as well, so they don't have to run their own Kitana instance.

Kitana was built for [Sub-Zero](https://github.com/pannal/Sub-Zero.bundle) originally, but handles other plugins just as well.

#### Isn't that a security concern?
Not at all. Without a valid Plex.TV authentication, Kitana can do nothing. All authentication data is stored serverside inside the current user's session storage (which is long running), so unwanted third party access to your server is virtually impossible. 

#### The Plex plugin UIs still suck, though!
Yes, they do. Kitana does little to improve that, besides adding responsiveness to the whole situation.

Also, it isn't designed to. Kitana is an intermediate solution to the recent problem posed by Plex Inc. and their plans to phase out all UI-based plugins from the Plex Media Server environment.

## Features
- small footprint by using the CherryPy framework
- heavy caching for faster plugin handling
- full PMS connection awareness and automatic fallback in case the configured connection is lost
- fully responsive (CSS3)
- made to run behind reverse proxies (it doesn't provide its own HTTPS interface)
- fully cross-platform 

## Screenshots
[Imgur Gallery](https://imgur.com/a/ovzXdjt)

## Installation
### Docker (the easy way, Windows included)
Install [Docker](https://docs.docker.com/install/#supported-platforms)

#### Standalone
This launches Kitana on port 31337:
- ```docker run --name kitana --restart unless-stopped -v kitana_data:/app/data -d -p 0.0.0.0:31337:31337 pannal/kitana:latest -B 0.0.0.0:31337```

#### Mount behind a reverse proxy (example: NGINX)
- ```docker run --name kitana --restart unless-stopped -v kitana_data:/app/data -d -p 127.0.0.1:31337:31337 pannal/kitana:latest -B 0.0.0.0:31337 -P```

#### Mount on /kitana and behind a reverse proxy (example: NGINX)
- ```docker run --name kitana --restart unless-stopped -v kitana_data:/app/data -d -p 127.0.0.1:31337:31337 pannal/kitana:latest -B 0.0.0.0:31337 -p /kitana -P```

#### Upgrading
- `docker stop kitana && docker rm kitana && docker pull pannal/kitana:latest`, then re-run it with the command above

### Docker-compose
```
  kitana:
    image: pannal/kitana:latest
    container_name: kitana
    volumes:
      - /FOLDER/TO/KITANA_DATA:/app/data
    ports:
      - 31337:31337
    links:
      - plex
    command: -B 0.0.0.0:31337 -p /kitana -P
    restart: unless-stopped
```

### Manual installation
Requirements:
- Python3.5

Installation:
- go to the Kitana folder
- `pip3 install -r requirements.txt`

Running:
- `python3 kitana.py`

#### Windows
- install Python 3.5 (preferrably [ActivePython](https://www.activestate.com/activepython/downloads))
- `pip3.5 install -r requirements_win32.txt`

Running:
- `python3.5 kitana.py` (Note: asset proxying seems slow on win32, adding `--shadow-assets=False` is advised)

Running behind IIS:
- `%windir%\system32\inetsrv\appcmd.exe set config -section:system.webServer/proxy -preserveHostHeader:true /commit:apphost` ([Stackoverflow](https://stackoverflow.com/a/14842856))

## Deployment
I've included [sample configs](https://github.com/pannal/Kitana/tree/master/deployment) for running Kitana using supervisord, and an NGINX reverse-proxy sample config you can use.

#### Portainer
- https://github.com/pannal/Kitana/issues/26#issuecomment-570200679

## Usage
- run kitana (see above)
- open your browser and visit your Kitana instance (standalone: http://your-ip:31337)
- authenticate against Plex.TV
- select your server (non-owned may not work; local connections are preferred)
- profit

#### Command line options (`python kitana.py --help`)
```
usage: kitana.py [-h] [-B HOST:PORT] [-a [BOOL]] [-i PLUGIN_IDENTIFIER]
                 [-l LANGUAGE] [-p PREFIX] [-P [BOOL]] [-PH [PROXY_HOST_VAR] |
                 -PB PROXY_BASE] [--shadow-assets [BOOL]] [-t TIMEOUT]
                 [-pt PLEXTV_TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  -B HOST:PORT, --bind HOST:PORT
                        Listen on address:port (default: 0.0.0.0:31337)
  -a [BOOL], --autoreload [BOOL]
                        Watch project files for changes and auto-reload?
                        (default: False)
  -i PLUGIN_IDENTIFIER, --plugin-identifier PLUGIN_IDENTIFIER
                        The default plugin/channel to view on a server
                        (default: com.plexapp.agents.subzero)
  -l LANGUAGE, --plugin-language LANGUAGE
                        The language to request when interacting with plugins
                        (default: en)
  -p PREFIX, --prefix PREFIX
                        Prefix to handle; used for reverse proxies normally
                        (default: "/")
  -P [BOOL], --behind-proxy [BOOL]
                        Assume being ran behind a reverse proxy (default:
                        False)
  -PH [PROXY_HOST_VAR], --proxy-host-var [PROXY_HOST_VAR]
                        When behind reverse proxy, get host from this var
                        (NGINX: "Host", Squid: "Origin", Lighty/Apache:
                        "X-Forwarded-Host", IIS: "Host" (see README))
                        (default: "Host")
  -PB PROXY_BASE, --proxy-base PROXY_BASE
                        When behind a reverse proxy, assume this base URI
                        instead of the bound address (e.g.: http://host.com;
                        no slash at the end). Do *not* include the :prefix:
                        here. (default: "Host (NGINX)")
  --shadow-assets [BOOL]
                        Pass PMS assets through the app to avoid exposing the
                        plex token? (default: True)
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout to the PMS (default: 5)
  -pt PLEXTV_TIMEOUT, --plextv-timeout PLEXTV_TIMEOUT
                        Connection timeout to the Plex.TV API (default: 15)
  --allow-not-owned [BOOL]
                        Allow access to not-owned servers? (default: False)

BOOL can be:
True: "y, yes, t, true, True, on, 1"
False: "n, no, f, false, False, off, 0".

[BOOL] indicates that when the switch but no value is given, True is used.

```

## Todo
- use proper logging interface (as of now, `print()` is used)
- add verbosity options
- add HTTPS option
- allow the use of config files instead of the command line options
- add an auto update mechanism for everything but Docker
- (implement a video player for video plugins?)
- add theming engine
- add service for win32

## Acknowledgments
- Thanks to Tautulli for providing the [Javascript for proper authentication with Plex.TV](https://github.com/Tautulli/Tautulli/blob/master/data/interfaces/default/js/script.js).
- Icon/Art based on Fan Icon from [http://www.malagatravelguide.net](http://www.malagatravelguide.net)
- PyWin32 CherryPy Console/Service handler from [googleappengine](https://chromium.googlesource.com/external/googleappengine/python/+/master/lib/cherrypy/cherrypy/process/win32.py)
