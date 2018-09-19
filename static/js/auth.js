
// borrowed from: https://github.com/Tautulli/Tautulli/blob/master/data/interfaces/default/js/script.js

function PopupCenter(url, title, w, h) {
    // Fixes dual-screen position                         Most browsers      Firefox
    var dualScreenLeft = window.screenLeft != undefined ? window.screenLeft : window.screenX;
    var dualScreenTop = window.screenTop != undefined ? window.screenTop : window.screenY;

    var width = window.innerWidth ? window.innerWidth : document.documentElement.clientWidth ? document.documentElement.clientWidth : screen.width;
    var height = window.innerHeight ? window.innerHeight : document.documentElement.clientHeight ? document.documentElement.clientHeight : screen.height;

    var left = ((width / 2) - (w / 2)) + dualScreenLeft;
    var top = ((height / 2) - (h / 2)) + dualScreenTop;
    var newWindow = window.open(url, title, 'scrollbars=yes, width=' + w + ', height=' + h + ', top=' + top + ', left=' + left);

    // Puts focus on the newWindow
    if (window.focus) {
        newWindow.focus();
    }

    return newWindow;
}

var plex_oauth_window = null;
const plex_oauth_loader = '<style>' +
        '.login-loader-container {' +
            'font-family: "Open Sans", Arial, sans-serif;' +
            'position: absolute;' +
            'top: 0;' +
            'right: 0;' +
            'bottom: 0;' +
            'left: 0;' +
        '}' +
        '.login-loader-message {' +
            'color: #282A2D;' +
            'text-align: center;' +
            'position: absolute;' +
            'left: 50%;' +
            'top: 25%;' +
            'transform: translate(-50%, -50%);' +
        '}' +
        '.login-loader {' +
            'border: 5px solid #ccc;' +
            '-webkit-animation: spin 1s linear infinite;' +
            'animation: spin 1s linear infinite;' +
            'border-top: 5px solid #282A2D;' +
            'border-radius: 50%;' +
            'width: 50px;' +
            'height: 50px;' +
            'position: relative;' +
            'left: calc(50% - 25px);' +
        '}' +
        '@keyframes spin {' +
            '0% { transform: rotate(0deg); }' +
            '100% { transform: rotate(360deg); }' +
        '}' +
    '</style>' +
    '<div class="login-loader-container">' +
        '<div class="login-loader-message">' +
            '<div class="login-loader"></div>' +
            '<br>' +
            'Redirecting to the Plex login page...' +
        '</div>' +
    '</div>';

function closePlexOAuthWindow() {
    if (plex_oauth_window) {
        plex_oauth_window.close();
    }
}

getPlexOAuthPin = function () {
    var deferred = $.Deferred();
    console.log(x_plex_headers);

    $.ajax({
        url: 'https://plex.tv/api/v2/pins?strong=true',
        type: 'POST',
        headers: x_plex_headers,
        success: function(data) {
            plex_oauth_window.location = 'https://app.plex.tv/auth/#!?clientID=' + x_plex_headers['X-Plex-Client-Identifier'] + '&code=' + data.code;
            deferred.resolve({pin: data.id, code: data.code});
        },
        error: function() {
            closePlexOAuthWindow();
            deferred.reject();
        }
    });
    return deferred;
};

var polling = null;

function PlexOAuth(success, error, pre) {
    if (typeof pre === "function") {
        pre()
    }
    clearTimeout(polling);
    closePlexOAuthWindow();
    plex_oauth_window = PopupCenter('', 'Plex-OAuth', 600, 700);
    $(plex_oauth_window.document.body).html(plex_oauth_loader);

    getPlexOAuthPin().then(function (data) {
        const pin = data.pin;
        const code = data.code;
        var keep_polling = true;

        (function poll() {
            polling = setTimeout(function () {
                $.ajax({
                    url: 'https://plex.tv/api/v2/pins/' + pin,
                    type: 'GET',
                    headers: x_plex_headers,
                    success: function (data) {
                        if (data.authToken){
                            keep_polling = false;
                            closePlexOAuthWindow();
                            if (typeof success === "function") {
                                success(data.authToken)
                            }
                        }
                    },
                    error: function () {
                        keep_polling = false;
                        closePlexOAuthWindow();
                        if (typeof error === "function") {
                            error()
                        }
                    },
                    complete: function () {
                        if (keep_polling){
                            poll();
                        } else {
                            clearTimeout(polling);
                        }
                    },
                    timeout: 1000
                });
            }, 1000);
        })();
    }, function () {
        closePlexOAuthWindow();
        if (typeof error === "function") {
            error()
        }
    });
}