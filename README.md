# FileUploadServer

Small HTTP(S)/FTP server to share some files.

Inspired by droopy but with support for

- multiple directories
- muliple accounts
- letsencrypt certificate renewal

## Letsencrypt Support (mostly untested)

Letsencrypt certificate renewal offers a HTTP01_challenge consisting of
`token` and `thumb` to be downloadable from URL

`http://domain/.well-known/acme-challenge/token`.

To install the challenge on the FileUploadServer just issue an HTTP
GET to URL

`http://domain/.well-known/acme-challenge/upload/token/thumb`, e.g.

    curl -i http://my.domain/.well-known/acme-challenge/upload/some_token/some_thumb
    HTTP/1.0 200 OK
    Content-Type: text/plain; charset=utf-8
    Content-Length: 2
    Server: Werkzeug/0.12.2-dev Python/3.6.3
    Date: Mon, 20 Nov 2017 10:24:55 GMT

    ok 

Now the challenge will be answered:

    % curl -i http://my.domain/.well-known/acme-challenge/some_token 
    HTTP/1.0 200 OK
    Content-Type: text/plain; charset=utf-8
    Content-Length: 21
    Server: Werkzeug/0.12.2-dev Python/3.6.3
    Date: Mon, 20 Nov 2017 10:26:17 GMT

    some_token.some_thumb%

## Building

`$ build.sh` will build a Debian package.

## Installation

`$ sudo dpkg -i fus_1.1.0_all.deb` installs the package. It is
integrated with systemd, hence:

Startup: `$ sudo systemctl start fus.service`

Stopping: `$ systemcts stop fus.service`

Autostart after reboot: `$systemctl enable fus.service`

Status: `$ sudo systemctl status fus.conf`

Troubleshooting: e.g. `$ sudo journalctl -xe`


Configuration is in /etc/fus.conf. 



 
