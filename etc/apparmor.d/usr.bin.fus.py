# Last Modified: Wed Dec 15 22:39:32 2021
abi <abi/3.0>,

include <tunables/global>

/usr/bin/fus.py {
  include <abstractions/base>
  include <abstractions/nis>
  include <abstractions/openssl>
  include <abstractions/python>

  network inet stream,
  network inet6 stream,

  deny /usr/local/lib/python3.9/dist-packages/hnswlib-0.4.0-py3.9-linux-x86_64.egg/ r,

  /etc/fus.conf r,
  /etc/mime.types r,
  /etc/ssl/certs/eierkopp.crt r,
  /etc/ssl/private/eierkopp.key r,
  /usr/bin/ r,
  /usr/bin/fus.py r,
  /usr/bin/python3.9 ix,
  owner /dev/shm/* rwl,
  owner /home/fus/data/{,**} r,
  owner /home/fus/data/{,**} w,
  owner /var/log/fus/* rw,
  owner /{usr/,}lib{,32,64}/** rw,

}
