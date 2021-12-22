#!/bin/bash

dpkg-buildpackage -b --no-sign

VERSION=$(dpkg-parsechangelog -S version)

dpkg-deb -c ../fus_${VERSION}_all.deb
