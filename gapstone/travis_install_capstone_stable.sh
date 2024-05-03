#!/bin/sh

set -ex
mkdir -p $HOME/src && cd $HOME/src
git clone --depth=50 --branch=4.0.2 https://github.com/knightsc/gapstone.git && cd capstone
echo `git log | head`
PREFIX=$HOME/capstone make && PREFIX=$HOME/capstone make install
cd $TRAVIS_BUILD_DIR