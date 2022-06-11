#!/usr/bin/env zsh

# Change the values below to your own environment
# The remote host is a MacOS machine
LOCAL_ROOT=/home/chris/Projects/kittendns
REMOTE_ROOT=/Users/chris/Projects/kittendns
REMOTE_PATH=/Users/chris/.asdf/shims
REMOTE_GOPATH=/Users/chris/go
REMOTE_HOST=192.168.1.204

# Exit immediataly on error code
set -e

info() {
  echo ""
  echo "################################################################################"
  echo "$1"
  echo "################################################################################"
  echo ""
}

remoteprepare() {
  info "Preparing remote environment for execution"
  ssh $REMOTE_HOST mkdir -p $REMOTE_ROOT/scripts
  scp $LOCAL_ROOT/scripts/release.sh $REMOTE_HOST:$REMOTE_ROOT/scripts/release.sh
  ssh $REMOTE_HOST chmod +x $REMOTE_ROOT/scripts/release.sh
}

localmake() {
  branch="$1"
  info "Building local $branch environment"
  cd $LOCAL_ROOT
  git checkout $branch
  git pull
  [[ -d dist ]] && rm -rf dist
  make release
  make plugins
}

requestremotemake() {
  branch="$1"
  info "Requesting remote $branch build"
  ssh -t $REMOTE_HOST GOPATH=$REMOTE_GOPATH PATH=$REMOTE_PATH:\$PATH $REMOTE_ROOT/scripts/release.sh $branch iamremote
}

remotemake() {
  branch="$1"
  info "Building remote $branch environment"
  cd $REMOTE_ROOT
  git checkout $branch
  git pull
  [[ -d dist ]] && rm -rf dist
  make release_darwin
  make plugins_darwin
}

retrieveremote() {
  info "Retrieving remote artifacts"
  for pkg in $(ssh $REMOTE_HOST ls $REMOTE_ROOT/dist); do
    for artefact in $(ssh $REMOTE_HOST ls $REMOTE_ROOT/dist/$pkg); do
      mkdir -p $LOCAL_ROOT/dist/$pkg
      scp $REMOTE_HOST:$REMOTE_ROOT/dist/$pkg/$artefact $LOCAL_ROOT/dist/$pkg/$artefact
      echo $artefact
    done
  done
}

archivelocal() {
  info "Archiving local artifacts"
  cd dist
  [[ -f *.zip ]] && rm -f *.zip
  for pkg in *; do
    echo $pkg
    cd $pkg
    zip ../$pkg.zip *
    cd ..
  done
  cd ..
}

ACT="$1"
[[ "$2" == "iamremote" ]] && ACT=${ACT}remote

case $ACT in
  dev)
    localmake dev
    remoteprepare
    requestremotemake dev
    retrieveremote
    archivelocal
    ;;
  main)
    localmake main
    remoteprepare
    requestremotemake main
    retrieveremote
    archivelocal
    ;;
  devremote)
    remotemake dev
    ;;
  mainremote)
    remotemake main
    ;;
  *)
    echo "Select dev or main."
    ;;
esac
