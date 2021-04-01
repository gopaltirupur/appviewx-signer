#!/bin/bash

DOCKER_PREFIX=appviewx-istio/appviewx-signer
DOCKER_TAG=1.0
d=$(date '+%d-%b-%Y-%T')
mkdir ../build/$d

echo "building the operator"
cd ..
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go;

echo "operator builded successfully"


cp ./bin/defaults/appviewx.env ./build/$d/
cp ./bin/defaults/istio.yaml ./build/$d/
cp ./bin/defaults/install.sh ./build/$d/
cp ./bin/defaults/external-ca-secret.yaml ./build/$d/
cp -r ./config ./build/$d/

make docker-build DOCKER_PREFIX=$DOCKER_PREFIX/ DOCKER_TAG=$DOCKER_TAG;
docker save -o ./build/$d/appviewx-signer.tar $DOCKER_PREFIX/controller:$DOCKER_TAG;

echo $(pwd)
echo "Installation success"

#cd ./build
#tar -cvzf $d.tar.gz ./$d
#rm -rf $d
