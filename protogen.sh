#!/usr/bin/env bash

curdir=./entity
protos=(`find ./proto -name '*.proto'`)

# ----------------------------------------------------
#                 CLEANUP AND PREPARE
# ----------------------------------------------------
# Cleanup go related directories and files
rm -rf ./entity
mkdir ./entity

# ----------------------------------------------------
#           GENERATE GO STUBS FOR GOLANG
# ----------------------------------------------------
echo "---------------------------------------------";
echo "Generating standard proto files for Golang";
echo "---------------------------------------------";
# Protobuffer and GRPC generation
for i in "${!protos[@]}"; do
    if [[ ! -d "${curdir}/${protos[$i]}" ]]; then
echo "compiling: ${protos[$i]}";
protoc \
 -I proto \
 -I vendor/ \
 --go_out=./${curdir} \
 --go_opt=paths=source_relative \
"${protos[$i]}"
    fi
done
