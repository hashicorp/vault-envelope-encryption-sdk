#!/usr/bin/env bash

echo "==> Checking that code complies with gofumpt requirements..."

go_files=$(find . -name '*.go' | grep -v vendor)
gofmt_files=$(gofumpt -l ${go_files})
if [[ -n ${gofmt_files} ]]; then
    echo 'gofmt needs running on the following files:'
    echo "${gofmt_files}"
    echo "You can use the command: \`make fmt\` to reformat code."
    exit 1
fi

echo "==> Checking that code complies with goimports requirements..."

goimports_files=$(goimports -l ${go_files})
if [[ -n ${goimports_files} ]]; then
    echo 'goimports needs running on the following files:'
    echo "${goimports_files}"
    echo "You can use the command: \`make fmt\` to reformat code."
    exit 1
fi