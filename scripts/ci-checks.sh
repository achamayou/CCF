#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if [ "$1" == "-f" ]; then
  FIX=1
else
  FIX=0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ROOT_DIR=$( dirname "$SCRIPT_DIR" )
pushd "$ROOT_DIR" > /dev/null

# GitHub actions workflow commands: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
function group(){
    # Only do this in GitHub actions, where CI is defined according to
    # https://docs.github.com/en/actions/learn-github-actions/environment-variables#default-environment-variables
    if [[ ${CI} ]]; then
      echo "::group::$1"
    else
      echo "-=[ $1 ]=-"
    fi
}
function endgroup() {
    if [[ ${CI} ]]; then
      echo "::endgroup::"
    fi
}


group "Shell scripts"
git ls-files | grep -e '\.sh$' | grep -E -v "^3rdparty" | xargs shellcheck -S warning -s bash
endgroup

# No inline TODOs in the codebase, use tickets, with a pointer to the code if necessary.
group "TODOs"
"$SCRIPT_DIR"/check-todo.sh .
endgroup

group "Public includes"
# Enforce that no private headers are included from public header files
violations=$(find "$ROOT_DIR/include/ccf" -type f -print0 | xargs --null grep -e "#include \"" | grep -v "#include \"ccf" | sort)
if [[ -n "$violations" ]]; then
  echo "Public headers include private implementation files:"
  echo "$violations"
  exit 1
else
  echo "No public-private include violations"
fi
endgroup

group "Public header namespaces"
# Enforce that all public headers namespace their exports
# NB: This only greps for a namespace definition in each file, doesn't precisely enforce that no types escape that namespace - mistakes are possible
violations=$(find "$ROOT_DIR/include/ccf" -type f -name "*.h" -print0 | xargs --null grep -L "namespace ccf" | sort || true)
if [[ -n "$violations" ]]; then
  echo "Public headers missing ccf namespace:"
  echo "$violations"
  exit 1
else
  echo "No public header namespace violations"
fi
endgroup

group "Release notes"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/extract-release-notes.py -f
else
  "$SCRIPT_DIR"/extract-release-notes.py
fi
endgroup

group "C/C++ format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-format.sh -f include src samples
else
  "$SCRIPT_DIR"/check-format.sh include src samples
fi
endgroup

group "Headers are included"
"$SCRIPT_DIR"/headers-are-included.sh

group "TypeScript, JavaScript, Markdown, TypeSpec, YAML and JSON format"
npm install --loglevel=error --no-save prettier @typespec/prettier-plugin-typespec 1>/dev/null
if [ $FIX -ne 0 ]; then
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | grep -v -e 'tests/sandbox/' | xargs npx prettier --write
else
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | grep -v -e 'tests/sandbox/' | xargs npx prettier --check
fi
endgroup

group "OpenAPI"
npm install --loglevel=error --no-save @apidevtools/swagger-cli 1>/dev/null
find doc/schemas/*.json -exec npx swagger-cli validate {} \;
find doc/schemas/gov/*/*.json -exec npx swagger-cli validate {} \;
endgroup

group "Copyright notice headers"
python3 "$SCRIPT_DIR"/notice-check.py
endgroup

group "CMake format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-cmake-format.sh -f cmake samples src tests CMakeLists.txt
else
  "$SCRIPT_DIR"/check-cmake-format.sh cmake samples src tests CMakeLists.txt
fi
endgroup

group "Python dependencies"
# Virtual Environment w/ dependencies for Python steps
if [ ! -f "scripts/env/bin/activate" ]
    then
        python3 -m venv scripts/env
fi

source scripts/env/bin/activate
pip install -U pip
pip install -U wheel black mypy ruff 1>/dev/null
endgroup

group "Python format"
if [ $FIX -ne 0 ]; then
  git ls-files tests/ python/ scripts/ tla/ .cmake-format.py | grep -e '\.py$' | xargs black
else
  git ls-files tests/ python/ scripts/ tla/ .cmake-format.py | grep -e '\.py$' | xargs black --check
fi
endgroup

group "Python lint dependencies"
# Install test dependencies before linting
pip install -U -r tests/requirements.txt 1>/dev/null
pip install -U -e python 1>/dev/null
endgroup

group "Python lint"
if [ $FIX -ne 0 ]; then
  ruff check --fix python/ tests/
else
  ruff check python/ tests/
fi
endgroup

group "Python types"
git ls-files python/ | grep -e '\.py$' | xargs mypy
endgroup