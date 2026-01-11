#!/usr/bin/bash

set -eo pipefail

branch=$(git rev-parse --abbrev-ref HEAD)

if [[ "$branch" = gh-pages ]]; then
    echo 'Already on gh-pages branch!'>&2
    exit 1
fi

./logmon.py --config-schema > new_schema.yaml
uv run generate-schema-doc new_schema.yaml new_index.html
mv schema_doc.css new_schema_doc.css
mv schema_doc.min.js new_schema_doc.min.js

git checkout gh-pages

mv new_schema.yaml schema.yaml
mv new_index.html index.html
mv new_schema_doc.css schema_doc.css
mv new_schema_doc.min.js schema_doc.min.js

if git status --porcelain --untracked-files=no | grep '^.M' >/dev/null; then
    git commit schema.yaml index.html schema_doc.css schema_doc.css schema_doc.min.js -m "updated schema documentation"
    git push
    echo "Updated schema documentation."
else
    echo 'No changes!'>&2
fi

git checkout "$branch"
