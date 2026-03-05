# Lambda Layer

The `python/` directory is not tracked in git. Dependencies are built using Docker or Podman to ensure correct Linux binaries.

## Build

```bash
cd lambdas
# Use docker or podman
docker run --rm --entrypoint /bin/bash \
  -v "$(pwd)/layer:/layer" \
  public.ecr.aws/lambda/python:3.12 \
  -c "pip install pydantic jinja2 boto3 --target /layer/python/ --no-cache-dir"
cp -r shared analyzers layer/python/
```
