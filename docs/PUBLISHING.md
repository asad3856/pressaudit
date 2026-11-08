# Publishing PressAudit to PyPI

The package is PyPI-ready: `pyproject.toml` carries the metadata, the
bundled vulnerability database is included as package data, and the
build was verified locally (`python -m build` + `twine check` pass).

## Check the name

`pressaudit` was free on PyPI at the last check (8 Nov 2026 — the
project page returned 404). Re-check before the first upload:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://pypi.org/pypi/pressaudit/json
```

404 means free; 200 means taken.

## Build and check

```bash
python3 -m venv /tmp/pressaudit-build-venv
/tmp/pressaudit-build-venv/bin/pip install build twine
/tmp/pressaudit-build-venv/bin/python -m build
/tmp/pressaudit-build-venv/bin/python -m twine check dist/*
```

## Upload (needs a PyPI account + API token)

Uploading cannot be done by the maintainer's agent alone — it needs the
owner's PyPI credentials. Steps for the owner:

1. Create an account at https://pypi.org/account/register/
2. Create an API token at https://pypi.org/manage/account/token/
   (scope it to the `pressaudit` project after the first upload).
3. Upload:

```bash
/tmp/pressaudit-build-venv/bin/python -m twine upload dist/*
```

Then anyone can install it with:

```bash
pip install pressaudit
```

## After the first release

- Bump `__version__` in `src/pressaudit/__init__.py` and `pyproject.toml`,
  add a CHANGELOG entry, rebuild, and upload the new version.
- Never re-upload the same version number — PyPI rejects it.
