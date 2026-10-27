# Contributing

Keep changes focused on readable OpenBSD PF configuration and checked reloads.
Prefer small, explicit behavior to additional configuration switches or abstractions.
Explain the traffic scenario a change supports and any effect on existing
configuration or generated rules.

## Development

Follow the [installation instructions](README.md#install) to obtain a checkout
and Python. Use Python 3.11 or later and the standard library for implementation
and tests. Run the portable suite and validate the examples from the repository
root. With the OpenBSD Python package used in those instructions:

```sh
/usr/local/bin/python3.14 -m unittest discover -s tests
/usr/local/bin/python3.14 -m makepf check examples/handbook
/usr/local/bin/python3.14 -m makepf check examples/faq
/usr/local/bin/python3.14 -m makepf check examples/dual-stack
```

On another system, use the installed Python 3.11 or later interpreter. The build
uses that interpreter at runtime by default; `tools/build.py --python PATH`
selects a different runtime interpreter when preparing an archive for another
host.

For changes to PF output, check the examples with native OpenBSD `pfctl` and
test affected allowed and denied flows in an isolated network. Report what ran
and what did not. Syntax validation is useful evidence, but it does not replace
packet tests for ordering, state, NAT, redirection or IPv6 control traffic.
Reload changes also need isolated tests for rejected candidates, persistence,
backups and state preservation. Never test reloads on a development host's live
firewall.

Add regression tests for substantive behavior changes and errors. Keep examples
and the configuration reference consistent with the accepted syntax. Avoid
generated output, local environment details and unrelated refactoring in patches.

## Python distributions

The executable archive needs only Python's standard library. Preparing a PyPI
wheel and source distribution uses the standard packaging tools `build`,
`setuptools` and `twine`; these are build and verification dependencies, not
MakePF runtime dependencies. From the repository root:

```sh
/usr/local/bin/python3.14 -m venv .venv
.venv/bin/python -m pip install build twine
.venv/bin/python -m build
.venv/bin/python -m twine check --strict dist/*.whl dist/*.tar.gz
```

With pipx installed, test the wheel without publishing it:

```sh
pipx install --python /usr/local/bin/python3.14 ./dist/makepf-1.0.0-py3-none-any.whl
makepf --version
```

Builds and CI do not upload packages. Publishing to PyPI is a separate release
action.

## Documentation and formatting

Use American English, short procedures and explicit prerequisites. Identify the
file or working directory before each example. Use `sh` fences without shell prompts,
`doas` for administrative commands and separate `text` blocks for example output.
Keep the README's Markdown title.

Use spaces, UTF-8 and LF line endings. The repository's `.editorconfig` sets
four-space indentation and two-space indentation for YAML. Configuration tables
use enough spaces between fields to align each column with its header; they do
not use fixed-width indentation as a column separator. Preserve this alignment
when adding rows.

## License

By contributing, you agree that your contribution may be distributed under the
repository's BSD 2-Clause License. Retain attribution for any material you reuse.
