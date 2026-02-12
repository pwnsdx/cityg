# City-G Whitepaper

This directory contains the LaTeX source for the City-G protocol whitepaper.

## Files

- `whitepaper.tex`: main manuscript
- `references.bib`: bibliography database

## Build

From this directory:

```bash
pdflatex whitepaper.tex
bibtex whitepaper
pdflatex whitepaper.tex
pdflatex whitepaper.tex
```

Output:

- `whitepaper.pdf`

## Notes

- The whitepaper is explanatory and should stay aligned with the normative specification in `docs/specs.md`.
- If the spec evolves, update both technical wording and security-property tables accordingly.
