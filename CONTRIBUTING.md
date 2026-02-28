# Contributing to AI Network Analyzer

Thank you for considering contributing! This project is open to improvements, bug fixes, and new features.

## How to Contribute

### Reporting Issues

1. Check [existing issues](../../issues) to avoid duplicates
2. Open a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Your environment (OS, Python version, Ollama version)

### Submitting Changes

1. **Fork** this repository
2. **Create a branch** for your feature: `git checkout -b feature/add-tls-analysis`
3. **Make your changes** in `src/network_analyzer.py`
4. **Test locally**: `python src/network_analyzer.py` (UI works without Ollama; LLM calls will fail gracefully)
5. **Commit** with a clear message: `git commit -m "Add TLS version detection to PCAP analysis"`
6. **Push** and open a **Pull Request**

### Development Guidelines

- **Single-file architecture** — The app is intentionally a single Python file. Keep it that way for deployment simplicity.
- **HTML is inline** — All HTML/CSS/JS lives inside a Python triple-quoted string (`HTML_TEMPLATE`). See [docs/05_ADDING_FEATURES.md](docs/05_ADDING_FEATURES.md) for escaping rules.
- **Test your changes** — At minimum, verify the web UI loads and file upload works.
- **No PII** — Never commit real IP addresses, hostnames, usernames, or subscription IDs.

### Code Style

- Python: Follow PEP 8, use descriptive variable names
- JavaScript: No frameworks — vanilla JS only
- CSS: Use CSS variables defined in `:root` for colors

### Types of Contributions Welcome

| Type | Examples |
|---|---|
| **New analysis features** | TLS inspection, QUIC support, DNS-over-HTTPS |
| **UI improvements** | Better mobile layout, chart visualizations, export to PDF |
| **LLM prompt tuning** | Better system prompts for more accurate analysis |
| **Documentation** | Typo fixes, additional examples, video walkthroughs |
| **Bug fixes** | Edge cases in PCAP parsing, session handling issues |
| **Performance** | Faster file parsing, streaming LLM responses |

### Architecture Reference

See [docs/05_ADDING_FEATURES.md](docs/05_ADDING_FEATURES.md) for:
- Full code architecture map with line numbers
- Where to edit for each type of change
- Step-by-step examples of adding PCAP metrics, HAR metrics, and UI components
- Critical gotchas (Python string escaping, emoji encoding, etc.)

## Code of Conduct

Be respectful, constructive, and inclusive. We're all here to learn and build.

## Questions?

Open an issue with the `question` label and we'll help!
