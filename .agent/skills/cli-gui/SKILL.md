---
name: cli-gui
description: Guide for building CLI commands or GUI components.
---

Analyze how the project builds CLI or GUI interfaces:
1. Find `.py` files defining CLI commands or GUI windows
2. Check for CLI: argparse, click, typer, fire, rich, prompt_toolkit
3. Check for GUI: tkinter, PyQt5/6, PySide6, wxPython, kivy, streamlit, gradio
4. Create `.agent/skills/cli-gui/SKILL.md` with references folder containing:
   - interface_setup.md: Entry point, framework init, theming
   - command_patterns.md (CLI): Command structure, args, output formatting
   - widget_patterns.md (GUI): Widget layout, events, state management

Skip if project doesn't have CLI or GUI.
