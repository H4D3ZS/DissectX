# DissectX Terminal User Interface (TUI)

## Overview

The DissectX TUI provides an interactive terminal-based interface for binary analysis. Built with the Textual framework, it offers a modern, keyboard-driven experience with multiple panels for viewing code, strings, functions, and cross-references.

## Features

### Panel-Based Layout

The TUI is organized into four main panels:

1. **Code Panel** - Displays disassembled code with addresses and instructions
2. **Strings Panel** - Shows extracted strings from the binary
3. **Functions Panel** - Lists identified functions with addresses
4. **Cross-References Panel** - Displays cross-reference information

### Keyboard Navigation

The TUI supports comprehensive keyboard navigation:

#### Panel Focus
- `c` - Focus code panel
- `s` - Focus strings panel
- `f` - Focus functions panel
- `x` - Focus cross-references panel
- `Tab` - Next panel
- `Shift+Tab` - Previous panel

#### Scrolling
- `Up/Down` - Scroll line by line
- `PageUp/PageDown` - Scroll page by page
- `Home` - Scroll to top
- `End` - Scroll to bottom

#### General
- `q` - Quit application
- `h` - Show help

## Usage

### Basic Usage

```python
from src.tui import DissectXTUI

# Create and run TUI
app = DissectXTUI()
app.run()
```

### With Analysis Results

```python
from src.tui import DissectXTUI

# Assuming you have analysis results
results = analyze_binary("sample.exe")

# Create TUI with results
app = DissectXTUI(analysis_results=results)
app.run()
```

### Demo Script

Run the included demo to see the TUI in action:

```bash
python demo_tui.py
```

## Architecture

### Main Components

- **DissectXTUI** - Main application class that manages the TUI
- **CodePanel** - Widget for displaying disassembled code
- **StringsPanel** - Widget for displaying extracted strings
- **FunctionsPanel** - Widget for displaying function list
- **XRefsPanel** - Widget for displaying cross-references

### Data Flow

1. Analysis results are loaded into the TUI application
2. Each panel extracts relevant data from the results
3. Panels render their content based on the data
4. User interactions trigger panel updates and navigation

## Requirements

- Python 3.8+
- textual >= 0.41.0

Install dependencies:

```bash
pip install textual>=0.41.0
```

## Testing

Run the test suite:

```bash
pytest tests/test_tui.py -v
```

## Future Enhancements

The TUI framework is designed to be extensible. Future enhancements may include:

- Interactive code navigation (jump to address)
- Search functionality within panels
- Syntax highlighting for code
- Annotation system for marking important findings
- Command-line interface within TUI
- Session save/load functionality
- Export capabilities

## Design Decisions

### Why Textual?

Textual was chosen for the TUI framework because:

1. **Modern Python TUI Framework** - Built specifically for Python with modern async support
2. **Rich Rendering** - Supports colors, styles, and complex layouts
3. **Reactive Components** - Easy to build responsive, interactive interfaces
4. **CSS-like Styling** - Familiar styling approach for layout and appearance
5. **Active Development** - Well-maintained with good documentation

### Panel Layout

The grid-based layout was chosen to:

- Maximize screen real estate usage
- Provide clear visual separation between different data types
- Allow easy focus switching between panels
- Support future expansion with additional panels

### Keyboard-First Design

The TUI emphasizes keyboard navigation because:

- Faster for power users
- Consistent with terminal workflow
- Reduces context switching
- Accessible without mouse

## Contributing

When extending the TUI:

1. Follow the existing panel structure
2. Ensure all panels are focusable (`can_focus = True`)
3. Add keyboard bindings to the main app's `BINDINGS` list
4. Update help text when adding new shortcuts
5. Write tests for new functionality
6. Update this README with new features

## License

Part of the DissectX project. See main project LICENSE for details.
