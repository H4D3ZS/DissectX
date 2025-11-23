# DissectX Web UI

A    web-based user interface for DissectX binary analysis results.

## Features

### Core Functionality
- **Interactive Dashboard**: Overview of analysis results with quick navigation
- **Function Browser**: Browse and explore detected functions with detailed views
- **String Viewer**: Display extracted strings with addresses and context
- **Cross-Reference Analysis**: Visualize relationships between functions, strings, and data
- **Syntax Highlighting**: Code highlighting using highlight.js for better readability
- **Search Functionality**: Search across functions, strings, and instructions
- **Export Capabilities**: Export analysis results to HTML and PDF formats

### Technical Features
- Built with Flask 3.0+ for robust web serving
- Responsive design that works on desktop and mobile
- RESTful API endpoints for programmatic access
- Template-based rendering with Jinja2
- Static file serving for CSS, JavaScript, and assets

## Installation

Install the required dependencies:

```bash
pip install flask>=3.0.0 weasyprint>=60.0
```

## Usage

### Basic Usage

```python
from src.web.server import WebUIServer

# Sample analysis results
analysis_results = {
    'binary_info': {
        'filename': 'sample.exe',
        'format': 'PE32',
        'architecture': 'x86'
    },
    'functions': {...},
    'strings': [...],
    'xrefs': {...}
}

# Create and start the server
server = WebUIServer(analysis_results)
server.start(port=8080)
```

### Using the Demo

Run the included demo script:

```bash
python demo_web_ui.py
```

Then open your browser to `http://localhost:8080`

### Integration with Analysis Pipeline

```python
from src.binary_analyzer import BinaryAnalyzer
from src.web.server import WebUIServer

# Perform analysis
analyzer = BinaryAnalyzer()
strings = analyzer.extract_strings('binary.exe')

# Prepare results
results = {
    'binary_info': {'filename': 'binary.exe'},
    'strings': strings,
    # ... other analysis data
}

# Start web UI
server = WebUIServer(results)
server.start(port=8080, debug=False)
```

## API Endpoints

### Web Routes

- `GET /` - Dashboard/home page
- `GET /analysis` - Analysis results overview
- `GET /functions` - List all functions
- `GET /function/<id>` - Detailed function view
- `GET /strings` - List all strings
- `GET /xrefs` - Cross-references view

### API Routes

- `GET /api/results` - Get analysis results as JSON
- `GET /api/search?q=<query>&type=<type>` - Search analysis results
  - `type` can be: `all`, `strings`, `functions`, `code`

### Export Routes

- `GET /export/html` - Export analysis as HTML file
- `GET /export/pdf` - Export analysis as PDF file (requires weasyprint)

## Architecture

### Directory Structure

```
src/web/
├── __init__.py          # Module initialization
├── server.py            # Flask server and routes
├── templates/           # Jinja2 HTML templates
│   ├── base.html       # Base template with navigation
│   ├── index.html      # Dashboard
│   ├── analysis.html   # Analysis overview
│   ├── functions.html  # Function listing
│   ├── function_detail.html  # Function details
│   ├── strings.html    # String listing
│   ├── xrefs.html      # Cross-references
│   └── error.html      # Error page
└── static/             # Static assets
    ├── css/
    │   └── style.css   # Main stylesheet
    └── js/
        └── main.js     # JavaScript functionality
```

### Data Model

The Web UI expects analysis results in the following format:

```python
{
    'binary_info': {
        'filename': str,
        'format': str,
        'architecture': str,
        'bit_width': int,
        'entry_point': str,
        'base_address': str
    },
    'functions': {
        '<address>': {
            'name': str,
            'size': int,
            'calls': [str],
            'called_by': [str],
            'instructions': [dict],
            'strings': [str],
            'pseudocode': str
        }
    },
    'strings': [
        str or {'value': str, 'address': str}
    ],
    'xrefs': {
        'function_calls': {str: [str]},
        'function_callers': {str: [str]},
        'string_refs': {str: [str]},
        'data_refs': {str: [str]}
    },
    'flags': [
        {
            'value': str,
            'confidence': str,
            'location': str
        }
    ]
}
```

## Customization

### Styling

Edit `src/web/static/css/style.css` to customize the appearance. CSS variables are defined at the top for easy theming:

```css
:root {
    --primary-color: #007bff;
    --secondary-color: #6c757d;
    --background-color: #f5f5f5;
    /* ... */
}
```

### Templates

Templates use Jinja2 syntax and extend from `base.html`. Create custom templates by:

1. Creating a new HTML file in `templates/`
2. Extending the base template: `{% extends "base.html" %}`
3. Defining content blocks: `{% block content %}...{% endblock %}`

### Adding Routes

Add new routes in `server.py`:

```python
@self.app.route('/custom')
def custom_route():
    return render_template('custom.html', data=custom_data)
```

## Requirements Validation

This implementation satisfies the following requirements:

### Requirement 16.1: Web Server Setup
✅ Flask web server configured and running on http://localhost:8080
✅ Routes and templates properly configured

### Requirement 16.2: Interactive HTML Reports
✅ HTML reports generated from analysis results
✅ Navigation between different sections

### Requirement 16.3: Interactive Navigation
✅ Clickable links to navigate between functions, strings, and references
✅ Breadcrumb navigation for context

### Requirement 16.4: Syntax Highlighting
✅ Integrated highlight.js for code syntax highlighting
✅ Applied to assembly and pseudo-code sections

### Requirement 16.5: Export Functionality
✅ HTML export via `/export/html`
✅ PDF export via `/export/pdf` (requires weasyprint)

## Testing

Run the test suite:

```bash
pytest tests/test_web_ui.py -v
```

Test coverage includes:
- Server initialization
- All route handlers
- Search functionality
- Report generation
- HTML escaping
- API endpoints

## Performance Considerations

- **Large Binaries**: For binaries with thousands of functions/strings, consider pagination
- **PDF Export**: PDF generation can be memory-intensive for large reports
- **Caching**: Consider implementing caching for frequently accessed data
- **Production**: Use a production WSGI server (gunicorn, uWSGI) instead of Flask's development server

## Security Notes

- HTML content is properly escaped to prevent XSS attacks
- File uploads are not supported (analysis results only)
- Consider adding authentication for production deployments
- PDF export uses WeasyPrint which is safe for untrusted content

## Troubleshooting

### PDF Export Not Working

Install WeasyPrint dependencies:

```bash
# macOS
brew install cairo pango gdk-pixbuf libffi

# Ubuntu/Debian
apt-get install python3-cffi python3-brotli libpango-1.0-0 libpangoft2-1.0-0

# Then install weasyprint
pip install weasyprint
```

### Port Already in Use

Change the port when starting the server:

```python
server.start(port=8081)
```

### Templates Not Found

Ensure the templates directory exists and contains all required HTML files.

## Future Enhancements

Potential improvements for future versions:

- Real-time analysis updates via WebSockets
- Collaborative annotation features
- Graph visualization for call graphs and CFGs
- Diff view for binary comparison
- Plugin system for custom visualizations
- User authentication and session management
- Database backend for persistent storage

## License

Part of the DissectX project. See main LICENSE file for details.
