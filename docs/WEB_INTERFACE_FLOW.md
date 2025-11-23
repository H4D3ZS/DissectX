# DissectX Web Interface Flow

## Upload & Analysis Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     User Uploads Binary                      │
│                  (Click or Drag & Drop)                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   POST /upload                               │
│  • Save file to /tmp/dissectx_scans/                        │
│  • Calculate MD5, SHA1, SHA256 hashes                       │
│  • Run BinaryAnalyzer with advanced features                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  Analysis Complete                           │
│  • Extract strings, functions, API calls                    │
│  • Generate call graph                                      │
│  • Detect security patterns                                 │
│  • Create scan entry with hashes                            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Save to Scan History                            │
│  • Add to recent_scans list                                 │
│  • Save to scans.json                                       │
│  • Keep last 50 scans                                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Redirect to Dashboard                           │
│  • Display analysis results                                 │
│  • Show all analysis sections                               │
└─────────────────────────────────────────────────────────────┘
```

## Navigation Structure

```
┌─────────────────────────────────────────────────────────────┐
│                      Dashboard (/)                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  • Analysis Overview                                 │   │
│  │  • Functions                                         │   │
│  │  • Strings                                           │   │
│  │  • Cross-References                                  │   │
│  │  • Advanced Analysis                                 │   │
│  │  • Call Graph                                        │   │
│  │  • Recent Scans  ◄── NEW!                           │   │
│  │  • Upload New Binary                                 │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                         │
                         │ Click "Recent Scans"
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                 Recent Scans (/recent-scans)                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Scan Card 1                                         │   │
│  │  • Filename: malware.exe                            │   │
│  │  • Date: 2025-11-23 14:30:00                        │   │
│  │  • Hashes: MD5, SHA1, SHA256                        │   │
│  │  • Stats: Strings, Functions, Flags                 │   │
│  │  [View Details] [Copy SHA256]                       │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Scan Card 2                                         │   │
│  │  ...                                                 │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                         │
                         │ Click "View Details"
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Scan Detail (/scan/<scan_id>)                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Hash Verification                                   │   │
│  │  • MD5:    [hash] [Copy]                            │   │
│  │  • SHA1:   [hash] [Copy]                            │   │
│  │  • SHA256: [hash] [Copy]                            │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Binary Information                                  │   │
│  │  • File Type, Architecture, Format                  │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Statistics                                          │   │
│  │  [Strings] [Security] [Functions] [Flags]           │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Strings Preview (First 50)                         │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Security Strings                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  [← Back to Recent Scans] [View Full Analysis]             │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

```
┌──────────────┐
│ Binary File  │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────┐
│         File Hash Calculation             │
│  • MD5:    Quick checksum                │
│  • SHA1:   Standard hash                 │
│  • SHA256: Secure hash                   │
└──────┬───────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│         Binary Analysis                   │
│  • Disassembly                           │
│  • String extraction                     │
│  • Function detection                    │
│  • Call graph generation                 │
│  • Security pattern detection            │
└──────┬───────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│         Scan Entry Creation               │
│  {                                        │
│    "id": "sha256[:16]",                  │
│    "filename": "binary.exe",             │
│    "timestamp": "2025-11-23T14:30:00",   │
│    "hashes": {                           │
│      "md5": "...",                       │
│      "sha1": "...",                      │
│      "sha256": "..."                     │
│    },                                    │
│    "summary": {                          │
│      "file_type": "PE",                  │
│      "total_strings": 1234,              │
│      "total_functions": 56,              │
│      "security_flags": 3                 │
│    }                                     │
│  }                                       │
└──────┬───────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│    Persistent Storage (scans.json)        │
│  [                                        │
│    { scan1 },                            │
│    { scan2 },                            │
│    ...                                   │
│  ]                                       │
└──────────────────────────────────────────┘
```

## Key Features

### 1. Upload Functionality
- **Click to Upload**: Native file picker via `<label>` element
- **Drag & Drop**: Custom event handlers for file drop
- **Progress Indicator**: Visual feedback during analysis
- **Error Handling**: Clear error messages on failure

### 2. Hash Verification
- **Multiple Algorithms**: MD5, SHA1, SHA256
- **Copy to Clipboard**: One-click hash copying
- **Visual Feedback**: Success animation on copy

### 3. Scan History
- **Persistent Storage**: JSON file in temp directory
- **Deduplication**: Same file (by SHA256) replaces old entry
- **Capacity Limit**: Keeps last 50 scans
- **Quick Access**: Browse and re-analyze previous files

### 4. Scan Details
- **Full Metadata**: All binary information
- **Hash Display**: All three hash types
- **Statistics**: Visual cards for key metrics
- **String Preview**: First 50 strings
- **Security Focus**: Highlighted security-related findings

## File Structure

```
src/web/
├── server.py                    # Flask server with new routes
├── templates/
│   ├── base.html               # Updated navigation
│   ├── index.html              # Fixed upload, added Recent Scans card
│   ├── recent_scans.html       # NEW: Scan history listing
│   ├── scan_detail.html        # NEW: Individual scan view
│   ├── analysis.html
│   ├── functions.html
│   ├── strings.html
│   ├── xrefs.html
│   ├── advanced_analysis.html
│   └── graph.html
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── main.js

/tmp/dissectx_scans/            # Scan storage
├── scans.json                  # Scan database
├── binary1.exe                 # Uploaded files
├── binary2.elf
└── ...
```

## Browser Compatibility

- **Modern Browsers**: Chrome, Firefox, Safari, Edge (latest versions)
- **Required Features**:
  - Fetch API
  - FormData
  - Clipboard API
  - ES6 JavaScript
  - CSS Grid

## Performance Considerations

1. **File Size**: 100MB upload limit
2. **Scan History**: Limited to 50 entries
3. **String Display**: Limited to 50 strings in preview
4. **Analysis Time**: Depends on binary size and complexity
5. **Storage**: Temp directory cleanup may be needed periodically
