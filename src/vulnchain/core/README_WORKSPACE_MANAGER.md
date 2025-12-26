# Workspace Manager

The Workspace Manager provides multi-challenge organization capabilities for the VulnChain CTF framework. It allows users to organize different CTF challenges into separate workspaces, each with its own configuration, findings, session data, and logs.

## Features

- **Workspace Creation**: Create isolated workspaces for different CTF challenges
- **State Management**: Store and load complete workspace state including target configuration, session data, and findings
- **Workspace Switching**: Easily switch between different workspaces
- **Finding Management**: Save and retrieve security findings within workspaces
- **Export/Import**: Package workspaces into portable archives for sharing or backup
- **Statistics**: Get workspace statistics including finding counts and severity distribution

## Architecture

Each workspace is stored as a directory structure:

```
workspaces/
└── {workspace_id}/
    ├── workspace.json       # Workspace configuration and metadata
    ├── findings/            # Individual finding files
    │   └── {finding_id}.json
    ├── logs/                # Log files
    └── evidence/            # Evidence files (screenshots, etc.)
```

## Usage

### Creating a Workspace

```python
from app.core.workspace_manager import WorkspaceManager

manager = WorkspaceManager()

# Create a new workspace
workspace = manager.create_workspace(
    name="HackTheBox Challenge 1",
    metadata={
        "platform": "HackTheBox",
        "difficulty": "Medium",
        "category": "Web"
    }
)

print(f"Created workspace: {workspace.workspace_id}")
```

### Loading and Switching Workspaces

```python
# List all workspaces
workspaces = manager.list_workspaces()
for ws in workspaces:
    print(f"{ws.name} ({ws.workspace_id})")

# Switch to a specific workspace
workspace = manager.switch_workspace(workspace_id)

# Get current workspace
current = manager.get_current_workspace()
```

### Managing Target Configuration

```python
from app.models.target import TargetConfig

# Update target configuration
target = TargetConfig(
    url="https://example.com",
    custom_headers={"X-API-Key": "secret"},
    waf_bypass_profile="cloudflare"
)

manager.update_target(workspace_id, target)
```

### Managing Session Data

```python
from app.models.target import Session

# Update session
session = Session(
    session_id="session-123",
    domain="example.com",
    cookies={"session": "abc123"}
)

manager.update_session(workspace_id, session)
```

### Saving Findings

```python
from app.core.workspace_manager import Finding
from datetime import datetime, timezone

# Create a finding
finding = Finding(
    finding_id="finding-001",
    workspace_id=workspace_id,
    vulnerability_type="SQL Injection",
    severity="critical",
    title="SQL Injection in login form",
    description="The login form is vulnerable to SQL injection...",
    affected_url="https://example.com/login",
    proof_of_concept="' OR '1'='1",
    remediation="Use parameterized queries",
    discovered_at=datetime.now(timezone.utc),
    flags=["CTF{sql_injection_found}"]
)

# Save finding to workspace
manager.save_finding(workspace_id, finding)
```

### Retrieving Findings

```python
# Get all findings
findings = manager.get_findings(workspace_id)

# Filter by severity
critical_findings = manager.get_findings(
    workspace_id,
    severity="critical"
)

# Filter by vulnerability type
sqli_findings = manager.get_findings(
    workspace_id,
    vulnerability_type="SQL Injection"
)
```

### Workspace Statistics

```python
# Get workspace statistics
stats = manager.get_workspace_stats(workspace_id)

print(f"Total findings: {stats['total_findings']}")
print(f"Critical: {stats['severity_counts']['critical']}")
print(f"High: {stats['severity_counts']['high']}")
print(f"Total flags: {stats['total_flags']}")
```

### Exporting Workspaces

```python
# Export workspace to archive
archive_data = manager.export_workspace(workspace_id)

# Save to file
with open("workspace_backup.tar.gz", "wb") as f:
    f.write(archive_data)
```

### Importing Workspaces

```python
# Load archive from file
with open("workspace_backup.tar.gz", "rb") as f:
    archive_data = f.read()

# Import workspace
imported_workspace = manager.import_workspace(archive_data)

print(f"Imported workspace: {imported_workspace.name}")
```

### Deleting Workspaces

```python
# Delete a workspace
manager.delete_workspace(workspace_id)
```

## Data Models

### Workspace

```python
@dataclass
class Workspace:
    workspace_id: str
    name: str
    target: Optional[TargetConfig] = None
    findings: List[Finding] = field(default_factory=list)
    session: Optional[Session] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
```

### Finding

```python
@dataclass
class Finding:
    finding_id: str
    workspace_id: str
    vulnerability_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    affected_url: str
    proof_of_concept: str
    remediation: str
    discovered_at: datetime
    flags: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
```

## Requirements Validation

This implementation satisfies the following requirements:

- **Requirement 26.1**: Initialize workspace structure with directories for configurations, findings, and session data
- **Requirement 26.2**: Store configurations, findings, and session data within workspaces
- **Requirement 26.3**: Switch between workspaces with complete state loading
- **Requirement 26.4**: Package workspace into portable archive for export
- **Requirement 26.5**: Restore complete state from archive during import

## Error Handling

The Workspace Manager includes comprehensive error handling:

- `ValueError` is raised when:
  - Workspace not found
  - Invalid archive format
  - Workspace already exists during import
  - Invalid workspace data

## Thread Safety

The current implementation is not thread-safe. For concurrent access, consider adding locking mechanisms or using a database backend.

## Future Enhancements

- Database backend for better scalability
- Workspace templates
- Workspace sharing and collaboration
- Incremental backups
- Workspace versioning
- Cloud storage integration
