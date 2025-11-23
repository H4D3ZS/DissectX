"""
Main TUI application for DissectX.

Provides an interactive terminal interface with panel-based layout for
binary analysis, including code viewing, string analysis, function listing,
and cross-reference tracking.
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Static, Input
from textual.binding import Binding
from textual.reactive import reactive
import re
import json
from pathlib import Path


class DissectXTUI(App):
    """
    DissectX Terminal User Interface.
    
    An interactive TUI for reverse engineering and binary analysis with
    panel-based layout and keyboard navigation.
    """
    
    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 3;
        grid-gutter: 1;
    }
    
    #code-panel {
        column-span: 2;
        row-span: 2;
        border: solid $primary;
        overflow-y: auto;
    }
    
    #code-panel:focus {
        border: solid $success;
    }
    
    #strings-panel {
        border: solid $secondary;
        overflow-y: auto;
    }
    
    #strings-panel:focus {
        border: solid $success;
    }
    
    #functions-panel {
        border: solid $secondary;
        overflow-y: auto;
    }
    
    #functions-panel:focus {
        border: solid $success;
    }
    
    #xrefs-panel {
        column-span: 2;
        border: solid $accent;
        overflow-y: auto;
    }
    
    #xrefs-panel:focus {
        border: solid $success;
    }
    
    .panel-title {
        background: $boost;
        color: $text;
        padding: 0 1;
    }
    
    .panel-content {
        padding: 1;
        height: 100%;
    }
    
    #search-input {
        dock: top;
        height: 3;
        margin: 0 1;
    }
    
    #search-input.hidden {
        display: none;
    }
    
    #annotation-input {
        dock: top;
        height: 3;
        margin: 0 1;
    }
    
    #annotation-input.hidden {
        display: none;
    }
    
    #command-input {
        dock: top;
        height: 3;
        margin: 0 1;
    }
    
    #command-input.hidden {
        display: none;
    }
    
    .search-highlight {
        background: $warning;
        color: $text;
    }
    
    .annotation {
        color: $success;
        text-style: italic;
    }
    
    /* Syntax highlighting styles */
    .asm-mnemonic {
        color: $accent;
    }
    
    .asm-register {
        color: $success;
    }
    
    .asm-immediate {
        color: $warning;
    }
    
    .asm-address {
        color: $primary;
    }
    
    .asm-comment {
        color: $text-muted;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("c", "focus_code", "Code", show=True),
        Binding("s", "focus_strings", "Strings", show=True),
        Binding("f", "focus_functions", "Functions", show=True),
        Binding("x", "focus_xrefs", "XRefs", show=True),
        Binding("h", "show_help", "Help", show=True),
        Binding("/", "show_search", "Search", show=True),
        Binding(":", "show_command", "Command", show=True),
        Binding("escape", "clear_search", "Clear Search", show=False),
        Binding("t", "toggle_syntax", "Toggle Syntax", show=True),
        Binding("a", "add_annotation", "Add Comment", show=True),
        Binding("ctrl+s", "save_annotations", "Save Annotations", show=False),
        Binding("ctrl+l", "load_annotations", "Load Annotations", show=False),
        Binding("ctrl+e", "export_session", "Export Session", show=False),
        Binding("ctrl+i", "import_session", "Import Session", show=False),
        Binding("tab", "focus_next", "Next Panel", show=False),
        Binding("shift+tab", "focus_previous", "Previous Panel", show=False),
        Binding("up", "scroll_up", "Scroll Up", show=False),
        Binding("down", "scroll_down", "Scroll Down", show=False),
        Binding("pageup", "page_up", "Page Up", show=False),
        Binding("pagedown", "page_down", "Page Down", show=False),
        Binding("home", "scroll_home", "Top", show=False),
        Binding("end", "scroll_end", "Bottom", show=False),
    ]
    
    def __init__(self, analysis_results=None):
        """
        Initialize the TUI application.
        
        Args:
            analysis_results: Optional AnalysisResults object containing
                            binary analysis data to display
        """
        super().__init__()
        self.analysis_results = analysis_results
        self.title = "DissectX - Binary Analysis TUI"
        self.search_query = ""
        self.search_active = False
        self.syntax_highlighting_enabled = True
        self.annotations = {}  # address -> comment mapping
        self.annotations_file = ".dissectx_annotations.json"
        self.command_history = []  # Command history for up/down navigation
        self.history_index = -1  # Current position in history
    
    def compose(self) -> ComposeResult:
        """
        Compose the TUI layout with header, footer, and panels.
        
        Returns:
            ComposeResult with all UI components
        """
        yield Header()
        yield Input(placeholder="Search...", id="search-input", classes="hidden")
        yield Input(placeholder="Add comment (address: comment)...", id="annotation-input", classes="hidden")
        yield Input(placeholder="Command (type 'help' for commands)...", id="command-input", classes="hidden")
        yield CodePanel(id="code-panel")
        yield StringsPanel(id="strings-panel")
        yield FunctionsPanel(id="functions-panel")
        yield XRefsPanel(id="xrefs-panel")
        yield Footer()
    
    def on_mount(self) -> None:
        """Called when the app is mounted. Initialize panels with data."""
        # Load annotations from file if it exists
        self._load_annotations_from_file()
        
        if self.analysis_results:
            self.load_analysis_results(self.analysis_results)
    
    def load_analysis_results(self, results):
        """
        Load analysis results into the TUI panels.
        
        Args:
            results: AnalysisResults object containing binary analysis data
        """
        self.analysis_results = results
        
        # Update panels with analysis data
        code_panel = self.query_one("#code-panel", CodePanel)
        code_panel.load_code(results)
        
        strings_panel = self.query_one("#strings-panel", StringsPanel)
        strings_panel.load_strings(results)
        
        functions_panel = self.query_one("#functions-panel", FunctionsPanel)
        functions_panel.load_functions(results)
        
        xrefs_panel = self.query_one("#xrefs-panel", XRefsPanel)
        xrefs_panel.load_xrefs(results)
    
    def action_focus_code(self) -> None:
        """Focus the code panel."""
        self.query_one("#code-panel").focus()
    
    def action_focus_strings(self) -> None:
        """Focus the strings panel."""
        self.query_one("#strings-panel").focus()
    
    def action_focus_functions(self) -> None:
        """Focus the functions panel."""
        self.query_one("#functions-panel").focus()
    
    def action_focus_xrefs(self) -> None:
        """Focus the cross-references panel."""
        self.query_one("#xrefs-panel").focus()
    
    def action_show_help(self) -> None:
        """Show help information."""
        help_text = """
        DissectX TUI Keyboard Shortcuts:
        
        Navigation:
        q           - Quit application
        c           - Focus code panel
        s           - Focus strings panel
        f           - Focus functions panel
        x           - Focus cross-references panel
        Tab         - Next panel
        Shift+Tab   - Previous panel
        
        Search & Commands:
        /           - Open search input
        :           - Open command prompt (type 'help' for commands)
        Escape      - Clear search and close input
        Enter       - Apply search/execute command
        
        Display:
        t           - Toggle syntax highlighting
        
        Annotations & Sessions:
        a           - Add comment/annotation
        Ctrl+S      - Save annotations to file
        Ctrl+L      - Load annotations from file
        Ctrl+E      - Export session
        Ctrl+I      - Import session
        
        Scrolling:
        Up/Down     - Scroll line by line
        PageUp/Down - Scroll page by page
        Home        - Scroll to top
        End         - Scroll to bottom
        
        h           - Show this help
        """
        self.notify(help_text, title="Help", timeout=15)
    
    def action_scroll_up(self) -> None:
        """Scroll the focused panel up."""
        focused = self.focused
        if focused and hasattr(focused, 'scroll_up'):
            focused.scroll_up()
    
    def action_scroll_down(self) -> None:
        """Scroll the focused panel down."""
        focused = self.focused
        if focused and hasattr(focused, 'scroll_down'):
            focused.scroll_down()
    
    def action_page_up(self) -> None:
        """Scroll the focused panel up by one page."""
        focused = self.focused
        if focused and hasattr(focused, 'scroll_page_up'):
            focused.scroll_page_up()
    
    def action_page_down(self) -> None:
        """Scroll the focused panel down by one page."""
        focused = self.focused
        if focused and hasattr(focused, 'scroll_page_down'):
            focused.scroll_page_down()
    
    def action_scroll_home(self) -> None:
        """Scroll the focused panel to the top."""
        focused = self.focused
        if focused and hasattr(focused, 'scroll_home'):
            focused.scroll_home()
    
    def action_scroll_end(self) -> None:
        """Scroll the focused panel to the bottom."""
        focused = self.focused
        if focused and hasattr(focused, 'scroll_end'):
            focused.scroll_end()
    
    def action_show_search(self) -> None:
        """Show the search input."""
        search_input = self.query_one("#search-input", Input)
        search_input.remove_class("hidden")
        search_input.focus()
        self.search_active = True
    
    def action_clear_search(self) -> None:
        """Clear and hide the search input."""
        search_input = self.query_one("#search-input", Input)
        search_input.value = ""
        search_input.add_class("hidden")
        self.search_query = ""
        self.search_active = False
        
        # Clear search highlighting in all panels
        self._clear_search_in_panels()
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle input submission."""
        if event.input.id == "search-input":
            self.search_query = event.value
            self._apply_search_to_panels()
            
            # Hide search input after submission
            event.input.add_class("hidden")
            self.search_active = False
            
            # Return focus to previously focused panel
            if self.focused:
                self.focused.focus()
        
        elif event.input.id == "annotation-input":
            # Parse annotation input (format: address: comment)
            annotation_text = event.value.strip()
            if annotation_text:
                self._parse_and_add_annotation(annotation_text)
            
            # Clear and hide annotation input
            event.input.value = ""
            event.input.add_class("hidden")
            
            # Return focus to code panel
            code_panel = self.query_one("#code-panel", CodePanel)
            code_panel.focus()
        
        elif event.input.id == "command-input":
            # Parse and execute command
            command_text = event.value.strip()
            if command_text:
                # Execute command (history is added in _execute_command)
                self._execute_command(command_text)
            
            # Clear and hide command input
            event.input.value = ""
            event.input.add_class("hidden")
            
            # Return focus to code panel
            code_panel = self.query_one("#code-panel", CodePanel)
            code_panel.focus()
    
    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search input changes for live filtering."""
        if event.input.id == "search-input":
            self.search_query = event.value
            self._apply_search_to_panels()
    
    def _apply_search_to_panels(self) -> None:
        """Apply search filter to all panels."""
        code_panel = self.query_one("#code-panel", CodePanel)
        code_panel.apply_search(self.search_query)
        
        strings_panel = self.query_one("#strings-panel", StringsPanel)
        strings_panel.apply_search(self.search_query)
        
        functions_panel = self.query_one("#functions-panel", FunctionsPanel)
        functions_panel.apply_search(self.search_query)
        
        xrefs_panel = self.query_one("#xrefs-panel", XRefsPanel)
        xrefs_panel.apply_search(self.search_query)
    
    def _clear_search_in_panels(self) -> None:
        """Clear search highlighting in all panels."""
        code_panel = self.query_one("#code-panel", CodePanel)
        code_panel.clear_search()
        
        strings_panel = self.query_one("#strings-panel", StringsPanel)
        strings_panel.clear_search()
        
        functions_panel = self.query_one("#functions-panel", FunctionsPanel)
        functions_panel.clear_search()
        
        xrefs_panel = self.query_one("#xrefs-panel", XRefsPanel)
        xrefs_panel.clear_search()
    
    def _parse_and_add_annotation(self, annotation_text: str) -> None:
        """
        Parse and add annotation.
        
        Args:
            annotation_text: Annotation in format "address: comment" or just "comment"
        """
        # Try to parse address: comment format
        if ':' in annotation_text:
            parts = annotation_text.split(':', 1)
            address_str = parts[0].strip()
            comment = parts[1].strip()
            
            # Parse address (hex or decimal)
            try:
                if address_str.startswith('0x'):
                    address = int(address_str, 16)
                else:
                    address = int(address_str)
                
                # Add annotation
                self.annotations[address] = comment
                
                # Update code panel
                code_panel = self.query_one("#code-panel", CodePanel)
                code_panel.annotations = self.annotations
                code_panel.refresh()
                
                self.notify(f"Annotation added at 0x{address:08x}", timeout=2)
                
                # Auto-save annotations
                self._save_annotations_to_file()
            except ValueError:
                self.notify("Invalid address format. Use: 0x1234 or 1234", timeout=3)
        else:
            self.notify("Format: address: comment (e.g., 0x1000: This is important)", timeout=3)
    
    def _save_annotations_to_file(self) -> None:
        """Save annotations to JSON file."""
        try:
            # Convert integer keys to strings for JSON
            annotations_str = {str(addr): comment for addr, comment in self.annotations.items()}
            
            with open(self.annotations_file, 'w') as f:
                json.dump(annotations_str, f, indent=2)
        except Exception as e:
            self.notify(f"Error saving annotations: {e}", timeout=3)
    
    def _load_annotations_from_file(self) -> None:
        """Load annotations from JSON file."""
        try:
            if Path(self.annotations_file).exists():
                with open(self.annotations_file, 'r') as f:
                    annotations_str = json.load(f)
                
                # Convert string keys back to integers
                self.annotations = {int(addr): comment for addr, comment in annotations_str.items()}
        except Exception as e:
            # Silently fail if file doesn't exist or is invalid
            self.annotations = {}
    
    def action_toggle_syntax(self) -> None:
        """Toggle syntax highlighting on/off."""
        self.syntax_highlighting_enabled = not self.syntax_highlighting_enabled
        
        # Update code panel
        code_panel = self.query_one("#code-panel", CodePanel)
        code_panel.syntax_highlighting = self.syntax_highlighting_enabled
        code_panel.refresh()
        
        # Notify user
        status = "enabled" if self.syntax_highlighting_enabled else "disabled"
        self.notify(f"Syntax highlighting {status}", timeout=2)
    
    def action_add_annotation(self) -> None:
        """Show the annotation input."""
        annotation_input = self.query_one("#annotation-input", Input)
        annotation_input.remove_class("hidden")
        annotation_input.focus()
    
    def action_save_annotations(self) -> None:
        """Save annotations to file."""
        self._save_annotations_to_file()
        self.notify("Annotations saved", timeout=2)
    
    def action_load_annotations(self) -> None:
        """Load annotations from file."""
        self._load_annotations_from_file()
        self.notify("Annotations loaded", timeout=2)
        
        # Refresh code panel to show annotations
        code_panel = self.query_one("#code-panel", CodePanel)
        code_panel.annotations = self.annotations
        code_panel.refresh()
    
    def action_show_command(self) -> None:
        """Show the command input."""
        command_input = self.query_one("#command-input", Input)
        command_input.remove_class("hidden")
        command_input.focus()
    
    def action_export_session(self) -> None:
        """Export the current session to a file."""
        self._export_session()
    
    def action_import_session(self) -> None:
        """Import a session from a file."""
        self._import_session()
    
    def _execute_command(self, command_text: str) -> None:
        """
        Parse and execute a command.
        
        Args:
            command_text: Command string to execute
        """
        # Add to command history
        if command_text and command_text not in self.command_history[-1:]:
            self.command_history.append(command_text)
            self.history_index = len(self.command_history)
        
        # Split command into parts
        parts = command_text.split(None, 1)
        if not parts:
            return
        
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        # Dispatch to appropriate command handler
        if command == "help":
            self._cmd_help(args)
        elif command == "goto" or command == "g":
            self._cmd_goto(args)
        elif command == "xref" or command == "x":
            self._cmd_xref(args)
        elif command == "search" or command == "find":
            self._cmd_search(args)
        elif command == "comment" or command == "c":
            self._cmd_comment(args)
        elif command == "export" or command == "e":
            self._cmd_export(args)
        elif command == "import" or command == "i":
            self._cmd_import(args)
        else:
            self.notify(f"Unknown command: {command}. Type 'help' for available commands.", timeout=3)
    
    def _cmd_help(self, args: str) -> None:
        """
        Display help for commands.
        
        Args:
            args: Optional command to get help for
        """
        if args:
            # Show help for specific command
            command = args.lower()
            help_texts = {
                "goto": "goto <address|function> - Navigate to a specific address or function\n"
                        "Examples: goto 0x1000, goto main, g 0x401000",
                "xref": "xref [address] - Display cross-references for current or specified address\n"
                        "Examples: xref, xref 0x1000, x 0x401000",
                "search": "search <pattern> - Search for pattern in strings and code\n"
                          "Examples: search flag, find password",
                "comment": "comment <address>: <text> - Add a comment at the specified address\n"
                           "Examples: comment 0x1000: Important function, c 0x401000: Entry point",
                "export": "export [filename] - Export current session to a file\n"
                          "Examples: export, export session.json, e analysis.json",
                "import": "import <filename> - Import a session from a file\n"
                          "Examples: import session.json, i analysis.json",
            }
            
            if command in help_texts:
                self.notify(help_texts[command], title=f"Help: {command}", timeout=10)
            else:
                self.notify(f"No help available for: {command}", timeout=3)
        else:
            # Show general help
            help_text = """
            Available Commands:
            
            goto (g) <address|function> - Navigate to address/function
            xref (x) [address]          - Show cross-references
            search (find) <pattern>     - Search strings and code
            comment (c) <addr>: <text>  - Add comment at address
            export (e) [filename]       - Export session
            import (i) <filename>       - Import session
            help [command]              - Show help (for specific command)
            
            Press ':' to open command prompt
            Press 'h' for keyboard shortcuts
            """
            self.notify(help_text, title="Command Help", timeout=15)
    
    def _cmd_goto(self, args: str) -> None:
        """
        Navigate to a specific address or function.
        
        Args:
            args: Address (hex or decimal) or function name
        """
        if not args:
            self.notify("Usage: goto <address|function>", timeout=3)
            return
        
        # Try to parse as address
        address = None
        try:
            if args.startswith('0x'):
                address = int(args, 16)
            elif args.isdigit():
                address = int(args)
        except ValueError:
            pass
        
        if address is not None:
            # Navigate to address
            code_panel = self.query_one("#code-panel", CodePanel)
            if code_panel.goto_address(address):
                self.notify(f"Navigated to 0x{address:08x}", timeout=2)
            else:
                self.notify(f"Address 0x{address:08x} not found", timeout=3)
        else:
            # Try to find function by name
            functions_panel = self.query_one("#functions-panel", FunctionsPanel)
            func_addr = functions_panel.find_function_by_name(args)
            if func_addr is not None:
                code_panel = self.query_one("#code-panel", CodePanel)
                code_panel.goto_address(func_addr)
                self.notify(f"Navigated to function '{args}' at 0x{func_addr:08x}", timeout=2)
            else:
                self.notify(f"Function '{args}' not found", timeout=3)
    
    def _cmd_xref(self, args: str) -> None:
        """
        Display cross-references for an address.
        
        Args:
            args: Optional address (uses current address if not specified)
        """
        address = None
        
        if args:
            # Parse specified address
            try:
                if args.startswith('0x'):
                    address = int(args, 16)
                elif args.isdigit():
                    address = int(args)
            except ValueError:
                self.notify(f"Invalid address: {args}", timeout=3)
                return
        else:
            # Use current address from code panel
            code_panel = self.query_one("#code-panel", CodePanel)
            address = code_panel.get_current_address()
        
        if address is None:
            self.notify("No address specified or selected", timeout=3)
            return
        
        # Display XREFs for address
        xrefs_panel = self.query_one("#xrefs-panel", XRefsPanel)
        xrefs_panel.show_xrefs_for_address(address)
        xrefs_panel.focus()
        
        self.notify(f"Showing XREFs for 0x{address:08x}", timeout=2)
    
    def _cmd_search(self, args: str) -> None:
        """
        Search for a pattern in strings and code.
        
        Args:
            args: Search pattern
        """
        if not args:
            self.notify("Usage: search <pattern>", timeout=3)
            return
        
        # Apply search to all panels
        self.search_query = args
        self._apply_search_to_panels()
        
        self.notify(f"Searching for: {args}", timeout=2)
    
    def _cmd_comment(self, args: str) -> None:
        """
        Add a comment at a specific address.
        
        Args:
            args: Comment in format "address: text"
        """
        if not args:
            self.notify("Usage: comment <address>: <text>", timeout=3)
            return
        
        # Parse and add annotation
        self._parse_and_add_annotation(args)
    
    def _cmd_export(self, args: str) -> None:
        """
        Export the current session to a file.
        
        Args:
            args: Optional filename (defaults to session.json)
        """
        filename = args.strip() if args else "dissectx_session.json"
        
        try:
            self._export_session(filename)
            self.notify(f"Session exported to {filename}", timeout=2)
        except Exception as e:
            self.notify(f"Export failed: {e}", timeout=3)
    
    def _cmd_import(self, args: str) -> None:
        """
        Import a session from a file.
        
        Args:
            args: Filename to import
        """
        if not args:
            self.notify("Usage: import <filename>", timeout=3)
            return
        
        filename = args.strip()
        
        try:
            self._import_session(filename)
            self.notify(f"Session imported from {filename}", timeout=2)
        except Exception as e:
            self.notify(f"Import failed: {e}", timeout=3)
    
    def _export_session(self, filename: str = "dissectx_session.json") -> None:
        """
        Export the current session to a JSON file.
        
        Args:
            filename: Output filename
        """
        session_data = {
            "annotations": {f"0x{addr:x}": comment for addr, comment in self.annotations.items()},
            "search_query": self.search_query,
            "syntax_highlighting": self.syntax_highlighting_enabled,
        }
        
        # Add current panel states
        code_panel = self.query_one("#code-panel", CodePanel)
        current_addr = code_panel.get_current_address()
        session_data["current_address"] = f"0x{current_addr:x}" if current_addr else None
        
        with open(filename, 'w') as f:
            json.dump(session_data, f, indent=2)
    
    def _import_session(self, filename: str = "dissectx_session.json") -> None:
        """
        Import a session from a JSON file.
        
        Args:
            filename: Input filename
        """
        if not Path(filename).exists():
            raise FileNotFoundError(f"Session file not found: {filename}")
        
        with open(filename, 'r') as f:
            session_data = json.load(f)
        
        # Restore annotations
        if "annotations" in session_data:
            # Parse addresses (handle both hex and decimal strings)
            self.annotations = {}
            for addr_str, comment in session_data["annotations"].items():
                if addr_str.startswith('0x'):
                    addr = int(addr_str, 16)
                else:
                    addr = int(addr_str)
                self.annotations[addr] = comment
            
            code_panel = self.query_one("#code-panel", CodePanel)
            code_panel.annotations = self.annotations
            code_panel.refresh()
        
        # Restore search query
        if "search_query" in session_data:
            self.search_query = session_data["search_query"]
            if self.search_query:
                self._apply_search_to_panels()
        
        # Restore syntax highlighting
        if "syntax_highlighting" in session_data:
            self.syntax_highlighting_enabled = session_data["syntax_highlighting"]
            code_panel = self.query_one("#code-panel", CodePanel)
            code_panel.syntax_highlighting = self.syntax_highlighting_enabled
            code_panel.refresh()
        
        # Restore current address
        if "current_address" in session_data and session_data["current_address"]:
            addr_str = session_data["current_address"]
            if addr_str.startswith('0x'):
                addr = int(addr_str, 16)
            else:
                addr = int(addr_str)
            code_panel = self.query_one("#code-panel", CodePanel)
            code_panel.goto_address(addr)


class CodePanel(Static):
    """Panel for displaying disassembled code."""
    
    can_focus = True
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.code_data = []
        self.search_query = ""
        self.filtered_data = []
        self.syntax_highlighting = True
        self.annotations = {}  # address -> comment mapping
        
        # Common x86/x64 registers
        self.registers = {
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
            'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
            'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp',
            'al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh',
            'rip', 'eip', 'ip',
            # ARM registers
            'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
            'sp', 'lr', 'pc',
            # x86 segment registers
            'cs', 'ds', 'es', 'fs', 'gs', 'ss',
        }
        
        # Common instruction mnemonics
        self.mnemonics = {
            'mov', 'push', 'pop', 'call', 'ret', 'jmp', 'je', 'jne', 'jz', 'jnz',
            'add', 'sub', 'mul', 'div', 'inc', 'dec', 'xor', 'and', 'or', 'not',
            'cmp', 'test', 'lea', 'nop', 'int', 'syscall', 'sysenter',
            'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe',
            'shl', 'shr', 'sal', 'sar', 'rol', 'ror',
            'movzx', 'movsx', 'movsxd',
            'ldr', 'str', 'b', 'bl', 'bx', 'blx',  # ARM
        }
    
    def render(self) -> str:
        """Render the code panel content."""
        if not self.code_data:
            return "[dim]Code Panel[/dim]\n\nNo code loaded. Load a binary to begin analysis."
        
        # Use filtered data if search is active
        display_data = self.filtered_data if self.search_query else self.code_data
        
        # Format code for display
        lines = ["[bold]Code Panel[/bold]"]
        if self.search_query:
            lines.append(f"[dim]Search: {self.search_query} ({len(display_data)} results)[/dim]\n")
        else:
            lines.append("")
        
        for addr, instr in display_data[:50]:  # Show first 50 instructions
            # Apply syntax highlighting
            if self.syntax_highlighting:
                instr_formatted = self._apply_syntax_highlighting(instr)
            else:
                instr_formatted = instr
            
            # Highlight search matches
            if self.search_query:
                instr_formatted = self._highlight_matches(instr_formatted, self.search_query)
            
            # Add instruction line
            lines.append(f"[dim]0x{addr:08x}[/dim]  {instr_formatted}")
            
            # Add annotation if present
            if addr in self.annotations:
                lines.append(f"           [italic green]; {self.annotations[addr]}[/italic green]")
        
        if len(display_data) > 50:
            lines.append(f"\n[dim]... and {len(display_data) - 50} more instructions[/dim]")
        
        return "\n".join(lines)
    
    def load_code(self, results):
        """
        Load code from analysis results.
        
        Args:
            results: AnalysisResults object
        """
        if hasattr(results, 'instructions') and results.instructions:
            self.code_data = [
                (instr.address, f"{instr.mnemonic} {', '.join(str(op) for op in instr.operands)}")
                for instr in results.instructions
            ]
        else:
            self.code_data = []
        self.filtered_data = self.code_data
        self.refresh()
    
    def apply_search(self, query: str) -> None:
        """
        Apply search filter to code data.
        
        Args:
            query: Search query string
        """
        self.search_query = query
        if not query:
            self.filtered_data = self.code_data
        else:
            # Filter code data based on query (case-insensitive)
            query_lower = query.lower()
            self.filtered_data = [
                (addr, instr) for addr, instr in self.code_data
                if query_lower in instr.lower() or query_lower in f"{addr:08x}"
            ]
        self.refresh()
    
    def clear_search(self) -> None:
        """Clear search filter."""
        self.search_query = ""
        self.filtered_data = self.code_data
        self.refresh()
    
    def _highlight_matches(self, text: str, query: str) -> str:
        """
        Highlight search matches in text.
        
        Args:
            text: Text to highlight
            query: Search query
            
        Returns:
            Text with highlighted matches
        """
        if not query:
            return text
        
        # Case-insensitive highlighting
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        
        # Find all matches
        matches = list(pattern.finditer(text))
        if not matches:
            return text
        
        # Build highlighted text
        result = []
        last_end = 0
        for match in matches:
            result.append(text[last_end:match.start()])
            result.append(f"[reverse]{text[match.start():match.end()]}[/reverse]")
            last_end = match.end()
        result.append(text[last_end:])
        
        return "".join(result)
    
    def _apply_syntax_highlighting(self, instruction: str) -> str:
        """
        Apply syntax highlighting to assembly instruction.
        
        Args:
            instruction: Assembly instruction string
            
        Returns:
            Instruction with syntax highlighting markup
        """
        if not instruction:
            return instruction
        
        # Split instruction into parts
        parts = instruction.split(None, 1)
        if not parts:
            return instruction
        
        mnemonic = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ""
        
        # Highlight mnemonic
        if mnemonic in self.mnemonics:
            result = f"[bold cyan]{parts[0]}[/bold cyan]"
        else:
            result = parts[0]
        
        if operands:
            result += " "
            # Highlight operands
            result += self._highlight_operands(operands)
        
        return result
    
    def _highlight_operands(self, operands: str) -> str:
        """
        Highlight operands in assembly instruction.
        
        Args:
            operands: Operands string
            
        Returns:
            Operands with syntax highlighting
        """
        # Split by comma to handle multiple operands
        parts = []
        current = []
        in_bracket = False
        
        for char in operands:
            if char == '[':
                in_bracket = True
            elif char == ']':
                in_bracket = False
            elif char == ',' and not in_bracket:
                parts.append(''.join(current).strip())
                current = []
                continue
            current.append(char)
        
        if current:
            parts.append(''.join(current).strip())
        
        # Highlight each operand
        highlighted_parts = []
        for part in parts:
            highlighted_parts.append(self._highlight_single_operand(part))
        
        return ', '.join(highlighted_parts)
    
    def _highlight_single_operand(self, operand: str) -> str:
        """
        Highlight a single operand.
        
        Args:
            operand: Single operand string
            
        Returns:
            Operand with syntax highlighting
        """
        operand = operand.strip()
        
        # Check if it's a register
        operand_lower = operand.lower()
        if operand_lower in self.registers:
            return f"[green]{operand}[/green]"
        
        # Check if it's a memory reference [...]
        if operand.startswith('[') and operand.endswith(']'):
            inner = operand[1:-1]
            return f"[yellow][[/yellow]{self._highlight_operands(inner)}[yellow]][/yellow]"
        
        # Check if it's an immediate value (hex or decimal)
        if operand.startswith('0x') or operand.startswith('-0x'):
            return f"[magenta]{operand}[/magenta]"
        
        # Check if it's a decimal number
        if operand.lstrip('-').isdigit():
            return f"[magenta]{operand}[/magenta]"
        
        # Default: return as-is
        return operand
    
    def goto_address(self, address: int) -> bool:
        """
        Navigate to a specific address in the code.
        
        Args:
            address: Address to navigate to
            
        Returns:
            True if address was found, False otherwise
        """
        # Find the address in code data
        for i, (addr, instr) in enumerate(self.code_data):
            if addr == address:
                # Found the address - in a real implementation, we would scroll to it
                # For now, just filter to show it
                self.filtered_data = [(addr, instr)]
                self.refresh()
                return True
        
        return False
    
    def get_current_address(self) -> int:
        """
        Get the current address being viewed.
        
        Returns:
            Current address or None if no code loaded
        """
        if self.filtered_data:
            return self.filtered_data[0][0]
        elif self.code_data:
            return self.code_data[0][0]
        return None


class StringsPanel(Static):
    """Panel for displaying extracted strings."""
    
    can_focus = True
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.strings_data = []
        self.search_query = ""
        self.filtered_data = []
    
    def render(self) -> str:
        """Render the strings panel content."""
        if not self.strings_data:
            return "[dim]Strings Panel[/dim]\n\nNo strings found."
        
        # Use filtered data if search is active
        display_data = self.filtered_data if self.search_query else self.strings_data
        
        lines = ["[bold]Strings Panel[/bold]"]
        if self.search_query:
            lines.append(f"[dim]Search: {self.search_query} ({len(display_data)} results)[/dim]\n")
        else:
            lines.append("")
        
        for i, string_info in enumerate(display_data[:30]):  # Show first 30 strings
            if isinstance(string_info, tuple):
                addr, string = string_info
                string_display = string[:60]
                if self.search_query:
                    string_display = self._highlight_matches(string_display, self.search_query)
                lines.append(f"0x{addr:08x}  {string_display}")
            else:
                string_display = string_info[:60]
                if self.search_query:
                    string_display = self._highlight_matches(string_display, self.search_query)
                lines.append(f"{string_display}")
        
        if len(display_data) > 30:
            lines.append(f"\n[dim]... and {len(display_data) - 30} more strings[/dim]")
        
        return "\n".join(lines)
    
    def load_strings(self, results):
        """
        Load strings from analysis results.
        
        Args:
            results: AnalysisResults object
        """
        if hasattr(results, 'strings') and results.strings:
            self.strings_data = results.strings
        else:
            self.strings_data = []
        self.filtered_data = self.strings_data
        self.refresh()
    
    def apply_search(self, query: str) -> None:
        """
        Apply search filter to strings data.
        
        Args:
            query: Search query string
        """
        self.search_query = query
        if not query:
            self.filtered_data = self.strings_data
        else:
            # Filter strings data based on query (case-insensitive)
            query_lower = query.lower()
            self.filtered_data = []
            for string_info in self.strings_data:
                if isinstance(string_info, tuple):
                    addr, string = string_info
                    if query_lower in string.lower() or query_lower in f"{addr:08x}":
                        self.filtered_data.append(string_info)
                else:
                    if query_lower in string_info.lower():
                        self.filtered_data.append(string_info)
        self.refresh()
    
    def clear_search(self) -> None:
        """Clear search filter."""
        self.search_query = ""
        self.filtered_data = self.strings_data
        self.refresh()
    
    def _highlight_matches(self, text: str, query: str) -> str:
        """
        Highlight search matches in text.
        
        Args:
            text: Text to highlight
            query: Search query
            
        Returns:
            Text with highlighted matches
        """
        if not query:
            return text
        
        # Case-insensitive highlighting
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        
        # Find all matches
        matches = list(pattern.finditer(text))
        if not matches:
            return text
        
        # Build highlighted text
        result = []
        last_end = 0
        for match in matches:
            result.append(text[last_end:match.start()])
            result.append(f"[reverse]{text[match.start():match.end()]}[/reverse]")
            last_end = match.end()
        result.append(text[last_end:])
        
        return "".join(result)


class FunctionsPanel(Static):
    """Panel for displaying function list."""
    
    can_focus = True
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.functions_data = []
        self.search_query = ""
        self.filtered_data = []
    
    def render(self) -> str:
        """Render the functions panel content."""
        if not self.functions_data:
            return "[dim]Functions Panel[/dim]\n\nNo functions identified."
        
        # Use filtered data if search is active
        display_data = self.filtered_data if self.search_query else self.functions_data
        
        lines = ["[bold]Functions Panel[/bold]"]
        if self.search_query:
            lines.append(f"[dim]Search: {self.search_query} ({len(display_data)} results)[/dim]\n")
        else:
            lines.append("")
        
        for addr, func_name in display_data[:30]:  # Show first 30 functions
            if self.search_query:
                func_name_highlighted = self._highlight_matches(func_name, self.search_query)
                lines.append(f"0x{addr:08x}  {func_name_highlighted}")
            else:
                lines.append(f"0x{addr:08x}  {func_name}")
        
        if len(display_data) > 30:
            lines.append(f"\n[dim]... and {len(display_data) - 30} more functions[/dim]")
        
        return "\n".join(lines)
    
    def load_functions(self, results):
        """
        Load functions from analysis results.
        
        Args:
            results: AnalysisResults object
        """
        if hasattr(results, 'functions') and results.functions:
            self.functions_data = [
                (addr, func.get('name', f'sub_{addr:x}'))
                for addr, func in results.functions.items()
            ]
        else:
            self.functions_data = []
        self.filtered_data = self.functions_data
        self.refresh()
    
    def apply_search(self, query: str) -> None:
        """
        Apply search filter to functions data.
        
        Args:
            query: Search query string
        """
        self.search_query = query
        if not query:
            self.filtered_data = self.functions_data
        else:
            # Filter functions data based on query (case-insensitive)
            query_lower = query.lower()
            self.filtered_data = [
                (addr, func_name) for addr, func_name in self.functions_data
                if query_lower in func_name.lower() or query_lower in f"{addr:08x}"
            ]
        self.refresh()
    
    def clear_search(self) -> None:
        """Clear search filter."""
        self.search_query = ""
        self.filtered_data = self.functions_data
        self.refresh()
    
    def _highlight_matches(self, text: str, query: str) -> str:
        """
        Highlight search matches in text.
        
        Args:
            text: Text to highlight
            query: Search query
            
        Returns:
            Text with highlighted matches
        """
        if not query:
            return text
        
        # Case-insensitive highlighting
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        
        # Find all matches
        matches = list(pattern.finditer(text))
        if not matches:
            return text
        
        # Build highlighted text
        result = []
        last_end = 0
        for match in matches:
            result.append(text[last_end:match.start()])
            result.append(f"[reverse]{text[match.start():match.end()]}[/reverse]")
            last_end = match.end()
        result.append(text[last_end:])
        
        return "".join(result)
    
    def find_function_by_name(self, name: str) -> int:
        """
        Find a function by name.
        
        Args:
            name: Function name to search for
            
        Returns:
            Function address or None if not found
        """
        name_lower = name.lower()
        for addr, func_name in self.functions_data:
            if func_name.lower() == name_lower or name_lower in func_name.lower():
                return addr
        return None


class XRefsPanel(Static):
    """Panel for displaying cross-references."""
    
    can_focus = True
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.xrefs_data = []
        self.current_address = None
        self.search_query = ""
        self.filtered_data = []
    
    def render(self) -> str:
        """Render the cross-references panel content."""
        if not self.xrefs_data:
            return "[dim]Cross-References Panel[/dim]\n\nNo cross-references loaded. Select an address to view XREFs."
        
        # Use filtered data if search is active
        display_data = self.filtered_data if self.search_query else self.xrefs_data
        
        lines = ["[bold]Cross-References Panel[/bold]"]
        if self.current_address:
            lines.append(f"XREFs for 0x{self.current_address:08x}")
        if self.search_query:
            lines.append(f"[dim]Search: {self.search_query} ({len(display_data)} results)[/dim]\n")
        else:
            lines.append("")
        
        for xref_type, refs in display_data[:20]:  # Show first 20 xrefs
            if self.search_query:
                xref_type_highlighted = self._highlight_matches(xref_type, self.search_query)
                refs_highlighted = self._highlight_matches(str(refs), self.search_query)
                lines.append(f"{xref_type_highlighted}: {refs_highlighted}")
            else:
                lines.append(f"{xref_type}: {refs}")
        
        if len(display_data) > 20:
            lines.append(f"\n[dim]... and {len(display_data) - 20} more references[/dim]")
        
        return "\n".join(lines)
    
    def load_xrefs(self, results):
        """
        Load cross-references from analysis results.
        
        Args:
            results: AnalysisResults object
        """
        if hasattr(results, 'xrefs') and results.xrefs:
            # Extract sample xrefs for display
            xrefs_db = results.xrefs
            self.xrefs_data = []
            
            # Show function calls
            if hasattr(xrefs_db, 'function_calls'):
                for caller, callees in list(xrefs_db.function_calls.items())[:10]:
                    self.xrefs_data.append((
                        f"Call from 0x{caller:08x}",
                        f"to {len(callees)} function(s)"
                    ))
            
            # Show string references
            if hasattr(xrefs_db, 'string_refs'):
                for string, refs in list(xrefs_db.string_refs.items())[:10]:
                    self.xrefs_data.append((
                        f"String '{string[:30]}'",
                        f"used at {len(refs)} location(s)"
                    ))
        else:
            self.xrefs_data = []
        self.refresh()
    
    def show_xrefs_for_address(self, address):
        """
        Show cross-references for a specific address.
        
        Args:
            address: Address to show XREFs for
        """
        self.current_address = address
        # This will be enhanced in future tasks to show specific XREFs
        self.refresh()
    
    def apply_search(self, query: str) -> None:
        """
        Apply search filter to xrefs data.
        
        Args:
            query: Search query string
        """
        self.search_query = query
        if not query:
            self.filtered_data = self.xrefs_data
        else:
            # Filter xrefs data based on query (case-insensitive)
            query_lower = query.lower()
            self.filtered_data = [
                (xref_type, refs) for xref_type, refs in self.xrefs_data
                if query_lower in xref_type.lower() or query_lower in str(refs).lower()
            ]
        self.refresh()
    
    def clear_search(self) -> None:
        """Clear search filter."""
        self.search_query = ""
        self.filtered_data = self.xrefs_data
        self.refresh()
    
    def _highlight_matches(self, text: str, query: str) -> str:
        """
        Highlight search matches in text.
        
        Args:
            text: Text to highlight
            query: Search query
            
        Returns:
            Text with highlighted matches
        """
        if not query:
            return text
        
        # Case-insensitive highlighting
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        
        # Find all matches
        matches = list(pattern.finditer(text))
        if not matches:
            return text
        
        # Build highlighted text
        result = []
        last_end = 0
        for match in matches:
            result.append(text[last_end:match.start()])
            result.append(f"[reverse]{text[match.start():match.end()]}[/reverse]")
            last_end = match.end()
        result.append(text[last_end:])
        
        return "".join(result)


def run_tui(analysis_results=None):
    """
    Run the DissectX TUI application.
    
    Args:
        analysis_results: Optional AnalysisResults object to display
    """
    app = DissectXTUI(analysis_results=analysis_results)
    app.run()


if __name__ == "__main__":
    # Run TUI in standalone mode for testing
    run_tui()
