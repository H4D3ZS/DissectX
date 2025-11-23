"""Input handler for reading assembly code from various sources"""
import sys
from pathlib import Path
from typing import Optional, Tuple


class InputHandler:
    """Handles reading assembly code from files, stdin, or interactive input"""

    def __init__(self):
        """Initialize input handler"""
        self.show_stats = True  # Show statistics after reading

    def read_from_file(self, filepath: str) -> str:
        """
        Read assembly code from a file.
        
        Args:
            filepath: Path to the file containing assembly code
            
        Returns:
            Assembly code as a string
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            IOError: If the file cannot be read
            ValueError: If the file is empty
        """
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        if not path.is_file():
            raise IOError(f"Not a file: {filepath}")
        
        try:
            content = path.read_text(encoding='utf-8')
        except Exception as e:
            raise IOError(f"Cannot read file: {filepath}") from e
        
        if not content.strip():
            raise ValueError("No assembly code provided")
        
        return content
    
    def read_from_stdin(self, show_stats: bool = True) -> Tuple[str, dict]:
        """
        Read assembly code from standard input.

        Args:
            show_stats: Whether to display statistics after reading

        Returns:
            Tuple of (assembly_code, stats_dict)

        Raises:
            ValueError: If stdin is empty
        """
        if show_stats:
            print("📥 Reading from stdin...", file=sys.stderr)

        content = sys.stdin.read()

        if not content.strip():
            raise ValueError("No assembly code provided")

        # Calculate stats
        lines = content.strip().split('\n')
        stats = {
            'lines': len(lines),
            'bytes': len(content),
            'source': 'stdin'
        }

        if show_stats:
            print(f"✓ Read {stats['lines']} lines from stdin", file=sys.stderr)

        return content, stats
    
    def read_interactive(self, terminator: Optional[str] = 'END', show_line_count: bool = True) -> Tuple[str, dict]:
        """
        Read multi-line assembly code interactively until EOF or terminator.

        Args:
            terminator: String to signal end of input (default: 'END')
            show_line_count: Whether to display line count while reading

        Returns:
            Tuple of (assembly_code, stats_dict)

        Raises:
            ValueError: If no input is provided
        """
        lines = []

        # Enhanced prompt
        print("\n" + "="*70, file=sys.stderr)
        print("📝 Assembly Input Mode - Interactive", file=sys.stderr)
        print("="*70, file=sys.stderr)
        print("• Paste or type assembly code below", file=sys.stderr)
        print("• Press Ctrl+D (Mac/Linux) or Ctrl+Z (Windows) when done", file=sys.stderr)
        if terminator:
            print(f"• Or type '{terminator}' on its own line to finish", file=sys.stderr)
        print("="*70, file=sys.stderr)
        print("", file=sys.stderr)

        try:
            while True:
                try:
                    line = input()

                    # Check for terminator
                    if terminator and line.strip() == terminator:
                        break

                    lines.append(line)

                    # Show progress every 10 lines
                    if show_line_count and len(lines) % 10 == 0:
                        print(f"\r▶ {len(lines)} lines received", end='', file=sys.stderr, flush=True)

                except EOFError:
                    # Ctrl+D (Unix) or Ctrl+Z (Windows) pressed
                    if show_line_count:
                        print(file=sys.stderr)  # New line after progress
                    break
        except KeyboardInterrupt:
            # Ctrl+C pressed - treat as cancellation
            print("\n❌ Input cancelled", file=sys.stderr)
            raise ValueError("Input cancelled")

        content = '\n'.join(lines)

        if not content.strip():
            raise ValueError("No assembly code provided")

        # Final stats
        stats = {
            'lines': len(lines),
            'bytes': len(content),
            'source': 'interactive'
        }

        print(f"\n▶ {stats['lines']} lines received\n", file=sys.stderr)

        return content, stats
