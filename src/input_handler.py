"""Input handler for reading assembly code from various sources"""
import sys
from pathlib import Path
from typing import Optional


class InputHandler:
    """Handles reading assembly code from files, stdin, or interactive input"""
    
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
    
    def read_from_stdin(self) -> str:
        """
        Read assembly code from standard input.
        
        Returns:
            Assembly code as a string
            
        Raises:
            ValueError: If stdin is empty
        """
        content = sys.stdin.read()
        
        if not content.strip():
            raise ValueError("No assembly code provided")
        
        return content
    
    def read_interactive(self, terminator: Optional[str] = None) -> str:
        """
        Read multi-line assembly code interactively until EOF or terminator.
        
        Args:
            terminator: Optional string to signal end of input (default: EOF/Ctrl+D)
            
        Returns:
            Assembly code as a string
            
        Raises:
            ValueError: If no input is provided
        """
        lines = []
        
        print("Enter assembly code (press Ctrl+D or Ctrl+Z to finish):")
        if terminator:
            print(f"Or type '{terminator}' on a line by itself to finish.")
        
        try:
            while True:
                try:
                    line = input()
                    
                    # Check for terminator
                    if terminator and line.strip() == terminator:
                        break
                    
                    lines.append(line)
                except EOFError:
                    # Ctrl+D (Unix) or Ctrl+Z (Windows) pressed
                    break
        except KeyboardInterrupt:
            # Ctrl+C pressed - treat as cancellation
            raise ValueError("Input cancelled")
        
        content = '\n'.join(lines)
        
        if not content.strip():
            raise ValueError("No assembly code provided")
        
        return content
