"""
Helper utilities for the SysGuardX application.

This module provides various utility functions that are used throughout the application.
"""

import os
import re
import json
import hashlib
import uuid
import random
import string
import time
import functools
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from pathlib import Path
from datetime import datetime, timedelta

# Import config and logger
from .config import config
from .logger import get_logger

logger = get_logger(__name__)

def generate_id(prefix: str = '', length: int = 12) -> str:
    """
    Generate a unique ID with an optional prefix.
    
    Args:
        prefix: Optional prefix for the ID
        length: Length of the random part of the ID
        
    Returns:
        A unique string ID
    """
    random_str = ''.join(
        random.choices(
            string.ascii_lowercase + string.digits,
            k=length
        )
    )
    return f"{prefix}_{random_str}" if prefix else random_str

def get_timestamp() -> str:
    """
    Get the current timestamp in ISO 8601 format.
    
    Returns:
        Current timestamp as a string
    """
    return datetime.utcnow().isoformat() + 'Z'

def parse_timestamp(timestamp: str) -> datetime:
    """
    Parse an ISO 8601 formatted timestamp string to a datetime object.
    
    Args:
        timestamp: ISO 8601 formatted timestamp string
        
    Returns:
        A datetime object
    """
    # Remove the 'Z' timezone indicator if present
    if timestamp.endswith('Z'):
        timestamp = timestamp[:-1]
    
    # Parse with timezone info if available
    if '+' in timestamp or timestamp.endswith('Z'):
        return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    return datetime.fromisoformat(timestamp)

def format_duration(seconds: Union[int, float]) -> str:
    """
    Format a duration in seconds to a human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string (e.g., '2h 30m 15s')
    """
    seconds = int(seconds)
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or (hours > 0 and seconds > 0):
        parts.append(f"{minutes}m")
    if seconds > 0 or not parts:
        parts.append(f"{seconds}s")
        
    return ' '.join(parts)

def get_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256', 
                chunk_size: int = 65536) -> str:
    """
    Calculate the hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (e.g., 'md5', 'sha1', 'sha256')
        chunk_size: Size of chunks to read from the file
        
    Returns:
        The file's hash as a hexadecimal string
    """
    hash_func = getattr(hashlib, algorithm.lower(), hashlib.sha256)
    h = hash_func()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    
    return h.hexdigest()

def validate_email(email: str) -> bool:
    """
    Validate an email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if the email is valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
        
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def generate_password(length: int = 16) -> str:
    """
    Generate a random password with specified length.
    
    Args:
        length: Length of the password to generate
        
    Returns:
        A random password string
    """
    if length < 8:
        length = 8
        
    # Define character sets
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    # Ensure at least one character from each set
    password = [
        random.choice(lower),
        random.choice(upper),
        random.choice(digits),
        random.choice(special)
    ]
    
    # Fill the rest of the password
    all_chars = lower + upper + digits + special
    password.extend(random.choices(all_chars, k=length - len(password)))
    
    # Shuffle to avoid predictable patterns
    random.shuffle(password)
    return ''.join(password)

def retry(max_retries: int = 3, delay: float = 1.0, 
          exceptions: tuple = (Exception,), 
          backoff_factor: float = 2.0,
          logger: Optional[logging.Logger] = None) -> Callable:
    """
    A decorator for retrying a function with exponential backoff.
    
    Args:
        max_retries: Maximum number of retries
        delay: Initial delay between retries in seconds
        exceptions: Tuple of exceptions to catch and retry on
        backoff_factor: Multiplier for delay between retries
        logger: Logger instance for logging retries
        
    Returns:
        Decorated function with retry logic
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        wait_time = current_delay * (backoff_factor ** attempt)
                        if logger:
                            logger.warning(
                                f"Attempt {attempt + 1}/{max_retries} failed: {str(e)}. "
                                f"Retrying in {wait_time:.1f} seconds..."
                            )
                        time.sleep(wait_time)
                    else:
                        if logger:
                            logger.error(
                                f"All {max_retries} attempts failed. Last error: {str(e)}"
                            )
                        raise
            
            # This should never be reached due to the raise in the loop
            raise last_exception if last_exception else Exception("Unknown error in retry")
        return wrapper
    return decorator

def size_to_human_readable(size_bytes: int) -> str:
    """
    Convert a size in bytes to a human-readable string.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Human-readable size string (e.g., '1.5 MB')
    """
    if size_bytes == 0:
        return "0 B"
        
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    i = 0
    while size_bytes >= 1024 and i < len(units) - 1:
        size_bytes /= 1024
        i += 1
        
    return f"{size_bytes:.1f} {units[i]}"

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing or replacing unsafe characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename with unsafe characters replaced by underscores
    """
    # Replace or remove unsafe characters
    filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
    # Remove leading/trailing whitespace and dots
    filename = filename.strip(' .')
    # Replace multiple underscores with a single one
    filename = re.sub(r'_+', '_', filename)
    
    return filename or 'unnamed_file'

def json_serializer(obj: Any) -> Any:
    """
    JSON serializer for objects not serializable by default json code.
    
    Args:
        obj: Object to serialize
        
    Returns:
        JSON-serializable representation of the object
        
    Raises:
        TypeError: If the object cannot be serialized
    """
    if isinstance(obj, (datetime, datetime.date)):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif hasattr(obj, '__dict__'):
        return obj.__dict__
    elif isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

def to_json(obj: Any, indent: Optional[int] = None) -> str:
    """
    Convert an object to a JSON string with support for additional types.
    
    Args:
        obj: Object to serialize
        indent: Indentation level for pretty-printing
        
    Returns:
        JSON string representation of the object
    """
    return json.dumps(obj, default=json_serializer, indent=indent, ensure_ascii=False)

# Example usage
if __name__ == "__main__":
    # Test ID generation
    print(f"Generated ID: {generate_id('event')}")
    
    # Test timestamp functions
    timestamp = get_timestamp()
    print(f"Current timestamp: {timestamp}")
    print(f"Parsed timestamp: {parse_timestamp(timestamp)}")
    
    # Test duration formatting
    print(f"Duration: {format_duration(9015)}")
    
    # Test password generation
    print(f"Generated password: {generate_password(12)}")
    
    # Test email validation
    print(f"Is 'test@example.com' valid? {validate_email('test@example.com')}")
    
    # Test file size formatting
    print(f"File size: {size_to_human_readable(1536000)}")
    
    # Test sanitize filename
    print(f"Sanitized filename: {sanitize_filename('my/file:name?*.txt')}")
    
    # Test JSON serialization
    data = {
        'id': generate_id(),
        'timestamp': datetime.utcnow(),
        'nested': {'value': 42},
        'tags': {'important', 'test'}
    }
    print(f"JSON output:\n{to_json(data, indent=2)}")
    
    # Test retry decorator
    @retry(max_retries=3, delay=1, exceptions=(ValueError,))
    def might_fail():
        if random.random() < 0.7:
            raise ValueError("Temporary failure")
        return "Success!"
    
    print("Testing retry decorator...")
    try:
        print(might_fail())
    except Exception as e:
        print(f"All retries failed: {e}")
