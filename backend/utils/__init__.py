"""
Utility functions and classes for the SysGuardX application.

This package provides various utility modules that are used throughout the application:
- logger: Centralized logging configuration and utilities
- config: Application configuration management
- helpers: General-purpose helper functions
"""

# Import key utilities to make them available at the package level
from .logger import get_logger, AppLogger
from .config import config, Config
from .helpers import (
    generate_id,
    get_timestamp,
    parse_timestamp,
    format_duration,
    get_file_hash,
    validate_email,
    generate_password,
    retry,
    size_to_human_readable,
    sanitize_filename,
    json_serializer,
    to_json,
)

# Define what gets imported with 'from utils import *'
__all__ = [
    # Logger
    'get_logger',
    'AppLogger',
    
    # Config
    'config',
    'Config',
    
    # Helpers
    'generate_id',
    'get_timestamp',
    'parse_timestamp',
    'format_duration',
    'get_file_hash',
    'validate_email',
    'generate_password',
    'retry',
    'size_to_human_readable',
    'sanitize_filename',
    'json_serializer',
    'to_json',
]
