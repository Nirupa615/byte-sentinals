import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import sys
from typing import Optional

class AppLogger:
    """
    A centralized logging utility for the application.
    
    This class provides a consistent way to log messages across the application,
    with support for both file and console logging.
    """
    
    _instance = None
    
    def __new__(cls, log_dir: str = "logs", log_level: int = logging.INFO):
        """Create a singleton instance of the logger."""
        if cls._instance is None:
            cls._instance = super(AppLogger, cls).__new__(cls)
            cls._instance._initialized = False
            cls._instance.log_dir = log_dir
            cls._instance.log_level = log_level
            cls._instance._setup_logger()
            cls._instance._initialized = True
        return cls._instance
    
    def _setup_logger(self) -> None:
        """Configure the logger with file and console handlers."""
        # Create log directory if it doesn't exist
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Create a custom logger
        self.logger = logging.getLogger('SysGuardX')
        self.logger.setLevel(self.log_level)
        
        # Prevent adding multiple handlers in case of multiple initializations
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
        
        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        
        # Create file handler
        log_file = os.path.join(self.log_dir, f'sysguardx_{datetime.now().strftime("%Y%m%d")}.log')
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB per file
            backupCount=5,          # Keep 5 backup files
            encoding='utf-8'
        )
        file_handler.setLevel(self.log_level)
        file_handler.setFormatter(file_formatter)
        
        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(console_formatter)
        
        # Add handlers to the logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    @classmethod
    def get_logger(cls, name: Optional[str] = None) -> logging.Logger:
        """
        Get a logger instance with the specified name.
        
        Args:
            name: The name of the logger. If None, returns the root logger.
            
        Returns:
            A configured logger instance.
        """
        if cls._instance is None:
            cls()  # Initialize with default settings
        
        if name:
            # Create a child logger for the specified module/component
            logger = cls._instance.logger.getChild(name)
            logger.propagate = True  # Allow propagation to parent logger
            return logger
        return cls._instance.logger
    
    @classmethod
    def set_level(cls, level: int) -> None:
        """
        Set the logging level for all handlers.
        
        Args:
            level: The logging level (e.g., logging.DEBUG, logging.INFO)
        """
        if cls._instance is None:
            cls()  # Initialize with default settings
            
        cls._instance.logger.setLevel(level)
        for handler in cls._instance.logger.handlers:
            handler.setLevel(level)
    
    @classmethod
    def get_log_file_path(cls) -> str:
        """
        Get the path to the current log file.
        
        Returns:
            The absolute path to the current log file.
        """
        if cls._instance is None:
            return ""
            
        for handler in cls._instance.logger.handlers:
            if isinstance(handler, RotatingFileHandler):
                return os.path.abspath(handler.baseFilename)
        return ""

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    A convenience function to get a logger instance.
    
    This is the recommended way to get a logger in application code.
    
    Args:
        name: The name of the logger. If None, returns the root logger.
        
    Returns:
        A configured logger instance.
    """
    return AppLogger.get_logger(name)

# Example usage
if __name__ == "__main__":
    # Get a logger for the current module
    logger = get_logger(__name__)
    
    # Log some messages at different levels
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    
    # Log an exception with stack trace
    try:
        1 / 0
    except ZeroDivisionError as e:
        logger.exception("An error occurred:")
