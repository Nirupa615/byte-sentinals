import os
import json
import yaml
from typing import Any, Dict, Optional, Union
from pathlib import Path
from dotenv import load_dotenv
import logging

# Import logger
from .logger import get_logger

logger = get_logger(__name__)

class Config:
    """
    A configuration management utility that loads settings from multiple sources.
    
    Priority order for configuration (highest to lowest):
    1. Environment variables
    2. .env file
    3. config.yaml file
    4. Default values
    
    Environment variables should be prefixed with 'SYSGUARDX_' to avoid conflicts.
    """
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        """Implement singleton pattern."""
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize the configuration with default values and load from files."""
        if self._initialized:
            return
            
        # Default configuration
        self._config = {
            'app': {
                'name': 'SysGuardX',
                'version': '1.0.0',
                'environment': 'development',
                'debug': True,
                'secret_key': 'your-secret-key-here',  # Change this in production
                'host': '0.0.0.0',
                'port': 5000,
            },
            'database': {
                'uri': 'sqlite:///sysguardx.db',
                'echo': False,
                'pool_size': 10,
                'max_overflow': 20,
                'pool_recycle': 3600,
            },
            'security': {
                'jwt_secret': 'your-jwt-secret-key-here',  # Change this in production
                'jwt_expire_minutes': 1440,  # 24 hours
                'password_salt_rounds': 10,
                'cors_origins': ['*'],
                'rate_limit': '1000 per day, 100 per hour',
            },
            'logging': {
                'level': 'INFO',
                'max_size_mb': 10,
                'backup_count': 5,
                'format': '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S',
            },
            'ml': {
                'model_path': 'backend/ml_model/model.pkl',
                'threshold': 0.7,
                'batch_size': 100,
            },
            'storage': {
                'upload_folder': 'backend/static_uploads',
                'max_file_size_mb': 50,
                'allowed_extensions': ['json', 'xml', 'evtx', 'log'],
            },
        }
        
        # Load configuration from files and environment
        self._load_config()
        self._initialized = True
    
    def _load_config(self) -> None:
        """Load configuration from various sources with proper precedence."""
        # 1. Load from config.yaml if it exists
        config_file = Path('config.yaml')
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    file_config = yaml.safe_load(f) or {}
                self._deep_update(self._config, file_config)
                logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                logger.error(f"Error loading config file {config_file}: {e}")
        
        # 2. Load from .env file if it exists
        env_file = Path('.env')
        if env_file.exists():
            load_dotenv(dotenv_path=env_file, override=True)
            logger.info(f"Loaded environment variables from {env_file}")
        
        # 3. Override with environment variables
        self._load_from_env()
    
    def _load_from_env(self) -> None:
        """Update configuration from environment variables."""
        for key, value in os.environ.items():
            if not key.startswith('SYSGUARDX_'):
                continue
                
            # Convert SYSGUARDX_DATABASE_URI to config path ['database', 'uri']
            parts = key.lower().split('_')
            if len(parts) < 2:  # At least SYSGUARDX_KEY
                continue
                
            # Remove 'sysguardx' prefix and convert to config path
            parts = parts[1:]
            self._set_nested(self._config, parts, self._parse_env_value(value))
    
    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable string value to appropriate Python type."""
        if value.lower() in ('true', 'yes', 'on'):
            return True
        if value.lower() in ('false', 'no', 'off'):
            return False
        if value.isdigit():
            return int(value)
        try:
            return float(value)
        except ValueError:
            # Handle JSON arrays/dicts
            if value.startswith(('{', '[')) and value.endswith(('}', ']')):
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    pass
            return value
    
    def _deep_update(self, original: Dict, update: Dict) -> Dict:
        """Recursively update a dictionary."""
        for key, value in update.items():
            if isinstance(value, dict) and key in original and isinstance(original[key], dict):
                original[key] = self._deep_update(original[key], value)
            else:
                original[key] = value
        return original
    
    def _set_nested(self, d: Dict, keys: list, value: Any) -> None:
        """Set a value in a nested dictionary using a list of keys."""
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Example:
            config.get('app.name')
            config.get('database.uri')
        """
        try:
            return self._get_nested(self._config, key.split('.'))
        except (KeyError, AttributeError):
            return default
    
    def _get_nested(self, d: Dict, keys: list) -> Any:
        """Get a value from a nested dictionary using a list of keys."""
        if len(keys) == 1:
            return d[keys[0]]
        return self._get_nested(d[keys[0]], keys[1:])
    
    def to_dict(self) -> Dict:
        """Return the entire configuration as a dictionary."""
        return self._config
    
    def save_to_file(self, filepath: Union[str, Path] = 'config.yaml') -> None:
        """Save the current configuration to a YAML file."""
        try:
            with open(filepath, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False, sort_keys=False)
            logger.info(f"Configuration saved to {filepath}")
        except Exception as e:
            logger.error(f"Error saving configuration to {filepath}: {e}")
            raise
    
    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style access to configuration."""
        return self.get(key)
    
    def __contains__(self, key: str) -> bool:
        """Check if a configuration key exists."""
        try:
            self._get_nested(self._config, key.split('.'))
            return True
        except (KeyError, AttributeError):
            return False

# Create a singleton instance
config = Config()

# Example usage
if __name__ == "__main__":
    # Get the config instance
    cfg = Config()
    
    # Access configuration values
    print(f"App Name: {cfg.get('app.name')}")
    print(f"Database URI: {cfg.get('database.uri')}")
    print(f"Debug Mode: {cfg.get('app.debug')}")
    
    # Save current config to file
    cfg.save_to_file('config.example.yaml')
    
    # Print entire config as dictionary
    import pprint
    pprint.pprint(cfg.to_dict())
