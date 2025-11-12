# CityG Configuration Files

This directory contains example configuration files for CityG.

**📚 For complete configuration documentation, see [docs/configuration.md](../docs/configuration.md)**

## Available Configuration Files

- **`development.toml`** - Development configuration with optimal settings for local development
- **`production.toml`** - Production configuration optimized for production deployments
- **`ha-bluegreen.toml`** - Reference configuration for active-active or blue/green rollouts

## Quick Start

Copy one of the example files to use as your configuration:

```bash
# For development
cp config/development.toml cityg.toml

# For production
cp config/production.toml cityg.toml

# For HA / blue-green staging
cp config/ha-bluegreen.toml cityg.toml
```

## Environment Variable Overrides

All configuration values can be overridden using environment variables:

```bash
# Example: Override server address and capacity
export CITYG_SERVER_ADDRESS="0.0.0.0:9000"
export CITYG_SERVER_WEBSOCKET_CAPACITY=2000
export CITYG_PROTOCOL_MAX_CONCURRENT_HEADS=32
```

**Format**: `CITYG_<SECTION>_<KEY>=<value>`

## Complete Documentation

For detailed information about:
- All configuration parameters and their defaults
- Environment variable reference
- Configuration priority and search order
- JSON format support
- Docker/Kubernetes deployment
- Production best practices
- Configuration validation

**See the comprehensive guide**: [docs/configuration.md](../docs/configuration.md)
