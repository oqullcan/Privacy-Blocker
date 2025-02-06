# Privacy Hardening Script for Windows Systems

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Functions](#functions)
- [Configuration](#configuration)
- [Logging](#logging)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Overview
The **Privacy Hardening Script** is a PowerShell script designed to enhance the privacy and security of Windows systems. It implements a series of configurations aimed at minimizing data collection by disabling telemetry, managing services, and configuring secure DNS settings. This script is particularly useful for users who are concerned about their privacy and want to take proactive measures to protect their data.

## Features
- **Disable Non-Essential Services**: Stops and disables services that may collect user data.
- **Registry Settings**: Applies various registry settings to limit telemetry and data collection.
- **Hosts File Update**: Blocks telemetry domains by updating the hosts file.
- **Firewall Rules**: Configures firewall rules to block known telemetry IP addresses.
- **Secure DNS Configuration**: Sets secure DNS settings using Quad9 and DNS over HTTPS (DoH).
- **DNS Cache Management**: Flushes the DNS cache to ensure all changes take effect.
- **Logging**: Provides detailed logging of actions taken and any errors encountered.

## Requirements
- **PowerShell Version**: 5.1 or higher
- **Administrative Privileges**: The script must be run with administrative rights to modify system settings.
- **Windows Operating System**: Designed for Windows 10 and later versions.

## Usage
To run the script, follow these steps:
1. Open PowerShell as an Administrator.
2. Navigate to the directory where the script is located.
3. Execute the script:
   ```powershell
   irm “https://raw.githubusercontent.com/oqullcan/Privacy-Blocker/refs/heads/main/Privacy-Blocker.ps1” | iex
   ```

## Functions
The script contains several key functions, each responsible for a specific aspect of the hardening process:

### 1. Apply-RegistrySettings
- **Description**: Applies a series of registry settings to enhance privacy and limit telemetry.
- **Key Registry Changes**:
  - Disables telemetry and feedback notifications.
  - Limits enhanced diagnostic data collection.
  - Configures security settings related to user accounts and authentication.

### 2. Disable-Services
- **Description**: Disables non-essential Windows services that may collect data.
- **Services Disabled**:
  - Diagnostics Tracking Service
  - WAP Push Message Routing Service
  - Remote Registry Service
  - Windows Update Medic Service

### 3. Block-TelemetryHosts
- **Description**: Updates the hosts file to block known telemetry domains.
- **Example Domains Blocked**:
  - `settings-win.data.microsoft.com`
  - `telemetry.microsoft.com`
  - `browser.pipe.aria.microsoft.com`

### 4. Add-FirewallRules
- **Description**: Configures firewall rules to block known telemetry IP addresses.
- **Example IPs Blocked**:
  - `65.52.100.91`
  - `65.52.100.93`
  - `65.52.100.92`

### 5. Set-SecureDNS
- **Description**: Configures secure DNS settings using Quad9 and DNS over HTTPS (DoH).
- **DNS Servers Used**:
  - `9.9.9.9`
  - `149.112.112.112`

### 6. Flush-DNSCache
- **Description**: Flushes the DNS cache to ensure that all changes take effect immediately.

## Configuration
The script can be customized by modifying the following variables at the beginning of the script:
- `$SCRIPT_NAME`: The name of the script used in logging.
- `$SECURE_DNS_SERVERS`: The DNS servers to be used for secure DNS settings.

## Logging
The script includes a logging mechanism that records actions taken and any errors encountered during execution. Logs are output to the console and can be redirected to a file if needed.

## Contributing
Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes, please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes to your forked repository.
5. Submit a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
- Special thanks to the Security Engineering Team for their contributions and support in developing this script.
- Inspired by community efforts to enhance user privacy and security on Windows systems.

ty!
