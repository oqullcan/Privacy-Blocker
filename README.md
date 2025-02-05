# Privacy-Blocker

**Privacy-Blocker.ps1** is a comprehensive PowerShell script meticulously designed to enhance privacy and security within Windows operating systems. This script aims to mitigate telemetry data transmission, disable superfluous services, optimize registry settings, and configure robust firewall rules, thereby fortifying the system against potential privacy breaches.

## Features

- **Registry Optimization:** Configures critical registry settings to bolster privacy and security measures.
- **Service Management:** Disables unnecessary and potentially privacy-invasive Windows services.
- **Telemetry Blocking:** Prevents telemetry-related communications via modifications to the `hosts` file.
- **Firewall Rules Configuration:** Establishes custom firewall rules to regulate both inbound and outbound connections.
- **Automated Updates:** The script can be periodically updated to align with the latest security and privacy standards.

## Installation

1. **Run PowerShell with administrator privileges:**
- Right-click on the Start menu and select “Windows PowerShell (Administrator)”.

2. **Set script execution permissions:**

```
powershell Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

3. **Run the script:**
```
irm “https://raw.githubusercontent.com/oqullcan/Privacy-Blocker/refs/heads/main/Privacy-Blocker.ps1” | iex
```

## Usage

By default, the script applies recommended privacy configurations. However, users may customize specific settings by modifying the script with a text editor, enabling granular control over applied changes.

## Warnings

- The script may disable certain Windows functionalities. It is strongly recommended to create a system backup prior to implementing critical changes.
- **Administrative privileges are required** as the script performs system-level modifications.

## Contributing

We welcome feedback, suggestions, and contributions. Feel free to submit pull requests via GitHub to improve the project.

## License

This project is licensed under the [MIT License](LICENSE).

---

**Your Privacy, Our Priority.**

