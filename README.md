# Windows Optimization Script

A comprehensive PowerShell script that applies essential Windows tweaks for improved performance, privacy, and user experience.

## ⚠️ Important Warning

**This script makes significant system changes. Use at your own risk.**

- Creates system restore point recommended before running
- Requires Administrator privileges (auto-elevates)
- Some changes may require a reboot to take effect
- Intended for advanced users who understand the implications

## Features

### Privacy & Telemetry
- Disables Windows telemetry and data collection
- Removes consumer features and suggested apps
- Disables activity history tracking
- Disables location tracking and WiFi Sense
- Disables PowerShell 7 telemetry

### Performance Optimizations
- Optimizes service startup types for better boot times
- Configures system responsiveness settings
- Disables unnecessary scheduled tasks
- Optimizes memory management settings
- Enables long path support

### User Experience
- Enables classic right-click menu (Windows 11)
- Disables GameDVR and Xbox features
- Removes Windows Feeds and Meet Now
- Enables "End Task" option in taskbar
- Disables Storage Sense auto-cleanup

### System Utilities
- Automatically opens system management tools after completion:
  - Programs and Features (Add/Remove Programs)
  - System Configuration (MSConfig)
  - Task Manager

## Usage

1. **Download the script**
   ```powershell
   # Download directly or clone the repository
   git clone https://github.com/yourusername/windows-optimization-script.git
   ```

2. **Run as Administrator** (script will auto-elevate)
   ```powershell
   .\Windows-Optimization-Script.ps1
   ```

3. **Follow the prompts** for Explorer restart

4. **Review opened system utilities** for additional customization

## What Gets Modified

### Registry Changes
- Telemetry and data collection settings
- Content delivery and consumer features
- Game DVR and Xbox integration
- Explorer and UI behavior
- System performance settings

### Services Configuration
- 200+ Windows services optimized for manual/automatic startup
- Critical services preserved as automatic
- Gaming and Xbox services set to manual
- Telemetry services disabled

### Scheduled Tasks
- Disables telemetry-related scheduled tasks
- Removes data collection and feedback tasks
- Preserves essential system maintenance tasks

## Compatibility

- **Windows 10** - Fully supported
- **Windows 11** - Fully supported (includes Windows 11 specific tweaks)
- **Architecture** - x64 and x86 systems
- **Editions** - Home, Pro, Enterprise

## Prerequisites

- PowerShell 5.1 or later
- Administrator privileges (script will request elevation)
- Windows 10 build 1903 or later recommended

## Safety Features

- **Error handling** - Continues if individual tweaks fail
- **Service validation** - Only modifies existing services
- **Registry safety** - Creates registry paths as needed
- **Detailed logging** - Shows all changes being made

## Reverting Changes

While the script doesn't include an automatic undo feature, you can:

1. **System Restore** - Use a restore point created before running
2. **Manual revert** - Most changes can be reversed through:
   - Services.msc (for service startup types)
   - Registry Editor (for registry changes)
   - Task Scheduler (for scheduled tasks)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test thoroughly on multiple Windows versions
4. Submit a pull request with detailed description

## Disclaimer

This script is provided "as is" without warranty. The authors are not responsible for any damage to your system. Always create a system restore point before running system modification scripts.

## License

MIT License - see LICENSE file for details

## Acknowledgments

Based on the Windows optimization techniques from:
- Chris Titus Tech Winutil project
- Various Windows performance optimization communities
- Microsoft official documentation

---

**Note**: This script combines multiple proven Windows optimization techniques into a single automated solution. Each modification has been carefully selected for maximum benefit with minimal risk to system stability.
