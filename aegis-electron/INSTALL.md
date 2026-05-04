# AEGIS Installation Guide

## Download the Right Version

| Your System | Download |
|-------------|----------|
| **macOS Apple Silicon** (M1/M2/M3/M4) | `AEGIS-x.x.x-mac-arm64.dmg` |
| **macOS Intel** | `AEGIS-x.x.x-mac-x64.dmg` |
| **Windows** | `AEGIS-Setup-x.x.x.exe` |
| **Linux x64** (Intel/AMD) | `AEGIS-x.x.x-linux-x64.AppImage` |
| **Linux ARM64** (Apple Silicon VM, RPi 4/5) | `AEGIS-x.x.x-linux-arm64.AppImage` |

### How to check your architecture

**macOS:**
```bash
uname -m
# arm64 = Apple Silicon → download arm64
# x86_64 = Intel → download x64
```

**Linux:**
```bash
uname -m
# x86_64 = Intel/AMD → download x64
# aarch64 = ARM64 → download arm64
```

---

## macOS Installation

### Step 1: Download
Download the appropriate `.dmg` file for your Mac (arm64 for Apple Silicon, x64 for Intel).

### Step 2: Remove Quarantine (Required for Beta)
Since AEGIS is not yet notarized with Apple, macOS will block it. Run this command first:

```bash
xattr -cr ~/Downloads/AEGIS-*.dmg
```

### Step 3: Install
1. Double-click the `.dmg` file
2. Drag AEGIS to your Applications folder
3. **Important:** Run this command on the installed app:
   ```bash
   xattr -cr /Applications/AEGIS.app
   ```

### Step 4: First Launch
- Right-click AEGIS and select "Open" (first time only)
- If you still see a warning, go to **System Settings → Privacy & Security** and click "Open Anyway"

### Troubleshooting macOS
If you see "AEGIS is damaged and can't be opened":
```bash
xattr -cr /Applications/AEGIS.app
```

---

## Windows Installation

### Step 1: Download
Download `AEGIS-Setup-x.x.x.exe`

### Step 2: Install
1. Double-click the installer
2. If Windows SmartScreen appears, click "More info" → "Run anyway"
3. Follow the installation wizard

### Step 3: Launch
Find AEGIS in your Start Menu or Desktop shortcut.

---

## Linux Installation

### Option A: AppImage (Recommended)

#### Prerequisites
AppImages require FUSE to run:
```bash
# Ubuntu/Debian/Kali
sudo apt update
sudo apt install fuse libfuse2

# Fedora
sudo dnf install fuse fuse-libs

# Arch
sudo pacman -S fuse2
```

#### Install & Run
```bash
# Make executable
chmod +x AEGIS-*-linux-*.AppImage

# Run
./AEGIS-*-linux-*.AppImage
```

#### If FUSE Doesn't Work
You can extract and run without FUSE:
```bash
./AEGIS-*-linux-*.AppImage --appimage-extract
./squashfs-root/AppRun
```

### Option B: Debian Package (.deb)

For Ubuntu, Debian, Kali, Pop!_OS, Linux Mint:
```bash
sudo dpkg -i AEGIS-*-linux-*.deb

# If there are dependency errors:
sudo apt install -f
```

Then launch from your application menu or run `aegis` from terminal.

### Option C: Tarball (.tar.gz)

Universal method that works everywhere:
```bash
# Extract
tar -xzf AEGIS-*-linux-*.tar.gz

# Run
cd AEGIS-*/
./aegis
```

---

## Verifying Your Download

Check the file integrity using the SHA256 checksums on the release page:

```bash
# macOS/Linux
shasum -a 256 AEGIS-*.dmg
shasum -a 256 AEGIS-*.AppImage

# Windows (PowerShell)
Get-FileHash AEGIS-Setup-*.exe -Algorithm SHA256
```

Compare the output with the checksums listed on the GitHub release page.

---

## Auto-Updates

AEGIS includes automatic updates! Once installed:
- The app checks for updates on startup
- You can manually check in **Settings → Check for Updates**
- When an update is available, you'll see a notification
- Click "Restart" to apply the update

---

## Reporting Issues

If you encounter any problems:
1. Check the [GitHub Issues](https://github.com/WorldBuilder21/aegis-releases/issues)
2. Include your OS version, AEGIS version, and steps to reproduce
3. Attach any error messages or screenshots

Thank you for beta testing AEGIS!
