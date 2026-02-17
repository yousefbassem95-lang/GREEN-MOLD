#!/bin/bash
# Green Mold Cure - Linux/macOS Installer
# This script installs Green Mold Cure and its dependencies

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              GREEN MOLD CURE INSTALLER                    ║"
echo "║                   Linux/macOS Version                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.10"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo -e "${RED}Error: Python 3.10 or higher is required.${NC}"
    echo "Current version: $python_version"
    exit 1
fi
echo -e "${GREEN}✓ Python $python_version detected${NC}"

# Check pip
echo -e "${YELLOW}Checking pip...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}Error: pip3 is not installed.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ pip3 detected${NC}"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Install dependencies
echo ""
echo -e "${YELLOW}Installing Python dependencies...${NC}"
cd "$PROJECT_DIR"
pip3 install -r requirements.txt

# Create application directory
echo ""
echo -e "${YELLOW}Setting up application directory...${NC}"
APP_DIR="$HOME/.green_mold_cure"
mkdir -p "$APP_DIR"
mkdir -p "$APP_DIR/quarantine"
mkdir -p "$APP_DIR/logs"
mkdir -p "$APP_DIR/config"

# Set permissions
chmod 700 "$APP_DIR/quarantine"
chmod 700 "$APP_DIR/logs"
chmod 755 "$APP_DIR"

echo -e "${GREEN}✓ Application directory created: $APP_DIR${NC}"

# Create launcher script
echo ""
echo -e "${YELLOW}Creating launcher script...${NC}"
LAUNCHER_DIR="$HOME/.local/bin"
mkdir -p "$LAUNCHER_DIR"

cat > "$LAUNCHER_DIR/green-mold-cure" << 'EOF'
#!/bin/bash
# Green Mold Cure Launcher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")/Projects/J0J0/Elixirs_and_Cures_projects/Green_Mold_Cure_project"

# Try to find the project directory
if [ -f "$PROJECT_DIR/src/main.py" ]; then
    cd "$PROJECT_DIR"
    python3 src/main.py "$@"
else
    # Fallback to current directory
    python3 -c "import sys; sys.path.insert(0, '.'); from src.main import main; main()" "$@"
fi
EOF

chmod +x "$LAUNCHER_DIR/green-mold-cure"
echo -e "${GREEN}✓ Launcher script created: $LAUNCHER_DIR/green-mold-cure${NC}"

# Add to PATH if not already
if [[ ":$PATH:" != *":$LAUNCHER_DIR:"* ]]; then
    echo ""
    echo -e "${YELLOW}Adding $LAUNCHER_DIR to PATH...${NC}"
    
    # Detect shell
    if [ -f "$HOME/.bashrc" ]; then
        echo "export PATH=\"$LAUNCHER_DIR:\$PATH\"" >> "$HOME/.bashrc"
        echo -e "${GREEN}✓ Added to .bashrc${NC}"
    fi
    if [ -f "$HOME/.zshrc" ]; then
        echo "export PATH=\"$LAUNCHER_DIR:\$PATH\"" >> "$HOME/.zshrc"
        echo -e "${GREEN}✓ Added to .zshrc${NC}"
    fi
    
    echo -e "${YELLOW}Please restart your terminal or run: export PATH=\"$LAUNCHER_DIR:\$PATH${NC}"
fi

# Create .env template
echo ""
echo -e "${YELLOW}Creating .env template...${NC}"
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cat > "$PROJECT_DIR/.env" << 'EOF'
# Green Mold Cure - Environment Variables
# Copy this file to .env and fill in your API keys

# VirusTotal API Key (optional - get from virustotal.com)
VIRUSTOTAL_API_KEY=

# Hybrid Analysis API Key (optional - get from hybrid-analysis.com)
HYBRID_ANALYSIS_API_KEY=

# Any.run API Key (optional - get from any.run)
ANYRUN_API_KEY=

# AlienVault OTX API Key (optional - get from otx.alienvault.com)
ALIENVAULT_API_KEY=

# Tor Proxy Settings (optional - for .onion feeds)
TOR_PROXY_HOST=127.0.0.1
TOR_PROXY_PORT=9050
EOF
    echo -e "${GREEN}✓ .env template created${NC}"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

# Final instructions
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                  INSTALLATION COMPLETE                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Green Mold Cure has been installed successfully!${NC}"
echo ""
echo "To run the application:"
echo "  1. Navigate to the project directory:"
echo "     cd $PROJECT_DIR"
echo ""
echo "  2. Run the application:"
echo "     python3 src/main.py"
echo ""
echo "  Or use the launcher (after restarting terminal):"
echo "     green-mold-cure"
echo ""
echo -e "${YELLOW}Optional Setup:${NC}"
echo "  - Configure API keys in .env file for enhanced threat intelligence"
echo "  - Install Tor for .onion feed support"
echo "  - Run with sudo for full system scan capabilities"
echo ""
echo -e "${YELLOW}Documentation:${NC}"
echo "  - See README.md for usage instructions"
echo "  - See system_constraints.md for platform limitations"
echo ""
