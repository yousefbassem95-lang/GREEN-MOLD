#!/bin/bash
# Green Mold Cure - Android Termux Setup
# This script sets up Green Mold Cure for Android Termux environment

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           GREEN MOLD CURE - TERMUX SETUP                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}Checking Termux environment...${NC}"

# Check if running in Termux
if [ -z "$PREFIX" ]; then
    echo -e "${RED}Error: This script must be run in Termux${NC}"
    echo "Install Termux from F-Droid or Google Play Store"
    exit 1
fi

echo -e "${GREEN}✓ Termux detected${NC}"

# Update packages
echo ""
echo -e "${YELLOW}Updating packages...${NC}"
pkg update -y

# Install Python
echo ""
echo -e "${YELLOW}Installing Python...${NC}"
pkg install python -y

# Install required tools
echo ""
echo -e "${YELLOW}Installing required tools...${NC}"
pkg install clang llvm libcrypt zlib openssl -y

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Install Python dependencies
echo ""
echo -e "${YELLOW}Installing Python dependencies...${NC}"
cd "$PROJECT_DIR"

# Some packages may need to be installed differently on Termux
pip install click rich requests aiohttp cryptography python-dotenv tqdm

# Optional packages that may not be available
echo ""
echo -e "${YELLOW}Attempting to install optional packages...${NC}"
pip install python-magic pefile || echo -e "${YELLOW}Some optional packages skipped${NC}"

# Create application directory
echo ""
echo -e "${YELLOW}Setting up application directory...${NC}"
APP_DIR="$HOME/.green_mold_cure"
mkdir -p "$APP_DIR"
mkdir -p "$APP_DIR/quarantine"
mkdir -p "$APP_DIR/logs"
mkdir -p "$APP_DIR/config"

echo -e "${GREEN}✓ Application directory created: $APP_DIR${NC}"

# Create launcher script
echo ""
echo -e "${YELLOW}Creating launcher script...${NC}"
cat > "$PREFIX/bin/green-mold-cure" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# Green Mold Cure Termux Launcher
cd "$HOME/Green_Mold_Cure_project" 2>/dev/null || cd "$HOME/green_mold_cure" 2>/dev/null
python src/main.py "$@"
EOF

chmod +x "$PREFIX/bin/green-mold-cure"
echo -e "${GREEN}✓ Launcher script created${NC}"

# Request storage permissions
echo ""
echo -e "${YELLOW}Requesting storage permissions...${NC}"
termux-setup-storage 2>/dev/null || true

# Create .env template
echo ""
echo -e "${YELLOW}Creating .env template...${NC}"
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cat > "$PROJECT_DIR/.env" << 'EOF'
# Green Mold Cure - Environment Variables
# Termux configuration

# API Keys (optional)
VIRUSTOTAL_API_KEY=
HYBRID_ANALYSIS_API_KEY=
ANYRUN_API_KEY=
ALIENVAULT_API_KEY=

# Tor is not typically available on Termux
TOR_PROXY_HOST=127.0.0.1
TOR_PROXY_PORT=9050
EOF
    echo -e "${GREEN}✓ .env template created${NC}"
fi

# Termux-specific notes
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              TERMUX SETUP COMPLETE                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Green Mold Cure is ready for Termux!${NC}"
echo ""
echo "Important Notes for Termux:"
echo "  • Scanning is limited to user-accessible directories"
echo "  • System partition scanning requires root access"
echo "  • Storage access granted to: ~/storage/shared (Internal storage)"
echo ""
echo "To run the application:"
echo "  green-mold-cure"
echo ""
echo "Or manually:"
echo "  cd $PROJECT_DIR"
echo "  python src/main.py"
echo ""
echo -e "${YELLOW}Termux Limitations:${NC}"
echo "  • No real-time protection (background processes limited)"
echo "  • Limited to accessible storage areas"
echo "  • Some Python packages may not be available"
echo ""
