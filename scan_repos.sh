#!/bin/bash
# ============================================
# .env Leak Scanner for Git Repositories
# Scans for exposed secrets in git history
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCAN_DIR="${1:-.}"
FOUND=0
TOTAL=0

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     .env LEAK SCANNER FOR GIT REPOS      ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "Scanning: ${YELLOW}${SCAN_DIR}${NC}"
echo ""

# Find all git repos
for repo in $(find "$SCAN_DIR" -maxdepth 3 -name ".git" -type d 2>/dev/null); do
    REPO_DIR=$(dirname "$repo")
    REPO_NAME=$(basename "$REPO_DIR")
    TOTAL=$((TOTAL + 1))
    
    # Check for .env files in history
    ENV_FILES=$(cd "$REPO_DIR" && git log --all --diff-filter=A --name-only --pretty=format: -- '*.env' '.env*' '*env.local*' '*env.production*' '*compose.env*' 2>/dev/null | sort -u | grep -v '^$')
    
    if [ -n "$ENV_FILES" ]; then
        echo -e "${RED}[!] ${REPO_NAME}${NC}"
        
        for env_file in $ENV_FILES; do
            # Check if still tracked
            TRACKED=$(cd "$REPO_DIR" && git ls-files "$env_file" 2>/dev/null)
            if [ -n "$TRACKED" ]; then
                echo -e "    ${RED}STILL TRACKED: ${env_file}${NC}"
            else
                echo -e "    ${YELLOW}In history: ${env_file}${NC}"
            fi
            
            # Check if content is in history
            CONTENT=$(cd "$REPO_DIR" && git log --all -p -- "$env_file" 2>/dev/null | grep -E '^\+[^+]' | grep -E '(API_KEY|PASSWORD|SECRET|TOKEN|URI)=' | head -3)
            if [ -n "$CONTENT" ]; then
                echo -e "    ${RED}SECRETS VISIBLE IN HISTORY:${NC}"
                echo "$CONTENT" | while read -r line; do
                    KEY=$(echo "$line" | cut -d'=' -f1 | tr -d '+')
                    echo -e "      ${RED}${KEY}=***EXPOSED***${NC}"
                done
                FOUND=$((FOUND + 1))
            fi
        done
        echo ""
    fi
    
    # Also check for currently tracked .env files (not in gitignore)
    TRACKED_ENV=$(cd "$REPO_DIR" && git ls-files -- '*.env' '.env*' '*env.local*' 2>/dev/null | grep -v '.example' | grep -v '.sample')
    if [ -n "$TRACKED_ENV" ]; then
        echo -e "${RED}[!] ${REPO_NAME} - Currently tracked .env files:${NC}"
        echo "$TRACKED_ENV" | while read -r f; do
            echo -e "    ${RED}${f}${NC}"
        done
        echo ""
    fi
done

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "Repos scanned: ${TOTAL}"
echo -e "Repos with exposed secrets: ${RED}${FOUND}${NC}"

if [ "$FOUND" -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}HOW TO FIX:${NC}"
    echo -e "1. Install git-filter-repo: ${CYAN}pip install git-filter-repo${NC}"
    echo -e "2. Remove from history:"
    echo -e "   ${CYAN}git filter-repo --invert-paths --path .env${NC}"
    echo -e "3. Re-add remote:"
    echo -e "   ${CYAN}git remote add origin <url>${NC}"
    echo -e "4. Force push:"
    echo -e "   ${CYAN}git push --force --all${NC}"
    echo -e "5. ${RED}ROTATE ALL EXPOSED CREDENTIALS${NC}"
    echo -e "6. Add to .gitignore:"
    echo -e "   ${CYAN}.env${NC}"
    echo -e "   ${CYAN}.env.local${NC}"
    echo -e "   ${CYAN}.env.*.local${NC}"
    echo -e "   ${CYAN}*.env${NC}"
fi
