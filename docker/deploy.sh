#!/bin/bash
# Hephaestus - Interactive Deployment Script
# Helps users choose between production and testing environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo ""
echo "========================================"
echo "  Hephaestus - Server Security Scanner"
echo "  Docker Deployment Helper"
echo "========================================"
echo ""

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is available
if ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not available. Please install Docker Compose."
    exit 1
fi

print_success "Docker and Docker Compose are available"
echo ""

# Ask user what they want to deploy
echo "What would you like to deploy?"
echo ""
echo "  1) Production - Hephaestus Scanner only (for scanning external sites)"
echo "  2) Testing Lab - Vulnerable servers (Apache + Nginx for security testing)"
echo "  3) Both - Production scanner + Testing lab"
echo "  4) Stop all services"
echo "  5) Remove all containers and data (reset)"
echo ""
read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        print_info "Deploying Hephaestus Scanner (Production)..."
        echo ""

        cd "$(dirname "$0")"

        # Create directories with correct permissions for hephaestus user (UID 1000)
        mkdir -p ./data ./reports
        chmod 755 ./data ./reports

        docker compose -f compose.yml up -d --build

        echo ""
        print_success "Hephaestus Scanner deployed successfully!"
        echo ""
        print_info "Usage:"
        echo "  docker compose -f docker/compose.yml exec hephaestus python -m heph --target <URL>"
        echo ""
        print_info "Example:"
        echo "  docker compose -f docker/compose.yml exec hephaestus python -m heph --target https://example.com --html"
        echo ""
        print_info "Reports will be saved to: docker/reports/ (auto-detected)"
        print_info "Database location: docker/data/argos.db (auto-detected)"
        ;;

    2)
        print_warning "WARNING: The testing lab is INTENTIONALLY VULNERABLE!"
        print_warning "DO NOT expose it to the public internet!"
        echo ""
        read -p "Do you understand and want to continue? (yes/no): " confirm

        if [ "$confirm" != "yes" ]; then
            print_info "Deployment cancelled."
            exit 0
        fi

        print_info "Deploying Testing Lab (Vulnerable Apache + Nginx)..."
        echo ""

        cd "$(dirname "$0")"

        docker compose -f compose.testing.yml up -d

        echo ""
        print_info "Waiting 15 seconds for services to initialize..."
        sleep 15

        echo ""
        print_success "Testing Lab deployed successfully!"
        echo ""
        print_info "Vulnerable servers are available at:"
        echo "  • Apache: http://localhost:8080 | https://localhost:8443"
        echo "  • Nginx:  http://localhost:8081 | https://localhost:8444"
        echo ""
        print_info "Test vulnerabilities:"
        echo "  curl http://localhost:8080/.env          # Exposed .env file"
        echo "  curl http://localhost:8080/phpinfo.php   # PHP info disclosure"
        echo "  curl -I http://localhost:8080            # Server version in headers"
        echo ""
        print_info "Scan with Hephaestus (from host):"
        echo "  python -m heph --target http://localhost:8080"
        echo "  python -m heph --target http://localhost:8081"
        echo ""
        print_info "Check status:"
        echo "  docker compose -f docker/compose.testing.yml ps"
        ;;

    3)
        print_warning "WARNING: The testing lab is INTENTIONALLY VULNERABLE!"
        print_warning "DO NOT expose it to the public internet!"
        echo ""
        read -p "Do you understand and want to continue? (yes/no): " confirm

        if [ "$confirm" != "yes" ]; then
            print_info "Deployment cancelled."
            exit 0
        fi

        print_info "Deploying both Production and Testing Lab..."
        echo ""

        cd "$(dirname "$0")"

        # Create directories with correct permissions for hephaestus user (UID 1000)
        mkdir -p ./data ./reports
        chmod 755 ./data ./reports

        # Start testing lab first (creates hephaestus-lab network)
        print_info "Starting testing lab (creates network)..."
        docker compose -f compose.testing.yml up -d

        # Then start production scanner (joins existing network)
        print_info "Starting production scanner..."
        docker compose -f compose.yml up -d --build

        echo ""
        print_info "Waiting 15 seconds for testing lab to initialize..."
        sleep 15

        echo ""
        print_success "Both environments deployed successfully!"
        echo ""
        print_info "Production Scanner:"
        echo "  docker compose -f docker/compose.yml exec hephaestus python -m heph --target <URL> --html"
        echo ""
        print_info "Testing Lab:"
        echo "  Apache: http://localhost:8080"
        echo "  Nginx:  http://localhost:8081"
        echo ""
        print_info "Scan testing lab from container (reports auto-saved to docker/reports/):"
        echo "  docker compose -f docker/compose.yml exec hephaestus python -m heph --target http://hephaestus-vulnerable-apache --html"
        echo "  docker compose -f docker/compose.yml exec hephaestus python -m heph --target http://hephaestus-vulnerable-nginx --html"
        ;;

    4)
        print_info "Stopping all services..."
        echo ""

        cd "$(dirname "$0")"

        # Stop production if running
        if docker compose -f compose.yml ps -q 2>/dev/null | grep -q .; then
            print_info "Stopping production environment..."
            docker compose -f compose.yml down
        fi

        # Stop testing if running
        if docker compose -f compose.testing.yml ps -q 2>/dev/null | grep -q .; then
            print_info "Stopping testing environment..."
            docker compose -f compose.testing.yml down
        fi

        echo ""
        print_success "All services stopped"
        ;;

    5)
        print_warning "WARNING: This will remove ALL containers and data!"
        print_warning "Reports and database will be PERMANENTLY DELETED!"
        echo ""
        read -p "Are you sure? Type 'DELETE' to confirm: " confirm

        if [ "$confirm" != "DELETE" ]; then
            print_info "Reset cancelled."
            exit 0
        fi

        print_info "Removing all containers and data..."
        echo ""

        cd "$(dirname "$0")"

        # Remove production
        if docker compose -f compose.yml ps -q 2>/dev/null | grep -q . || docker compose -f compose.yml ps -a -q 2>/dev/null | grep -q .; then
            print_info "Removing production environment..."
            docker compose -f compose.yml down -v
        fi

        # Remove testing
        if docker compose -f compose.testing.yml ps -q 2>/dev/null | grep -q . || \
           docker compose -f compose.testing.yml ps -a -q 2>/dev/null | grep -q .; then
            print_info "Removing testing environment..."
            docker compose -f compose.testing.yml down -v
        fi

        # Remove data directories if they exist
        if [ -d "./data" ]; then
            print_info "Removing ./data directory..."
            rm -rf ./data
        fi

        if [ -d "./reports" ]; then
            print_info "Removing ./reports directory..."
            rm -rf ./reports
        fi

        echo ""
        print_success "All containers and data removed"
        ;;

    *)
        print_error "Invalid choice. Please run the script again."
        exit 1
        ;;
esac

echo ""
echo "========================================"
echo ""
