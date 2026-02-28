#!/bin/bash

# docs/render_architecture.sh
#
# Renders the Mermaid architecture diagram to PNG.
#
# Prerequisites:
# - Node.js 18+ and npm (preferred)
# - OR Docker (fallback)
#
# Output: docs/architecture.png

set -e

echo "=========================================="
echo "Rendering Architecture Diagram"
echo "=========================================="

render_with_npx() {
  npx -y @mermaid-js/mermaid-cli -i docs/architecture.mmd -o docs/architecture.png
}

render_with_docker() {
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -v "$PWD:/data" \
    minlag/mermaid-cli \
    -i /data/docs/architecture.mmd \
    -o /data/docs/architecture.png
}

if command -v npx &>/dev/null; then
  echo "Found: npx (using npm/npx)"
  echo ""

  echo "+ npx -y @mermaid-js/mermaid-cli -i docs/architecture.mmd -o docs/architecture.png"
  if render_with_npx; then
    echo "✓ Architecture diagram rendered to docs/architecture.png (npx)"
  else
    echo "✗ npx render failed"
    if command -v docker &>/dev/null; then
      echo ""
      echo "Found: Docker (falling back to containerized mermaid-cli)"
      echo "+ docker run --rm -u \"$(id -u):$(id -g)\" -v \"$PWD:/data\" minlag/mermaid-cli -i /data/docs/architecture.mmd -o /data/docs/architecture.png"
      render_with_docker
      echo "✓ Architecture diagram rendered to docs/architecture.png (docker fallback)"
    else
      echo "No Docker available for fallback."
      exit 1
    fi
  fi

elif command -v docker &>/dev/null; then
  echo "Found: Docker (using containerized mermaid-cli)"
  echo ""
  echo "+ docker run --rm -u \"$(id -u):$(id -g)\" -v \"$PWD:/data\" minlag/mermaid-cli -i /data/docs/architecture.mmd -o /data/docs/architecture.png"
  render_with_docker
  echo "✓ Architecture diagram rendered to docs/architecture.png (docker)"

else
  echo ""
  echo "=========================================="
  echo "ERROR: Cannot render architecture diagram"
  echo "=========================================="
  echo ""
  echo "Neither Node.js (with npm) nor Docker is available."
  echo ""
  echo "To render the diagram, you need:"
  echo ""
  echo "Option 1: Install Node.js and npm"
  echo "  Visit: https://nodejs.org/"
  echo "  Verify: node --version && npm --version"
  echo ""
  echo "Option 2: Use Docker"
  echo "  Visit: https://docs.docker.com/get-docker/"
  echo "  Verify: docker --version"
  echo ""
  echo "Option 3: Provide pre-rendered image"
  echo "  Render docs/architecture.mmd to PNG manually"
  echo "  Save as: docs/architecture.png"
  echo ""
  exit 1
fi

if [[ ! -s docs/architecture.png ]]; then
  echo ""
  echo "ERROR: docs/architecture.png was not created or is empty"
  exit 1
fi

echo ""
echo "=========================================="
echo "Render Complete"
echo "=========================================="
echo ""
echo "Output file: docs/architecture.png"
echo "File size: $(du -h docs/architecture.png)"
echo ""
