#!/bin/bash
# OpenVPN Connect for Linux - Quick Launch Script
cd "$(dirname "$0")"
exec npx electron . --no-sandbox "$@"
