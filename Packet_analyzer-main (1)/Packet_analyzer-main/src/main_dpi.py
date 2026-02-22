#!/usr/bin/env python3
"""
main_dpi.py - DPI Engine entry point using full DPI Engine class.
Python equivalent of src/main_dpi.cpp
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "include"))

from dpi_engine import DPIEngine


USAGE = """\

╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                            ║
║               Deep Packet Inspection System                   ║
╚══════════════════════════════════════════════════════════════╝

Usage: {prog} <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --rules <file>         Load blocking rules from file
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --verbose              Enable verbose output

Examples:
  {prog} capture.pcap filtered.pcap
  {prog} capture.pcap filtered.pcap --block-app YouTube
  {prog} capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  {prog} capture.pcap filtered.pcap --rules blocking_rules.txt

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Architecture:
  ┌─────────────┐
  │ PCAP Reader │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_lbs
         ▼
  ┌──────┴──────┐
  │ Load Balancer │  LB threads distribute to FPs
  └──┬────┴────┬──┘
     │         │  hash(5-tuple) % fps_per_lb
     ▼         ▼
  ┌──┴──┐   ┌──┴──┐
  │FP0-1│   │FP2-3│  FP threads: DPI, classification, blocking
  └──┬──┘   └──┬──┘
     │         │
     ▼         ▼
  ┌──┴─────────┴──┐
  │ Output Writer │  Writes forwarded packets to output
  └───────────────┘
"""


def main():
    if len(sys.argv) < 3:
        print(USAGE.format(prog=sys.argv[0]))
        return 1

    input_file  = sys.argv[1]
    output_file = sys.argv[2]

    config = DPIEngine.Config()
    block_ips:    list = []
    block_apps:   list = []
    block_domains: list = []
    rules_file:   str  = ""

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            i += 1; block_ips.append(sys.argv[i])
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            i += 1; block_apps.append(sys.argv[i])
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            i += 1; block_domains.append(sys.argv[i])
        elif arg == "--rules" and i + 1 < len(sys.argv):
            i += 1; rules_file = sys.argv[i]
        elif arg == "--lbs" and i + 1 < len(sys.argv):
            i += 1; config.num_load_balancers = int(sys.argv[i])
        elif arg == "--fps" and i + 1 < len(sys.argv):
            i += 1; config.fps_per_lb = int(sys.argv[i])
        elif arg == "--verbose":
            config.verbose = True
        elif arg in ("--help", "-h"):
            print(USAGE.format(prog=sys.argv[0]))
            return 0
        i += 1

    engine = DPIEngine(config)

    if not engine.initialize():
        print("Failed to initialize DPI engine", file=sys.stderr)
        return 1

    if rules_file:
        engine.load_rules(rules_file)

    for ip  in block_ips:    engine.block_ip(ip)
    for app in block_apps:   engine.block_app(app)
    for dom in block_domains: engine.block_domain(dom)

    if not engine.process_file(input_file, output_file):
        print("Failed to process file", file=sys.stderr)
        return 1

    print("\nProcessing complete!")
    print(f"Output written to: {output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
