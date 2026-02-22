# Windows Setup Guide (Python Version)

## Requirements

- Python 3.8 or newer (no external packages needed)

## Install Python on Windows

1. Download Python from https://www.python.org/downloads/
2. During installation, check **"Add Python to PATH"**
3. Open Command Prompt and verify:
   ```
   python --version
   ```

## Running the Project

No build step needed — Python runs directly.

### Simple Packet Viewer
```cmd
python src\main.py test_dpi.pcap
python src\main.py test_dpi.pcap 10
```

### Simple DPI Engine (Single-threaded)
```cmd
python src\main_working.py test_dpi.pcap output.pcap
python src\main_working.py test_dpi.pcap output.pcap --block-app YouTube
```

### Multi-threaded DPI Engine
```cmd
python src\dpi_mt.py test_dpi.pcap output.pcap
python src\dpi_mt.py test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50
```

### Full DPI Engine (with all features)
```cmd
python src\main_dpi.py test_dpi.pcap output.pcap --block-app TikTok
```

### Generate Test Data
```cmd
python generate_test_pcap.py
```

## Troubleshooting

**ImportError: No module named 'xxx'**
- Make sure you run scripts from the project root directory:
  ```
  cd Packet_analyzer-main
  python src\main_working.py test_dpi.pcap out.pcap
  ```

**FileNotFoundError**
- Ensure `test_dpi.pcap` exists. Run `python generate_test_pcap.py` first.
