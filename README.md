# FridaXplorer

FridaXplorer is an interactive command-line client for automating and streamlining Frida operations on iOS and Android devices. It allows users to attach to processes, spawn applications, and execute Frida scripts dynamically.

## Features

- **Device Enumeration:** List connected devices.
- **Process Interaction:** Attach to or spawn a process.
- **Module Execution:** Load and run Frida modules.
- **Codeshare Integration:** Fetch and execute scripts from Frida Codeshare.
- **Output Management:** Capture, filter, and save output.

## Requirements

- Python 3.x
- Frida
- Requests
- BeautifulSoup4

## Installation

1. Clone this repository:
   ```sh
   git clone https://github.com/interhack86/FridaXplorer.git
   cd FridaXplorer
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage

Run the interactive client:
```sh
python3 fridaxplorer.py
```

### Commands

- `set_platform <ios|android>`: Define target platform.
- `list_devices`: List connected devices.
- `connect <process_name>`: Attach to a running process.
- `spawn <process_name> <module_name>`: Spawn a process and load a module.
- `list_modules`: List available modules.
- `load_module <module_name>`: Load and execute a module.
- `search_codeshare <keyword>`: Search scripts on Frida Codeshare.
- `show_output`: Display captured output.
- `save_output <filename>`: Save captured output to a file.
- `exit`: Exit the interactive client.

## Example

```sh
(fridaXplorer) set_platform android
(fridaXplorer) list_devices
(fridaXplorer) connect com.example.app
(fridaXplorer) spawn com.example.app enum_methods_android
(fridaXplorer) show_output
(fridaXplorer) save_output output.txt
```

## Contributing

Feel free to submit issues or pull requests to improve FridaXplorer.

## License

This project is licensed under the MIT License.
