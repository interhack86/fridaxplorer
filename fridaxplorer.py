import frida
import sys
import importlib
from config.config import AVAILABLE_MODULES_IOS, AVAILABLE_MODULES_ANDROID
import cmd
import json
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import requests, re

class FridaClient(cmd.Cmd):
    intro = "Welcome to Frida's interactive client. Type ‘help’ or ‘?’ to list the commands.\n"
    prompt = '(fridaXplorer) '
    connected = False
    session = None
    process_name = None
    app_name = None
    platform = None
    captured_output = []


    def do_set_platform(self, platform):
        """Define target platform: set_platform <ios|android>"""
        if platform.lower() not in ['ios', 'android']:
            print("Invalid platform. Use ‘ios’ or ‘android’..")
            return
        self.platform = platform.lower()
        print(f"Platform established in: {self.platform}")

    def do_list_devices(self, arg):
        """List connected devices: list_devices"""
        try:
            devices = frida.enumerate_devices()
            print("Connected devices:")
            for device in devices:
                print(f"- {device.id} ({device.name})")
        except Exception as e:
            print(f"Error listing devices: {e}")

    def do_connect(self, process_name):
        """Connect to a running process: connect <process_name>."""
        try:
            self.session = frida.get_usb_device().attach(process_name)
            self.process_name = process_name
            self.connected = True
            print(f"Connected to the process: {process_name}")
        except Exception as e:
            print(f"Error connecting to the process: {e}")
            self.connected = False

    def do_name(self, args):
        """Assign app name"""
        try:
            
            arg_list = args.split()
            if len(arg_list) == 0:
                print("Use: name <app_name>")
                return

            print(f"Name of the assigned app: {arg_list[0]}")

            self.app_name = arg_list[0]

        except Exception as e:
            print(f"Error to assigning name: {e}")

    def do_spawn(self, args):
        """Spawn a process and load a module: spawn <process_name> <module_name>."""

        if not self.platform:
            print("Error: Set platform first with 'set platform <ios|android>'.")
            return
        try:
            
            arg_list = args.split()
            if self.app_name:
                if len(arg_list) < 1:
                    print("Use: spawn <module_name>")
                    return
                process_name = self.app_name
                module_name = arg_list[0]

                if module_name == 'codeshare':
                    try:
                        url = arg_list[1]
                    except:
                        print("Error in url")
                        return
            else:
                if len(arg_list) < 2:
                    print("Use: spawn <process_name> <module_name>")
                    return

                process_name = arg_list[0]
                module_name = arg_list[1]

                if module_name == 'codeshare':
                    try:
                        url = arg_list[2]
                    except:
                        print("Error in url")
                        return
                        
            if module_name != 'codeshare':
                available_modules = AVAILABLE_MODULES_IOS if self.platform == 'ios' else AVAILABLE_MODULES_ANDROID
                if module_name not in available_modules:
                    print(f"The module {module_name} is not available. Use 'list_modules' to see the available modules.")
                    return

                if module_name in ['enum_methods_ios', 'enum_methods_android']:
                    param_value = input("Enter the parameter value for the script: ")
                else:
                    param_value = ''
            else:
                module = self.get_codeshare(url)
                param_value = 'codeshare'

            # spawn process
            device = frida.get_usb_device()
            pid = device.spawn([process_name])
            self.session = device.attach(pid)
            print(f"Process ‘{process_name}’ spawned with PID {pid}.")

            if module_name != 'codeshare':
            # load module
                module_path = f"modules.{module_name}"
                module = importlib.import_module(module_path)
            self.execute_script(module, param_value)

            # resume process pid
            device.resume(pid)
            print(f"Process '{process_name}' resumed with module '{module_name}' loaded.")

        except Exception as e:
            print(f"Error spawning the process: {e}")

    def do_list_modules(self, arg):
        """List available modules: list_modules"""
        if not self.platform:
            print("Error: Set platform first with 'set platform <ios|android>'.")
            return

        available_modules = AVAILABLE_MODULES_IOS if self.platform == 'ios' else AVAILABLE_MODULES_ANDROID

        print("Available modules:")
        for module in available_modules:
            print(f"- {module}")

    def do_filter(self, arg):
        """Strings Filter"""
        for line in self.captured_output:
            if str(arg).lower() in str(line).lower():
                print(line)

    def do_load_module(self, module_name):
        """Load and run a module: load_module <module_name>."""
        if not self.connected:
            print("Error: Not connected to any process. Use 'connect' first.")
            return

        arg_list = module_name.split()
        module_name = arg_list[0]

        if module_name == 'codeshare':
            try:
                url = arg_list[1]
                print(url)
            except:
                print("Error in url")
                return
                        
        if module_name != 'codeshare':
            available_modules = AVAILABLE_MODULES_IOS if self.platform == 'ios' else AVAILABLE_MODULES_ANDROID

            if module_name in available_modules:
                module_path = f"modules.{module_name}"
                try:
                    # Dynamic import
                    module = importlib.import_module(module_path)
                    self.execute_script(module)
                except ImportError as e:
                    print(f"Error loading the module {module_name}: {e}")
            else:
                print(f"Module {module_name} is not available. Use 'list_modules' to see available modules.")
        else:
            module = self.get_codeshare(url)
            param_value = 'codeshare'
            try:
                self.execute_script(module, param_value)
            except ImportError as e:
                print(f"Error loading the module {module_name}: {e}")

    def execute_script(self, module, options = ''):
        """Execute the script of a module"""
        try:
            self.do_clear_output() 
            
            if options:
                if options == 'codeshare':
                    script_code = module
                else:
                    script_code = module.get_script(options)
            else:
                script_code = module.get_script() 
            script = self.session.create_script(script_code)
            script.on('message', self.on_message)
            script.load()
            print(f"Script loaded and executed.")
        except Exception as e:
            print(f"Error executing the script: {e}")

    def on_message(self, message, data):
        """Handle Frida script messages and capture them in a variable"""
        if message['type'] == 'send':
            payload = message['payload']
            
            self.captured_output.append(payload)

    def do_show_output(self, arg):
        """Display the output captured"""
        print("Output captured:")
        for line in self.captured_output:
            print(line)

    def do_clear_output(self):
        """Clean Output"""
        self.captured_output = []
        print("Captured output cleaned.")

    def do_save_output(self, file_name):
        """Save the captured output to a file: save_output <filename>."""
        try:
            with open(file_name, 'w') as f:
                for line in self.captured_output:
                    f.write(str(line) + '\n')
            print(f"Captured output saved in {file_name}")
        except Exception as e:
            print(f"Error saving output: {e}")

    def do_exit(self, arg):
        """Exiting the interactive client"""
        print("Exiting the interactive client...")
        return True

    def fetch_scripts(self,page):
        url = f"https://codeshare.frida.re/browse?page={page}"
        response = requests.get(url)
        html = response.text
        h2_tags = re.findall(r'<h2>(.*?)</h2>', html, flags=re.IGNORECASE)
        return h2_tags

    def do_search_codeshare(self, keyword, end_page=20):
        try:
            urls = []
            print(f"[+] Extracting all the scripts with the word '{keyword}' in their names.")
            print()
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for i in range(1, end_page + 1):
                    futures.append(executor.submit(self.fetch_scripts, i))

                for future in futures:
                    h2_tags = future.result()
                    keyword_scripts = [h2 for h2 in h2_tags if re.search(keyword, h2, flags=re.IGNORECASE)]
                    for script in keyword_scripts:
                        match = re.search(r'href="(.*?)"', script)
                        if match:
                            urls.append(match.group(1))

            for url in urls:
                print(url)
        except Exception as e:
            print(e)

    def get_codeshare(self, url):
        get_script = url.split('/@')[1]
        if "/" == get_script[-1]:
            get_script = get_script[0:-1]

        r = requests.get(f"https://codeshare.frida.re/api/project/{get_script}.js")
        return r.json()['source']

            
if __name__ == '__main__':
    client = FridaClient()
    client.cmdloop()
