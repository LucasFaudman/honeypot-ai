import requests
import sys
from time import sleep

args = sys.argv[1:]
RESOURCES_PATH = './resources'
SKIP_HEADLESS = False
if args:
    RESOURCES_PATH = args[0]
    
    if len(args) > 1:
        SKIP_HEADLESS = args[1].lower() == '--skip-headless'

    
def options_menu(options, prompt, param_name='option', default=-1):
    """
    Display a menu of options and prompt the user to select one.
    """
    selected = None
    while not selected:
        print(prompt)
        for i, option in enumerate(options):
            print(f"({i+1}) {option}")
        print()
        default_option = options[default]
        selected = input(f"Enter 1-{len(options)} to select a {param_name} (default: {options.index(default_option) + 1} {default_option}): ")
        if not selected:
            selected = default
        elif not selected.isdigit() or int(selected) < 1 or int(selected) > len(options):
            print(f"\nInvalid {param_name} number: {selected}. Enter 1-{len(options)}")
            sleep(2)
            selected = None
        else:
            selected = int(selected) - 1

    return options[selected]


versions_url = 'https://googlechromelabs.github.io/chrome-for-testing/latest-versions-per-milestone-with-downloads.json'
versions = requests.get(versions_url).json()
milestones = versions['milestones']
latest_milestone = list(milestones)[-1]

version_options = [f"Version {ms}" for ms in milestones if milestones[ms]['downloads'].get('chromedriver')]
version_q = f"""
Which chrome version number do you have installed? 
Open chrome and go to:
     chrome://settings/help
you will see a version number like Version 121.0.6167.85 (Official Build) (x86_64)
which corresponds to chromedriver version 121

Available chromedriver versions:""" 
selected_version = options_menu(version_options, version_q, 'version number', -1).split(' ')[1]
if int(selected_version) >= 120 and not SKIP_HEADLESS:
    headless = input("Do you want to use the headless version of chromedriver? (y/n): ").lower() == 'y'
else:
    headless = False
executable = 'chromedriver' if not headless else 'chrome-headless-shell'

platform_options = [download['platform'] for download in milestones[selected_version]['downloads'][executable]]
platform_q = f"""Which platform are you using?

Available platforms:""" 
platform = options_menu(platform_options, platform_q, 'platform', 0)

filename = f"{executable}{selected_version}-{platform}.zip"
destfolder = input(f"Where do you want to save {filename}? (default: {RESOURCES_PATH}): ").rstrip('/') or RESOURCES_PATH

for download in milestones[selected_version]['downloads'][executable]:
    if download['platform'] == platform:
        download_url = download['url']

        print(f"Downloading {filename} from {download_url}...")
        with open(f"{destfolder}/{filename}", 'wb') as f:
            f.write(requests.get(download_url).content)

        print(f"Downloaded {filename} to {destfolder}/{filename}")
        break

print('Done.')


