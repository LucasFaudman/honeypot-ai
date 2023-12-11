import requests


versions_url = 'https://googlechromelabs.github.io/chrome-for-testing/latest-versions-per-milestone-with-downloads.json'


versions = requests.get(versions_url).json()
milestones = versions['milestones']
latest_milestone = list(milestones)[-1]

available_versions = '\n    - '.join(ms for ms in milestones if milestones[ms]['downloads'].get('chromedriver'))
version_q = f"""Which chrome version number do you have installed? 
Available versions: 
    - {available_versions}
Select a version number (default: {latest_milestone}): """


selected_version = input(version_q) or latest_milestone

if int(selected_version) >= 120:
    headless = input("Do you want to use the headless version of chromedriver? (y/n): ").lower() == 'y'
else:
    headless = False

executable = 'chromedriver' if not headless else 'chrome-headless-shell'

available_platforms = '\n    - '.join(ms['platform'] for ms in milestones[selected_version]['downloads'][executable])
platform_q = f"""Which platform are you using?
Available platforms: 
    - {available_platforms}
Select a platform: """

platform = input(platform_q)
filename = f"{executable}{selected_version}-{platform}.zip"

destfile = input(f"Where do you want to save {filename}? (default: current directory): ") or '.'

for download in milestones[selected_version]['downloads'][executable]:
    if download['platform'] == platform:
        download_url = download['url']
       
        print(f"Downloading {filename} from {download_url}...")

        with open(f"{destfile}/{filename}", 'wb') as f:
            f.write(requests.get(download_url).content)

        print(f"Downloaded {filename} to {destfile}/{filename}")

        break

print('Done.')


