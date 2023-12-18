# ShoDomain-Seeker

ShoDomain Seeker is a Python script designed to facilitate the discovery of subdomains associated with a given domain using the Shodan API. This tool is particularly useful for security professionals, penetration testers, and anyone involved in domain reconnaissance.

## Features
- Shodan API Integration: Utilizes the Shodan API to retrieve detailed information about subdomains.
- Informative Output: Displays relevant details, including subdomain names, IP/DNS information, and the last scan made by Shodan.
- File Output: Option to save results to a file for further analysis and documentation.
## Usage
### Prerequisites
- Python 3.x
- Shodan API Key (Sign up for a Shodan account and obtain your API key [here](https://developer.shodan.io/api/requirements))
### Installation
Clone the repository:

```
git clone https://github.com/TiiTcHY/ShoDomain-Seeker.git
cd ShoDomain-Seeker
```
### Running the Script
```
python shodan_subdomain_seeker.py -d <target_domain> -s <your_shodan_api_key>
```
### Options:

- -d, --domain: Specify the target domain to find subdomains.
- -s, --shodan_key: Provide your Shodan API key.
- -v, --verbose: Show detailed output.
- -o, --file_name: Save results to a file.

## Examples
### Basic Usage:
```
python shodan_subdomain_seeker.py -d example.com -s YOUR_SHODAN_API_KEY
```
### Save Results to a File:
```
python shodan_subdomain_seeker.py -d example.com -s YOUR_SHODAN_API_KEY -o output.txt
```
### For more information and options, run:
```
python shodan_subdomain_seeker.py --help
```

## Acknowledgments
ASCII art in the script generated using [text-image.com](text-image.com).




