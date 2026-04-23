# rpenc-cli
Rust Portable ENCryption tool made to protect your data on portable(or not) drives.

Launch *generator.sh* or *generator.bat* to generate rpenc folders and files in folder of launch. 
Launch *rpenc.sh* or *rpenc.bat* from command line to start rpenc.
- [Usage](#Usage)
- [Installation](#Installation)
- [File naming](#File-naming)
- [Progress](#Progress)

## Installation
Unix: 
```bash
curl -o "generator.sh" "https://raw.githubusercontent.com/Cinnamon415/rpenc-cli/refs/heads/main/generator.sh"
chmod +x ./generator.sh
./generator.sh
```
Windows: 
```batch
curl -o "generator.bat" "https://raw.githubusercontent.com/Cinnamon415/rpenc-cli/refs/heads/main/generator.bat"
./generator.bat
```


## Usage
```
Usage: rpenc <COMMAND>

Commands:
  encrypt  
  decrypt  
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```
```
Usage: rpenc encrypt [OPTIONS]

Options:
  -i, --input <INPUT>          
  -o, --output <OUTPUT>        
  -d, --delete-origins           
  -n, --file-name <FILE_NAME>  
  -f, --full                   
  -h, --help                   Print help
```
```
Usage: rpenc decrypt [OPTIONS]

Options:
  -i, --input <INPUT>    
  -o, --output <OUTPUT>  
  -d, --delete-origin
  -h, --help             Print help
```
Whithout arguments --input or --output `rpenc encrypt` encrypts your files in parent directory of rpenc dir. Encrypted files for default are stored in `rpenc/encrypted/`.
**Input and output args must be directories**
Use `--delete-origins` or `-d` for `encrypt` if you want to delete files and folders that will be encrypted.

## File naming
|Name                                           |Mode
|-----------------------------------------------|----------------------------------------|
|`encrypted-data-1766044242.087331609s-3294.enc`|Default                                 |
|`[NAME]-1766044242.087331609s-3294.enc`        |`--file-name [NAME]` or `-n`            |
|`[NAME].enc`                                   |`--file-name [NAME] --full` or `-fn`    |

## Progress
- [x] Archivating
- [x] Encrypting/Decrypting
- [x] Arguments
- [x] CD/CI
- [ ] Config
- [ ] GUI
- [ ] AES-mode and hardware acceleration

## Testing Help Needed

If you'd like to help test **rpenc-cli** across different platforms:
1. Create a new issue with the label **`Testing`**
2. Include in your report:
   - Screenshots or short video demonstrating the issue
   - Full program output
   - Your operating system name and version (e.g., Windows 11 22H2, macOS Sonoma 14.5, Ubuntu 24.04)
   - Clear steps to reproduce the problem

> 💡 **Tip**: Test both encryption and decryption workflows with different file types

> 🏆 **Bug Hunters**: Users who report verified issues will be credited in the **Special Thanks** section of next release notes!

Your feedback is greatly appreciated and helps make rpenc-cli more reliable for everyone.

---

### Important Note
All recent changes are currently available **only in the beta branch** because I lack access to multiple operating systems for comprehensive testing. **Your contribution** by testing on your system would be invaluable to ensure cross-platform compatibility.
