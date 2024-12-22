# Universal Warehouse Redirector (uwhr)

A rather simplistic lib to remove the need to edit `hosts` file.

Lib is proxying either `dinput8.dll`, or less common `iphlpapi.dll`.

## Supported titles

- Transformers Revenge of the Fallen
- Race Driver Grid
- Guitar Hero 3
- Singularity

## Compatibility table

| Title                              | dinpu8.dll | iphlpapi.dll |
|------------------------------------|------------|--------------|
| Transformers Revenge of the Fallen | ❌          | ✅            |
| Race Driver Grid                   | ✅          | ✅            |
| Guitar Hero 3                      | ✅          | ✅            |
| Singularity                        | ✅          | ✅            |

## Instalation

1. **Download the Latest Release**

Grab the latest version of the tool from the Releases page.

2. **Place the File**

Move the downloaded file to the same folder as your game's .exe file.

3. **Launch the Game**

Start your game as usual.

If everything is set up correctly, the game will run without any errors, and a file named `uwhr.log` will be created in the game folder.
