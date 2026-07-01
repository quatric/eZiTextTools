# eZiTextTools

**eZiTextTools** is a Python script to unpack the words in the predictive text entry system used by the Wii. It supports reading Zi Corporation's eZiText files (which are included in the `data`) folder. It also has some support for ATOK files by JustSystems, which is used for the Japanese language.

Currently, extracting eZiText .znd and .zsd files are supported, as well as AtokApt.atd and AtokNintendo.atd (but not AtokNintendo.atd). Rebuilding is supported, but currently only .znd files can be rebuild properly. The .zsd files do not work on the Wii.

The PS3 also has the same eZiText wordlist, except not the words Nintendo added (in the .znd files). You can verify this by typing in "zicorp" into the PS3 keyboard text input, then you will see a string with the date the text library was made. However, I was not able to find where the dictionaries are stored on a modded PS3.

## Usage

Type in `python ezitext.py -h` for usage information.

## Contact

General questions or comments can be sent to [quatricsoftware@gmail.com](mailto:quatricsoftware@gmail.com). No support will be provided for this tool.

## License

eZiTextTools uses the MIT license.

Copyright (c) 2026 quatric
