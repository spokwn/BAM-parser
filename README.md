# BAM Parser

Retrieves the paths and last execution time from the **BAM** artefact.

## What does it do?

- Parses the paths from the executed files on the BAM regedit key.
- Corrects the path from the format `\Device\HarddiskVolume<number>\` to the disk letter.
- Gets the last run time of the file.
- Gets if a the file was run in the last user's logon instance.
- Performs digital signature checks for each file present.
  - Reports "Deleted" if the file is not found.
  - Detects specific digital signatures (e.g., Slinky and Vape).
- Applies generic checks to each present file
- Checks for replaces using journal for every file.
  
## Generics:

1. **Generic A**: Basic strings for autoclickers.
2. **Generic A2**: Import combination for autoclickers.
3. **Generic A3**: Generic detection for C# autoclickers.
4. **Generic B**: Generic protection detection for non-C# files.
5. **Generic B2**: Generic protection detection for non-C# files.
6. **Generic B3**: Generic protection detection for non-C# files.
7. **Generic B4**: Generic protection detection for non-C# files.
8. **Generic B5**: Generic protection detection for non-C# files.
9. **Generic B6**: Generic protection detection for non-C# files.
10. **Generic B7**: Generic protection detection for non-C# files.
11. **Generic C**: Basic generic protection detection for C# files.
12. **Generic D**: Well done generic protection detection for C# files.
13. **Generic E**: Basic generic protection detection for C# and compiled python files.
14. **Generic F**: Advanced generic detection for packed executables.
15. **Generic F2**: Advanced generic detection for packed executables.
16. **Generic F3**: Advanced generic detection for packed executables.
17. **Generic F4**: Advanced generic detection for packed executables.
18. **Generic F5**: Advanced generic detection for packed executables.
19. **Generic F6**: Advanced generic detection for very packed executables.
20. **Generic F7**: Advanced generic detection for SUPER packed executables.
21. **Generic G**: Advanced generic detection for suspicious injector executables.
22. **Generic G2**: Advanced generic detection for suspicious injector executables.
23. **Generic G3**: Advanced generic detection for suspicious injector executables.
24. **Generic G4**: Advanced generic detection for suspicious injector executables
25. **Specific A**: Detects some free cheats using strings, this cheats are mostly the ones who didnt flag any generic at some point.
26. **Specific B**: Detects some paid cheats using advanced methods, it currently just detects 2, but aren't needed as generic already detected them.

Note: All generics should be relatively safe, but don't panic if they trigger. A2 and F generics may cause occasional "false flags", which are not intended to be fixed to maintain detection of real cheats, though they were improved lately.

## NOTES: 

- You can copy the paths of the cell you click on using "ctrl + left click".
- If you see a path showing up on red, click on it, it will show replace details it found.
- You can parse the values again pressing the button at the top left.
- You can show up only not signed files clicking on the checkbox at the top left.
- You can show up only generic flagged files clicking on the checkbox at the top left.
- You can show up only in instance executed files clicking on the checkbox at the top left.
