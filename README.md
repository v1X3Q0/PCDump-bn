# Pseudo C Dump (v1.1)
Author: **Asher Davila L.**

_Binary Ninja plugin to dump the Pseudo C generated by Binja into a folder._

## Description:

This Binary Ninja plugin is written in Python 3 and it aims to assist with reverse engineering  and vulnerability research. It dumps the Pseudo C representation of a binary, generated by Binja's decompiler, into a specified folder. 

Even though Binja has a built-in File -> Export option, it saves the output into a single file and contains extra information such as Segments, Sections, memory addresses, and other information that might not be necessary, depending on the intended use of the generated output.

The motivation for writing this plugin is to extract the Pseudo C representation of a binary in a format that can be easily imported into an IDE, or parsed by static analysis tools like [Semgrep](https://github.com/returntocorp/semgrep).

PCDump-bn plugin is inspired by [atxsinn3r](https://github.com/atxsinn3r)'s Binja plugin, [BinjaHLILDump](https://github.com/atxsinn3r/BinjaHLILDump), which dumps the HLIL, and by [0xdea](https://github.com/0xdea) Ghidra's [plugin](https://github.com/0xdea/ghidra-scripts/blob/main/Haruspex.java), which dumps the pseudo-code generated by the Ghidra decompiler.


### Usage

When using pcdump, a shell will pop up expecting input in a manner resembling the following:

```bash
usage: pcdump [-h] [--func FUNC] [--range RANGE] [--write_location WRITE_LOCATION]

options:
  -h, --help            show this help message and exit
  --func FUNC, -f FUNC  functions name or address to parse
  --range RANGE, -r RANGE
                        range, specified as a string separated by a -
  --write_location WRITE_LOCATION, -d WRITE_LOCATION
                        location to write the output to
```

if write_location isn't filled out in the submitted arguments, a window will be prompted for the user to provide a filepath for the pcdump output directory.

A function specified can be either a name or a hexadecimal address.

A range specified should be in the format 0xXXX-0xXXX being the start to end address. Any function whose start address is in the range will be dumped.

If neither func nor range are specified, all the functions will be dumped.

## The output, and how to get it into a compilable state

What will be dumped are c files. As of November 11th 2024, the unfortunate caveats to this process are:
- Binja often types as `void*` and then dereferences it.
    - The solution I had for this was just find and replace `void*` with `void**`, for double dereferences this fails. Casting to some intuitive `size_t` may also be a good solution.
- Binja won't be afraid to add a float to a pointer then deref.
- Binja will name some conditional variables like `cond:N`.
    - The solution I found was to find and replace all instances of `cond:` with `cond_`.
- The files generated are c, though they have some c++ macros like `nullptr`.
    - I define `nullptr` as `NULL`.
- The files generated also use the `bool` type.
    - I define `bool` as `int`.

### TODO

- Its definitely in the `TODO` to implement some of these in the file generation process.
- The other `TODO` would be to do header tracking, so that the generated c files can have all their includes resolved for eachother.

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 3814

## Contributing

Any feedback and any help from external maintainers are appreciated.

* Create an [issue](https://github.com/AsherDLL/PCDump-bn/issues) for feature requests or bugs that you have found.

* Submit a pull request for fixes and enhancements for this tool.

## License

This plugin is released under an [Apache 2.0 License](./LICENSE).
