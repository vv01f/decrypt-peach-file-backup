You may need to retrieve information from the file backup to use your existing account with the [Peach API](https://docs.peachbitcoin.com/#introduction)

[This implementation] (in Python3) of the [original tool] (in NodeJS) extends the functionality by:
* exporting the PGP keys and
* encryption of changes to settings
* control the salt used for encryption
* a GUI alongside the CLI script

For running the Graphical User Interface, start: `./unlocker.py`

For the main use case on the command line, run: `./unlocker_cli.py -d <filename> -p <password>`

For more information on options, run: `./unlocker_cli.py --help`

## Dependencies

You may get the script running with common dependency management tools and the provided `myproject.toml`.

On NixOS or with the Nix package manager simply run: `nix-shell`


<!-- Links -->
[This implementation]: https://github.com/vv01f/decrypt-peach-file-backup
[original tool]: https://github.com/Peach2Peach/decrypt-peach-file-backup
