You may need to retrieve information from the file backup to use your existing account with the [Peach API](https://docs.peachbitcoin.com/#introduction)

[This implementation] (in Python3) of the [orginal tool] (in NodeJS) extends the functionality by:
* exporting the PGP keys and
* encryption of changes to settings

For the main use case, from the command line, run: `./decrypt.py <filename> <password>`

For more information on options, run: `./decrypt.py --help`

## Dependencies

You may get the script running with common dependency management tools.

On NixOS or with the Nix package manager simply run: `nix-shell`


<!-- Links -->
[This implementation]: https://github.com/vv01f/decrypt-peach-file-backup
[original tool]: https://github.com/Peach2Peach/decrypt-peach-file-backup
