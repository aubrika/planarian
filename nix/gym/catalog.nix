# The fault catalog as one TOML document: the directory's *.toml files in
# filename order, concatenated, as crates/gym/src/catalog.rs reads it.
dir:
let
  names = builtins.sort builtins.lessThan
    (builtins.filter (n: builtins.match ".*\\.toml" n != null) (builtins.attrNames (builtins.readDir dir)));
in
builtins.fromTOML (builtins.concatStringsSep "\n" (map (n: builtins.readFile (dir + "/${n}")) names))
