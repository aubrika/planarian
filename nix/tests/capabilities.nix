# A finite property over systemd's capability aliases and inversion syntax.
# The oracle is the Linux capability ids, independent of the parser's table.
{ lib }:
let
  grants = import ../capabilities.nix { inherit lib; };
  network = [ "CAP_NET_ADMIN" "CAP_NET_RAW" ];
  cases = [
    { name = "CAP_CHOWN"; id = 0; }
    { name = "CAP_NET_ADMIN"; id = 12; }
    { name = "CAP_NET_RAW"; id = 13; }
    { name = "CAP_BPF"; id = 39; }
    { name = "CAP_CHECKPOINT_RESTORE"; id = 40; }
  ];
  spellings = c: [ c.name (lib.toLower c.name) (toString c.id) ];
  subsets = lib.foldl' (acc: c: acc ++ map (xs: xs ++ [ c ]) acc) [ [ ] ] cases;
  property = candidate:
    # One held/gainable capability has the same meaning by name, case or id,
    # as a string or a list assignment. Nonnumeric names are whitespace-free.
    builtins.all (c: builtins.all (s:
      candidate s network == builtins.elem c.id [ 12 13 ]
      && candidate [ s ] network == builtins.elem c.id [ 12 13 ]) (spellings c)) cases
    # An inverted assignment grants network authority unless both network
    # capabilities are excluded. Exercise every subset and spelling with
    # spaces, tabs, newlines and carriage returns as separators.
    && builtins.all (excluded:
      let want = !(builtins.any (c: c.id == 12) excluded && builtins.any (c: c.id == 13) excluded); in
      builtins.all (separator:
        builtins.all (render:
          candidate ("~" + lib.concatStringsSep separator (map render excluded)) network == want
        ) [ (c: c.name) (c: lib.toLower c.name) (c: toString c.id) ]
      ) [ " " "\t" "\n" "\r" ]
    ) subsets
    # Future or ambiguous syntax can over-hold, never silently waive one.
    && builtins.all (s: candidate s network) [
      "CAP_FUTURE_UNKNOWN" "~CAP_NET_ADMIN CAP_NET_RAW CAP_FUTURE_UNKNOWN"
      [ "~CAP_NET_ADMIN" "CAP_NET_RAW" ]
    ];
  # Exact pre-review predicate: the property must reject it, so this check
  # records mutation evidence whenever module-eval runs, not only once.
  oldWords = v:
    if builtins.isList v then lib.concatMap oldWords v
    else if builtins.isString v then lib.filter (w: w != "") (lib.splitString " " v)
    else [ (toString v) ];
  original = set: caps:
    let ws = oldWords set; inverted = ws != [ ] && lib.hasPrefix "~" (builtins.head ws); in
    if inverted then lib.any (c: !(builtins.elem c (map (lib.removePrefix "~") ws))) caps
    else lib.any (c: builtins.elem c ws) caps;
in
assert property grants;
assert !(property original);
true
