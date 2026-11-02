# §12d (owner decision, Nov 2): the network tools NOT ordered after
# planarian-netwatch.service, because they are in netwatch's own startup
# chain and ordering them after it would be a cycle. A plain value, like
# own-units.nix: no configuration can widen it, and a configuration that
# orders a network tool before netwatch fails evaluation instead.
#
# Empty: netwatch is ordered after nothing (it starts at the front of boot,
# its module loaded in the initrd, its directory its own RuntimeDirectory),
# so every network tool, early-boot ones included, starts after it.
# Listed in the export as `networkToolsUnordered`.
[ ]
