#!/bin/bash
FILE='/usr/share/man/man5/login.defs.5.gz'
REGEXP='^\.IP "[A-Z_]* (.*)"$'
SEDOR='s/(\(.*\) or \(.*\))/(\1|\2)/g'              # " or " -> "|"
SEDNUM='s/number/integer/g'                         # "number" -> "integer"
SEDEXP='s/^.IP "\([A-Z_]*\) (\(.*\))"$/\1:\2/g'     # man page to YCPList

echo "ITEMS INDEX:"
echo "------------"
zcat "$FILE" | grep "$REGEXP" | sed "$SEDOR" | sed "$SEDNUM" | sed "$SEDEXP"

echo >&2
echo "Filtered lines:" >&2
echo "---------------" >&2
zcat "$FILE" | grep "\.IP" | grep -v "$REGEXP" >&2
