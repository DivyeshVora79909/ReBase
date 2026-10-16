-- Public reads are pure. Only schema-declared dependencies are reactive.
DEFINE FUNCTION OVERWRITE fn::value::at($value: any, $path: string) {
    IF $path = '' { RETURN $value; };
    IF !string::matches($path, '^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*$') { THROW 'REBASE_READ_PATH'; };
    RETURN string::split($path, '.').fold($value, |$value, $part| {
        IF $value = NONE { RETURN NONE; };
        IF !type::is_object($value) { THROW 'REBASE_READ_PATH'; };
        RETURN $value[$part];
    });
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::record::read_value($rid: record, $path: string, $fallback: any) {
    LET $parts = string::split($path, '.');
    IF $path = '' OR $parts[0] IN fn::rebase::slots($rid) { THROW 'REBASE_READ_RECORD_FIELD'; };
    IF fn::rebase::root_allowed({ rid: $rid, slot: $parts[0] }) {
        IF $parts[1] != 'summary' { THROW 'REBASE_READ_RECORD_FIELD'; };
        RETURN fn::tree::read_value($rid, $parts[0], 'summary', [], array::join(array::slice($parts, 2), '.'), $fallback);
    };
    RETURN fn::value::at((SELECT * FROM ONLY $rid), $path) ?? $fallback;
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::tree::read_value($owner: record, $slot: string, $operation: string,
    $arguments: array, $path: string, $fallback: any) {
    IF $operation IN ['before', 'range', 'summary'] {
        RETURN fn::value::at(fn::tree::read($owner, $slot, $operation, $arguments), $path) ?? $fallback;
    };
    IF $operation IN ['latest', 'next', 'exact'] {
        IF $operation != 'exact' AND (array::len($arguments) < 1 OR array::len($arguments) > 2) { THROW 'TREE_READ_ARGUMENT'; };
        LET $link = IF $operation = 'exact' THEN fn::tree::read($owner, $slot, 'find', $arguments)
            ELSE fn::tree::read($owner, $slot, 'seek', [$arguments[0], $operation = 'latest', $arguments[1] ?? false]) END;
        LET $value = fn::tree::read($owner, $slot, 'value', [$link]);
        LET $selected = IF $link = NONE THEN NONE ELSE object::extend($value, { record: $link.rid, key: $value.first }) END;
        RETURN fn::value::at($selected, $path) ?? $fallback;
    };
    THROW 'REBASE_READ_OPERATION';
} PERMISSIONS FULL;
