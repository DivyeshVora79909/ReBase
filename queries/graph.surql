# dag pure format from any node
LET $root = groups:root;

LET $nodes = array::distinct([
    $root,
    $root.dominates
].flatten());

LET $user_edges = (
    SELECT VALUE {
        child: id,
        parents: parents
    }
    FROM user
    WHERE id IN $nodes
);

LET $group_edges = (
    SELECT VALUE {
        child: id,
        parents: parents
    }
    FROM groups
    WHERE id IN $nodes
);

LET $all = array::flatten([
    $user_edges,
    $group_edges
]);

LET $edges = array::flatten(
    $all.map(|$row| {
        ($row.parents ?? [])
            .filter(|$parent| $parent IN $nodes)
            .map(|$parent| {
                {
                    source: $parent,
                    target: $row.child
                }
            })
    })
);

RETURN {
    nodes: $nodes,
    edges: array::distinct($edges)
};

# dag tree format from any node
DEFINE FUNCTION fn::dag_children($node: record) {
    RETURN array::distinct([
        $node<~(user FIELD parents),
        $node<~(groups FIELD parents)
    ].flatten());
};

fn::dag_children(groups:root);

DEFINE FUNCTION fn::dag_tree($node: record) {
    RETURN {
        id: $node,
        children: fn::dag_children($node).map(|$child| 
            fn::dag_tree($child)
        )
    };
};

fn::dag_tree(groups:root);

# dag cytoscope format from any node
LET $root = groups:root;

LET $nodes = array::distinct([
    $root,
    $root.dominates
].flatten());

LET $user_rows = (
    SELECT VALUE {
        id: id,
        parents: parents
    }
    FROM user
    WHERE id IN $nodes
);

LET $group_rows = (
    SELECT VALUE {
        id: id,
        parents: parents
    }
    FROM groups
    WHERE id IN $nodes
);

LET $rows = array::flatten([
    $user_rows,
    $group_rows
]);

LET $edges = array::flatten(
    $rows.map(|$row| {
        ($row.parents ?? [])
            .filter(|$parent| $parent IN $nodes)
            .map(|$parent| {
                {
                    data: {
                        id: <string>$parent + "->" + <string>$row.id,
                        source: <string>$parent,
                        target: <string>$row.id
                    }
                }
            })
    })
);

RETURN {
    nodes: $nodes.map(|$id| {
        data: {
            id: <string>$id
        }
    }),
    edges: array::distinct($edges)
};

# other usefull queries
groups:root<~(groups FIELD parents)<~(groups FIELD parents)<~(groups FIELD parents);
groups:root<~(groups FIELD parents)<~(groups FIELD parents);
groups:root<~(groups FIELD parents);
groups:root<~(user FIELD parents);
groups:root.dominates.parents;
groups:root.dominates;
groups:root.{..}(.parents);
groups:root.{..+collect}(...);
