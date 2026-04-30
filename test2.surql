REMOVE DATABASE test;
DEFINE DATABASE test;
USE NS test DB test;

DEFINE TABLE doc SCHEMAFULL;

DEFINE FIELD level1 ON doc TYPE option<array<object>>;
DEFINE FIELD level1.*.item_name ON doc TYPE string;
DEFINE FIELD level1.*.qty ON doc TYPE decimal;

DEFINE FIELD zz_integrity_check ON doc TYPE array<object>
    VALUE ( SELECT item_name, math::sum(qty) AS net_qty FROM ($this.level1 ??[]) GROUP BY item_name )
    ASSERT $value.filter(|$v| $v.net_qty < 0).len() == 0;

DEFINE FIELD zz_integrity_check.*.item_name ON doc TYPE string;
DEFINE FIELD zz_integrity_check.*.net_qty ON doc TYPE decimal;

-- TEST SUCCESS
CREATE doc:success SET level1 =[
    { item_name: 'Steel Bar', qty: 5 },
    { item_name: 'Steel Bar', qty: -2 }, 
    { item_name: 'Screw', qty: 10 }      
];

-- TEST THROW
CREATE doc:failure SET level1 =[
    { item_name: 'Steel Bar', qty: 5 },
    { item_name: 'Steel Bar', qty: -7 }  
];
