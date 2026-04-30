REMOVE TABLE IF EXISTS person;
REMOVE TABLE IF EXISTS order;

DEFINE TABLE person SCHEMAFULL;
    DEFINE FIELD name   ON person TYPE string;
    DEFINE FIELD age    ON person TYPE int;
    DEFINE FIELD city   ON person TYPE string;
    DEFINE FIELD tags   ON person TYPE array;
    DEFINE FIELD tags.* ON person TYPE string;

DEFINE TABLE order SCHEMAFULL;
    DEFINE FIELD buyer ON order TYPE record<person>;
    DEFINE FIELD item  ON order TYPE string;
    DEFINE FIELD total ON order TYPE float;

CREATE person:alice   SET name = "Alice",   age = 30, city = "NYC", tags = ["admin", "founder"];
CREATE person:bob     SET name = "Bob",     age = 25, city = "LA",  tags = ["member"];
CREATE person:charlie SET name = "Charlie", age = 35, city = "NYC", tags = ["admin", "moderator"];

CREATE order:o1 SET buyer = person:alice, item = "laptop", total = 999.99;
CREATE order:o2 SET buyer = person:bob,   item = "phone",  total = 699.50;
CREATE order:o3 SET buyer = person:alice, item = "book",   total = 39.99;

-- RESULT
SELECT VALUE name FROM person WHERE age > 28 ORDER BY name LIMIT 10 START 0;
SELECT VALUE name FROM ONLY person:alice;
SELECT name, age, tags FROM ONLY person:alice;
SELECT name, age, tags FROM person WHERE age > 28 ORDER BY name LIMIT 10 START 0;
SELECT name, age, tags AS tag FROM person SPLIT ON tags;
SELECT item, total, buyer.name AS name, buyer.* AS person FROM order ORDER BY total LIMIT 10 START 0 FETCH buyer;
SELECT city, count() AS cnt, math::mean(age) AS avg_age FROM person GROUP BY city;
SELECT * FROM order WHERE buyer IN (SELECT VALUE id FROM person WHERE city = "NYC");
SELECT name, tags AS tag FROM person WHERE tags CONTAINS "admin" SPLIT ON tags;
SELECT * FROM (SELECT name, tags AS tag FROM person SPLIT ON tags) WHERE tag = "admin";



"
[
	'Alice',
	'Charlie'
]

'Alice'

{
	age: 30,
	name: 'Alice',
	tags: [
		'admin',
		'founder'
	]
}

[
	{
		age: 30,
		name: 'Alice',
		tags: [
			'admin',
			'founder'
		]
	},
	{
		age: 35,
		name: 'Charlie',
		tags: [
			'admin',
			'moderator'
		]
	}
]

[
	{
		age: 30,
		name: 'Alice',
		tag: 'admin'
	},
	{
		age: 30,
		name: 'Alice',
		tag: 'founder'
	},
	{
		age: 25,
		name: 'Bob',
		tag: 'member'
	},
	{
		age: 35,
		name: 'Charlie',
		tag: 'admin'
	},
	{
		age: 35,
		name: 'Charlie',
		tag: 'moderator'
	}
]

[
	{
		item: 'book',
		name: 'Alice',
		person: {
			age: 30,
			city: 'NYC',
			id: person:alice,
			name: 'Alice',
			tags: [
				'admin',
				'founder'
			]
		},
		total: 39.99f
	},
	{
		item: 'phone',
		name: 'Bob',
		person: {
			age: 25,
			city: 'LA',
			id: person:bob,
			name: 'Bob',
			tags: [
				'member'
			]
		},
		total: 699.5f
	},
	{
		item: 'laptop',
		name: 'Alice',
		person: {
			age: 30,
			city: 'NYC',
			id: person:alice,
			name: 'Alice',
			tags: [
				'admin',
				'founder'
			]
		},
		total: 999.99f
	}
]

[
	{
		avg_age: 25,
		city: 'LA',
		cnt: 1
	},
	{
		avg_age: 32.5f,
		city: 'NYC',
		cnt: 2
	}
]

[
	{
		buyer: person:alice,
		id: order:o1,
		item: 'laptop',
		total: 999.99f
	},
	{
		buyer: person:alice,
		id: order:o3,
		item: 'book',
		total: 39.99f
	}
]

[
	{
		name: 'Alice',
		tag: 'admin'
	},
	{
		name: 'Alice',
		tag: 'founder'
	},
	{
		name: 'Charlie',
		tag: 'admin'
	},
	{
		name: 'Charlie',
		tag: 'moderator'
	}
]

[
	{
		name: 'Alice',
		tag: 'admin'
	},
	{
		name: 'Charlie',
		tag: 'admin'
	}
]
"