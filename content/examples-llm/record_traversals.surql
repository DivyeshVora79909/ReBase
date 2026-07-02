DEFINE TABLE person SCHEMAFULL;
DEFINE FIELD parent ON person TYPE option<record<person>> REFERENCE ON DELETE REJECT;
DEFINE FIELD name ON person TYPE string;
DEFINE FIELD age ON person TYPE option<int>;

CREATE person:grandparent SET name = 'Grandparent Alice', age = 80;

CREATE person:parent1 SET name = 'Parent Bob', age = 55, parent = person:grandparent;
CREATE person:parent2 SET name = 'Parent Carol', age = 52, parent = person:grandparent;

CREATE person:child1 SET name = 'Child Dave', age = 30, parent = person:parent1;
CREATE person:child2 SET name = 'Child Eve', age = 28, parent = person:parent1;
CREATE person:child3 SET name = 'Child Frank', age = 26, parent = person:parent2;

CREATE person:grandchild1 SET name = 'Grandchild Grace', age = 5, parent = person:child1;
CREATE person:grandchild2 SET name = 'Grandchild Hank', age = 6, parent = person:child1;
CREATE person:grandchild3 SET name = 'Grandchild Silva', age = 3, parent = person:child2;
CREATE person:grandchild4 SET name = 'Grandchild Tom', age = 7, parent = person:child2;
CREATE person:grandchild5 SET name = 'Grandchild John', age = 9, parent = person:child3;

CREATE person:other SET name = 'Stranger', age = 99;


-- REVERSE TRAVERSAL
person:grandparent<~person<~person<~person;
person:grandparent<~person<~person;
person:grandparent<~person;

person:parent1<~person<~person;
person:parent1<~person;

person:child1<~person;


-- FORWARD TRAVERSAL
person:parent1.parent;
person:child1.parent.parent;
person:grandchild1.parent.parent.parent;


person:grandparent<~person<~person<~person.age;
person:parent1<~person<~person.age;
UPDATE person:parent1<~person<~person SET age = age + 1;
person:grandparent<~person<~person<~person.age;
person:parent1<~person<~person.age;

"
-------- Query 1 (6ms100us) --------

NONE

-------- Query 2 (10ms600us) --------

NONE

-------- Query 3 (1ms) --------

NONE

-------- Query 4 (400us) --------

NONE

-------- Query 5 (33ms700us) --------

[
	{
		age: 80,
		id: person:grandparent,
		name: 'Grandparent Alice'
	}
]

-------- Query 6 (2ms200us) --------

[
	{
		age: 55,
		id: person:parent1,
		name: 'Parent Bob',
		parent: person:grandparent
	}
]

-------- Query 7 (600us) --------

[
	{
		age: 52,
		id: person:parent2,
		name: 'Parent Carol',
		parent: person:grandparent
	}
]

-------- Query 8 (500us) --------

[
	{
		age: 30,
		id: person:child1,
		name: 'Child Dave',
		parent: person:parent1
	}
]

-------- Query 9 (700us) --------

[
	{
		age: 28,
		id: person:child2,
		name: 'Child Eve',
		parent: person:parent1
	}
]

-------- Query 10 (2ms400us) --------

[
	{
		age: 26,
		id: person:child3,
		name: 'Child Frank',
		parent: person:parent2
	}
]

-------- Query 11 (900us) --------

[
	{
		age: 5,
		id: person:grandchild1,
		name: 'Grandchild Grace',
		parent: person:child1
	}
]

-------- Query 12 (700us) --------

[
	{
		age: 6,
		id: person:grandchild2,
		name: 'Grandchild Hank',
		parent: person:child1
	}
]

-------- Query 13 (500us) --------

[
	{
		age: 3,
		id: person:grandchild3,
		name: 'Grandchild Silva',
		parent: person:child2
	}
]

-------- Query 14 (600us) --------

[
	{
		age: 7,
		id: person:grandchild4,
		name: 'Grandchild Tom',
		parent: person:child2
	}
]

-------- Query 15 (700us) --------

[
	{
		age: 9,
		id: person:grandchild5,
		name: 'Grandchild John',
		parent: person:child3
	}
]

-------- Query 16 (1ms100us) --------

[
	{
		age: 99,
		id: person:other,
		name: 'Stranger'
	}
]

-------- Query 17 (15ms600us) --------

[
	person:grandchild1,
	person:grandchild2,
	person:grandchild3,
	person:grandchild4,
	person:grandchild5
]

-------- Query 18 (700us) --------

[
	person:child1,
	person:child2,
	person:child3
]

-------- Query 19 (200us) --------

[
	person:parent1,
	person:parent2
]

-------- Query 20 (300us) --------

[
	person:grandchild1,
	person:grandchild2,
	person:grandchild3,
	person:grandchild4
]

-------- Query 21 (100us) --------

[
	person:child1,
	person:child2
]

-------- Query 22 (200us) --------

[
	person:grandchild1,
	person:grandchild2
]

-------- Query 23 (4ms500us) --------

person:grandparent

-------- Query 24 (500us) --------

person:grandparent

-------- Query 25 (400us) --------

person:grandparent

-------- Query 26 (800us) --------

[
	5,
	6,
	3,
	7,
	9
]

-------- Query 27 (500us) --------

[
	5,
	6,
	3,
	7
]

-------- Query 28 (12ms900us) --------

[
	{
		age: 6,
		id: person:grandchild1,
		name: 'Grandchild Grace',
		parent: person:child1
	},
	{
		age: 7,
		id: person:grandchild2,
		name: 'Grandchild Hank',
		parent: person:child1
	},
	{
		age: 4,
		id: person:grandchild3,
		name: 'Grandchild Silva',
		parent: person:child2
	},
	{
		age: 8,
		id: person:grandchild4,
		name: 'Grandchild Tom',
		parent: person:child2
	}
]

-------- Query 29 (900us) --------

[
	6,
	7,
	4,
	8,
	9
]

-------- Query 30 (600us) --------

[
	6,
	7,
	4,
	8
]
"