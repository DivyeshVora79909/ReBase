REMOVE TABLE IF EXISTS person;

DEFINE TABLE OVERWRITE person SCHEMAFULL;
    DEFINE FIELD name ON person TYPE string;
    DEFINE FIELD email ON person TYPE string
        VALUE string::lowercase(string::trim($value));
    DEFINE FIELD created_at ON person TYPE datetime
        VALUE $before OR time::now() READONLY;
    DEFINE FIELD age ON person TYPE int;
    DEFINE FIELD achievements ON person TYPE decimal;
    DEFINE FIELD experience ON person TYPE decimal
        VALUE age * achievements;
    DEFINE FIELD z_search ON person TYPE string
        VALUE string::lowercase(name + " " + email);
    DEFINE FIELD adult ON person TYPE bool VALUE {
        IF age > 18 { true } ELSE { false }
    };
    DEFINE FIELD eligible ON person TYPE bool VALUE {
        LET $adult = adult;
        LET $tall = age > 120;
        RETURN $adult AND $tall;
    };

-- RESULT
CREATE person:alice SET name = 'Alice', email = ' Alice@Example.com ', age = 25, achievements = 5;
UPDATE person:alice SET name = 'MAX', email = ' MAX@Example.com ', age = 30, achievements = 2;
CREATE person:bob SET name = 'Bob', email = ' Bob@Example.com ', age = 123, achievements = 2;