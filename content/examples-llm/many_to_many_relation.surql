-- m:n relation problem
REMOVE TABLE IF EXISTS student;
REMOVE TABLE IF EXISTS course;

DEFINE TABLE course SCHEMAFULL;
    DEFINE FIELD name ON course TYPE string;

DEFINE TABLE student SCHEMAFULL;
    DEFINE FIELD name ON student TYPE string;
    DEFINE FIELD courses ON student TYPE set<record<course>> DEFAULT <set> [] REFERENCE ON DELETE REJECT;
    -- DEFINE INDEX idx_courses ON student COLUMNS courses.*;

-- INSERTION
INSERT INTO course (<array> 1..=1000).map(|$i| { 
    id: type::record('course', $i), 
    name: 'Course ' + <string>$i 
});

INSERT INTO student (<array> 1..=1000).map(|$s| {
    LET $offset = <int> math::floor(rand::float() * 1000);
    RETURN {
        id: type::record('student', $s),
        name: 'Student ' + <string>$s,
        courses: <set> (<array> 1..=100).map(|$i| type::record('course', (($offset + $i) % 1000) + 1))
    };
});

-- RESULT: 
-- insert 1000 27s for reference, indexed, set courses
-- insert 1000 27s for reference, set courses
-- insert 1000 4.3s for indexed, set courses
-- insert 1000 4.2s for set courses

SELECT courses.name FROM student:polymath;
SELECT id FROM student WHERE courses CONTAINS course:1;
SELECT id FROM course:1<~(student FIELD courses);
SELECT id FROM course:1<~student;


-- QUERIES
student:1.*;
student:1.courses;
course:1.*;
-- 1:n join
student:1.courses[0].*;
(<array>(student:1.courses)).*;
SELECT VALUE (<array>courses) FROM student:1 fetch course;
SELECT * FROM ((SELECT VALUE <array>courses FROM student:1)[0]) FETCH course;
course:5<~student;
course:5<~student.name;
course:5<~student.*;

-- m:n join
SELECT <~student as students, name from course;
SELECT value <~student from course limit 5;

-- m:n join aggregations
SELECT math::sum(array::len(<~student)) AS total_edges FROM course GROUP ALL;
SELECT count(<~student) from course group all;

-- brute force to get all the edges
SELECT math::sum(courses.len()) AS total_edges FROM student GROUP ALL; -- 3s800ms with 10000 courses 1000 students 10000000 edges
SELECT count() FROM (array::flatten(SELECT VALUE <array>courses FROM student)) group all; -- 5s with 10000 courses 1000 students 10000000 edges
SELECT math::sum(array::len(<~student)) AS total_edges FROM course GROUP ALL; -- 1m10s with 10000 courses 1000 students 10000000 edges

-- DEDUCTION: many to many join is optimised only for the domain or right sided set, the left sided reverse traversal moderate speed, for full join very high complexity, requires intersection between right and left - right
-- THRIVES IN ENVIRONMENT REQUIRING RIGHT SIDED SKEWNESS, e.g user-permissions, student-courses, person-health, .....
-- BOTTLENECKS IN ENVIRONMENT REQUIRING BOTH SIDED SKEWNESS, e.g intern-senior, user-groups, stock-asset, .....