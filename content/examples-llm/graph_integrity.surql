REMOVE TABLE IF EXISTS project;
REMOVE TABLE IF EXISTS epic;
REMOVE TABLE IF EXISTS feature;
REMOVE TABLE IF EXISTS deliverable;
REMOVE TABLE IF EXISTS task;

-- 1. THE ROOT
DEFINE TABLE project SCHEMAFULL;
    DEFINE FIELD name ON project TYPE string;

-- 2. THE LEFT BRANCH (Epic -> Feature)
DEFINE TABLE epic SCHEMAFULL;
    DEFINE FIELD project ON epic TYPE record<project> REFERENCE ON DELETE CASCADE;

DEFINE TABLE feature SCHEMAFULL;
    DEFINE FIELD epic ON feature TYPE record<epic> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD project ON feature TYPE record<project> VALUE epic.project;
    DEFINE FIELD updated_at ON feature TYPE datetime VALUE time::now();

-- 3. THE RIGHT BRANCH (Deliverable)
DEFINE TABLE deliverable SCHEMAFULL;
    DEFINE FIELD project ON deliverable TYPE record<project> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD updated_at ON deliverable TYPE datetime VALUE time::now();

-- 4. THE JUNCTION (Task) - O(1) Enforcement
DEFINE TABLE task SCHEMAFULL;
    DEFINE FIELD feature ON task TYPE record<feature> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD deliverable ON task TYPE record<deliverable> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD project ON task TYPE record<project> VALUE {
        IF feature.project != deliverable.project {
            THROW "PENTAGON_VIOLATION: The Feature's lineage and Deliverable's lineage do not trace back to the same Project.";
        };
        RETURN feature.project;
    };
    DEFINE FIELD updated_at ON task TYPE datetime VALUE time::now();


-- 5. THE "DOMINO PING" CASCADES for integrity
DEFINE EVENT ping_feature ON epic WHEN $event = 'UPDATE' AND $before.project != $after.project THEN {
    UPDATE (<~feature) SET updated_at = time::now();
};

DEFINE EVENT ping_task_from_feature ON feature WHEN $event = 'UPDATE' AND $before.project != $after.project THEN {
    UPDATE (<~task) SET updated_at = time::now();
};

DEFINE EVENT ping_task_from_deliverable ON deliverable WHEN $event = 'UPDATE' AND $before.project != $after.project THEN {
    UPDATE (<~task) SET updated_at = time::now();
};

-- 6. TESTING THE PENTAGON
CREATE project:alpha SET name = "Alpha";
CREATE project:beta  SET name = "Beta";

CREATE epic:1 SET project = project:alpha;
CREATE feature:1 SET epic = epic:1; 

CREATE deliverable:1 SET project = project:alpha;
CREATE deliverable:2 SET project = project:beta;

-- TEST 1: Valid Junction (Success)
CREATE task:valid SET feature = feature:1, deliverable = deliverable:1;
SELECT id, project FROM task:valid; -- Expected: project:alpha

-- TEST 2: Invalid Junction (Throws PENTAGON_VIOLATION)
CREATE task:invalid SET feature = feature:1, deliverable = deliverable:2;

-- TEST 3: The "Domino Rollback" (Masterclass Test)
-- We try to move Epic 1 to Project Beta.
-- What happens: Epic updates -> Pings Feature 1 -> Feature 1 updates its Project to Beta -> 
-- Pings Task Valid -> Task Valid sees Feature is Beta but Deliverable is Alpha -> THROWS ERROR!
-- Result: Epic 1's update is completely ABORTED and rolled back!

UPDATE epic:1 SET project = project:beta;

-- Verify Epic 1 is still safely locked to Alpha:
SELECT id, project FROM epic:1;

-- TEST 4: Changing a deliverable's project (used by a valid task) → MUST FAIL
-- deliverable:1 is currently project:alpha, used by task:valid.
-- Moving it to beta would break the link.
UPDATE deliverable:1 SET project = project:beta;

-- Verify deliverable:1 is still on alpha (the update should have rolled back)
SELECT project FROM deliverable:1; -- Expected: project:alpha

-- TEST 5: Changing a feature's epic (which changes its project) → MUST FAIL
-- feature:1 currently belongs to epic:1 (project:alpha), used by task:valid.
-- Moving it to a new epic under beta would cause mismatch.
CREATE epic:2 SET project = project:beta;
UPDATE feature:1 SET epic = epic:2;

-- Verify feature:1's project is still alpha (epic change rolled back)
SELECT epic, project FROM feature:1; -- Expected: epic:1, project:alpha

-- TEST 6: Directly updating a task's deliverable to a cross‑project one → MUST FAIL
UPDATE task:valid SET deliverable = deliverable:2;

-- Verify task:valid still points to deliverable:1
SELECT deliverable FROM task:valid; -- Expected: deliverable:1

-- TEST 7: Moving the entire epic (which cascades feature.project) when no tasks exist → SUCCESS
-- First create a new feature without tasks, then move its epic.
CREATE epic:3 SET project = project:alpha;
CREATE feature:2 SET epic = epic:3;
-- This should succeed (no broken tasks)
UPDATE epic:3 SET project = project:beta;
SELECT project FROM feature:2; -- Expected: project:beta (cascaded update)

-- TEST 8: Adding a task AFTER a successful project change → valid if consistent
CREATE deliverable:3 SET project = project:beta;
CREATE task:beta_task SET feature = feature:2, deliverable = deliverable:3;
SELECT project FROM task:beta_task; -- Expected: project:beta

-- TEST 9: Deleting a deliverable that is referenced by a task → cascade delete
-- task:valid references deliverable:1. Deleting deliverable:1 should delete task:valid.
DELETE deliverable:1;
SELECT * FROM task:valid; -- Expected: empty (record not found)

-- TEST 10: Updating a deliverable's project when it has no tasks → SUCCESS
-- deliverable:2 is project:beta, currently not used by any task.
UPDATE deliverable:2 SET project = project:alpha;
SELECT project FROM deliverable:2; -- Expected: project:alpha
