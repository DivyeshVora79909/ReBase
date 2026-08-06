-- ==============================================================================
-- FILE 06: TABLE FIELDS (CRM ONTOLOGY & DAG STRUCTURE)
-- ==============================================================================
USE NS main DB main;

-- ==============================================================================
-- LEVEL 0: CLASSIFICATION SETS (Stateless Lookups & Enums)
-- ==============================================================================
-- These are user-configurable states. They have no backend validation logic attached,
-- ensuring the system graph remains pure and unaffected by client-side definitions.

DEFINE TABLE lifecycle_status SCHEMAFULL;
DEFINE FIELD a_name ON lifecycle_status TYPE string;
DEFINE FIELD a_color ON lifecycle_status TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON lifecycle_status TYPE object DEFAULT {};

DEFINE TABLE opportunity_status SCHEMAFULL;
DEFINE FIELD a_name ON opportunity_status TYPE string;
DEFINE FIELD a_color ON opportunity_status TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON opportunity_status TYPE object DEFAULT {};

DEFINE TABLE task_status SCHEMAFULL;
DEFINE FIELD a_name ON task_status TYPE string;
DEFINE FIELD a_color ON task_status TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON task_status TYPE object DEFAULT {};

DEFINE TABLE quote_status SCHEMAFULL;
DEFINE FIELD a_name ON quote_status TYPE string;
DEFINE FIELD a_color ON quote_status TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON quote_status TYPE object DEFAULT {};

DEFINE TABLE order_status SCHEMAFULL;
DEFINE FIELD a_name ON order_status TYPE string;
DEFINE FIELD a_color ON order_status TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON order_status TYPE object DEFAULT {};

DEFINE TABLE priority SCHEMAFULL;
DEFINE FIELD a_name ON priority TYPE string;
DEFINE FIELD a_color ON priority TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON priority TYPE object DEFAULT {};

DEFINE TABLE rating SCHEMAFULL;
DEFINE FIELD a_name ON rating TYPE string;
DEFINE FIELD a_color ON rating TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON rating TYPE object DEFAULT {};

DEFINE TABLE activity_type SCHEMAFULL;
DEFINE FIELD a_name ON activity_type TYPE string;
DEFINE FIELD a_color ON activity_type TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON activity_type TYPE object DEFAULT {};

DEFINE TABLE campaign_type SCHEMAFULL;
DEFINE FIELD a_name ON campaign_type TYPE string;
DEFINE FIELD a_color ON campaign_type TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON campaign_type TYPE object DEFAULT {};

DEFINE TABLE industry SCHEMAFULL;
DEFINE FIELD a_name ON industry TYPE string;
DEFINE FIELD a_color ON industry TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON industry TYPE object DEFAULT {};

DEFINE TABLE source SCHEMAFULL;
DEFINE FIELD a_name ON source TYPE string;
DEFINE FIELD a_color ON source TYPE string DEFAULT '#000000';
DEFINE FIELD a_style ON source TYPE object DEFAULT {};

DEFINE TABLE currency SCHEMAFULL;
DEFINE FIELD a_code ON currency TYPE string;
DEFINE FIELD a_symbol ON currency TYPE string;

DEFINE TABLE unit SCHEMAFULL;
DEFINE FIELD a_name ON unit TYPE string;


-- ==============================================================================
-- LEVEL 1: INDEPENDENT ANCHORS
-- ==============================================================================
-- The root nodes of the graph. These entities exist independently.

DEFINE TABLE organization SCHEMAFULL;
DEFINE FIELD a_name ON organization TYPE string;
DEFINE FIELD a_website ON organization TYPE string DEFAULT "";
DEFINE FIELD a_email ON organization TYPE string DEFAULT "";
DEFINE FIELD a_phone ON organization TYPE string DEFAULT "";
DEFINE FIELD a_billing_address ON organization TYPE string DEFAULT "";
DEFINE FIELD a_shipping_address ON organization TYPE string DEFAULT "";
DEFINE FIELD a_lifecycle_status ON organization TYPE option<record<lifecycle_status>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_industry ON organization TYPE option<record<industry>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_rating ON organization TYPE option<record<rating>> REFERENCE ON DELETE REJECT DEFAULT NONE;


DEFINE TABLE person SCHEMAFULL;
DEFINE FIELD a_first_name ON person TYPE string;
DEFINE FIELD a_last_name ON person TYPE string DEFAULT "";
DEFINE FIELD a_email ON person TYPE string DEFAULT "";
DEFINE FIELD a_phone ON person TYPE string DEFAULT "";
DEFINE FIELD a_job_title ON person TYPE string DEFAULT "";
DEFINE FIELD a_organization ON person TYPE option<record<organization>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_lifecycle_status ON person TYPE option<record<lifecycle_status>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_source ON person TYPE option<record<source>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_rating ON person TYPE option<record<rating>> REFERENCE ON DELETE REJECT DEFAULT NONE;


DEFINE TABLE product SCHEMAFULL;
DEFINE FIELD a_name ON product TYPE string;
DEFINE FIELD a_sku ON product TYPE string DEFAULT "";
DEFINE FIELD a_description ON product TYPE string DEFAULT "";
DEFINE FIELD a_unit_price ON product TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec;
DEFINE FIELD a_is_active ON product TYPE bool DEFAULT true;
DEFINE FIELD a_unit ON product TYPE option<record<unit>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_currency ON product TYPE option<record<currency>> REFERENCE ON DELETE REJECT DEFAULT NONE;


DEFINE TABLE campaign SCHEMAFULL;
DEFINE FIELD a_name ON campaign TYPE string;
DEFINE FIELD a_start_date ON campaign TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD a_end_date ON campaign TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD a_budget ON campaign TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec;
DEFINE FIELD a_type ON campaign TYPE option<record<campaign_type>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_status ON campaign TYPE option<record<lifecycle_status>> REFERENCE ON DELETE REJECT DEFAULT NONE;


DEFINE TABLE pipeline SCHEMAFULL;
DEFINE FIELD a_name ON pipeline TYPE string;
DEFINE FIELD a_is_active ON pipeline TYPE bool DEFAULT true;


DEFINE TABLE tag SCHEMAFULL;
DEFINE FIELD a_name ON tag TYPE string;
DEFINE FIELD a_hex_color ON tag TYPE string DEFAULT '#000000';


-- ==============================================================================
-- LEVEL 2: RELATIONAL BRANCHES (DAG Setup)
-- ==============================================================================

DEFINE TABLE stage SCHEMAFULL;
DEFINE FIELD a_name ON stage TYPE string;
DEFINE FIELD a_probability_pct ON stage TYPE int DEFAULT 0 ASSERT $value >= 0 AND $value <= 100;
DEFINE FIELD a_order_index ON stage TYPE int DEFAULT 0;
DEFINE FIELD a_pipeline ON stage TYPE record<pipeline> REFERENCE ON DELETE CASCADE;


DEFINE TABLE opportunity SCHEMAFULL;
DEFINE FIELD a_name ON opportunity TYPE string;
DEFINE FIELD a_close_date ON opportunity TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD a_probability ON opportunity TYPE int DEFAULT 0 ASSERT $value >= 0 AND $value <= 100;
DEFINE FIELD a_person ON opportunity TYPE option<record<person>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_organization ON opportunity TYPE option<record<organization>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_pipeline ON opportunity TYPE option<record<pipeline>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_stage ON opportunity TYPE option<record<stage>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_status ON opportunity TYPE option<record<opportunity_status>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_currency ON opportunity TYPE option<record<currency>> REFERENCE ON DELETE REJECT DEFAULT NONE;

DEFINE FIELD e_guard ON opportunity TYPE bool VALUE {
    IF $this.a_person = NONE AND $this.a_organization = NONE {
        THROW "DAG FRACTURE: Opportunity must be linked to at least a Person or an Organization.";
    };
    
    IF $this.a_stage != NONE AND $this.a_pipeline != NONE {
        IF $this.a_stage.a_pipeline != $this.a_pipeline {
            THROW "DAG FRACTURE: The assigned Stage does not belong to the assigned Pipeline.";
        };
    };
    RETURN true;
} ASSERT $value = true;


-- ==============================================================================
-- LEVEL 3: TRANSACTIONAL TREES
-- ==============================================================================

DEFINE TABLE quote SCHEMAFULL;
DEFINE FIELD a_quote_number ON quote TYPE string;
DEFINE FIELD a_valid_until ON quote TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD a_opportunity ON quote TYPE record<opportunity> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_status ON quote TYPE option<record<quote_status>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_currency ON quote TYPE option<record<currency>> REFERENCE ON DELETE REJECT DEFAULT NONE;


DEFINE TABLE order SCHEMAFULL;
DEFINE FIELD a_order_number ON order TYPE string;
DEFINE FIELD a_order_date ON order TYPE datetime DEFAULT time::now();
DEFINE FIELD a_parent ON order TYPE option<record<opportunity | quote>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_organization ON order TYPE option<record<organization>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_status ON order TYPE option<record<order_status>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_currency ON order TYPE option<record<currency>> REFERENCE ON DELETE REJECT DEFAULT NONE;

DEFINE FIELD e_guard ON order TYPE bool VALUE {
    -- Ensure absolute mathematical graph topology
    IF $this.a_parent != NONE AND $this.a_organization != NONE {
        LET $parent_org = 
            IF record::tb($this.a_parent) = 'quote' THEN $this.a_parent.a_opportunity.a_organization 
            ELSE IF record::tb($this.a_parent) = 'opportunity' THEN $this.a_parent.a_organization 
            ELSE NONE END;

        -- We only throw if the parent explicitly had an organization and it doesn't match the order's billing organization.
        IF $parent_org != NONE AND $parent_org != $this.a_organization {
            THROW "DAG FRACTURE: The Order's Organization does not match the Parent's (Quote/Opportunity) Organization.";
        };
    };
    RETURN true;
} ASSERT $value = true;


-- ==============================================================================
-- LEVEL 4: MATHEMATICAL LINES (Dependent Child Entities)
-- ==============================================================================

DEFINE TABLE opportunity_line SCHEMAFULL;
DEFINE FIELD a_opportunity ON opportunity_line TYPE record<opportunity> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_product ON opportunity_line TYPE option<record<product>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_qty ON opportunity_line TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_price ON opportunity_line TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD a_discount ON opportunity_line TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec;

DEFINE FIELD d1_raw_base ON opportunity_line TYPE decimal VALUE ($this.a_qty * $this.a_price);
DEFINE FIELD d2_net_base ON opportunity_line TYPE decimal VALUE ($this.d1_raw_base - $this.a_discount);

DEFINE FIELD e_guard ON opportunity_line TYPE bool VALUE {
    IF $this.d2_net_base < 0dec { THROW "MATH_ERR: Net base value cannot be negative. Discount exceeds raw base."; };
    RETURN true;
} ASSERT $value = true;


DEFINE TABLE quote_line SCHEMAFULL;
DEFINE FIELD a_quote ON quote_line TYPE record<quote> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_product ON quote_line TYPE option<record<product>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_qty ON quote_line TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_price ON quote_line TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD a_discount ON quote_line TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec;

DEFINE FIELD d1_raw_base ON quote_line TYPE decimal VALUE ($this.a_qty * $this.a_price);
DEFINE FIELD d2_net_base ON quote_line TYPE decimal VALUE ($this.d1_raw_base - $this.a_discount);

DEFINE FIELD e_guard ON quote_line TYPE bool VALUE {
    IF $this.d2_net_base < 0dec { THROW "MATH_ERR: Net base value cannot be negative. Discount exceeds raw base."; };
    RETURN true;
} ASSERT $value = true;


DEFINE TABLE order_line SCHEMAFULL;
DEFINE FIELD a_order ON order_line TYPE record<order> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_product ON order_line TYPE option<record<product>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_qty ON order_line TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_price ON order_line TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD a_discount ON order_line TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec;

DEFINE FIELD d1_raw_base ON order_line TYPE decimal VALUE ($this.a_qty * $this.a_price);
DEFINE FIELD d2_net_base ON order_line TYPE decimal VALUE ($this.d1_raw_base - $this.a_discount);

DEFINE FIELD e_guard ON order_line TYPE bool VALUE {
    IF $this.d2_net_base < 0dec { THROW "MATH_ERR: Net base value cannot be negative. Discount exceeds raw base."; };
    RETURN true;
} ASSERT $value = true;


-- ==============================================================================
-- LEVEL 5: POLYMORPHIC GRAPH LEAVES (Cross-Cutting Edges)
-- ==============================================================================

DEFINE TABLE task SCHEMAFULL;
DEFINE FIELD a_target ON task TYPE record<person | organization | opportunity | quote | order | campaign> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_subject ON task TYPE string;
DEFINE FIELD a_description ON task TYPE string DEFAULT "";
DEFINE FIELD a_due_date ON task TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD a_assigned_to ON task TYPE option<record<user>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_status ON task TYPE option<record<task_status>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_priority ON task TYPE option<record<priority>> REFERENCE ON DELETE REJECT DEFAULT NONE;


DEFINE TABLE activity SCHEMAFULL;
DEFINE FIELD a_target ON activity TYPE record<person | organization | opportunity | quote | order | campaign> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_subject ON activity TYPE string;
DEFINE FIELD a_description ON activity TYPE string DEFAULT "";
DEFINE FIELD a_activity_date ON activity TYPE datetime DEFAULT time::now();
DEFINE FIELD a_type ON activity TYPE option<record<activity_type>> REFERENCE ON DELETE REJECT DEFAULT NONE;


DEFINE TABLE note SCHEMAFULL;
DEFINE FIELD a_target ON note TYPE record<person | organization | opportunity | quote | order | campaign> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_title ON note TYPE string;
DEFINE FIELD a_content ON note TYPE string DEFAULT "";


DEFINE TABLE attachment SCHEMAFULL;
DEFINE FIELD a_target ON attachment TYPE record<person | organization | opportunity | quote | order | campaign> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_file_name ON attachment TYPE string;
DEFINE FIELD a_file_url ON attachment TYPE string;
DEFINE FIELD a_file_size_bytes ON attachment TYPE int DEFAULT 0 ASSERT $value >= 0;