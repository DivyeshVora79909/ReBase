-- ==============================================================================
-- FILE 07: O(1) AGGREGATIONS & BI VIEWS (MATHEMATICAL CRM DAG)
-- ==============================================================================
USE NS main DB main;

-- ==============================================================================
-- 1. POLYMORPHIC LEAVES (Graph Cross-Cutting Totals)
-- ==============================================================================
-- Because a_target is polymorphic, these views automatically partition across 
-- Person, Org, Opportunity, Quote, Order, and Campaign purely by their Record ID.

DEFINE TABLE OVERWRITE v_task_target AS SELECT a_target AS target, count() AS total_tasks FROM task GROUP BY target;
DEFINE TABLE OVERWRITE v_activity_target AS SELECT a_target AS target, count() AS total_activities FROM activity GROUP BY target;
DEFINE TABLE OVERWRITE v_note_target AS SELECT a_target AS target, count() AS total_notes FROM note GROUP BY target;
DEFINE TABLE OVERWRITE v_attachment_target AS SELECT a_target AS target, count() AS total_attachments, math::sum(a_file_size_bytes) AS total_bytes FROM attachment GROUP BY target;


-- ==============================================================================
-- 2. TRANSACTION LINES -> DIRECT PARENT (Subtotals)
-- ==============================================================================
-- These views give the immediate mathematical state to the exact parent document.

DEFINE TABLE OVERWRITE v_oppl_opp AS SELECT a_opportunity AS opportunity, count() AS line_count, math::sum(a_qty) AS sum_qty, math::sum(d2_net_base) AS sum_net, math::sum(a_discount) AS sum_discount FROM opportunity_line GROUP BY opportunity;

DEFINE TABLE OVERWRITE v_quotel_quote AS SELECT a_quote AS quote, count() AS line_count, math::sum(a_qty) AS sum_qty, math::sum(d2_net_base) AS sum_net, math::sum(a_discount) AS sum_discount FROM quote_line GROUP BY quote;

DEFINE TABLE OVERWRITE v_orderl_order AS SELECT a_order AS order, count() AS line_count, math::sum(a_qty) AS sum_qty, math::sum(d2_net_base) AS sum_net, math::sum(a_discount) AS sum_discount FROM order_line GROUP BY order;


-- ==============================================================================
-- 3. DAG STRUCTURAL TRACKING (The "Shadow State")
-- ==============================================================================
-- Instead of using status strings (e.g., "Quoted", "Ordered"), we determine reality 
-- by mathematically checking if the downward graph edges exist.

-- How many quotes does an opportunity have?
DEFINE TABLE OVERWRITE v_quote_opp AS SELECT a_opportunity AS opportunity, count() AS total_quotes FROM quote GROUP BY opportunity;

-- How many orders spawned from this parent (Quote OR Opportunity)?
DEFINE TABLE OVERWRITE v_order_parent AS SELECT a_parent AS parent, count() AS total_orders FROM order GROUP BY parent;


-- ==============================================================================
-- 4. PRODUCT CATALOG ANALYTICS (Line -> Product)
-- ==============================================================================
-- Computes the performance, price variance, and velocity of every product in the catalog.

DEFINE TABLE OVERWRITE v_oppl_prod AS SELECT a_product AS product, count() AS opp_freq, math::sum(a_qty) AS pipeline_qty, math::sum(d2_net_base) AS pipeline_val FROM opportunity_line GROUP BY product;

DEFINE TABLE OVERWRITE v_quotel_prod AS SELECT a_product AS product, count() AS quote_freq, math::sum(a_qty) AS quoted_qty, math::sum(d2_net_base) AS quoted_val FROM quote_line GROUP BY product;

DEFINE TABLE OVERWRITE v_orderl_prod AS SELECT a_product AS product, count() AS order_freq, math::sum(a_qty) AS sold_qty, math::sum(d2_net_base) AS sold_val, math::mean(a_price) AS avg_sold_price, math::variance(a_price) AS var_sold_price, math::max(a_price) AS max_price, math::min(a_price) AS min_price FROM order_line GROUP BY product;


-- ==============================================================================
-- 5. DAG SKIPS -> ORGANIZATION (Lifetime Value & Pipeline Health)
-- ==============================================================================
-- This is where the magic happens. We skip the middleman tables and group 
-- the mathematical lines directly by their ultimate Organization target.

DEFINE TABLE OVERWRITE v_opp_org AS SELECT a_organization AS org, count() AS total_opps, math::mean(a_probability) AS avg_probability FROM opportunity GROUP BY org;

DEFINE TABLE OVERWRITE v_oppl_org AS SELECT a_opportunity.a_organization AS org, math::sum(d2_net_base) AS total_pipeline_val FROM opportunity_line GROUP BY org;

DEFINE TABLE OVERWRITE v_order_org AS SELECT a_organization AS org, count() AS total_orders FROM order GROUP BY org;

DEFINE TABLE OVERWRITE v_orderl_org AS SELECT a_order.a_organization AS org, math::sum(d2_net_base) AS lifetime_val, math::sum(a_qty) AS lifetime_items FROM order_line GROUP BY org;


-- ==============================================================================
-- 6. DAG SKIPS -> PERSON (B2C & Contact Impact)
-- ==============================================================================
-- Tracks the pipeline value tied directly to individual people.

DEFINE TABLE OVERWRITE v_opp_person AS SELECT a_person AS person, count() AS total_opps FROM opportunity GROUP BY person;

DEFINE TABLE OVERWRITE v_oppl_person AS SELECT a_opportunity.a_person AS person, math::sum(d2_net_base) AS total_pipeline_val FROM opportunity_line GROUP BY person;


-- ==============================================================================
-- 7. BI & TIME-SERIES (Read-Only Analytics)
-- ==============================================================================
-- These views use time::group(). They will NOT trigger upward pings (ignored by 
-- the ReBase compiler for validation) but provide instant O(1) dashboard charts.

-- Daily global revenue and item count
DEFINE TABLE OVERWRITE v_bi_orderl_daily AS SELECT time::group(a_order.a_order_date, 'day') AS day, math::sum(d2_net_base) AS daily_revenue, math::sum(a_qty) AS items_sold FROM order_line GROUP BY day;

-- Monthly organizational revenue velocity
DEFINE TABLE OVERWRITE v_bi_orderl_org_monthly AS SELECT time::group(a_order.a_order_date, 'month') AS month, a_order.a_organization AS org, math::sum(d2_net_base) AS monthly_revenue FROM order_line GROUP BY month, org;

-- Monthly pipeline generation
DEFINE TABLE OVERWRITE v_bi_opp_created_monthly AS SELECT time::group(created_at, 'month') AS month, count() AS new_opportunities FROM opportunity GROUP BY month;