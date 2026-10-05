-- Tenant-wide CRM reports are deliberately published to members with source select permission.

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_task_target AS SELECT tenant, a_target AS target, count() AS total_tasks FROM task GROUP BY tenant, target;
-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_activity_target AS SELECT tenant, a_target AS target, count() AS total_activities FROM activity GROUP BY tenant, target;
-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_note_target AS SELECT tenant, a_target AS target, count() AS total_notes FROM note GROUP BY tenant, target;
-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_attachment_target AS SELECT tenant, a_target AS target, count() AS total_attachments, math::sum(a_file_size_bytes) AS total_bytes FROM attachment GROUP BY tenant, target;



-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_oppl_opp AS SELECT tenant, a_opportunity AS opportunity, count() AS line_count, math::sum(a_qty) AS sum_qty, math::sum(d2_net_base) AS sum_net, math::sum(a_discount) AS sum_discount FROM opportunity_line GROUP BY tenant, opportunity;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_quotel_quote AS SELECT tenant, a_quote AS quote, count() AS line_count, math::sum(a_qty) AS sum_qty, math::sum(d2_net_base) AS sum_net, math::sum(a_discount) AS sum_discount FROM quote_line GROUP BY tenant, quote;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_orderl_order AS SELECT tenant, a_order AS order, count() AS line_count, math::sum(a_qty) AS sum_qty, math::sum(d2_net_base) AS sum_net, math::sum(a_discount) AS sum_discount FROM order_line GROUP BY tenant, order;



-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_quote_opp AS SELECT tenant, a_opportunity AS opportunity, count() AS total_quotes FROM quote GROUP BY tenant, opportunity;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_order_parent AS SELECT tenant, a_parent AS parent, count() AS total_orders FROM order GROUP BY tenant, parent;



-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_oppl_prod AS SELECT tenant, a_product AS product, count() AS opp_freq, math::sum(a_qty) AS pipeline_qty, math::sum(d2_net_base) AS pipeline_val FROM opportunity_line GROUP BY tenant, product;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_quotel_prod AS SELECT tenant, a_product AS product, count() AS quote_freq, math::sum(a_qty) AS quoted_qty, math::sum(d2_net_base) AS quoted_val FROM quote_line GROUP BY tenant, product;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_orderl_prod AS SELECT tenant, a_product AS product, count() AS order_freq, math::sum(a_qty) AS sold_qty, math::sum(d2_net_base) AS sold_val, math::mean(a_price) AS avg_sold_price, math::variance(a_price) AS var_sold_price, math::max(a_price) AS max_price, math::min(a_price) AS min_price FROM order_line GROUP BY tenant, product;



-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_opp_org AS SELECT tenant, a_organization AS org, count() AS total_opps, math::mean(a_probability) AS avg_probability FROM opportunity GROUP BY tenant, org;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_oppl_org AS SELECT tenant, a_opportunity.a_organization AS org, math::sum(d2_net_base) AS total_pipeline_val FROM opportunity_line GROUP BY tenant, org;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_order_org AS SELECT tenant, a_organization AS org, count() AS total_orders FROM order GROUP BY tenant, org;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_orderl_org AS SELECT tenant, a_order.a_organization AS org, math::sum(d2_net_base) AS lifetime_val, math::sum(a_qty) AS lifetime_items FROM order_line GROUP BY tenant, org;



-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_opp_person AS SELECT tenant, a_person AS person, count() AS total_opps FROM opportunity GROUP BY tenant, person;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_oppl_person AS SELECT tenant, a_opportunity.a_person AS person, math::sum(d2_net_base) AS total_pipeline_val FROM opportunity_line GROUP BY tenant, person;



-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_bi_orderl_daily AS SELECT tenant, time::group(a_order.a_order_date, 'day') AS day, math::sum(d2_net_base) AS daily_revenue, math::sum(a_qty) AS items_sold FROM order_line GROUP BY tenant, day;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_bi_orderl_org_monthly AS SELECT tenant, time::group(a_order.a_order_date, 'month') AS month, a_order.a_organization AS org, math::sum(d2_net_base) AS monthly_revenue FROM order_line GROUP BY tenant, month, org;

-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_bi_opp_created_monthly AS SELECT tenant, time::group(created_at, 'month') AS month, count() AS new_opportunities FROM opportunity GROUP BY tenant, month;
