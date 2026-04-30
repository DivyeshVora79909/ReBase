REMOVE TABLE IF EXISTS campaign;
DEFINE TABLE campaign SCHEMAFULL;

DEFINE FIELD name ON campaign TYPE string;
    DEFINE FIELD finances ON campaign TYPE object DEFAULT {};
    DEFINE FIELD finances.* ON campaign TYPE decimal;
    
    DEFINE FIELD regions ON campaign TYPE array<object> DEFAULT[];
    DEFINE FIELD regions.*.region_name ON campaign TYPE string;
    DEFINE FIELD regions.*.status ON campaign TYPE string;
    
    DEFINE FIELD regions.*.managers ON campaign TYPE array<object> DEFAULT[];
    DEFINE FIELD regions.*.managers.*.name ON campaign TYPE string;
    
    DEFINE FIELD regions.*.managers.*.teams ON campaign TYPE array<object> DEFAULT[];
    DEFINE FIELD regions.*.managers.*.teams.*.role ON campaign TYPE string;
    
    DEFINE FIELD regions.*.managers.*.teams.*.stats ON campaign TYPE object;
    DEFINE FIELD regions.*.managers.*.teams.*.stats.leads ON campaign TYPE int;
    DEFINE FIELD regions.*.managers.*.teams.*.stats.costs ON campaign TYPE decimal;

DEFINE FIELD top_performing_roles ON campaign TYPE array<object> DEFAULT[] VALUE {
    LET $managers = array::flatten(regions.managers);
    LET $teams = array::flatten($managers.teams);

    RETURN (
        SELECT 
            role, 
            math::sum(stats.costs) AS total_costs,
            math::sum(stats.leads) AS total_leads
        FROM $teams
        WHERE stats.leads > 0
        GROUP BY role
        ORDER BY total_costs DESC
        LIMIT 5
    );
};

DEFINE FIELD top_performing_roles.*.role ON campaign TYPE string;
DEFINE FIELD top_performing_roles.*.total_costs ON campaign TYPE decimal;
DEFINE FIELD top_performing_roles.*.total_leads ON campaign TYPE decimal;

DEFINE FIELD global_total_costs ON campaign TYPE decimal VALUE {
    LET $managers = array::flatten(regions.managers);
    LET $teams = array::flatten($managers.teams);

    RETURN (
        SELECT VALUE math::sum(stats.costs)
        FROM $teams
        GROUP ALL
    )[0] ?? 0dec;
};

DEFINE FIELD total_budget ON campaign TYPE decimal
    VALUE math::sum(object::values(finances)) ?? 0dec;

DEFINE FIELD active_region_leads ON campaign TYPE decimal VALUE {
    LET $active_regions = regions[WHERE status = "active"];
    LET $managers = array::flatten($active_regions.managers);
    LET $teams = array::flatten($managers.teams);

    RETURN (
        SELECT VALUE math::sum(stats.leads)
        FROM $teams
        GROUP ALL
    )[0] ?? 0dec;
};

-- RESULT
CREATE campaign:launch SET 
    name = "Global Launch",
    finances = { q1_budget: 5000.00dec, q2_budget: 7000.00dec },
    regions =[
        {
            region_name: "North America",
            status: "active",
            managers:[
                {
                    name: "Alice",
                    teams:[
                        { role: "Marketing", stats: { leads: 120, costs: 400.00dec } },
                        { role: "Dev", stats: { leads: 0, costs: 1500.00dec } },
                        { role: "Sales", stats: { leads: 500, costs: 800.00dec } }
                    ]
                }
            ]
        },
        {
            region_name: "Europe",
            status: "inactive",
            managers:[
                {
                    name: "Bob",
                    teams:[
                        { role: "Marketing", stats: { leads: 80, costs: 300.00dec } }
                    ]
                }
            ]
        }
    ];


"
[
	{
		active_region_leads: 620dec,
		finances: {
			q1_budget: 5000dec,
			q2_budget: 7000dec
		},
		global_total_costs: 3000dec,
		id: campaign:launch,
		name: 'Global Launch',
		regions: [
			{
				managers: [
					{
						name: 'Alice',
						teams: [
							{
								role: 'Marketing',
								stats: {
									costs: 400dec,
									leads: 120
								}
							},
							{
								role: 'Dev',
								stats: {
									costs: 1500dec,
									leads: 0
								}
							},
							{
								role: 'Sales',
								stats: {
									costs: 800dec,
									leads: 500
								}
							}
						]
					}
				],
				region_name: 'North America',
				status: 'active'
			},
			{
				managers: [
					{
						name: 'Bob',
						teams: [
							{
								role: 'Marketing',
								stats: {
									costs: 300dec,
									leads: 80
								}
							}
						]
					}
				],
				region_name: 'Europe',
				status: 'inactive'
			}
		],
		top_performing_roles: [
			{
				role: 'Sales',
				total_costs: 800dec,
				total_leads: 500dec
			},
			{
				role: 'Marketing',
				total_costs: 700dec,
				total_leads: 200dec
			}
		],
		total_budget: 12000dec
	}
]
"