// F3: run on a scratch graph holding one repo's exposure subgraph with effort capacities.
// Max flow = total effort of the cheapest set of dependency links that removes every path.
MATCH (s:Node {key: 'ROOT'})
MATCH (t:Node) WHERE t.key IN $targets
WITH s, collect(t) AS targets
CALL algo.maxFlow({sourceNodes: [s], targetNodes: targets,
                   relationshipTypes: ['REQ'], capacityProperty: 'capacity'})
YIELD maxFlow, edges, edgeFlows
RETURN maxFlow, [e IN edges | [startNode(e).key, endNode(e).key]] AS flow_edges, edgeFlows
