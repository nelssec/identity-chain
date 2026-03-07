package graph

import (
	"fmt"
	"sync"
)

type Graph struct {
	mu               sync.RWMutex
	nodes            map[string]*Node
	outEdges         map[string][]*Edge
	inEdges          map[string][]*Edge
	edges            map[string]*Edge
	nodesByType      map[NodeType][]*Node
	nodesByNamespace map[string][]*Node
	saToWorkloads    map[string][]string
	// Metadata is an open-ended key/value store for graph-level annotations
	// such as the DistroProfile detected during collection.
	Metadata map[string]interface{}
}

func New() *Graph {
	return &Graph{
		nodes:            make(map[string]*Node),
		outEdges:         make(map[string][]*Edge),
		inEdges:          make(map[string][]*Edge),
		edges:            make(map[string]*Edge),
		nodesByType:      make(map[NodeType][]*Node),
		nodesByNamespace: make(map[string][]*Node),
		saToWorkloads:    make(map[string][]string),
		Metadata:         make(map[string]interface{}),
	}
}

func (g *Graph) AddNode(n *Node) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[n.ID]; exists {
		return fmt.Errorf("node %s already exists", n.ID)
	}

	g.nodes[n.ID] = n
	g.nodesByType[n.Type] = append(g.nodesByType[n.Type], n)

	if n.Namespace != "" {
		g.nodesByNamespace[n.Namespace] = append(g.nodesByNamespace[n.Namespace], n)
	}

	return nil
}

func (g *Graph) AddEdge(e *Edge) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[e.From]; !exists {
		return fmt.Errorf("source node %s does not exist", e.From)
	}
	if _, exists := g.nodes[e.To]; !exists {
		return fmt.Errorf("target node %s does not exist", e.To)
	}

	if _, exists := g.edges[e.ID]; exists {
		return nil
	}

	g.edges[e.ID] = e
	g.outEdges[e.From] = append(g.outEdges[e.From], e)
	g.inEdges[e.To] = append(g.inEdges[e.To], e)

	if e.Type == EdgeUses {
		g.saToWorkloads[e.To] = append(g.saToWorkloads[e.To], e.From)
	}

	return nil
}

func (g *Graph) GetNode(id string) *Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[id]
}

func (g *Graph) GetNodesByType(nodeType NodeType) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodesByType[nodeType]
}

func (g *Graph) GetNodesByNamespace(namespace string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodesByNamespace[namespace]
}

func (g *Graph) GetOutEdges(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.outEdges[nodeID]
}

func (g *Graph) GetInEdges(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.inEdges[nodeID]
}

func (g *Graph) GetWorkloadsUsingSA(saNodeID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var workloads []*Node
	for _, wID := range g.saToWorkloads[saNodeID] {
		if w := g.nodes[wID]; w != nil {
			workloads = append(workloads, w)
		}
	}
	return workloads
}

func (g *Graph) FindNode(nodeType NodeType, namespace, name string) *Node {
	id := GenerateNodeID(nodeType, namespace, name)
	return g.GetNode(id)
}

func (g *Graph) Stats() GraphStats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := GraphStats{
		TotalNodes: len(g.nodes),
		TotalEdges: len(g.edges),
		NodeCounts: make(map[NodeType]int),
		EdgeCounts: make(map[EdgeType]int),
	}

	for nodeType, nodes := range g.nodesByType {
		stats.NodeCounts[nodeType] = len(nodes)
	}

	for _, edge := range g.edges {
		stats.EdgeCounts[edge.Type]++
	}

	return stats
}

type GraphStats struct {
	TotalNodes int              `json:"total_nodes"`
	TotalEdges int              `json:"total_edges"`
	NodeCounts map[NodeType]int `json:"node_counts"`
	EdgeCounts map[EdgeType]int `json:"edge_counts"`
}

func (g *Graph) AllNodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

func (g *Graph) AllEdges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edges := make([]*Edge, 0, len(g.edges))
	for _, e := range g.edges {
		edges = append(edges, e)
	}
	return edges
}
