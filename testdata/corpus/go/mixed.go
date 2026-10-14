package mix

type Node struct {
	Next *Node
	Val  int
}

func NewNode(v int) *Node {
	return &Node{Val: v}
}

func (n *Node) Append(v int) {
	cur := n
	for cur.Next != nil {
		cur = cur.Next
	}
	cur.Next = &Node{Val: v}
}

const MaxNodes = 100

var head *Node
