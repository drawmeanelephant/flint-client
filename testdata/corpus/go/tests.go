package checks

import "testing"

func TestAdd(t *testing.T) {
	if 1+1 != 2 {
		t.Fatal("math broke")
	}
}

func TestSub(t *testing.T) {
	if 2-1 != 1 {
		t.Fatal("sub broke")
	}
}

func TestMul(t *testing.T) {
	if 2*2 != 4 {
		t.Fatal("mul broke")
	}
}
