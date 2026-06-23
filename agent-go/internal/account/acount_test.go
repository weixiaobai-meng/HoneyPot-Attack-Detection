package account

import (
	"reflect"
	"testing"
)

func TestNewAccountDeployer(t *testing.T) {
	tests := []struct {
		name string
		want *AccountDeployer
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAccountDeployer(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAccountDeployer() = %v, want %v", got, tt.want)
			}
		})
	}
}
