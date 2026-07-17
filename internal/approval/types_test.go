package approval

import (
	"testing"
	"time"
)

func TestRequestTransition(t *testing.T) {
	t.Parallel()

	now := time.Date(2030, time.January, 2, 15, 4, 5, 0, time.UTC)
	tests := []struct {
		name      string
		from      ApprovalState
		to        ApprovalState
		wantError bool
	}{
		{name: "pending to approved", from: ApprovalPending, to: ApprovalApproved},
		{name: "pending to denied", from: ApprovalPending, to: ApprovalDenied},
		{name: "pending to expired", from: ApprovalPending, to: ApprovalExpired},
		{name: "idempotent approved", from: ApprovalApproved, to: ApprovalApproved},
		{name: "approved cannot become denied", from: ApprovalApproved, to: ApprovalDenied, wantError: true},
		{name: "denied cannot become approved", from: ApprovalDenied, to: ApprovalApproved, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := Request{RequestID: "request-1", State: test.from, Version: 1}
			updated, err := request.Transition(test.to, "approver@example.edu", "reviewed", now)
			if (err != nil) != test.wantError {
				t.Fatalf("Transition() error = %v, wantError %v", err, test.wantError)
			}
			if err == nil && updated.State != test.to {
				t.Fatalf("Transition() state = %q, want %q", updated.State, test.to)
			}
		})
	}
}
