//go:build scenario

package scenario

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/ancyloce/contelys-cloud-identity/test/fixture"
)

// The image has no shell, so Docker and Compose check an instance's readiness with Identity's own
// subcommand health, which fails while the instance is not ready and passes once it is (Identity ADR
// 0009). The image's health check runs it.
func TestDockerChecksReadinessWithTheHealthSubcommand(t *testing.T) {
	in := newInputs(t, sharedPostgres.create(t))
	in.remove(t, internalSigningKey)
	instance := startIdentity(t, in)

	if code := instance.health(t); code == 0 {
		t.Errorf("identity health exited 0 while the instance is not ready")
	}

	in.write(t, internalSigningKey, fixture.SigningKey(t))
	eventually(t, 30*time.Second, func() (bool, string) {
		code := instance.health(t)
		return code == 0, "identity health exited " + strconv.Itoa(code) + " once the instance has its keys"
	})
	eventually(t, 40*time.Second, func() (bool, string) {
		state, err := instance.container.State(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if state.Health == nil {
			return false, "the container has no health check"
		}
		return state.Health.Status == "healthy", "Docker sees the container as " + string(state.Health.Status)
	})
}

// health runs identity health inside the instance's container, as the image's health check does, and
// returns its exit code.
func (i *identity) health(t *testing.T) int {
	t.Helper()
	code, _, err := i.container.Exec(context.Background(), []string{"/identity", "health", "-config", inputsDir + "/" + configFile})
	if err != nil {
		t.Fatal(err)
	}
	return code
}
