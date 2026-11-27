//go:build scenario

package scenario

import (
	"context"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// The operator commands of design section 07 are subcommands of the image. An operator names the
// principal, the reason and themselves, and a command that lacks one of them is refused before it
// does anything.
func TestTheOperatorCommandsRequireAPrincipalAReasonAndAnOperator(t *testing.T) {
	for _, command := range []string{"disable", "enable", "erase"} {
		code, output := runImage(t, command, "-config", inputsDir+"/"+configFile)
		if code != 2 || !contains(output, "-principal", "-reason", "-operator") {
			t.Errorf("identity %s without its flags exited %d with %q, want 2 and the flags it lacks", command, code, output)
		}
	}
}

// runImage runs the image with args until it exits, and returns its exit code and what it wrote.
func runImage(t *testing.T, args ...string) (int, string) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      image,
			Cmd:        args,
			WaitingFor: wait.ForExit(),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("run identity %v: %v", args, err)
	}
	state, err := c.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return state.ExitCode, output(c)
}
