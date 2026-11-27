//go:build scenario

package scenario

import (
	"context"
	"testing"

	"github.com/testcontainers/testcontainers-go"

	"github.com/ancyloce/contelys-cloud-identity/test/fixture"
)

// An instance with its database and its signing keys reports ready, to a caller that presents no
// client certificate, as Edge's health checks do (design section 12).
func TestAnInstanceWithItsDatabaseAndKeysIsReady(t *testing.T) {
	instance := startIdentity(t, newInputs(t, sharedPostgres.create(t)))

	instance.becomesReady(t, "with its database and keys")
}

// Without its database an instance still starts and reports not ready, because it cannot decide
// admission. It applies its migrations once the database answers and becomes ready, and it reports
// not ready again while the database cannot be read (design section 12).
func TestAnInstanceWithoutItsDatabaseIsNotReady(t *testing.T) {
	const alias = "postgres-of-its-own"
	instance := startIdentity(t, newInputs(t, "postgres://identity@"+alias+":5432/identity_late?sslmode=disable"))

	instance.becomesNotReady(t, "before the database exists", "database")

	ctx := context.Background()
	own, err := startPostgres(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	testcontainers.CleanupContainer(t, own.container)
	if err := own.exec(ctx, "CREATE DATABASE identity_late OWNER identity"); err != nil {
		t.Fatal(err)
	}
	instance.becomesReady(t, "once the database answers")

	if err := own.container.Stop(ctx, nil); err != nil {
		t.Fatal(err)
	}
	instance.becomesNotReady(t, "while the database is stopped", "database")

	if err := own.container.Start(ctx); err != nil {
		t.Fatal(err)
	}
	instance.becomesReady(t, "once the database answers again")
}

// Without its two signing keys an instance cannot issue an internal token, so it reports not ready.
// A file that holds no Ed25519 key counts as no key. Once both keys are in place, the instance is
// ready without a restart (design section 12).
func TestAnInstanceWithoutItsSigningKeysIsNotReady(t *testing.T) {
	in := newInputs(t, sharedPostgres.create(t))
	in.remove(t, internalSigningKey)
	in.remove(t, workloadSigningKey)
	instance := startIdentity(t, in)

	instance.becomesNotReady(t, "without the key files", "signing-keys")

	_, notEd25519, _ := ca.Issue(t, "not-a-signing-key")
	in.write(t, internalSigningKey, notEd25519)
	in.write(t, workloadSigningKey, fixture.SigningKey(t))
	instance.becomesNotReady(t, "with an internal signing key that is not Ed25519", "signing-keys")

	in.write(t, internalSigningKey, fixture.SigningKey(t))
	instance.becomesReady(t, "with both keys")
}

// Only sign-in needs the secret of the client identity, so an instance without it still starts and is
// ready, because it can decide admission (design section 12).
func TestAnInstanceWithoutKeycloaksSecretIsReady(t *testing.T) {
	in := newInputs(t, sharedPostgres.create(t))
	in.remove(t, keycloakSecret)
	instance := startIdentity(t, in)

	instance.becomesReady(t, "without the secret of the client identity")
}
