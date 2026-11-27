// Package postgres is Identity's database (design, section 08): the connection pool, the migrations
// that the binary embeds, and the stores over the queries that sqlc generates under gen/.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/ancyloce/contelys-cloud-identity/internal/infrastructure/postgres/gen"
)

//go:generate go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate -f ../../../sqlc.yaml

//go:embed migrations/*.sql
var migrations embed.FS

// errNotMigrated is the readiness failure of an instance whose migrations are not applied yet.
var errNotMigrated = errors.New("the migrations are not applied yet")

// Database is Identity's database.
type Database struct {
	pool     *pgxpool.Pool
	queries  *gen.Queries
	migrated atomic.Bool
}

// Open prepares the pool for the database at url, without connecting yet. The password is never part
// of url: each new connection reads it from passwordFile (ADR 0020), so that an instance whose
// database or password is missing still starts and reports that it is not ready.
func Open(url, passwordFile string) (*Database, error) {
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("the database url: %w", err)
	}
	if config.ConnConfig.Password != "" {
		return nil, errors.New("the database url holds a password: it comes from password_file")
	}
	config.BeforeConnect = func(_ context.Context, connection *pgx.ConnConfig) error {
		password, err := os.ReadFile(passwordFile)
		if err != nil {
			return fmt.Errorf("the database password: %w", err)
		}
		connection.Password = strings.TrimRight(string(password), "\r\n")
		return nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}
	return &Database{pool: pool, queries: gen.New(pool)}, nil
}

// Migrate applies the migrations that the database lacks. Instances that start together take goose's
// advisory lock on the database and migrate one at a time. Each version of Identity only adds to its
// schema, and what a version stops using is removed by a later one, so the instances of the previous
// version keep working while the next one migrates (ADR 0032).
func (d *Database) Migrate(ctx context.Context) error {
	files, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return err
	}
	db := stdlib.OpenDBFromPool(d.pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files, goose.WithSessionLocker(locker))
	if err != nil {
		return err
	}
	if _, err := provider.Up(ctx); err != nil {
		return err
	}
	d.migrated.Store(true)
	return nil
}

// Check is the readiness signal of the database: the migrations are applied and principals can be
// read, as admission reads them.
func (d *Database) Check(ctx context.Context) error {
	if !d.migrated.Load() {
		return errNotMigrated
	}
	return d.queries.ReadPrincipals(ctx)
}

// Close closes the pool.
func (d *Database) Close() {
	d.pool.Close()
}
