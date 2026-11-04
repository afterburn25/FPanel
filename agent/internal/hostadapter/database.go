package hostadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type DatabaseProvisionResult struct {
	Engine   string `json:"engine"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password"` // returned once; caller must not persist plaintext
	Status   string `json:"status"`
}

func randomPassword(n int) (string, error) {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, n)
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = chars[int(raw[i])%len(chars)]
	}
	return string(b), nil
}
func sqlLiteral(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }

func resolveDatabasePassword(requested string) (string, bool, error) {
	if requested == "" {
		p, err := randomPassword(32)
		return p, true, err
	}
	if len(requested) < 12 || len(requested) > 128 || strings.ContainsAny(requested, "\r\n\x00") {
		return "", false, errors.New("database password must be 12-128 characters and contain no line breaks")
	}
	return requested, false, nil
}

func (a *Adapter) runInput(ctx context.Context, input, name string, args ...string) (string, error) {
	if name == "runuser" && !a.cfg.CertificationMode {
		userName, command, commandArgs, err := parseRunuserInvocation(args)
		if err != nil {
			return "", err
		}
		return runIsolatedUserCommand(ctx, "privora-user-input", a.cfg.CommandTimeout, userName, command, commandArgs, input, "")
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.CommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return out.String(), nil
}

func (a *Adapter) ProvisionMariaDB(ctx context.Context, database, user, requestedPassword string) (DatabaseProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return DatabaseProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("mariadb"); err != nil {
		return DatabaseProvisionResult{}, err
	}
	if !dbIdentRE.MatchString(database) || !dbIdentRE.MatchString(user) {
		return DatabaseProvisionResult{}, errors.New("invalid database identifier")
	}
	password, _, err := resolveDatabasePassword(requestedPassword)
	if err != nil {
		return DatabaseProvisionResult{}, err
	}
	if _, ok := commandExists("mariadb"); !ok {
		return DatabaseProvisionResult{}, errors.New("mariadb client not installed")
	}
	check := fmt.Sprintf("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=%s; SELECT User FROM mysql.user WHERE User=%s AND Host='localhost';\n", sqlLiteral(database), sqlLiteral(user))
	out, err := a.runInput(ctx, check, "mariadb", "--protocol=socket", "--batch", "--skip-column-names")
	if err != nil {
		return DatabaseProvisionResult{}, err
	}
	if strings.TrimSpace(out) != "" {
		return DatabaseProvisionResult{}, errors.New("database or database user already exists")
	}
	sql := fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\nCREATE USER %s@'localhost' IDENTIFIED BY %s;\nGRANT ALL PRIVILEGES ON `%s`.* TO %s@'localhost';\nFLUSH PRIVILEGES;\n", database, sqlLiteral(user), sqlLiteral(password), database, sqlLiteral(user))
	if _, err = a.runInput(ctx, sql, "mariadb", "--protocol=socket", "--batch"); err != nil {
		rollback := fmt.Sprintf("DROP USER IF EXISTS %s@'localhost'; DROP DATABASE IF EXISTS `%s`;\n", sqlLiteral(user), database)
		_, _ = a.runInput(context.Background(), rollback, "mariadb", "--protocol=socket", "--batch")
		return DatabaseProvisionResult{}, err
	}
	return DatabaseProvisionResult{Engine: "mariadb", Database: database, User: user, Password: password, Status: "provisioned-real"}, nil
}

func (a *Adapter) ProvisionMySQL(ctx context.Context, database, user, requestedPassword string) (DatabaseProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return DatabaseProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("mysql"); err != nil {
		return DatabaseProvisionResult{}, err
	}
	if !dbIdentRE.MatchString(database) || !dbIdentRE.MatchString(user) {
		return DatabaseProvisionResult{}, errors.New("invalid database identifier")
	}
	password, _, err := resolveDatabasePassword(requestedPassword)
	if err != nil {
		return DatabaseProvisionResult{}, err
	}
	if _, ok := commandExists("mysql"); !ok {
		return DatabaseProvisionResult{}, errors.New("mysql client not installed")
	}
	check := fmt.Sprintf("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=%s; SELECT User FROM mysql.user WHERE User=%s AND Host='localhost';\n", sqlLiteral(database), sqlLiteral(user))
	out, err := a.runInput(ctx, check, "mysql", "--protocol=socket", "--batch", "--skip-column-names")
	if err != nil {
		return DatabaseProvisionResult{}, err
	}
	if strings.TrimSpace(out) != "" {
		return DatabaseProvisionResult{}, errors.New("database or database user already exists")
	}
	sql := fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;\nCREATE USER %s@'localhost' IDENTIFIED BY %s;\nGRANT ALL PRIVILEGES ON `%s`.* TO %s@'localhost';\nFLUSH PRIVILEGES;\n", database, sqlLiteral(user), sqlLiteral(password), database, sqlLiteral(user))
	if _, err = a.runInput(ctx, sql, "mysql", "--protocol=socket", "--batch"); err != nil {
		rollback := fmt.Sprintf("DROP USER IF EXISTS %s@'localhost'; DROP DATABASE IF EXISTS `%s`;\n", sqlLiteral(user), database)
		_, _ = a.runInput(context.Background(), rollback, "mysql", "--protocol=socket", "--batch")
		return DatabaseProvisionResult{}, err
	}
	return DatabaseProvisionResult{Engine: "mysql", Database: database, User: user, Password: password, Status: "provisioned-real"}, nil
}

func (a *Adapter) ProvisionPostgreSQL(ctx context.Context, database, user, requestedPassword string) (DatabaseProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return DatabaseProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("postgresql"); err != nil {
		return DatabaseProvisionResult{}, err
	}
	if !dbIdentRE.MatchString(database) || !dbIdentRE.MatchString(user) {
		return DatabaseProvisionResult{}, errors.New("invalid database identifier")
	}
	password, _, err := resolveDatabasePassword(requestedPassword)
	if err != nil {
		return DatabaseProvisionResult{}, err
	}
	if _, ok := commandExists("psql"); !ok {
		return DatabaseProvisionResult{}, errors.New("psql not installed")
	}
	if _, ok := commandExists("runuser"); !ok {
		return DatabaseProvisionResult{}, errors.New("runuser not installed")
	}
	check := fmt.Sprintf("SELECT datname FROM pg_database WHERE datname=%s; SELECT rolname FROM pg_roles WHERE rolname=%s;\n", sqlLiteral(database), sqlLiteral(user))
	out, err := a.runInput(ctx, check, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1")
	if err != nil {
		return DatabaseProvisionResult{}, err
	}
	if strings.TrimSpace(out) != "" {
		return DatabaseProvisionResult{}, errors.New("database or database user already exists")
	}
	roleSQL := fmt.Sprintf("CREATE ROLE \"%s\" LOGIN PASSWORD %s;\n", user, sqlLiteral(password))
	if _, err = a.runInput(ctx, roleSQL, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1"); err != nil {
		return DatabaseProvisionResult{}, err
	}
	dbSQL := fmt.Sprintf("CREATE DATABASE \"%s\" OWNER \"%s\";\n", database, user)
	if _, err = a.runInput(ctx, dbSQL, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1"); err != nil {
		_, _ = a.runInput(context.Background(), fmt.Sprintf("DROP ROLE IF EXISTS \"%s\";\n", user), "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1")
		return DatabaseProvisionResult{}, err
	}
	return DatabaseProvisionResult{Engine: "postgresql", Database: database, User: user, Password: password, Status: "provisioned-real"}, nil
}

func (a *Adapter) RotateDatabasePassword(ctx context.Context, engine, database, user, requestedPassword string) (string, error) {
	if !a.cfg.AllowMutations {
		return "", errors.New("host mutations disabled")
	}
	if !dbIdentRE.MatchString(database) || !dbIdentRE.MatchString(user) {
		return "", errors.New("invalid database identifier")
	}
	if err := a.requireCertified(engine); err != nil {
		return "", err
	}
	password, _, err := resolveDatabasePassword(requestedPassword)
	if err != nil {
		return "", err
	}
	switch engine {
	case "mysql", "mariadb":
		client := engine
		if engine == "mysql" {
			client = "mysql"
		}
		sql := fmt.Sprintf("ALTER USER %s@'localhost' IDENTIFIED BY %s; FLUSH PRIVILEGES;\n", sqlLiteral(user), sqlLiteral(password))
		if _, err = a.runInput(ctx, sql, client, "--protocol=socket", "--batch"); err != nil {
			return "", err
		}
	case "postgresql":
		sql := fmt.Sprintf("ALTER ROLE \"%s\" PASSWORD %s;\n", user, sqlLiteral(password))
		if _, err = a.runInput(ctx, sql, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1"); err != nil {
			return "", err
		}
	default:
		return "", errors.New("unsupported database engine")
	}
	return password, nil
}

func (a *Adapter) RenameDatabaseUser(ctx context.Context, engine, database, oldUser, newUser, requestedPassword string) (string, error) {
	if !a.cfg.AllowMutations {
		return "", errors.New("host mutations disabled")
	}
	if !dbIdentRE.MatchString(database) || !dbIdentRE.MatchString(oldUser) || !dbIdentRE.MatchString(newUser) {
		return "", errors.New("invalid database identifier")
	}
	if err := a.requireCertified(engine); err != nil {
		return "", err
	}
	if oldUser == newUser {
		if requestedPassword == "" {
			return "", errors.New("database user is unchanged")
		}
		return a.RotateDatabasePassword(ctx, engine, database, oldUser, requestedPassword)
	}
	password, _, err := resolveDatabasePassword(requestedPassword)
	if err != nil {
		return "", err
	}
	switch engine {
	case "mysql", "mariadb":
		client := engine
		if engine == "mysql" {
			client = "mysql"
		}
		check := fmt.Sprintf("SELECT User FROM mysql.user WHERE User=%s AND Host='localhost';\n", sqlLiteral(newUser))
		out, err := a.runInput(ctx, check, client, "--protocol=socket", "--batch", "--skip-column-names")
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(out) != "" {
			return "", errors.New("database user already exists")
		}
		sql := fmt.Sprintf("RENAME USER %s@'localhost' TO %s@'localhost'; ALTER USER %s@'localhost' IDENTIFIED BY %s; FLUSH PRIVILEGES;\n", sqlLiteral(oldUser), sqlLiteral(newUser), sqlLiteral(newUser), sqlLiteral(password))
		if _, err = a.runInput(ctx, sql, client, "--protocol=socket", "--batch"); err != nil {
			rollback := fmt.Sprintf("RENAME USER %s@'localhost' TO %s@'localhost'; FLUSH PRIVILEGES;\n", sqlLiteral(newUser), sqlLiteral(oldUser))
			_, _ = a.runInput(context.Background(), rollback, client, "--protocol=socket", "--batch")
			return "", err
		}
	case "postgresql":
		check := fmt.Sprintf("SELECT rolname FROM pg_roles WHERE rolname=%s;\n", sqlLiteral(newUser))
		out, err := a.runInput(ctx, check, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1")
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(out) != "" {
			return "", errors.New("database user already exists")
		}
		sql := fmt.Sprintf("BEGIN; ALTER ROLE \"%s\" RENAME TO \"%s\"; ALTER ROLE \"%s\" PASSWORD %s; COMMIT;\n", oldUser, newUser, newUser, sqlLiteral(password))
		if _, err = a.runInput(ctx, sql, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1"); err != nil {
			return "", err
		}
	default:
		return "", errors.New("unsupported database engine")
	}
	return password, nil
}

func (a *Adapter) DeleteDatabase(ctx context.Context, engine, database, user string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if !dbIdentRE.MatchString(database) || !dbIdentRE.MatchString(user) {
		return errors.New("invalid database identifier")
	}
	if err := a.requireCertified(engine); err != nil {
		return err
	}
	switch engine {
	case "mysql", "mariadb":
		client := engine
		if engine == "mysql" {
			client = "mysql"
		}
		sql := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`; DROP USER IF EXISTS %s@'localhost'; FLUSH PRIVILEGES;\n", database, sqlLiteral(user))
		_, err := a.runInput(ctx, sql, client, "--protocol=socket", "--batch")
		return err
	case "postgresql":
		sql := fmt.Sprintf("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND pid <> pg_backend_pid(); DROP DATABASE IF EXISTS \"%s\"; DROP ROLE IF EXISTS \"%s\";\n", sqlLiteral(database), database, user)
		_, err := a.runInput(ctx, sql, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1")
		return err
	default:
		return errors.New("unsupported database engine")
	}
}
