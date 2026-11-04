package hostadapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type DatabaseInspection struct {
	Engine             string   `json:"engine"`
	Database           string   `json:"database"`
	User               string   `json:"user"`
	SizeBytes          int64    `json:"size_bytes"`
	ActiveConnections  int      `json:"active_connections"`
	Grants             []string `json:"grants"`
	SlowQuerySupported bool     `json:"slow_query_supported"`
	SlowQueryEnabled   bool     `json:"slow_query_enabled"`
	Status             string   `json:"status"`
}

type DatabaseExportResult struct {
	Database  string `json:"database"`
	Engine    string `json:"engine"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

func parseFirstInt64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(strings.Split(strings.TrimSpace(s), "\n")[0]), 10, 64)
	return n
}

func (a *Adapter) InspectDatabase(ctx context.Context, engine, database, user string) (DatabaseInspection, error) {
	if !dbIdentRE.MatchString(database) || !dbIdentRE.MatchString(user) {
		return DatabaseInspection{}, errors.New("invalid database identifier")
	}
	if err := a.requireCertified(engine); err != nil {
		return DatabaseInspection{}, err
	}
	out := DatabaseInspection{Engine: engine, Database: database, User: user, Status: "live"}
	switch engine {
	case "mysql", "mariadb":
		client := engine
		if engine == "mysql" {
			client = "mysql"
		}
		q := fmt.Sprintf("SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema=%s; SELECT COUNT(*) FROM information_schema.processlist WHERE db=%s; SHOW GRANTS FOR %s@'localhost'; SELECT @@GLOBAL.slow_query_log;\n", sqlLiteral(database), sqlLiteral(database), sqlLiteral(user))
		raw, err := a.runInput(ctx, q, client, "--protocol=socket", "--batch", "--skip-column-names")
		if err != nil {
			return out, err
		}
		lines := strings.Split(strings.TrimSpace(raw), "\n")
		if len(lines) > 0 {
			out.SizeBytes = parseFirstInt64(lines[0])
		}
		if len(lines) > 1 {
			n, _ := strconv.Atoi(strings.TrimSpace(lines[1]))
			out.ActiveConnections = n
		}
		if len(lines) > 2 {
			for _, line := range lines[2 : len(lines)-1] {
				if strings.TrimSpace(line) != "" {
					out.Grants = append(out.Grants, strings.TrimSpace(line))
				}
			}
		}
		out.SlowQuerySupported = true
		if len(lines) > 0 {
			last := strings.ToUpper(strings.TrimSpace(lines[len(lines)-1]))
			out.SlowQueryEnabled = last == "1" || last == "ON"
		}
	case "postgresql":
		q := fmt.Sprintf("SELECT pg_database_size(%s); SELECT count(*) FROM pg_stat_activity WHERE datname=%s; SELECT has_database_privilege(%s,%s,'CONNECT'),has_database_privilege(%s,%s,'CREATE'),has_database_privilege(%s,%s,'TEMP');\n", sqlLiteral(database), sqlLiteral(database), sqlLiteral(user), sqlLiteral(database), sqlLiteral(user), sqlLiteral(database), sqlLiteral(user), sqlLiteral(database))
		raw, err := a.runInput(ctx, q, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1")
		if err != nil {
			return out, err
		}
		lines := []string{}
		for _, line := range strings.Split(raw, "\n") {
			if strings.TrimSpace(line) != "" {
				lines = append(lines, strings.TrimSpace(line))
			}
		}
		if len(lines) > 0 {
			out.SizeBytes = parseFirstInt64(lines[0])
		}
		if len(lines) > 1 {
			out.ActiveConnections = int(parseFirstInt64(lines[1]))
		}
		if len(lines) > 2 {
			out.Grants = []string{"database privileges: " + lines[2]}
		}
		out.SlowQuerySupported = true
	default:
		return out, errors.New("unsupported database engine")
	}
	return out, nil
}

func (a *Adapter) MaintainDatabase(ctx context.Context, engine, database, action string) (string, error) {
	if !a.cfg.AllowMutations {
		return "", errors.New("host mutations disabled")
	}
	if !dbIdentRE.MatchString(database) {
		return "", errors.New("invalid database identifier")
	}
	if err := a.requireCertified(engine); err != nil {
		return "", err
	}
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "check" && action != "repair" && action != "optimize" {
		return "", errors.New("unsupported maintenance action")
	}
	switch engine {
	case "mysql", "mariadb":
		tool := "mysqlcheck"
		if engine == "mariadb" {
			if _, ok := commandExists("mariadb-check"); ok {
				tool = "mariadb-check"
			}
		}
		args := []string{"--protocol=socket"}
		switch action {
		case "check":
			args = append(args, "--check")
		case "repair":
			args = append(args, "--repair")
		case "optimize":
			args = append(args, "--optimize")
		}
		args = append(args, database)
		return a.run(ctx, tool, args...)
	case "postgresql":
		var q string
		switch action {
		case "check":
			q = "SELECT 1;"
		case "repair":
			q = fmt.Sprintf("REINDEX DATABASE \"%s\";", database)
		case "optimize":
			q = fmt.Sprintf("VACUUM (ANALYZE) \"%s\";", database)
		}
		return a.runInput(ctx, q, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--dbname", database, "--set=ON_ERROR_STOP=1")
	}
	return "", errors.New("unsupported database engine")
}

func (a *Adapter) ExportDatabase(ctx context.Context, engine, database, owner string) (DatabaseExportResult, error) {
	if !dbIdentRE.MatchString(database) || !validUser(owner) {
		return DatabaseExportResult{}, errors.New("invalid database export identity")
	}
	if err := a.requireCertified(engine); err != nil {
		return DatabaseExportResult{}, err
	}
	dir := filepath.Join("/var/lib/privora-panel/database-exports", owner)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return DatabaseExportResult{}, err
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.sql", database, time.Now().UTC().Format("20060102T150405Z")))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return DatabaseExportResult{}, err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	switch engine {
	case "mysql", "mariadb":
		tool := "mysqldump"
		if engine == "mariadb" {
			if _, yes := commandExists("mariadb-dump"); yes {
				tool = "mariadb-dump"
			}
		}
		cmd = exec.CommandContext(cctx, tool, "--protocol=socket", "--single-transaction", "--routines", "--triggers", database)
	case "postgresql":
		var stderr bytes.Buffer
		err := a.runAsSystemUserIO(cctx, 15*time.Minute, "postgres", "pg_dump", []string{"--no-owner", "--no-privileges", "--format=p", database}, nil, f, &stderr, "")
		if err != nil {
			return DatabaseExportResult{}, fmt.Errorf("database export failed: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		if err := f.Sync(); err != nil {
			return DatabaseExportResult{}, err
		}
		st, err := f.Stat()
		if err != nil {
			return DatabaseExportResult{}, err
		}
		ok = true
		return DatabaseExportResult{Database: database, Engine: engine, Path: path, SizeBytes: st.Size(), CreatedAt: time.Now().UTC().Format(time.RFC3339)}, nil
	default:
		return DatabaseExportResult{}, errors.New("unsupported database engine")
	}
	var stderr bytes.Buffer
	cmd.Stdout = f
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return DatabaseExportResult{}, fmt.Errorf("database export failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := f.Sync(); err != nil {
		return DatabaseExportResult{}, err
	}
	st, err := f.Stat()
	if err != nil {
		return DatabaseExportResult{}, err
	}
	ok = true
	return DatabaseExportResult{Database: database, Engine: engine, Path: path, SizeBytes: st.Size(), CreatedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

func safeAccountImportPath(owner, raw string) (string, error) {
	if !validUser(owner) {
		return "", errors.New("invalid database owner")
	}
	home := filepath.Join("/home", owner)
	candidate := raw
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(home, candidate)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(home, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("import source must remain inside the hosting account home directory")
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("import source must be a regular file")
	}
	if st.Size() > 2<<30 {
		return "", errors.New("import source exceeds the 2 GiB safety limit")
	}
	return resolved, nil
}

func (a *Adapter) ImportDatabase(ctx context.Context, engine, database, owner, source string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if !dbIdentRE.MatchString(database) {
		return errors.New("invalid database identifier")
	}
	if err := a.requireCertified(engine); err != nil {
		return err
	}
	path, err := safeAccountImportPath(owner, source)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	switch engine {
	case "mysql", "mariadb":
		client := engine
		if engine == "mysql" {
			client = "mysql"
		}
		cmd = exec.CommandContext(cctx, client, "--protocol=socket", "--database", database)
	case "postgresql":
		var stderr bytes.Buffer
		err := a.runAsSystemUserIO(cctx, 15*time.Minute, "postgres", "psql", []string{"--no-psqlrc", "--dbname", database, "--set=ON_ERROR_STOP=1"}, f, io.Discard, &stderr, "")
		if err != nil {
			return fmt.Errorf("database import failed: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return nil
	default:
		return errors.New("unsupported database engine")
	}
	cmd.Stdin = f
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("database import failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
