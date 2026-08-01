package panel

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestValidateMigrationTableMetadata(t *testing.T) {
	valid := validMigrationTableMetadata()
	if err := validateMigrationTableMetadata(valid); err != nil {
		t.Fatalf("valid migration table was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*mysqlTableMetadata)
	}{
		{
			name: "wrong engine",
			mutate: func(table *mysqlTableMetadata) {
				table.engine = "MyISAM"
			},
		},
		{
			name: "missing version",
			mutate: func(table *mysqlTableMetadata) {
				delete(table.columns, "version")
			},
		},
		{
			name: "unexpected extra column",
			mutate: func(table *mysqlTableMetadata) {
				table.columns["unexpected"] = mysqlColumnMetadata{dataType: "int", columnType: "int", nullable: "NO"}
			},
		},
		{
			name: "wrong name collation",
			mutate: func(table *mysqlTableMetadata) {
				column := table.columns["name"]
				column.collation = "ascii_general_ci"
				table.columns["name"] = column
			},
		},
		{
			name: "wrong primary key",
			mutate: func(table *mysqlTableMetadata) {
				table.indexes["PRIMARY"][0].columnName = "name"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table := validMigrationTableMetadata()
			test.mutate(&table)
			assertMigrationRequired(t, validateMigrationTableMetadata(table))
		})
	}
}

func TestValidateTrafficBatchTableMetadata(t *testing.T) {
	valid := validTrafficBatchTableMetadata()
	if err := validateTrafficBatchTableMetadata(valid); err != nil {
		t.Fatalf("valid traffic batch table was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*mysqlTableMetadata)
	}{
		{
			name: "wrong engine",
			mutate: func(table *mysqlTableMetadata) {
				table.engine = "MyISAM"
			},
		},
		{
			name: "missing batch id",
			mutate: func(table *mysqlTableMetadata) {
				delete(table.columns, "batch_id")
			},
		},
		{
			name: "unexpected extra column",
			mutate: func(table *mysqlTableMetadata) {
				table.columns["unexpected"] = mysqlColumnMetadata{dataType: "int", columnType: "int", nullable: "NO"}
			},
		},
		{
			name: "wrong batch id length",
			mutate: func(table *mysqlTableMetadata) {
				column := table.columns["batch_id"]
				column.columnType = "char(16)"
				table.columns["batch_id"] = column
			},
		},
		{
			name: "nullable node id",
			mutate: func(table *mysqlTableMetadata) {
				column := table.columns["node_id"]
				column.nullable = "YES"
				table.columns["node_id"] = column
			},
		},
		{
			name: "wrong primary key",
			mutate: func(table *mysqlTableMetadata) {
				table.indexes["PRIMARY"][0].columnName = "node_id"
			},
		},
		{
			name: "wrong secondary index order",
			mutate: func(table *mysqlTableMetadata) {
				table.indexes["node_created_at"][0].columnName = "created_at"
				table.indexes["node_created_at"][1].columnName = "node_id"
			},
		},
		{
			name: "prefix secondary index",
			mutate: func(table *mysqlTableMetadata) {
				table.indexes["node_created_at"][0].prefix = sql.NullInt64{Int64: 2, Valid: true}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table := validTrafficBatchTableMetadata()
			test.mutate(&table)
			assertMigrationRequired(t, validateTrafficBatchTableMetadata(table))
		})
	}
}

func validMigrationTableMetadata() mysqlTableMetadata {
	return mysqlTableMetadata{
		engine: "InnoDB",
		columns: map[string]mysqlColumnMetadata{
			"version": {
				dataType:   "bigint",
				columnType: "bigint unsigned",
				nullable:   "NO",
			},
			"name": {
				dataType:   "varchar",
				columnType: "varchar(128)",
				nullable:   "NO",
				charset:    "ascii",
				collation:  "ascii_bin",
			},
			"applied_at": {
				dataType:   "timestamp",
				columnType: "timestamp(6)",
				nullable:   "NO",
			},
		},
		indexes: map[string][]mysqlIndexColumnMetadata{
			"PRIMARY": {
				{
					columnName: "version",
					sequence:   1,
					indexType:  "BTREE",
				},
			},
		},
	}
}

func validTrafficBatchTableMetadata() mysqlTableMetadata {
	return mysqlTableMetadata{
		engine: "InnoDB",
		columns: map[string]mysqlColumnMetadata{
			"batch_id": {
				dataType:   "char",
				columnType: "char(32)",
				nullable:   "NO",
				charset:    "ascii",
				collation:  "ascii_bin",
			},
			"node_id": {
				dataType:   "int",
				columnType: "int",
				nullable:   "NO",
			},
			"created_at": {
				dataType:   "bigint",
				columnType: "bigint",
				nullable:   "NO",
			},
		},
		indexes: map[string][]mysqlIndexColumnMetadata{
			"PRIMARY": {
				{
					columnName: "batch_id",
					sequence:   1,
					indexType:  "BTREE",
				},
			},
			"node_created_at": {
				{
					columnName: "node_id",
					nonUnique:  true,
					sequence:   1,
					indexType:  "BTREE",
				},
				{
					columnName: "created_at",
					nonUnique:  true,
					sequence:   2,
					indexType:  "BTREE",
				},
			},
		},
	}
}

func assertMigrationRequired(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrDatabaseMigrationRequired) {
		t.Fatalf("expected ErrDatabaseMigrationRequired, got %v", err)
	}
	if !strings.Contains(err.Error(), mysqlMigrationPath) {
		t.Fatalf("error does not point to %s: %v", mysqlMigrationPath, err)
	}
}
