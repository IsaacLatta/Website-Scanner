from dataclasses import dataclass
from typing import List, Literal
from scanner.modules.error.signature import Signature

DatabaseCategory = Literal[
    "relational",
    "nosql_document",
    "nosql_keyvalue",
    "nosql_widecolumn",
    "search_engine",
    "time_series",
    "graph",
    "analytics_warehouse",
    "embedded",
    "service",
    "event_store",
]

DATABASE_SIGNATURES: List[Signature] = [
    Signature(
        display_name="PostgreSQL",
        category="relational",
        aliases=["postgresql", "postgres", "postgre", "psql"],
    ),
    Signature(
        display_name="MySQL",
        category="relational",
        aliases=["mysql"],
    ),
    Signature(
        display_name="SQLite",
        category="embedded",
        aliases=["sqlite", "sqlite3"],
    ),
    Signature(
        display_name="Microsoft SQL Server",
        category="relational",
        aliases=["microsoft sql server", "sql server", "mssql", "ms sql"],
    ),
    Signature(
        display_name="MongoDB",
        category="nosql_document",
        aliases=["mongodb", "mongo"],
    ),
    Signature(
        display_name="Redis",
        category="nosql_keyvalue",
        aliases=["redis"],
    ),
    Signature(
        display_name="MariaDB",
        category="relational",
        aliases=["mariadb", "maria db"],
    ),
    Signature(
        display_name="Elasticsearch",
        category="search_engine",
        aliases=["elasticsearch", "elastic search", "es cluster"],
    ),
    Signature(
        display_name="Oracle Database",
        category="relational",
        aliases=["oracle", "oracle database", "oracle db"],
    ),
    Signature(
        display_name="Amazon DynamoDB",
        category="nosql_keyvalue",
        aliases=["dynamodb", "amazon dynamodb", "aws dynamodb"],
    ),
    Signature(
        display_name="Firebase Realtime Database",
        category="nosql_document",
        aliases=["firebase realtime database", "firebase realtime db", "firebase rtdb"],
    ),
    Signature(
        display_name="Cloud Firestore",
        category="nosql_document",
        aliases=["cloud firestore", "firestore"],
    ),
    Signature(
        display_name="BigQuery",
        category="analytics_warehouse",
        aliases=["bigquery", "google bigquery"],
    ),
    Signature(
        display_name="Microsoft Access",
        category="relational",
        aliases=["microsoft access", "ms access", "access database"],
    ),
    Signature(
        display_name="Supabase",
        category="service",  # Postgres-as-a-service / BaaS
        aliases=["supabase"],
    ),
    # Signature( # Too many false positives
    #     display_name="H2",
    #     category="embedded",
    #     aliases=["h2", "h2 database"],
    # ),
    Signature(
        display_name="Azure Cosmos DB",
        category="nosql_document",
        aliases=["cosmos db", "azure cosmos db", "cosmosdb"],
    ),
    Signature(
        display_name="Snowflake",
        category="analytics_warehouse",
        aliases=["snowflake"],
    ),
    Signature(
        display_name="InfluxDB",
        category="time_series",
        aliases=["influxdb", "influx db"],
    ),
    Signature(
        display_name="Apache Cassandra",
        category="nosql_widecolumn",
        aliases=["cassandra", "apache cassandra"],
    ),
    Signature(
        display_name="Databricks SQL",
        category="analytics_warehouse",
        aliases=["databricks sql", "databricks"],
    ),
    Signature(
        display_name="Neo4j",
        category="graph",
        aliases=["neo4j", "neo 4j"],
    ),
    Signature(
        display_name="IBM Db2",
        category="relational",
        aliases=["ibm db2", "db2"],
    ),
    Signature(
        display_name="ClickHouse",
        category="analytics_warehouse",
        aliases=["clickhouse", "click house"],
    ),
    Signature(
        display_name="Apache Solr",
        category="search_engine",
        aliases=["solr", "apache solr"],
    ),
    Signature(
        display_name="DuckDB",
        category="analytics_warehouse",
        aliases=["duckdb", "duck db"],
    ),
    Signature(
        display_name="Firebird",
        category="relational",
        aliases=["firebird", "firebird sql"],
    ),
    Signature(
        display_name="Apache CouchDB",
        category="nosql_document",
        aliases=["couchdb", "couch db", "apache couchdb"],
    ),
    Signature(
        display_name="CockroachDB",
        category="relational",
        aliases=["cockroachdb", "cockroach db"],
    ),
    Signature(
        display_name="Couchbase",
        category="nosql_document",
        aliases=["couchbase", "couchbase server"],
    ),
    Signature(
        display_name="Presto",
        category="analytics_warehouse",
        aliases=["presto", "prestodb", "presto db"],
    ),
    Signature(
        display_name="Datomic",
        category="nosql_document",
        aliases=["datomic"],
    ),
    Signature(
        display_name="EventStoreDB",
        category="event_store",
        aliases=["eventstoredb", "eventstore db", "eventstore"],
    ),
    Signature(
        display_name="RavenDB",
        category="nosql_document",
        aliases=["ravendb", "raven db"],
    ),
    Signature(
        display_name="TiDB",
        category="relational",
        aliases=["tidb", "ti db"],
    ),
]

DATABASE_NAMES = [d.display_name for d in DATABASE_SIGNATURES]
