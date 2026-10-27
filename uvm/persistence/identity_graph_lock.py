"""Outer transaction guard for supported identity graph participants."""
import sqlalchemy as sa

_KEY = (0x55564D, 0x494447)


def lock_identity_graph(connection):
    """Acquire before graph reads/policy/row locks; nested writers reuse it."""
    transaction = connection.get_transaction()
    if transaction is not None and connection.info.get("uvm_identity_graph_guard") is transaction:
        return
    if connection.dialect.name == "postgresql":
        connection.execute(sa.text("SELECT pg_advisory_xact_lock(:a, :b)"),
                           {"a": _KEY[0], "b": _KEY[1]})
    elif connection.dialect.name == "sqlite":
        # SQLAlchemy's begin may precede pysqlite's actual BEGIN. Reserve
        # the writer before graph reads without depending on a later schema.
        driver = connection.connection.driver_connection
        if not driver.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        elif connection.exec_driver_sql(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='workloads'").first():
            # Upgrade an existing deferred transaction too. In a pre-core
            # schema there are no workload rows; established writers retain
            # their own explicit schema-unavailable checks.
            connection.exec_driver_sql("UPDATE workloads SET revision = revision WHERE 1 = 0")
    else:
        raise ValueError("Identity graph transactions require PostgreSQL or SQLite")
    connection.info["uvm_identity_graph_guard"] = connection.get_transaction()
