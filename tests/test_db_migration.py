from sqlalchemy import create_engine, inspect, select, text

from nis2check.web.models import Organisation, make_session


def test_startup_adds_missing_columns(tmp_path):
    # simulate an older install: the users table exists but predates several columns
    url = f"sqlite:///{tmp_path / 'old.db'}"
    eng = create_engine(url)
    with eng.begin() as c:
        c.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR(255))"))
    eng.dispose()

    # opening the app's session must bring the schema up to the current model
    session = make_session(url)
    session.remove()

    cols = {c["name"] for c in inspect(create_engine(url)).get_columns("users")}
    assert {"role", "active", "password_hash", "must_change_password",
            "sso_subject", "last_login", "created_at"} <= cols


def test_startup_adds_frameworks_column_and_keeps_nis2(tmp_path):
    # an install from before the DORA column: the organisation row has no frameworks
    url = f"sqlite:///{tmp_path / 'old-org.db'}"
    eng = create_engine(url)
    with eng.begin() as c:
        c.execute(text("CREATE TABLE organisation (id INTEGER PRIMARY KEY, name VARCHAR(255))"))
        c.execute(text("INSERT INTO organisation (name) VALUES ('Old Co')"))
    eng.dispose()

    session = make_session(url)
    org = session.execute(select(Organisation)).scalar_one()
    assert org.name == "Old Co"
    assert org.frameworks in (None, "")
    assert org.framework_ids == ("nis2",)
    session.remove()

    cols = {c["name"] for c in inspect(create_engine(url)).get_columns("organisation")}
    assert "frameworks" in cols


def test_sync_is_idempotent_on_current_schema(tmp_path):
    # a fresh database created by make_session must need no further changes on reopen
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    make_session(url).remove()
    before = {c["name"] for c in inspect(create_engine(url)).get_columns("users")}
    make_session(url).remove()  # second open: no-op
    after = {c["name"] for c in inspect(create_engine(url)).get_columns("users")}
    assert before == after
