from sqlalchemy import select


def select_one(db, table, **kwargs):
    return db.session.execute(select(table).filter_by(**kwargs)).scalar()
