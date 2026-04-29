from fastapi import FastAPI

from app.database import Base, engine
from app.auth import router as auth_router
from app.data_routes import router as data_router


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Fake Data Prevention Project")

app.include_router(auth_router)
app.include_router(data_router)


@app.get("/")
def root():
    return {"message": "Fake Data Prevention API is running"}