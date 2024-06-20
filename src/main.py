from fastapi import FastAPI, Body
from pydantic import BaseModel

app = FastAPI()

@app.get("/")
def health_check_handler():
    return {"status": "ok"}


todo_data = {
    1: {
        "id": 1,
        "content": "Buy milk",
        "is_done": True,
    },
    2: {
        "id": 2,
        "content": "Buy eggs",
        "is_done": False,
    },
    3: {
        "id": 3,
        "content": "Buy bread",
        "is_done": False,
    },
}


@app.get("/todos")
def get_todos_handler(order: str | None = None):
    ret = list(todo_data.values())
    if order and order == "desc":
        return ret[::-1]
    return ret

@app.get("/todos/{todo_id}")
def get_todo_handler(todo_id: int):
    return todo_data[todo_id]

class CreateToDoRequest(BaseModel):
    id: int
    contents: str
    is_done: bool

@app.post("/todos")
def create_todo_handler(request: CreateToDoRequest):
    todo_data[request.id] = request.dict()
    return todo_data[request.id]


@app.patch("/todos/{todo_id}")
def update_todo_handler(
    todo_id: int,
    is_done: bool = Body(..., embed=True)
    ):
    todo = todo_data.get(todo_id)
    if todo:
        todo["is_done"] = is_done
        return todo
    return {}

@app.delete("/todos/{todo_id}")
def delete_todo_handler(todo_id: int):
    todo_data.pop(todo_id, None)
    return todo_data