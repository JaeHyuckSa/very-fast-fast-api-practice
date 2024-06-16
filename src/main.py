from fastapi import FastAPI, Body, HTTPException, Depends
from sqlalchemy.orm import Session
from database.connection import get_db
from database.repository import get_todos, get_todo_by_todo_id, create_todo, update_todo, delete_todo
from typing import List
from schema.request import CreateToDoRequest
from database.orm import ToDo
from schema.response import ToDoListSchema, ToDoSchema

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


@app.get("/todos", status_code=200)
def get_todos_handler(
    order: str | None = None,
    session: Session = Depends(get_db),
    ):
    todos: List[ToDo] = get_todos(session=session)
    if order and order == "desc":
        return ToDoListSchema(
        todos=[ToDoSchema.from_orm(todo) for todo in todos[::-1]]
    )
    return ToDoListSchema(
        todos=[ToDoSchema.from_orm(todo) for todo in todos]
    )

@app.get("/todos/{todo_id}", status_code=200)
def get_todo_handler(
    todo_id: int,
    session: Session = Depends(get_db),
) -> ToDoSchema:
    todo: ToDo | None = get_todo_by_todo_id(
        session=session, todo_id=todo_id
    )
    if  todo: 
        return ToDoSchema.from_orm(todo)
    raise HTTPException(status_code=404, detail="ToDo Not Found")
    

@app.post("/todos", status_code=201)
def create_todo_handler(
    request: CreateToDoRequest,
    session: Session = Depends(get_db),
    ) -> ToDoSchema:
    todo: ToDo = ToDo.create(request=request) # id=None
    todo: ToDo = create_todo(session=session, todo=todo) # id=int
    return ToDoSchema.from_orm(todo)


@app.patch("/todos/{todo_id}", status_code=200)
def update_todo_handler(
    todo_id: int,
    is_done: bool = Body(..., embed=True),
    session: Session = Depends(get_db),
    ):
    todo: ToDo | None = get_todo_by_todo_id(
        session=session, todo_id=todo_id
    )
    if  todo: 
        todo.done() if is_done else todo.undone()
        todo: ToDo = update_todo(session=session, todo=todo)
        return ToDoSchema.from_orm(todo)
    raise HTTPException(status_code=404, detail="ToDo Not Found")

@app.delete("/todos/{todo_id}", status_code=204)
def delete_todo_handler(
    todo_id: int,
    session: Session = Depends(get_db),
    ):
    todo: ToDo | None = get_todo_by_todo_id(
        session=session, todo_id=todo_id
    )
    if not todo:
        raise HTTPException(status_code=404, detail="ToDo Not Found")
    
    delete_todo(session=session, todo_id=todo_id)
        