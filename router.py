from fastapi import APIRouter, Depends
from schema import  ResponseSchema, TokenResponse, Login, Register
from sqlalchemy.orm import Session
from config import get_db
from passlib.context import CryptContext
from repository import JWTRepo, JWTBearer, UsersRepo
from model import Users

router = APIRouter(
    tags={"Users"}
)

# encrypt password
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

"""
   Authentication Router ------------------------------
"""

@router.post('/signup')
async def signup(request: Register, db: Session = Depends(get_db)):
    try:
        # insert user to db
        _user = Users(
        username=request.username,
        email=request.email,
        phone_number=request.phone_number,
        password=pwd_context.hash(request.password),
        first_name=request.first_name,
        last_name=request.last_name)
        UsersRepo.insert(db, _user)
        return ResponseSchema(code="200", status="Ok", message="Success save data").dict(exclude_none=True)
    except Exception as error:
        print(error.args)
        return ResponseSchema(code="500", status="Error", message="Internal Server Error").dict(exclude_none=True)

@router.post('/login')
async def login(request: Login, db: Session = Depends(get_db)):
    try:
       # find user by username
        _user = UsersRepo.find_by_username(db, Users, request.username)

        if not pwd_context.verify(request.password, _user.password):
            return ResponseSchema(code="400", status="Bad Request", message="Invalid password").dict(exclude_none=True)

        token = JWTRepo.generate_token({"sub": _user.username})
        return ResponseSchema(code="200", status="OK", message="success login!", result=TokenResponse(access_token=token, token_type="Bearer")).dict(exclude_none=True)
    except Exception as error:
        error_message = str(error.args)
        print(error_message)
        return ResponseSchema(code="500", status="Internal Server Error", message="Internal Server Error").dict(exclude_none=True)


"""
    Users Router ---------------------------------------------------

"""

@router.get("/users",) #dependencies=[Depends(JWTBearer())]
async def retrieve_all(db: Session = Depends(get_db)):
    _user = UsersRepo.retrieve_all(db, Users)
    return ResponseSchema(code="200", status="Ok", message="success retrieve data", result=_user).dict(exclude_none=True)