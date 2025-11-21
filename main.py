import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Pg as PgSchema, Review as ReviewSchema, Inquiry as InquirySchema


JWT_SECRET = os.getenv("JWT_SECRET", "supersecretpgbuddy")
JWT_ALGO = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


app = FastAPI(title="PG Buddy API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------- Helpers -----------------------

def oid(oid_str: str) -> ObjectId:
    try:
        return ObjectId(oid_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc["id"] = str(doc.pop("_id"))
    # Convert datetimes to isoformat
    for k, v in list(doc.items()):
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)
    return encoded_jwt


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise ValueError("Invalid auth scheme")
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": oid(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return serialize_doc(user)
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")


# ----------------------- Root & Health -----------------------

@app.get("/")
def read_root():
    return {"message": "PG Buddy API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
            response["database"] = "✅ Connected & Working"
            response["connection_status"] = "Connected"
    except Exception as e:
        response["database"] = f"⚠️  Error: {str(e)[:80]}"
    return response


# ----------------------- Auth -----------------------

class SignupPayload(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str
    phone: Optional[str] = None


@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: SignupPayload):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = pwd_context.hash(payload.password)
    user_doc = UserSchema(
        name=payload.name,
        email=payload.email,
        role=payload.role if payload.role in ["student", "owner"] else "student",
        phone=payload.phone,
        password_hash=password_hash,
        is_active=True,
    ).model_dump()

    user_id = db["user"].insert_one({**user_doc, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}).inserted_id

    token = create_access_token({"sub": str(user_id)})
    user_doc_return = serialize_doc(db["user"].find_one({"_id": user_id}))
    return TokenResponse(access_token=token, user=user_doc_return)


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginPayload):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not user.get("password_hash") or not pwd_context.verify(payload.password, user.get("password_hash")):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token({"sub": str(user["_id"])})
    return TokenResponse(access_token=token, user=serialize_doc(user))


@app.get("/auth/me")
async def me(current=Depends(get_current_user)):
    return current


# ----------------------- PGs -----------------------

class PgCreatePayload(BaseModel):
    name: str
    college: str
    rent: int
    facilities: List[str] = []
    gender: str = "unisex"
    images: List[str] = []
    city: Optional[str] = None
    address: Optional[str] = None
    location: Optional[dict] = None


@app.get("/pgs")
def list_pgs(
    q: Optional[str] = Query(None, description="search text"),
    college: Optional[str] = None,
    city: Optional[str] = None,
    min_price: Optional[int] = None,
    max_price: Optional[int] = None,
    amenities: Optional[str] = Query(None, description="comma separated amenities"),
    limit: int = 50,
    skip: int = 0,
):
    filt: Dict[str, Any] = {}
    if college:
        filt["college"] = {"$regex": college, "$options": "i"}
    if city:
        filt["city"] = {"$regex": city, "$options": "i"}
    if q:
        filt["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"address": {"$regex": q, "$options": "i"}},
            {"college": {"$regex": q, "$options": "i"}},
        ]
    price_range = {}
    if min_price is not None:
        price_range["$gte"] = min_price
    if max_price is not None:
        price_range["$lte"] = max_price
    if price_range:
        filt["rent"] = price_range
    if amenities:
        amen_list = [a.strip() for a in amenities.split(",") if a.strip()]
        if amen_list:
            filt["facilities"] = {"$all": amen_list}

    cursor = db["pg"].find(filt).skip(skip).limit(limit)
    items = []
    for doc in cursor:
        doc_s = serialize_doc(doc)
        # compute avg rating
        stats = db["review"].aggregate([
            {"$match": {"pg_id": str(doc_s["id"]) }},
            {"$group": {"_id": "$pg_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}}
        ])
        stat = next(stats, None)
        doc_s["avg_rating"] = round(stat["avg"], 2) if stat else 0
        doc_s["reviews_count"] = stat["count"] if stat else 0
        items.append(doc_s)
    return {"items": items}


@app.post("/pgs")
async def create_pg(payload: PgCreatePayload, current=Depends(get_current_user)):
    if current.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Only owners can create PGs")
    pg = PgSchema(
        name=payload.name,
        owner_id=current["id"],
        college=payload.college,
        city=payload.city,
        address=payload.address,
        rent=payload.rent,
        facilities=payload.facilities or [],
        gender=payload.gender or "unisex",
        images=payload.images or [],
        location=payload.location,
        views=0,
        inquiries_count=0,
    ).model_dump()

    inserted_id = db["pg"].insert_one({**pg, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}).inserted_id
    return serialize_doc(db["pg"].find_one({"_id": inserted_id}))


@app.get("/pgs/{pg_id}")
def get_pg(pg_id: str):
    doc = db["pg"].find_one({"_id": oid(pg_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="PG not found")
    # increment views
    db["pg"].update_one({"_id": oid(pg_id)}, {"$inc": {"views": 1}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    doc = db["pg"].find_one({"_id": oid(pg_id)})
    doc_s = serialize_doc(doc)
    # owner phone for WhatsApp
    owner = db["user"].find_one({"_id": oid(doc_s["owner_id"])}) if doc_s.get("owner_id") else None
    if owner:
        doc_s["owner_phone"] = owner.get("phone")
    # attach rating stats
    stats = db["review"].aggregate([
        {"$match": {"pg_id": pg_id}},
        {"$group": {"_id": "$pg_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}}
    ])
    stat = next(stats, None)
    doc_s["avg_rating"] = round(stat["avg"], 2) if stat else 0
    doc_s["reviews_count"] = stat["count"] if stat else 0
    return doc_s


class PgUpdatePayload(BaseModel):
    name: Optional[str] = None
    college: Optional[str] = None
    rent: Optional[int] = None
    facilities: Optional[List[str]] = None
    gender: Optional[str] = None
    images: Optional[List[str]] = None
    city: Optional[str] = None
    address: Optional[str] = None
    location: Optional[dict] = None


@app.put("/pgs/{pg_id}")
async def update_pg(pg_id: str, payload: PgUpdatePayload, current=Depends(get_current_user)):
    doc = db["pg"].find_one({"_id": oid(pg_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="PG not found")
    if current.get("role") != "owner" or str(doc.get("owner_id")) != current.get("id"):
        raise HTTPException(status_code=403, detail="Not allowed")

    updates = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    updates["updated_at"] = datetime.now(timezone.utc)
    db["pg"].update_one({"_id": oid(pg_id)}, {"$set": updates})
    return serialize_doc(db["pg"].find_one({"_id": oid(pg_id)}))


@app.delete("/pgs/{pg_id}")
async def delete_pg(pg_id: str, current=Depends(get_current_user)):
    doc = db["pg"].find_one({"_id": oid(pg_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="PG not found")
    if current.get("role") != "owner" or str(doc.get("owner_id")) != current.get("id"):
        raise HTTPException(status_code=403, detail="Not allowed")
    db["pg"].delete_one({"_id": oid(pg_id)})
    return {"status": "deleted"}


# ----------------------- Owner Views -----------------------

@app.get("/owner/pgs")
async def owner_pgs(current=Depends(get_current_user)):
    if current.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Owners only")
    items = [serialize_doc(d) for d in db["pg"].find({"owner_id": current["id"]})]
    return {"items": items}


@app.get("/owner/analytics")
async def owner_analytics(current=Depends(get_current_user)):
    if current.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Owners only")
    pgs = list(db["pg"].find({"owner_id": current["id"]}))
    result = []
    for pg in pgs:
        pg_id = str(pg["_id"]) 
        inquiries = db["inquiry"].count_documents({"pg_id": pg_id})
        reviews = db["review"].aggregate([
            {"$match": {"pg_id": pg_id}},
            {"$group": {"_id": "$pg_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}}
        ])
        stat = next(reviews, None)
        result.append({
            "pg_id": pg_id,
            "name": pg.get("name"),
            "views": pg.get("views", 0),
            "inquiries": inquiries,
            "avg_rating": round(stat["avg"], 2) if stat else 0,
            "reviews_count": stat["count"] if stat else 0,
        })
    return {"items": result}


# ----------------------- Reviews -----------------------

class ReviewCreatePayload(BaseModel):
    rating: int
    comment: Optional[str] = None


@app.get("/pgs/{pg_id}/reviews")
def list_reviews(pg_id: str):
    items = [serialize_doc(d) for d in db["review"].find({"pg_id": pg_id}).sort("created_at", -1)]
    # attach user names
    for it in items:
        user = db["user"].find_one({"_id": oid(it["user_id"])}) if it.get("user_id") else None
        it["user_name"] = user.get("name") if user else "User"
    return {"items": items}


@app.post("/pgs/{pg_id}/reviews")
async def create_review(pg_id: str, payload: ReviewCreatePayload, current=Depends(get_current_user)):
    # any logged-in user can post review
    if not db["pg"].find_one({"_id": oid(pg_id)}):
        raise HTTPException(status_code=404, detail="PG not found")
    review = ReviewSchema(pg_id=pg_id, user_id=current["id"], rating=payload.rating, comment=payload.comment).model_dump()
    inserted_id = db["review"].insert_one({**review, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}).inserted_id
    return serialize_doc(db["review"].find_one({"_id": inserted_id}))


# ----------------------- Inquiries -----------------------

class InquiryPayload(BaseModel):
    name: str
    email: EmailStr
    message: Optional[str] = None
    phone: Optional[str] = None


@app.post("/pgs/{pg_id}/inquiries")
async def create_inquiry(pg_id: str, payload: InquiryPayload):
    if not db["pg"].find_one({"_id": oid(pg_id)}):
        raise HTTPException(status_code=404, detail="PG not found")
    inquiry = InquirySchema(pg_id=pg_id, name=payload.name, email=payload.email, message=payload.message, phone=payload.phone).model_dump()
    inserted_id = db["inquiry"].insert_one({**inquiry, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}).inserted_id
    db["pg"].update_one({"_id": oid(pg_id)}, {"$inc": {"inquiries_count": 1}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    return serialize_doc(db["inquiry"].find_one({"_id": inserted_id}))


# ----------------------- 404 handler -----------------------

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
