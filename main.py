import os
from typing import Optional
from fastapi import FastAPI, Depends, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets

from database import (
    SessionLocal,
    engine,
    Base,
    User,
    OAuthClient,
    AuthorizationCode,
    AccessToken,
    get_db,
)
from auth import (
    get_password_hash,
    verify_password,
    create_access_token,
    verify_access_token,
)
from auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

# Create database tables (if they don't exist)
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Mount static files (for CSS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configure templates
templates = Jinja2Templates(directory="templates")

# --- Endpoints ---


@app.get("/authorize", response_class=HTMLResponse)
async def authorize_get(
    request: Request,
    client_id: str,
    redirect_uri: str,
    scope: str = None,
    state: str = None,
    view: str = "login", # Add view parameter
    db: Session = Depends(get_db),
):
    # TODO: Validate client_id and redirect_uri against registered clients in the database
    # If invalid, return an error page

    # Determine which template to render based on the 'view' parameter
    if view == "register":
        template_name = "register.html"
    else: # Default to login
        template_name = "login.html"

    return templates.TemplateResponse(
        template_name,
        {
            "request": request,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
        },
    )


@app.post("/authorize", response_class=HTMLResponse)
async def authorize_post(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    action: str = Form(...),
    name: str = Form(None),
    scope: str = Form(None),
    state: str = Form(None),
    db: Session = Depends(get_db),
):
    # TODO: Validate client_id and redirect_uri

    # Determine which template to render in case of an error
    error_template = "login.html" if action == "login" else "register.html"

    if action == "login":
        user = db.query(User).filter(User.email == email).first()
        if not user or not verify_password(password, user.hashed_password):
            # TODO: Render form with error message
            return templates.TemplateResponse(
                error_template,
                {
                    "request": request,
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": scope,
                    "state": state,
                    "error": "Invalid email or password",
                },
            )

    elif action == "register":
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            # TODO: Render form with error message
            return templates.TemplateResponse(
                error_template,
                {
                    "request": request,
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": scope,
                    "state": state,
                    "error": "Email already exists",
                },
            )

        hashed_password = get_password_hash(password)
        new_user = User(email=email, name=name, hashed_password=hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        user = new_user  # Set user to the newly created user for the next step

    else:
        # Invalid action
        # TODO: Render form with error message
        return templates.TemplateResponse(
            "authorize.html", # Fallback to authorize.html for invalid action
            {
                "request": request,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "error": "Invalid action",
            },
        )

    # If login/registration is successful, generate authorization code and redirect
    # TODO: Ensure client exists and redirect_uri is valid for the client
    oauth_client = (
        db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    )
    if not oauth_client or oauth_client.redirect_uri != redirect_uri:
        # TODO: Handle invalid client or redirect_uri
        raise HTTPException(status_code=400, detail="Invalid client or redirect URI")

    code = secrets.token_urlsafe(16)
    expires_at = datetime.utcnow() + timedelta(
        minutes=10
    )  # Authorization code expires in 10 minutes
    auth_code = AuthorizationCode(
        code=code, user_id=user.id, client_id=oauth_client.id, expires_at=expires_at
    )
    db.add(auth_code)
    db.commit()

    redirect_url = f"{redirect_uri}?code={code}"
    if state:
        redirect_url += f"&state={state}"

    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)


@app.get("/register-client", response_class=HTMLResponse)
async def register_client_get(request: Request):
    return templates.TemplateResponse("register_client.html", {"request": request})


@app.post("/register-client", response_class=HTMLResponse)
async def register_client_post(
    request: Request,
    app_name: str = Form(...),
    redirect_uri: str = Form(...),
    db: Session = Depends(get_db),
):
    # Generate client ID and secret
    client_id = secrets.token_urlsafe(16)
    # Hash client secret before storing
    client_secret_plain = secrets.token_urlsafe(32)
    hashed_client_secret = get_password_hash(client_secret_plain)

    # Save client to database
    new_client = OAuthClient(
        client_id=client_id,
        client_secret=hashed_client_secret,  # Store the hashed secret
        redirect_uri=redirect_uri,
    )
    db.add(new_client)
    db.commit()
    db.refresh(new_client)

    # Render success page with client ID and secret
    # We pass the plain client_secret here to display it to the user once
    return templates.TemplateResponse(
        "register_client.html",
        {
            "request": request,
            "client_id": client_id,
            "client_secret": client_secret_plain,
        },
    )


@app.post("/token")
async def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    print(f"[DEBUG] client_id={client_id}, client_secret={client_secret}")

    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant type")

    auth_code = (
        db.query(AuthorizationCode)
        .filter(
            AuthorizationCode.code == code,
            AuthorizationCode.is_used == False,
            AuthorizationCode.expires_at > datetime.utcnow(),
        )
        .first()
    )

    if not auth_code:
        raise HTTPException(
            status_code=400, detail="Invalid or expired authorization code"
        )

    oauth_client = (
        db.query(OAuthClient).filter(OAuthClient.id == auth_code.client_id).first()
    )

    # oauth_client = (
    #     db.query(OAuthClient)
    #     .filter(
    #         OAuthClient.id == auth_code.client_id,
    #         OAuthClient.client_id == client_id,
    #         OAuthClient.client_secret == client_secret,
    #         OAuthClient.redirect_uri == redirect_uri,
    #     )
    #     .first()
    # )

    if not oauth_client:
        raise HTTPException(
            status_code=400, detail="Invalid client credentials or redirect URI"
        )

    if oauth_client.redirect_uri != redirect_uri:
        raise HTTPException(status_code=400, detail="Redirect URI mismatch")

    # Mark authorization code as used
    auth_code.is_used = True
    db.add(auth_code)
    db.commit()

    # Generate access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(auth_code.user_id)}, expires_delta=access_token_expires
    )

    # Store access token (optional if using JWT and not needing to revoke)
    # new_access_token = AccessToken(
    #     token=access_token,
    #     user_id=auth_code.user_id,
    #     client_id=oauth_client.id,
    #     expires_at=datetime.utcnow() + access_token_expires
    # )
    # db.add(new_access_token)
    # db.commit()

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/user-info")
async def user_info(request: Request, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = request.headers.get("Authorization")
    if not token:
        raise credentials_exception

    try:
        scheme, param = token.split()
        if scheme.lower() != "bearer":
            raise credentials_exception
        token_data = verify_access_token(param, credentials_exception)
    except ValueError:
        raise credentials_exception

    user_id = token_data.get("sub")
    if user_id is None:
        raise credentials_exception

    # User ID is now a UUID (string), compare directly
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception

    # Return user information (excluding sensitive data like hashed password)
    return {"email": user.email, "name": user.name, "id": user.id}
