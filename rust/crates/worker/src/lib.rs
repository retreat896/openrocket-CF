use hmac::{Hmac, Mac};
use orc_core::{
    export_ork, hash_password, import_ork, model_from_json, model_json, new_password_salt,
    verify_password, ImportErrorKind, RocketModel,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use worker::{
    durable_object, event, Env, Headers, Method, Request, RequestInit, Response,
    ResponseBuilder, State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
};
use wasm_bindgen::JsValue;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

const SESSION_COOKIE: &str = "orc_session";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Identity {
    id: String,
    email: String,
    name: String,
    #[serde(default)]
    picture: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionPayload {
    u: String,
    e: String,
    n: String,
    p: Option<String>,
    exp: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProjectRow {
    id: String,
    name: String,
    owner_id: String,
    owner_name: String,
    owner_email: String,
    created_at: i64,
    updated_at: i64,
    version: i64,
    model: String,
    preview: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProjectListRow {
    id: String,
    name: String,
    role: String,
    owner_id: String,
    owner_name: String,
    owner_email: String,
    created_at: i64,
    updated_at: i64,
    preview: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RoleRow {
    role: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MemberRow {
    email: String,
    role: String,
    name: Option<String>,
    picture: Option<String>,
}

fn now_seconds() -> i64 {
    (worker::js_sys::Date::now() / 1000.0).floor() as i64
}

fn var_text(env: &Env, name: &str) -> Option<String> {
    env.var(name)
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty())
}

fn secret_text(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| var_text(env, name))
}

fn session_secret(env: &Env) -> String {
    secret_text(env, "SESSION_SECRET").unwrap_or_else(|| "local-development-only-change-me".to_string())
}

fn public_url(env: &Env, req: &Request) -> String {
    var_text(env, "PUBLIC_URL")
        .unwrap_or_else(|| {
            req.url()
                .map(|url| format!("{}://{}", url.scheme(), url.host_str().unwrap_or("localhost")))
                .unwrap_or_else(|_| "http://localhost:8787".to_string())
                .trim_end_matches('/')
                .to_string()
        })
        .trim_end_matches('/')
        .to_string()
}

fn sign_payload(secret: &str, payload: &impl Serialize) -> Option<String> {
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).ok()?);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(body.as_bytes());
    let digest = mac.finalize().into_bytes();
    Some(format!("{body}.{}", URL_SAFE_NO_PAD.encode(digest)))
}

fn verify_payload<T: for<'de> Deserialize<'de>>(secret: &str, token: &str) -> Option<T> {
    let (body, signature) = token.rsplit_once('.')?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(body.as_bytes());
    let expected = mac.finalize().into_bytes();
    let actual = URL_SAFE_NO_PAD.decode(signature).ok()?;
    if actual.len() != expected.len()
        || !actual
            .iter()
            .zip(expected.iter())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            .eq(&0)
    {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(body).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn parse_cookies(header: Option<String>) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for part in header.unwrap_or_default().split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        out.insert(name.to_string(), value.to_string());
    }
    out
}

async fn upsert_user(env: &Env, identity: &Identity) -> worker::Result<()> {
    let db = env.d1("DB")?;
    let now = now_seconds();
    let values = [
        JsValue::from_str(&identity.id),
        JsValue::from_str(&identity.email.to_lowercase()),
        JsValue::from_str(&identity.name),
        identity
            .picture
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or_else(JsValue::null),
        JsValue::from_f64(now as f64),
        JsValue::from_f64(now as f64),
    ];
    db.prepare(
        "INSERT INTO users (id,email,name,picture,created_at,last_login)
         VALUES (?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
           email=excluded.email,name=excluded.name,picture=COALESCE(excluded.picture,picture),
           last_login=excluded.last_login",
    )
    .bind(&values)?
    .run()
    .await?;
    Ok(())
}

async fn identity_from_request(req: &Request, env: &Env) -> worker::Result<Option<Identity>> {
    let cookie = parse_cookies(req.headers().get("Cookie")?).get(SESSION_COOKIE).cloned();
    let Some(cookie) = cookie else {
        return Ok(None);
    };
    let Some(payload) = verify_payload::<SessionPayload>(&session_secret(env), &cookie) else {
        return Ok(None);
    };
    if payload.exp <= now_seconds() {
        return Ok(None);
    }
    let identity = Identity {
        id: payload.u,
        email: payload.e,
        name: payload.n,
        picture: payload.p,
    };
    upsert_user(env, &identity).await?;
    Ok(Some(identity))
}

fn json_error(message: impl Into<String>, status: u16) -> worker::Result<Response> {
    let value = serde_json::json!({ "error": message.into() });
    ResponseBuilder::new()
        .with_status(status)
        .from_json(&value)
}

async fn project_role(env: &Env, project_id: &str, email: &str) -> worker::Result<Option<String>> {
    let db = env.d1("DB")?;
    let values = [
        JsValue::from_str(project_id),
        JsValue::from_str(&email.to_lowercase()),
    ];
    let row = db
        .prepare("SELECT role FROM members WHERE project_id=? AND email=?")
        .bind(&values)?
        .first::<RoleRow>(None)
        .await?;
    Ok(row.map(|row| row.role))
}

fn cookie_header(env: &Env, payload: &SessionPayload, secure: bool) -> Option<String> {
    let token = sign_payload(&session_secret(env), payload)?;
    let mut parts = vec![
        format!("{SESSION_COOKIE}={token}"),
        "Path=/".to_string(),
        "HttpOnly".to_string(),
        "SameSite=Lax".to_string(),
        format!("Max-Age={}", 30 * 24 * 60 * 60),
    ];
    if secure {
        parts.push("Secure".to_string());
    }
    Some(parts.join("; "))
}

async fn get_project(env: &Env, project_id: &str) -> worker::Result<Option<ProjectRow>> {
    let db = env.d1("DB")?;
    let value = [JsValue::from_str(project_id)];
    Ok(db
        .prepare(
            "SELECT p.id,p.name,p.owner_id,u.name AS owner_name,u.email AS owner_email,
                    p.created_at,p.updated_at,p.version,p.model,p.preview
             FROM projects p
             JOIN users u ON u.id=p.owner_id
             WHERE p.id=?",
        )
        .bind(&value)?
        .first::<ProjectRow>(None)
        .await?)
}

async fn init_room(env: &Env, project_id: &str, model: &RocketModel, version: i64) -> worker::Result<()> {
    let namespace = env.durable_object("DESIGN_ROOMS")?;
    let stub = namespace.id_from_name(project_id)?.get_stub()?;
    let body = serde_json::json!({ "model": model, "version": version });
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(
        &serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string()),
    )));
    let req = Request::new_with_init("http://room/init", &init)?;
    stub.fetch_with_request(req).await?;
    Ok(())
}

async fn handle_projects(mut req: Request, env: &Env) -> worker::Result<Response> {
    let path = req.path();
    let method = req.method();
    let identity = identity_from_request(&req, env).await?;

    if path == "/api/me" {
        return match identity {
            Some(identity) => Response::from_json(&identity),
            None => json_error("Please sign in.", 401),
        };
    }

    let Some(identity) = identity else {
        return json_error("Please sign in.", 401);
    };

    if path == "/api/projects" && method == Method::Get {
        let db = env.d1("DB")?;
        let value = [JsValue::from_str(&identity.email.to_lowercase())];
        let rows = db
            .prepare(
                "SELECT p.id,p.name,p.owner_id,u.name AS owner_name,u.email AS owner_email,
                        p.created_at,p.updated_at,p.version,p.preview,m.role
                 FROM members m
                 JOIN projects p ON p.id=m.project_id
                 JOIN users u ON u.id=p.owner_id
                 WHERE m.email=? ORDER BY p.updated_at DESC",
            )
            .bind(&value)?
            .all()
            .await?
            .results::<ProjectListRow>()?;
        let response: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.id,
                    "name": row.name,
                    "role": row.role,
                    "owner": {"id": row.owner_id, "name": row.owner_name, "email": row.owner_email},
                    "createdAt": row.created_at,
                    "updatedAt": row.updated_at,
                    "owner_id": row.owner_id,
                    "owner_name": row.owner_name,
                    "owner_email": row.owner_email,
                    "edited_at": row.updated_at,
                    "preview": row.preview,
                })
            })
            .collect();
        return Response::from_json(&response);
    }

    if path == "/api/projects" && method == Method::Post {
        #[derive(Deserialize)]
        struct CreateInput {
            name: Option<String>,
            example: Option<String>,
        }
        let input_text = String::from_utf8_lossy(&req.bytes().await.unwrap_or_default()).to_string();
        let input: CreateInput = serde_json::from_str(&input_text)
            .unwrap_or(CreateInput { name: None, example: None });
        let name = input
            .name
            .or(input.example)
            .unwrap_or_else(|| "Untitled rocket".to_string())
            .chars()
            .filter(|ch| !matches!(ch, '\0'..='\u{001f}'))
            .take(120)
            .collect::<String>();
        let name = if name.trim().is_empty() {
            "Untitled rocket".to_string()
        } else {
            name.trim().to_string()
        };
        let model = orc_core::import_ork(include_bytes!("../../../../server/templates/new-rocket.ork"))
            .map_err(|error| worker::Error::RustError(error.message))?;
        let model_json = model_json(&model).map_err(|error| worker::Error::RustError(error.to_string()))?;
        let id = Uuid::new_v4().to_string();
        let now = now_seconds();
        let db = env.d1("DB")?;
        let project_values = [
            JsValue::from_str(&id),
            JsValue::from_str(&name),
            JsValue::from_str(&identity.id),
            JsValue::from_f64(now as f64),
            JsValue::from_f64(now as f64),
            JsValue::from_str(&model_json),
        ];
        db.prepare(
            "INSERT INTO projects (id,name,owner_id,created_at,updated_at,version,model)
             VALUES (?,?,?,?,?,0,?)",
        )
        .bind(&project_values)?
        .run()
        .await?;
        let member_values = [
            JsValue::from_str(&id),
            JsValue::from_str(&identity.email.to_lowercase()),
            JsValue::from_str("owner"),
            JsValue::from_f64(now as f64),
        ];
        db.prepare(
            "INSERT INTO members (project_id,email,role,added_at) VALUES (?,?,?,?)",
        )
        .bind(&member_values)?
        .run()
        .await?;
        init_room(env, &id, &model, 0).await?;
        return Response::from_json(&serde_json::json!({ "id": id }));
    }

    if path == "/api/projects/import" && method == Method::Post {
        let bytes = req.bytes().await?;
        let model = import_ork(&bytes).map_err(|error| match error.kind {
            ImportErrorKind::RockSim => worker::Error::RustError(error.message),
            _ => worker::Error::RustError(error.message),
        })?;
        let name = req
            .headers()
            .get("X-Filename")?
            .unwrap_or_else(|| "Imported rocket".to_string())
            .split(|ch| matches!(ch, '/' | '\\'))
            .last()
            .unwrap_or("Imported rocket")
            .trim_end_matches(|ch| matches!(ch, '.' | 'o' | 'r' | 'k' | 'x' | 'm' | 'l' | 'z' | 'i' | 'p'))
            .chars()
            .take(120)
            .collect::<String>();
        let name = if name.trim().is_empty() {
            "Imported rocket".to_string()
        } else {
            name.trim().to_string()
        };
        let model_json = model_json(&model).map_err(|error| worker::Error::RustError(error.to_string()))?;
        let id = Uuid::new_v4().to_string();
        let now = now_seconds();
        let db = env.d1("DB")?;
        let values = [
            JsValue::from_str(&id),
            JsValue::from_str(&name),
            JsValue::from_str(&identity.id),
            JsValue::from_f64(now as f64),
            JsValue::from_f64(now as f64),
            JsValue::from_str(&model_json),
        ];
        db.prepare(
            "INSERT INTO projects (id,name,owner_id,created_at,updated_at,version,model)
             VALUES (?,?,?,?,?,0,?)",
        )
        .bind(&values)?
        .run()
        .await?;
        let member_values = [
            JsValue::from_str(&id),
            JsValue::from_str(&identity.email.to_lowercase()),
            JsValue::from_str("owner"),
            JsValue::from_f64(now as f64),
        ];
        db.prepare(
            "INSERT INTO members (project_id,email,role,added_at) VALUES (?,?,?,?)",
        )
        .bind(&member_values)?
        .run()
        .await?;
        init_room(env, &id, &model, 0).await?;
        return Response::from_json(&serde_json::json!({ "id": id }));
    }

    if path == "/api/motors" && method == Method::Get {
        let db = env.d1("DB")?;
        let values = [JsValue::from_str(&identity.id)];
        let rows = db
            .prepare("SELECT id,filename,content,summary,created_at FROM motors WHERE owner_id=? ORDER BY created_at DESC")
            .bind(&values)?
            .all()
            .await?
            .results::<serde_json::Value>()?;
        let motors: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|row| serde_json::json!({
                "id": row.get("id"),
                "filename": row.get("filename"),
                "content": row.get("content"),
                "summary": row.get("summary").and_then(|value| value.as_str()).and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok()).unwrap_or_else(|| serde_json::json!([])),
                "created_at": row.get("created_at"),
            }))
            .collect();
        return Response::from_json(&motors);
    }

    if path == "/api/motors" && method == Method::Post {
        let filename = req
            .headers()
            .get("X-Filename")?
            .unwrap_or_else(|| "motor.eng".to_string())
            .split(|character| matches!(character, '/' | '\\'))
            .last()
            .unwrap_or("motor.eng")
            .chars()
            .take(120)
            .collect::<String>();
        let content = String::from_utf8(req.bytes().await.unwrap_or_default())
            .unwrap_or_default();
        let id = Uuid::new_v4().to_string();
        let now = now_seconds();
        let db = env.d1("DB")?;
        db.prepare(
            "INSERT INTO motors (id,owner_id,filename,content,summary,created_at)
             VALUES (?,?,?,?,?,?)",
        )
        .bind(&[
            JsValue::from_str(&id),
            JsValue::from_str(&identity.id),
            JsValue::from_str(&filename),
            JsValue::from_str(&content),
            JsValue::from_str("[]"),
            JsValue::from_f64(now as f64),
        ])?
        .run()
        .await?;
        return Response::from_json(&serde_json::json!({
            "id": id,
            "filename": filename,
            "motors": [],
            "summary": [],
        }));
    }

    if path.starts_with("/api/motors/") && method == Method::Delete {
        let motor_id = path.strip_prefix("/api/motors/").unwrap_or("").trim_matches('/');
        let db = env.d1("DB")?;
        db.prepare("DELETE FROM motors WHERE id=? AND owner_id=?")
            .bind(&[
                JsValue::from_str(motor_id),
                JsValue::from_str(&identity.id),
            ])?
            .run()
            .await?;
        return Response::from_json(&serde_json::json!({ "ok": true }));
    }

    let parts: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    if parts.len() >= 3 && parts[0] == "api" && parts[1] == "projects" {
        let project_id = parts[2];
        let role = project_role(env, project_id, &identity.email).await?;
        if role.is_none() {
            return json_error("Project not found.", 404);
        }
        let role = role.unwrap();

        if parts.len() == 3 && method == Method::Get {
            let project = get_project(env, project_id).await?;
            let Some(project) = project else {
                return json_error("Project not found.", 404);
            };
            let model = model_from_json(&project.model)
                .unwrap_or_default();
            let db = env.d1("DB")?;
            let value = [JsValue::from_str(project_id)];
            let members = db
                .prepare(
                    "SELECT m.email,m.role,u.name,u.picture
                     FROM members m LEFT JOIN users u ON u.email=m.email
                     WHERE m.project_id=? ORDER BY m.email",
                )
                .bind(&value)?
                .all()
                .await?
                .results::<MemberRow>()?;
            let members: Vec<serde_json::Value> = members
                .into_iter()
                .map(|member| {
                    serde_json::json!({
                        "email": member.email,
                        "role": member.role,
                        "name": member.name,
                        "picture": member.picture,
                    })
                })
                .collect();
            return Response::from_json(&serde_json::json!({
                "id": project.id,
                "name": project.name,
                "role": role,
                "owner": {"id": project.owner_id, "name": project.owner_name, "email": project.owner_email},
                "createdAt": project.created_at,
                "updatedAt": project.updated_at,
                "version": project.version,
                "preview": project.preview,
                "model": model,
                "members": members,
            }));
        }

        if parts.len() == 3 && method == Method::Patch && ["owner", "editor"].contains(&role.as_str()) {
            #[derive(Deserialize)]
            struct RenameInput {
                name: Option<String>,
            }
            let input_text =
                String::from_utf8_lossy(&req.bytes().await.unwrap_or_default()).to_string();
            let input: RenameInput = serde_json::from_str(&input_text)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            let name = input
                .name
                .unwrap_or_default()
                .chars()
                .filter(|ch| !matches!(ch, '\0'..='\u{001f}'))
                .take(120)
                .collect::<String>()
                .trim()
                .to_string();
            if name.is_empty() {
                return json_error("Name required.", 400);
            }
            let db = env.d1("DB")?;
            let now = now_seconds();
            let values = [
                JsValue::from_str(&name),
                JsValue::from_f64(now as f64),
                JsValue::from_str(project_id),
            ];
            db.prepare("UPDATE projects SET name=?,updated_at=? WHERE id=?")
                .bind(&values)?
                .run()
                .await?;
            return Response::from_json(&serde_json::json!({ "ok": true }));
        }

        if parts.len() == 3 && method == Method::Delete && role == "owner" {
            let db = env.d1("DB")?;
            let value = [JsValue::from_str(project_id)];
            db.prepare("DELETE FROM projects WHERE id=?")
                .bind(&value)?
                .run()
                .await?;
            return Response::from_json(&serde_json::json!({ "ok": true }));
        }

        if parts.len() == 4 && parts[3] == "download" && method == Method::Get {
            let project = get_project(env, project_id).await?;
            let Some(project) = project else {
                return json_error("Project not found.", 404);
            };
            let model = model_from_json(&project.model)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            let exported = export_ork(&model)
                .map_err(|error| worker::Error::RustError(error.message))?;
            let headers = Headers::new();
            headers.set(
                "Content-Disposition",
                &format!(
                    "attachment; filename*=UTF-8''{}.ork",
                    project.name.replace('/', "_").replace('\\', "_")
                ),
            )?;
            headers.set("Content-Type", "application/octet-stream")?;
            let mut response = ResponseBuilder::new()
                .with_headers(headers)
                .fixed(exported.bytes);
            response.headers_mut().set("Cache-Control", "no-store")?;
            return Ok(response);
        }

        if parts.len() == 4 && parts[3] == "preview" && method == Method::Post
            && ["owner", "editor"].contains(&role.as_str())
        {
            let bytes = req.bytes().await?;
            let preview = String::from_utf8_lossy(&bytes).to_string();
            let preview_value: serde_json::Value = serde_json::from_str(&preview)
                .unwrap_or_else(|_| serde_json::json!({ "preview": preview }));
            let db_preview = serde_json::to_string(
                preview_value
                    .get("preview")
                    .unwrap_or(&preview_value),
            )
            .unwrap_or_default();
            let db = env.d1("DB")?;
            db.prepare("UPDATE projects SET preview=?,updated_at=? WHERE id=?")
                .bind(&[
                    JsValue::from_str(&db_preview),
                    JsValue::from_f64(now_seconds() as f64),
                    JsValue::from_str(project_id),
                ])?
                .run()
                .await?;
            return Response::from_json(&serde_json::json!({ "ok": true }));
        }

        if parts.len() == 4 && parts[3] == "motors" && method == Method::Get {
            let db = env.d1("DB")?;
            let project_value = [JsValue::from_str(project_id)];
            let members = db
                .prepare("SELECT email FROM members WHERE project_id=?")
                .bind(&project_value)?
                .all()
                .await?
                .results::<serde_json::Value>()?;
            let mut motor_rows = Vec::new();
            for member in members {
                if let Some(email) = member.get("email").and_then(|value| value.as_str()) {
                    let user = db
                        .prepare("SELECT id FROM users WHERE email=?")
                        .bind(&[JsValue::from_str(email)])?
                        .first::<serde_json::Value>(None)
                        .await?;
                    if let Some(user_id) = user
                        .and_then(|value| value.get("id").and_then(|value| value.as_str()).map(str::to_string))
                    {
                        let rows = db
                            .prepare("SELECT id,filename,content,summary FROM motors WHERE owner_id=?")
                            .bind(&[JsValue::from_str(&user_id)])?
                            .all()
                            .await?
                            .results::<serde_json::Value>()?;
                        motor_rows.extend(rows);
                    }
                }
            }
            let motors: Vec<serde_json::Value> = motor_rows
                .into_iter()
                .map(|row| serde_json::json!({
                    "name": row.get("filename").and_then(|value| value.as_str()).unwrap_or("motor"),
                    "content": row.get("content").and_then(|value| value.as_str()).unwrap_or_default(),
                }))
                .collect();
            return Response::from_json(&motors);
        }

        if parts.len() == 4 && parts[3] == "members" && role == "owner" && method == Method::Post {
            #[derive(Deserialize)]
            struct MemberInput {
                email: String,
                role: String,
            }
            let input_text =
                String::from_utf8_lossy(&req.bytes().await.unwrap_or_default()).to_string();
            let input: MemberInput = serde_json::from_str(&input_text)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            let email = input.email.trim().to_lowercase();
            if !email.contains('@') || !["editor", "viewer"].contains(&input.role.as_str()) {
                return json_error("A valid email and editor/viewer role are required.", 400);
            }
            let db = env.d1("DB")?;
            let now = now_seconds();
            let values = [
                JsValue::from_str(project_id),
                JsValue::from_str(&email),
                JsValue::from_str(&input.role),
                JsValue::from_f64(now as f64),
            ];
            db.prepare(
                "INSERT INTO members (project_id,email,role,added_at) VALUES (?,?,?,?)
                 ON CONFLICT(project_id,email) DO UPDATE SET role=excluded.role",
            )
            .bind(&values)?
            .run()
            .await?;
            return Response::from_json(&serde_json::json!({ "ok": true }));
        }

        if parts.len() == 5 && parts[3] == "members" && method == Method::Delete {
            let email = parts[4].to_lowercase();
            let owner = role == "owner";
            let self_leave = email == identity.email.to_lowercase();
            if !owner && !self_leave {
                return json_error("Only the owner can remove people.", 403);
            }
            let db = env.d1("DB")?;
            db.prepare("DELETE FROM members WHERE project_id=? AND email=?")
                .bind(&[
                    JsValue::from_str(project_id),
                    JsValue::from_str(&email),
                ])?
                .run()
                .await?;
            return Response::from_json(&serde_json::json!({ "ok": true }));
        }

        if parts.len() == 4 && parts[3] == "edits" && method == Method::Get {
            let db = env.d1("DB")?;
            let value = [JsValue::from_str(project_id)];
            let result = db
                .prepare("SELECT version,user_id,user_name,at,minor,changes,note FROM edits WHERE project_id=? ORDER BY version DESC LIMIT 600")
                .bind(&value)?
                .all()
                .await?;
            let rows = result.results::<serde_json::Value>()?;
            return Response::from_json(&serde_json::json!({ "groups": rows, "nextBefore": null }));
        }
    }

    json_error("Not found.", 404)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccountRow {
    id: String,
    email: String,
    name: String,
    password_salt: String,
    password_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccountIdRow {
    id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalAuthInput {
    email: String,
    password: String,
    #[serde(default)]
    name: String,
}

async fn handle_auth(mut req: Request, env: &Env) -> worker::Result<Response> {
    let path = req.path();
    let public_url = public_url(env, &req);
    let secure = public_url.starts_with("https://");

    if path == "/auth/config" {
        return Response::from_json(&serde_json::json!({
            "local": true,
        }));
    }

    if path == "/auth/logout" {
        let cookie = "orc_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
        let cookie = if secure {
            format!("{cookie}; Secure")
        } else {
            cookie.to_string()
        };
        let headers = Headers::new();
        headers.set("Set-Cookie", &cookie)?;
        return Ok(ResponseBuilder::new()
            .with_status(200)
            .with_headers(headers)
            .from_json(&serde_json::json!({ "ok": true }))?);
    }

    if path == "/auth/delete" && req.method() == Method::Post {
        let Some(identity) = identity_from_request(&req, env).await? else {
            return json_error("Please sign in.", 401);
        };
        let db = env.d1("DB")?;

        let owned = db
            .prepare("SELECT id FROM projects WHERE owner_id=?")
            .bind(&[JsValue::from_str(&identity.id)])?
            .all()
            .await?
            .results::<serde_json::Value>()?;
        for project in owned {
            if let Some(project_id) = project.get("id").and_then(|value| value.as_str()) {
                db.prepare("DELETE FROM projects WHERE id=?")
                    .bind(&[JsValue::from_str(project_id)])?
                    .run()
                    .await?;
            }
        }
        db.prepare("DELETE FROM members WHERE email=?")
            .bind(&[JsValue::from_str(&identity.email.to_lowercase())])?
            .run()
            .await?;
        db.prepare("DELETE FROM motors WHERE owner_id=?")
            .bind(&[JsValue::from_str(&identity.id)])?
            .run()
            .await?;
        db.prepare("DELETE FROM accounts WHERE id=?")
            .bind(&[JsValue::from_str(&identity.id)])?
            .run()
            .await?;
        db.prepare("DELETE FROM users WHERE id=?")
            .bind(&[JsValue::from_str(&identity.id)])?
            .run()
            .await?;

        let cookie = "orc_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
        let cookie = if secure {
            format!("{cookie}; Secure")
        } else {
            cookie.to_string()
        };
        let headers = Headers::new();
        headers.set("Set-Cookie", &cookie)?;
        return Ok(ResponseBuilder::new()
            .with_status(200)
            .with_headers(headers)
            .from_json(&serde_json::json!({ "ok": true }))?);
    }

    if path == "/auth/register" && req.method() == Method::Post {
        let bytes = req.bytes().await?;
        let input: LocalAuthInput = serde_json::from_slice(&bytes)
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
        let email = input.email.trim().to_lowercase();
        let name = input
            .name
            .trim()
            .chars()
            .filter(|character| !character.is_control())
            .take(120)
            .collect::<String>();
        if !email.contains('@') || email.len() > 254 {
            return json_error("Enter a valid email.", 400);
        }
        if name.is_empty() {
            return json_error("Enter your name.", 400);
        }
        if input.password.len() < 10 {
            return json_error("Password must be at least 10 characters.", 400);
        }

        let db = env.d1("DB")?;
        let email_value = [JsValue::from_str(&email)];
        let existing = db
            .prepare("SELECT id FROM accounts WHERE email=?")
            .bind(&email_value)?
            .first::<AccountIdRow>(None)
            .await?;
        if existing.is_some() {
            return json_error("An account with that email already exists.", 409);
        }

        let id = Uuid::new_v4().to_string();
        let salt = new_password_salt();
        let Some(password_hash) = hash_password(&input.password, &salt) else {
            return json_error("Could not secure that password.", 500);
        };
        let now = now_seconds();
        let account_values = [
            JsValue::from_str(&id),
            JsValue::from_str(&email),
            JsValue::from_str(&name),
            JsValue::from_str(&salt),
            JsValue::from_str(&password_hash),
            JsValue::from_f64(now as f64),
            JsValue::from_f64(now as f64),
        ];
        db.prepare(
            "INSERT INTO accounts
             (id,email,name,password_salt,password_hash,created_at,last_login)
             VALUES (?,?,?,?,?,?,?)",
        )
        .bind(&account_values)?
        .run()
        .await?;

        let identity = Identity {
            id: id.clone(),
            email: email.clone(),
            name: name.clone(),
            picture: None,
        };
        upsert_user(env, &identity).await?;
        let session = SessionPayload {
            u: identity.id,
            e: identity.email,
            n: identity.name,
            p: identity.picture,
            exp: now_seconds() + 30 * 24 * 60 * 60,
        };
        let cookies = cookie_header(env, &session, secure).into_iter().collect::<Vec<_>>();
        let headers = Headers::new();
        for cookie in cookies {
            headers.append("Set-Cookie", &cookie)?;
        }
        return Ok(ResponseBuilder::new()
            .with_status(200)
            .with_headers(headers)
            .from_json(&serde_json::json!({
                "id": id,
                "email": email,
                "name": name,
            }))?);
    }

    if path == "/auth/login" && req.method() == Method::Post {
        let bytes = req.bytes().await?;
        let input: LocalAuthInput = serde_json::from_slice(&bytes)
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
        let email = input.email.trim().to_lowercase();
        if !email.contains('@') || input.password.is_empty() {
            return json_error("Enter your email and password.", 400);
        }

        let db = env.d1("DB")?;
        let email_value = [JsValue::from_str(&email)];
        let account = db
            .prepare(
                "SELECT id,email,name,password_salt,password_hash
                 FROM accounts WHERE email=?",
            )
            .bind(&email_value)?
            .first::<AccountRow>(None)
            .await?;
        let Some(account) = account else {
            return json_error("Email or password is incorrect.", 401);
        };
        if !verify_password(&input.password, &account.password_salt, &account.password_hash) {
            return json_error("Email or password is incorrect.", 401);
        }

        let now = now_seconds();
        db.prepare("UPDATE accounts SET last_login=? WHERE id=?")
            .bind(&[
                JsValue::from_f64(now as f64),
                JsValue::from_str(&account.id),
            ])?
            .run()
            .await?;
        let identity = Identity {
            id: account.id,
            email: account.email,
            name: account.name,
            picture: None,
        };
        upsert_user(env, &identity).await?;
        let session = SessionPayload {
            u: identity.id.clone(),
            e: identity.email.clone(),
            n: identity.name.clone(),
            p: identity.picture.clone(),
            exp: now_seconds() + 30 * 24 * 60 * 60,
        };
        let cookies = cookie_header(env, &session, secure).into_iter().collect::<Vec<_>>();
        let headers = Headers::new();
        for cookie in cookies {
            headers.append("Set-Cookie", &cookie)?;
        }
        return Ok(ResponseBuilder::new()
            .with_status(200)
            .with_headers(headers)
            .from_json(&identity)?);
    }

    json_error("Not found.", 404)
}

async fn handle_room(req: Request, env: &Env) -> worker::Result<Response> {
    let path = req.path();
    let project_id = path
        .strip_prefix("/room/")
        .and_then(|value| value.split('/').next())
        .unwrap_or("")
        .to_string();
    if project_id.is_empty() {
        return json_error("Project not found.", 404);
    }
    let Some(identity) = identity_from_request(&req, env).await? else {
        return json_error("Please sign in.", 401);
    };
    let Some(role) = project_role(env, &project_id, &identity.email).await? else {
        return json_error("Project not found.", 404);
    };
    let namespace = env.durable_object("DESIGN_ROOMS")?;
    let stub = namespace.id_from_name(&project_id)?.get_stub()?;
    let headers = Headers::new();
    headers.set("upgrade", "websocket")?;
    headers.set("connection", "Upgrade")?;
    headers.set("X-ORC-Project", &project_id)?;
    headers.set("X-ORC-User-Id", &identity.id)?;
    headers.set("X-ORC-User-Name", &identity.name)?;
    headers.set("X-ORC-User-Email", &identity.email)?;
    headers.set("X-ORC-Role", &role)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    init.with_headers(headers);
    let request = Request::new_with_init("http://room/", &init)?;
    stub.fetch_with_request(request).await
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RoomState {
    model: RocketModel,
    version: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientAttachment {
    user_id: String,
    name: String,
    email: String,
    role: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RoomInit {
    model: RocketModel,
    version: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct D1RoomProject {
    model: String,
    version: i64,
}

#[durable_object]
pub struct DesignRoom {
    state: State,
    env: Env,
}

impl worker::DurableObject for DesignRoom {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        if req.path() == "/init" {
            let init: RoomInit = req.json().await?;
            self.state
                .storage()
                .put("room", RoomState {
                    model: init.model,
                    version: init.version,
                })
                .await?;
            return Response::empty();
        }

        let project_id = req
            .headers()
            .get("X-ORC-Project")?
            .unwrap_or_else(|| {
                self.state
                    .id()
                    .name()
                    .unwrap_or_else(|| "unknown".to_string())
            });
        let mut room = self
            .state
            .storage()
            .get::<RoomState>("room")
            .await?
            .unwrap_or_else(|| RoomState {
                model: RocketModel::default(),
                version: 0,
            });
        if room.model.objs.is_empty() {
            if let Ok(db) = self.env.d1("DB") {
                let values = [JsValue::from_str(&project_id)];
                if let Ok(Some(project)) = db
                    .prepare("SELECT model,version FROM projects WHERE id=?")
                    .bind(&values)?
                    .first::<D1RoomProject>(None)
                    .await
                {
                    if let Ok(model) = model_from_json(&project.model) {
                        room = RoomState {
                            model,
                            version: project.version,
                        };
                        let _ = self.state.storage().put("room", &room).await;
                    }
                }
            }
        }

        let pair = WebSocketPair::new()?;
        let attachment = ClientAttachment {
            user_id: req.headers().get("X-ORC-User-Id")?.unwrap_or_default(),
            name: req.headers().get("X-ORC-User-Name")?.unwrap_or_else(|| "User".to_string()),
            email: req.headers().get("X-ORC-User-Email")?.unwrap_or_default(),
            role: req.headers().get("X-ORC-Role")?.unwrap_or_else(|| "viewer".to_string()),
        };
        pair.server.serialize_attachment(&attachment)?;
        self.state.accept_web_socket(&pair.server);

        let mut members = Vec::new();
        for socket in self.state.get_websockets() {
            if let Ok(Some(member_attachment)) =
                socket.deserialize_attachment::<ClientAttachment>()
            {
                if member_attachment.email.is_empty()
                    || members.iter().any(|member: &serde_json::Value| {
                        member.get("email").and_then(|value| value.as_str())
                            == Some(member_attachment.email.as_str())
                    })
                {
                    continue;
                }
                members.push(serde_json::json!({
                    "id": member_attachment.user_id,
                    "name": member_attachment.name,
                    "email": member_attachment.email,
                    "role": member_attachment.role,
                    "selection": [],
                }));
            }
        }

        let hi = serde_json::json!({
            "type": "hi",
            "you": {
                "id": attachment.user_id,
                "name": attachment.name,
                "email": attachment.email,
                "role": attachment.role,
            },
            "members": members,
            "version": room.version,
            "role": attachment.role,
        });
        pair.server.send_with_str(&serde_json::to_string(&hi).unwrap_or_else(|_| "{}".to_string()))?;

        let mut motors = Vec::new();
        if let Ok(db) = self.env.d1("DB") {
            let motor_result = db
                .prepare(
                    "SELECT mo.filename,mo.content
                     FROM motors mo
                     JOIN users u ON u.id=mo.owner_id
                     JOIN members m ON m.email=u.email
                     WHERE m.project_id=?",
                )
                .bind(&[JsValue::from_str(&project_id)])?
                .all()
                .await;
            if let Ok(result) = motor_result {
                if let Ok(rows) = result.results::<serde_json::Value>() {
                    motors = rows
                        .into_iter()
                        .map(|row| serde_json::json!({
                            "name": row.get("filename").and_then(|value| value.as_str()).unwrap_or("motor"),
                            "content": row.get("content").and_then(|value| value.as_str()).unwrap_or_default(),
                        }))
                        .collect();
                }
            }
        }
        let welcome = serde_json::json!({
            "type": "welcome",
            "version": room.version,
            "role": attachment.role,
            "name": attachment.name,
            "model": room.model,
            "motors": motors,
        });
        pair.server.send_with_str(&serde_json::to_string(&welcome).unwrap_or_else(|_| "{}".to_string()))?;
        Response::from_websocket(pair.client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> worker::Result<()> {
        let text = match message {
            WebSocketIncomingMessage::String(text) => text,
            WebSocketIncomingMessage::Binary(_) => return Ok(()),
        };
        let envelope: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => return Ok(()),
        };
        let attachment = ws
            .deserialize_attachment::<ClientAttachment>()?
            .unwrap_or_else(|| ClientAttachment {
                user_id: String::new(),
                name: "User".to_string(),
                email: String::new(),
                role: "viewer".to_string(),
            });
        let message_type = envelope
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if let Some(rid) = envelope.get("rid").and_then(|value| value.as_str()) {
            let project_id = self
                .state
                .id()
                .name()
                .unwrap_or_else(|| "unknown".to_string());
            let mut room = self
                .state
                .storage()
                .get::<RoomState>("room")
                .await?
                .unwrap_or_else(|| RoomState {
                    model: RocketModel::default(),
                    version: 0,
                });
            let reply = match message_type {
                "init" => {
                    if attachment.role == "viewer" {
                        serde_json::json!({"ok": false, "error": "You have view-only access."})
                    } else if let Some(model) = envelope.get("model") {
                        match serde_json::from_value::<RocketModel>(model.clone()) {
                            Ok(model) => {
                                room.model = model;
                                room.version = envelope
                                    .get("version")
                                    .and_then(|value| value.as_i64())
                                    .unwrap_or(room.version);
                                let _ = self.state.storage().put("room", &room).await;
                                let model_json = model_json(&room.model).unwrap_or_else(|_| "{}".to_string());
                                if let Ok(db) = self.env.d1("DB") {
                                    let _ = db
                                        .prepare("UPDATE projects SET model=?,version=?,updated_at=? WHERE id=?")
                                        .bind(&[
                                            JsValue::from_str(&model_json),
                                            JsValue::from_f64(room.version as f64),
                                            JsValue::from_f64(now_seconds() as f64),
                                            JsValue::from_str(&project_id),
                                        ])?
                                        .run()
                                        .await;
                                }
                                serde_json::json!({"ok": true, "data": {"version": room.version}})
                            }
                            Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
                        }
                    } else {
                        serde_json::json!({"ok": false, "error": "Model required."})
                    }
                }
                "export" => serde_json::json!({
                    "ok": true,
                    "data": {"model": room.model, "version": room.version},
                }),
                "preview" => {
                    if let Ok(db) = self.env.d1("DB") {
                        let preview = envelope
                            .get("preview")
                            .and_then(|value| serde_json::to_string(value).ok())
                            .unwrap_or_else(|| "null".to_string());
                        let _ = db
                            .prepare("UPDATE projects SET preview=?,updated_at=? WHERE id=?")
                            .bind(&[
                                JsValue::from_str(&preview),
                                JsValue::from_f64(now_seconds() as f64),
                                JsValue::from_str(&project_id),
                            ])?
                            .run()
                            .await;
                    }
                    serde_json::json!({"ok": true, "data": {}})
                }
                "destroy" => serde_json::json!({"ok": true, "data": {}}),
                "snapshots" => {
                    let snapshots = if let Ok(db) = self.env.d1("DB") {
                        db.prepare("SELECT version,created_at FROM snapshots WHERE project_id=? ORDER BY version DESC LIMIT 200")
                            .bind(&[JsValue::from_str(&project_id)])?
                            .all()
                            .await
                            .ok()
                            .and_then(|result| result.results::<serde_json::Value>().ok())
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    serde_json::json!({"ok": true, "data": snapshots})
                }
                "snapshot" => {
                    let version = envelope
                        .get("version")
                        .and_then(|value| value.as_i64())
                        .unwrap_or(room.version);
                    let model = if let Ok(db) = self.env.d1("DB") {
                        db.prepare("SELECT model FROM snapshots WHERE project_id=? AND version=?")
                            .bind(&[
                                JsValue::from_str(&project_id),
                                JsValue::from_f64(version as f64),
                            ])?
                            .first::<serde_json::Value>(None)
                            .await
                            .ok()
                            .flatten()
                            .and_then(|row| row.get("model").and_then(|value| value.as_str()).map(str::to_string))
                    } else {
                        None
                    };
                    match model.and_then(|model| model_from_json(&model).ok()) {
                        Some(model) => serde_json::json!({"ok": true, "data": {"model": model, "version": version}}),
                        None => serde_json::json!({"ok": false, "error": "Snapshot not found."}),
                    }
                }
                "history" => {
                    let edits = if let Ok(db) = self.env.d1("DB") {
                        db.prepare("SELECT version,user_id,user_name,at,minor,changes,note FROM edits WHERE project_id=? ORDER BY version DESC LIMIT 600")
                            .bind(&[JsValue::from_str(&project_id)])?
                            .all()
                            .await
                            .ok()
                            .and_then(|result| result.results::<serde_json::Value>().ok())
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    serde_json::json!({"ok": true, "data": edits})
                }
                "revert" => serde_json::json!({"ok": false, "error": "Revert is not implemented in this rewrite yet."}),
                _ => serde_json::json!({"ok": false, "error": "Unknown room request."}),
            };
            let reply = serde_json::json!({
                "type": "reply",
                "rid": rid,
                "ok": reply.get("ok").and_then(|value| value.as_bool()).unwrap_or(false),
                "data": reply.get("data").cloned().unwrap_or(serde_json::json!(null)),
                "error": reply.get("error").cloned().unwrap_or(serde_json::json!(null)),
            });
            let _ = ws.send_with_str(&serde_json::to_string(&reply).unwrap_or_else(|_| "{}".to_string()));
            return Ok(());
        }
        if message_type == "presence" {
            for socket in self.state.get_websockets() {
                let _ = socket.send_with_str(&text);
            }
            return Ok(());
        }
        if message_type != "ops" {
            return Ok(());
        }
        if attachment.role == "viewer" {
            let seq = envelope.get("seq").and_then(|value| value.as_i64()).unwrap_or(0);
            let ack = serde_json::json!({ "type": "ack", "seq": seq });
            let _ = ws.send_with_str(&serde_json::to_string(&ack).unwrap_or_else(|_| "{}".to_string()));
            return Ok(());
        }
        let ops: Vec<orc_core::ModelOp> = envelope
            .get("ops")
            .and_then(|value| value.as_array())
            .and_then(|_| serde_json::from_value(envelope.get("ops").cloned().unwrap_or_default()).ok())
            .unwrap_or_default();
        let seq = envelope.get("seq").and_then(|value| value.as_i64()).unwrap_or(0);
        if ops.is_empty() {
            let ack = serde_json::json!({ "type": "ack", "seq": seq });
            let _ = ws.send_with_str(&serde_json::to_string(&ack).unwrap_or_else(|_| "{}".to_string()));
            return Ok(());
        }

        let mut room = self
            .state
            .storage()
            .get::<RoomState>("room")
            .await?
            .unwrap_or_else(|| RoomState {
                model: RocketModel::default(),
                version: 0,
            });
        let mut accepted = Vec::new();
        for op in ops {
            if let Some(applied) = orc_core::apply_op(&mut room.model, &op) {
                accepted.push(applied);
            }
        }
        if accepted.is_empty() {
            let ack = serde_json::json!({ "type": "ack", "seq": seq });
            let _ = ws.send_with_str(&serde_json::to_string(&ack).unwrap_or_else(|_| "{}".to_string()));
            return Ok(());
        }
        room.version += 1;
        self.state.storage().put("room", &room).await?;
        let project_id = self
            .state
            .id()
            .name()
            .unwrap_or_else(|| "unknown".to_string());
        if let Ok(db) = self.env.d1("DB") {
            if let Ok(model_json) = model_json(&room.model) {
                let values = [
                    JsValue::from_str(&model_json),
                    JsValue::from_f64(room.version as f64),
                    JsValue::from_f64(now_seconds() as f64),
                    JsValue::from_str(&project_id),
                ];
                let _ = db
                    .prepare("UPDATE projects SET model=?,version=?,updated_at=? WHERE id=?")
                    .bind(&values)?
                    .run()
                    .await;
                let changes = serde_json::to_string(&accepted).unwrap_or_else(|_| "[]".to_string());
                let edit_values = [
                    JsValue::from_str(&project_id),
                    JsValue::from_f64(room.version as f64),
                    JsValue::from_str(&attachment.user_id),
                    JsValue::from_str(&attachment.name),
                    JsValue::from_f64(now_seconds() as f64),
                    JsValue::from_f64(0.0),
                    JsValue::from_str(&changes),
                    JsValue::from_str("[]"),
                    JsValue::null(),
                ];
                let _ = db
                    .prepare(
                        "INSERT OR REPLACE INTO edits
                         (project_id,version,user_id,user_name,at,minor,changes,inverse,note)
                         VALUES (?,?,?,?,?,?,?,?,?)",
                    )
                    .bind(&edit_values)?
                    .run()
                    .await;
            }
        }
        let broadcast = serde_json::json!({
            "type": "ops",
            "version": room.version,
            "seq": seq,
            "ops": accepted,
        });
        let text = serde_json::to_string(&broadcast).unwrap_or_else(|_| "{}".to_string());
        for socket in self.state.get_websockets() {
            let _ = socket.send_with_str(&text);
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> worker::Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: worker::Error) -> worker::Result<()> {
        Ok(())
    }
}

async fn serve_jar(req: Request, env: &Env, key: &str) -> worker::Result<Response> {
    let bucket = env.bucket("OPENROCKET_ASSETS")?;

    let head = match bucket.head(key).await? {
        Some(object) => object,
        None => return Response::error("JAR is not uploaded to R2.", 404),
    };
    let total = head.size();

    let range_header = req.headers().get("Range")?;
    if let Some(range_header) = range_header {
        let range_header = range_header.trim();
        if let Some(spec) = range_header.strip_prefix("bytes=") {
            let mut parts = spec.split('-');
            let start_text = parts.next().unwrap_or("");
            let end_text = parts.next().unwrap_or("");
            let start = start_text.parse::<u64>().ok();
            let end = end_text.parse::<u64>().ok();
            let r2_range = match (start, end) {
                (Some(start), Some(end)) if end >= start => {
                    let length = (end - start + 1).min(total.saturating_sub(start));
                    worker::Range::OffsetWithLength { offset: start, length }
                }
                (Some(start), None) => worker::Range::OffsetToEnd { offset: start },
                (None, Some(suffix)) => worker::Range::Suffix { suffix },
                _ => worker::Range::OffsetWithLength { offset: 0, length: total },
            };
            if let Some(object) = bucket.get(key).range(r2_range).execute().await? {
                let actual = object.range().unwrap_or(worker::Range::OffsetWithLength {
                    offset: 0,
                    length: object.size(),
                });
                let (offset, length) = match actual {
                    worker::Range::OffsetWithLength { offset, length } => (offset, length),
                    worker::Range::OffsetToEnd { offset } => (offset, total.saturating_sub(offset)),
                    worker::Range::Prefix { length } => (0, length),
                    worker::Range::Suffix { suffix } => (total.saturating_sub(suffix), suffix),
                };
                if let Some(body) = object.body() {
                    let bytes = body.bytes().await?;
                    let headers = Headers::new();
                    headers.set("Content-Type", "application/java-archive")?;
                    headers.set("Accept-Ranges", "bytes")?;
                    headers.set("Cache-Control", "public, max-age=31536000, immutable")?;
                    headers.set(
                        "Content-Range",
                        &format!("bytes {}-{}/{}", offset, offset.saturating_add(length.saturating_sub(1)), total),
                    )?;
                    headers.set("Content-Length", &bytes.len().to_string())?;
                    return Ok(ResponseBuilder::new()
                        .with_status(206)
                        .with_headers(headers)
                        .fixed(bytes));
                }
            }
        }
    }

    let object = match bucket.get(key).execute().await? {
        Some(object) => object,
        None => return Response::error("JAR is missing.", 404),
    };
    let body = object.body().ok_or_else(|| worker::Error::RustError("JAR has no body.".into()))?;
    let bytes = body.bytes().await?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/java-archive")?;
    headers.set("Accept-Ranges", "bytes")?;
    headers.set("Cache-Control", "public, max-age=31536000, immutable")?;
    headers.set("Content-Length", &bytes.len().to_string())?;
    Ok(ResponseBuilder::new()
        .with_status(200)
        .with_headers(headers)
        .fixed(bytes))
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> worker::Result<Response> {
    let path = req.path();
    if path == "/healthz" {
        return Response::from_json(&serde_json::json!({ "ok": true }));
    }
    if path == "/or/OpenRocket-web.jar" {
        return serve_jar(req, &env, "OpenRocket-web.jar").await;
    }
    if path.starts_with("/or/") && path.ends_with(".jar") {
        let key = path.trim_start_matches('/');
        let key = key.strip_prefix("or/").unwrap_or(key);
        return serve_jar(req, &env, key).await;
    }
    if path.starts_with("/auth/") {
        return handle_auth(req, &env).await;
    }
    if path.starts_with("/api/") {
        return handle_projects(req, &env).await;
    }
    if path.starts_with("/room/") {
        return handle_room(req, &env).await;
    }
    match env.assets("ASSETS") {
        Ok(fetcher) => fetcher.fetch_request(req).await,
        Err(_) => Response::error("Static assets are not configured.", 500),
    }
}
