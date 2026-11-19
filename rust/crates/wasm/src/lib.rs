use orc_core::{apply_op, RocketModel};
use serde_json::Value;
use std::cell::RefCell;
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    Element, HtmlInputElement, MessageEvent, RequestInit, Response, WebSocket,
};

thread_local! {
    static APP: RefCell<AppState> = RefCell::new(AppState::default());
}

#[derive(Default)]
struct AppState {
    me: Option<Value>,
    project: Option<Value>,
    model: Option<RocketModel>,
    selected: Option<String>,
    ws: Option<WebSocket>,
}

fn window() -> web_sys::Window {
    web_sys::window().expect("no browser window")
}

fn document() -> web_sys::Document {
    window().document().expect("no document")
}

fn app_element() -> Element {
    document()
        .get_element_by_id("app")
        .expect("missing #app")
}

fn create(tag: &str) -> Element {
    document().create_element(tag).expect("create element")
}

fn set_text(element: &Element, text: &str) {
    element.set_text_content(Some(text));
}

fn set_class(element: &Element, class: &str) {
    element.set_attribute("class", class).ok();
}

fn append(parent: &Element, child: &Element) {
    parent.append_child(child).ok();
}

fn on_click(element: Element, callback: impl FnMut(web_sys::Event) + 'static) {
    let closure = Closure::wrap(Box::new(callback) as Box<dyn FnMut(web_sys::Event)>);
    element
        .add_event_listener_with_callback("click", closure.as_ref().unchecked_ref())
        .ok();
    closure.forget();
}

async fn request_text(url: &str, method: &str, body: Option<String>) -> Result<(u16, String), JsValue> {
    let init = RequestInit::new();
    init.set_method(method);
    init.set_credentials(web_sys::RequestCredentials::SameOrigin);
    let headers = web_sys::Headers::new()?;
    headers.set("X-ORC-Client", "1")?;
    if body.is_some() {
        headers.set("Content-Type", "application/json")?;
    }
    init.set_headers(&headers);
    if let Some(body) = body {
        init.set_body(&JsValue::from_str(&body));
    }
    let promise = window().fetch_with_str_and_init(url, &init);
    let response_value = JsFuture::from(promise).await?;
    let response: Response = response_value.dyn_into()?;
    let status = response.status();
    let text_value = JsFuture::from(response.text()?).await?;
    let text = text_value.as_string().unwrap_or_default();
    Ok((status, text))
}

async fn json_request(url: &str, method: &str, body: Option<Value>) -> Result<Value, JsValue> {
    let body = body.map(|body| serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string()));
    let (status, text) = request_text(url, method, body).await?;
    if !(200..300).contains(&status) {
        let message = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|value| value.get("error").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| format!("Request failed ({status})."));
        return Err(JsValue::from_str(&message));
    }
    serde_json::from_str(&text).map_err(|error| JsValue::from_str(&error.to_string()))
}

fn escape_xml_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn toast(message: &str) {
    let app = app_element();
    let existing = document().query_selector(".toast").ok().flatten();
    if let Some(existing) = existing {
        existing.remove();
    }
    let toast = create("div");
    set_class(&toast, "toast");
    set_text(&toast, message);
    append(&app, &toast);
    let closure = Closure::once(move || {
        toast.remove();
    });
    window()
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            closure.as_ref().unchecked_ref(),
            3500,
        )
        .ok();
    closure.forget();
}

fn input_value(id: &str) -> String {
    document()
        .get_element_by_id(id)
        .and_then(|element| element.dyn_into::<HtmlInputElement>().ok())
        .map(|input| input.value())
        .unwrap_or_default()
}

fn render_landing() {
    let app = app_element();
    app.set_inner_html(
        r##"<main class="landing">
            <section class="hero">
                <div class="brand-mark">OR</div>
                <h1>OpenRocket in Rust &amp; WebAssembly</h1>
                <p>Native browser editing, Cloudflare collaboration, and .ork-compatible projects.</p>
                <div class="auth-grid">
                    <form id="login-form" class="auth-card">
                        <h2>Sign in</h2>
                        <label>Email<input id="login-email" type="email" autocomplete="email" required></label>
                        <label>Password<input id="login-password" type="password" autocomplete="current-password" required></label>
                        <button id="login-button" class="primary" type="button">Sign in</button>
                    </form>
                    <form id="register-form" class="auth-card">
                        <h2>Create account</h2>
                        <label>Name<input id="register-name" type="text" autocomplete="name" required></label>
                        <label>Email<input id="register-email" type="email" autocomplete="email" required></label>
                        <label>Password<input id="register-password" type="password" autocomplete="new-password" minlength="10" required></label>
                        <button id="register-button" class="primary" type="button">Create account</button>
                    </form>
                </div>
            </section>
        </main>"##,
    );

    if let Some(button) = document().get_element_by_id("login-button") {
        on_click(button, |_| {
            spawn_local(async move {
                let email = input_value("login-email");
                let password = input_value("login-password");
                match json_request(
                    "/auth/login",
                    "POST",
                    Some(serde_json::json!({ "email": email, "password": password })),
                )
                .await
                {
                    Ok(_) => {
                        let _ = bootstrap().await;
                    }
                    Err(error) => toast(&error.as_string().unwrap_or_else(|| "Sign-in failed.".to_string())),
                }
            });
        });
    }

    if let Some(button) = document().get_element_by_id("register-button") {
        on_click(button, |_| {
            spawn_local(async move {
                let name = input_value("register-name");
                let email = input_value("register-email");
                let password = input_value("register-password");
                match json_request(
                    "/auth/register",
                    "POST",
                    Some(serde_json::json!({ "name": name, "email": email, "password": password })),
                )
                .await
                {
                    Ok(_) => {
                        let _ = bootstrap().await;
                    }
                    Err(error) => toast(&error.as_string().unwrap_or_else(|| "Account creation failed.".to_string())),
                }
            });
        });
    }
}

fn render_dashboard(projects: &[Value], me: &Value) {
    let app = app_element();
    app.set_inner_html("");

    let header = create("header");
    set_class(&header, "topbar");
    let brand = create("div");
    set_class(&brand, "brand");
    brand.set_inner_html("<span class=\"brand-mark\">OR</span><span>OpenRocket Cloud</span>");
    append(&header, &brand);

    let user_name = me
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("User");
    let user = create("button");
    set_class(&user, "user-button");
    set_text(&user, user_name);
    on_click(user.clone(), move |_| {
        spawn_local(async move {
            let _ = json_request("/auth/logout", "POST", None).await;
            let _ = window().location().set_href("/");
        });
    });
    append(&header, &user);
    append(&app, &header);

    let main = create("main");
    set_class(&main, "dashboard");
    let heading = create("div");
    set_class(&heading, "dashboard-heading");
    let title = create("h1");
    set_text(&title, "My designs");
    append(&heading, &title);
    let new_button = create("button");
    set_class(&new_button, "primary");
    set_text(&new_button, "New rocket");
    on_click(new_button.clone(), |_| {
        spawn_local(async move {
            let name = window().prompt_with_message("Rocket name").ok().flatten();
            let name = name.unwrap_or_else(|| "My rocket".to_string());
            match json_request(
                "/api/projects",
                "POST",
                Some(serde_json::json!({ "name": name })),
            )
            .await
            {
                Ok(project) => {
                    if let Some(id) = project.get("id").and_then(Value::as_str) {
                        open_project(id);
                    }
                }
                Err(error) => toast(&error.as_string().unwrap_or_else(|| "Could not create project.".to_string())),
            }
        });
    });
    append(&heading, &new_button);
    append(&main, &heading);

    let grid = create("section");
    set_class(&grid, "project-grid");
    for project in projects {
        let id = project
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let name = project
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Untitled rocket");
        let role = project
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("viewer");
        let card = create("article");
        set_class(&card, "project-card");
        card.set_inner_html(&format!(
            r#"<div class="rocket-preview"><svg viewBox="0 0 120 180" aria-hidden="true">
                <path d="M60 12 C82 42 82 122 60 158 C38 122 38 42 60 12Z" fill="currentColor"/>
                <path d="M60 158 L38 170 L82 170Z" fill="currentColor"/>
                <path d="M38 112 L18 142 L38 142Z M82 112 L102 142 L82 142Z" fill="currentColor"/>
            </svg></div>
            <div class="project-card-body"><h2>{}</h2><span class="role">{}</span></div>"#,
            html_escape(name),
            html_escape(role),
        ));
        on_click(card.clone(), move |_| open_project(&id));
        append(&grid, &card);
    }
    append(&main, &grid);
    append(&app, &main);
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn open_project(project_id: &str) {
    let project_id = project_id.to_string();
    spawn_local(async move {
        match json_request(&format!("/api/projects/{project_id}"), "GET", None).await {
            Ok(project) => {
                APP.with(|state| {
                    state.borrow_mut().project = Some(project.clone());
                    if let Some(model_value) = project.get("model") {
                        state.borrow_mut().model =
                            serde_json::from_value::<RocketModel>(model_value.clone()).ok();
                    }
                });
                render_project_shell(&project_id);
                connect_room(&project_id);
            }
            Err(error) => toast(&error.as_string().unwrap_or_else(|| "Could not open project.".to_string())),
        }
    });
}

fn connect_room(project_id: &str) {
    let location = window().location();
    let host = location.host().unwrap_or_else(|_| "localhost".to_string());
    let protocol = if location.protocol().unwrap_or_else(|_| "http:".to_string()) == "https:" {
        "wss:"
    } else {
        "ws:"
    };
    let socket = match WebSocket::new(&format!("{protocol}//{host}/room/{project_id}")) {
        Ok(socket) => socket,
        Err(error) => {
            toast(&error.as_string().unwrap_or_else(|| "Could not open collaboration room.".to_string()));
            return;
        }
    };
    APP.with(|state| state.borrow_mut().ws = Some(socket.clone()));

    let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
        let text = event.data().as_string().unwrap_or_default();
        let Ok(message) = serde_json::from_str::<Value>(&text) else {
            return;
        };
        match message.get("type").and_then(Value::as_str) {
            Some("welcome") => {
                if let Some(model) = message.get("model") {
                    if let Ok(model) = serde_json::from_value::<RocketModel>(model.clone()) {
                        APP.with(|state| {
                            state.borrow_mut().model = Some(model);
                        });
                        render_designer();
                    }
                }
            }
            Some("ops") => {
                let Some(ops) = message.get("ops").and_then(Value::as_array) else {
                    return;
                };
                let mut changed = false;
                APP.with(|state| {
                    let mut state = state.borrow_mut();
                    if let Some(model) = state.model.as_mut() {
                        for op_value in ops {
                            if let Ok(op) = serde_json::from_value(op_value.clone()) {
                                if apply_op(model, &op).is_some() {
                                    changed = true;
                                }
                            }
                        }
                    }
                });
                if changed {
                    render_designer();
                }
            }
            Some("ack") => {}
            _ => {}
        }
    }) as Box<dyn FnMut(MessageEvent)>);
    socket
        .set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();

    let on_close = Closure::once(move || {});
    socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
    on_close.forget();
}

fn render_project_shell(project_id: &str) {
    let app = app_element();
    let (name, role) = APP.with(|state| {
        let state = state.borrow();
        let name = state
            .project
            .as_ref()
            .and_then(|project| project.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("Rocket")
            .to_string();
        let role = state
            .project
            .as_ref()
            .and_then(|project| project.get("role"))
            .and_then(Value::as_str)
            .unwrap_or("viewer")
            .to_string();
        (name, role)
    });
    app.set_inner_html("");
    let header = create("header");
    set_class(&header, "topbar");
    let back = create("button");
    set_class(&back, "icon-button");
    set_text(&back, "←");
    on_click(back.clone(), |_| {
        spawn_local(async move {
            bootstrap().await;
        });
    });
    append(&header, &back);
    let title = create("div");
    set_class(&title, "project-title");
    set_text(&title, &name);
    append(&header, &title);
    let actions = create("div");
    set_class(&actions, "project-actions");
    let download = create("a");
    set_class(&download, "toolbar-button");
    download.set_attribute("href", &format!("/api/projects/{project_id}/download")).ok();
    set_text(&download, "Download");
    append(&actions, &download);
    if role == "owner" {
        let share = create("button");
        set_class(&share, "toolbar-button");
        set_text(&share, "Share");
        let share_id = project_id.to_string();
        on_click(share.clone(), move |_| {
            let share_id = share_id.clone();
            spawn_local(async move {
                let email = window().prompt_with_message("Share with account email").ok().flatten();
                let Some(email) = email else { return };
                let role = window().prompt_with_message("Role: editor or viewer").ok().flatten().unwrap_or_else(|| "viewer".to_string());
                if !["editor", "viewer"].contains(&role.as_str()) {
                    toast("Role must be editor or viewer.");
                    return;
                }
                match json_request(
                    &format!("/api/projects/{share_id}/members"),
                    "POST",
                    Some(serde_json::json!({ "email": email, "role": role })),
                )
                .await
                {
                    Ok(_) => toast("Sharing updated."),
                    Err(error) => toast(&error.as_string().unwrap_or_else(|| "Could not update sharing.".to_string())),
                }
            });
        });
        append(&actions, &share);
    }
    append(&header, &actions);
    append(&app, &header);

    let layout = create("main");
    set_class(&layout, "designer-layout");
    let tree = create("aside");
    set_class(&tree, "component-panel");
    tree.set_attribute("id", "component-panel").ok();
    append(&layout, &tree);
    let canvas = create("section");
    set_class(&canvas, "rocket-canvas");
    canvas.set_attribute("id", "rocket-canvas").ok();
    append(&layout, &canvas);
    let inspector = create("aside");
    set_class(&inspector, "inspector");
    inspector.set_attribute("id", "inspector").ok();
    append(&layout, &inspector);
    append(&app, &layout);
    render_designer();
}

fn render_designer() {
    APP.with(|state| {
        let state = state.borrow();
        let role = state
            .project
            .as_ref()
            .and_then(|project| project.get("role"))
            .and_then(Value::as_str)
            .unwrap_or("viewer");
        let model = match state.model.as_ref() {
            Some(model) => model,
            None => return,
        };
        let panel = document().get_element_by_id("component-panel");
        if let Some(panel) = panel {
            panel.set_inner_html("<div class=\"panel-heading\"><h2>Components</h2></div>");
            let list = create("div");
            set_class(&list, "component-list");
            let mut components: Vec<_> = model
                .objs
                .iter()
                .filter(|(_, object)| object.t != "openrocket")
                .filter(|(_, object)| matches!(object.t.as_str(), "rocket" | "stage" | "nosecone" | "bodytube" | "finset" | "parachute"))
                .collect();
            components.sort_by_key(|(id, object)| (object.o, id.to_string()));
            for (id, object) in components {
                let row = create("button");
                set_class(&row, "component-row");
                let label = object
                    .v
                    .get("name")
                    .and_then(|name| parse_xml_name(name))
                    .unwrap_or_else(|| object.t.clone());
                set_text(&row, &format!("{} · {}", label, object.t));
                let selected = state.selected.clone();
                let id_for_click = id.clone();
                on_click(row.clone(), move |_| {
                    APP.with(|state| state.borrow_mut().selected = Some(id_for_click.clone()));
                    render_designer();
                });
                if selected.as_deref() == Some(id.as_str()) {
                    row.set_attribute("aria-current", "true").ok();
                }
                append(&list, &row);
            }
            append(&panel, &list);
            if role != "viewer" {
                let toolbar = create("div");
                set_class(&toolbar, "component-toolbar");
                let add = create("button");
                set_class(&add, "toolbar-button");
                set_text(&add, "Add stage");
                on_click(add.clone(), |_| add_stage());
                append(&toolbar, &add);
                let remove = create("button");
                set_class(&remove, "toolbar-button danger");
                set_text(&remove, "Remove");
                on_click(remove.clone(), |_| remove_selected());
                append(&toolbar, &remove);
                append(&panel, &toolbar);
            }
        }

        let canvas = document().get_element_by_id("rocket-canvas");
        if let Some(canvas) = canvas {
            canvas.set_inner_html(
                r##"<svg class="rocket-drawing" viewBox="0 0 420 520" aria-label="Rocket preview">
                    <defs>
                        <linearGradient id="rocket-fill" x1="0" x2="1">
                            <stop offset="0" stop-color="#f6f0e6"/>
                            <stop offset="1" stop-color="#d7dfe8"/>
                        </linearGradient>
                    </defs>
                    <ellipse cx="210" cy="455" rx="118" ry="12" fill="#b8c1c8" opacity=".45"/>
                    <path d="M210 35 C270 105 270 320 210 420 C150 320 150 105 210 35Z" fill="url(#rocket-fill)" stroke="#26364a" stroke-width="4"/>
                    <path d="M150 300 L70 410 L150 390Z M270 300 L350 410 L270 390Z" fill="#c44a3a" stroke="#26364a" stroke-width="4"/>
                    <path d="M210 420 L150 448 L270 448Z" fill="#26364a" opacity=".9"/>
                </svg>"##,
            );
        }

        let inspector = document().get_element_by_id("inspector");
        if let Some(inspector) = inspector {
            inspector.set_inner_html("<div class=\"panel-heading\"><h2>Properties</h2></div>");
            let selected = state.selected.as_deref();
            let selected_object = selected.and_then(|id| model.objs.get(id));
            if let Some(object) = selected_object {
                let name = object
                    .v
                    .get("name")
                    .and_then(|name| parse_xml_name(name))
                    .unwrap_or_default();
                let label = create("label");
                set_class(&label, "field");
                label.set_inner_html("<span>Name</span>");
                let input = create("input");
                let input: HtmlInputElement = input.dyn_into().expect("input");
                input.set_value(&name);
                input.set_attribute("disabled", if role == "viewer" { "true" } else { "" }).ok();
                let id = selected.unwrap_or_default().to_string();
                let on_change = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    let target = event.target();
                    let Some(input) = target.and_then(|target| target.dyn_into::<HtmlInputElement>().ok()) else {
                        return;
                    };
                    send_set_op(&id, "name", &format!("<name>{}</name>", escape_xml_text(&input.value())));
                }) as Box<dyn FnMut(web_sys::Event)>);
                input
                    .add_event_listener_with_callback("change", on_change.as_ref().unchecked_ref())
                    .ok();
                on_change.forget();
                append(&label, &input);
                append(&inspector, &label);
            } else {
                let hint = create("div");
                set_class(&hint, "inspector-empty");
                set_text(&hint, "Select a component to edit its properties.");
                append(&inspector, &hint);
            }
        }
    });
}

fn parse_xml_name(value: &str) -> Option<String> {
    let start = value.find('>')? + 1;
    let end = value.rfind('<')?;
    if start > end {
        None
    } else {
        Some(value[start..end].replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))
    }
}

fn send_set_op(id: &str, key: &str, value: &str) {
    let op = orc_core::ModelOp {
        op: "set".to_string(),
        id: id.to_string(),
        p: None,
        o: None,
        t: None,
        v: Some(std::collections::BTreeMap::from([
            (key.to_string(), Some(value.to_string())),
        ])),
        k: None,
    };
    send_ops(vec![op]);
}

fn send_ops(ops: Vec<orc_core::ModelOp>) {
    APP.with(|state| {
        let state = state.borrow();
        let Some(ws) = state.ws.as_ref() else {
            toast("Collaboration room is not connected.");
            return;
        };
        let envelope = serde_json::json!({ "type": "ops", "seq": 1, "ops": ops });
        if let Err(error) = ws.send_with_str(&serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".to_string())) {
            toast(&error.as_string().unwrap_or_else(|| "Could not send edit.".to_string()));
        }
    });
}

fn add_stage() {
    APP.with(|state| {
        let state = state.borrow();
        let Some(model) = state.model.as_ref() else {
            return;
        };
        let rocket = model
            .objs
            .iter()
            .find(|(_, object)| object.t == "rocket")
            .map(|(id, _)| id.clone());
        let Some(parent) = rocket else {
            toast("This design has no rocket body.");
            return;
        };
        let op = orc_core::ModelOp {
            op: "put".to_string(),
            id: Uuid::new_v4().to_string(),
            p: Some(parent),
            o: Some(100),
            t: Some("stage".to_string()),
            v: Some(std::collections::BTreeMap::from([
                ("@".to_string(), Some(String::new())),
                ("name".to_string(), Some("<name>Stage</name>".to_string())),
            ])),
            k: Some(vec!["@".to_string(), "name".to_string()]),
        };
        send_ops(vec![op]);
    });
}

fn remove_selected() {
    APP.with(|state| {
        let state = state.borrow();
        let Some(id) = state.selected.clone() else {
            toast("Select a component first.");
            return;
        };
        let op = orc_core::ModelOp {
            op: "del".to_string(),
            id,
            p: None,
            o: None,
            t: None,
            v: None,
            k: None,
        };
        send_ops(vec![op]);
    });
}

async fn bootstrap() {
    match json_request("/api/me", "GET", None).await {
        Ok(me) => {
            APP.with(|state| state.borrow_mut().me = Some(me.clone()));
            match json_request("/api/projects", "GET", None).await {
                Ok(projects) => {
                    if let Some(projects) = projects.as_array() {
                        render_dashboard(projects, &me);
                    } else {
                        render_dashboard(&[], &me);
                    }
                }
                Err(error) => toast(&error.as_string().unwrap_or_else(|| "Could not load projects.".to_string())),
            }
        }
        Err(_) => {
            render_landing();
        }
    }
}

#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    spawn_local(async move {
        bootstrap().await;
    });
    Ok(())
}
