use flate2::read::GzDecoder;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use uuid::Uuid;
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};
use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD,
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

pub const DOC: &str = "doc";
pub const SIMS: &str = "sims";
pub const ATTRS: &str = "@";
pub const RAW: &str = "#raw";
pub const ATT: &str = "#att";

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RocketModel {
    pub objs: BTreeMap<String, RocketObject>,
}

impl RocketModel {
    pub fn size(&self) -> ModelSize {
        let mut bytes = 0usize;
        let mut objects = 0usize;
        for object in self.objs.values() {
            objects += 1;
            for value in object.v.values() {
                bytes += value.len();
            }
        }
        ModelSize { bytes, objects }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RocketObject {
    pub t: String,
    pub p: Option<String>,
    pub o: i64,
    pub k: Vec<String>,
    pub v: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelSize {
    pub bytes: usize,
    pub objects: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelOp {
    pub op: String,
    pub id: String,
    #[serde(default)]
    pub p: Option<String>,
    #[serde(default)]
    pub o: Option<i64>,
    #[serde(default)]
    pub t: Option<String>,
    #[serde(default)]
    pub v: Option<BTreeMap<String, Option<String>>>,
    #[serde(default)]
    pub k: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct XmlElement {
    pub tag: String,
    pub attrs: BTreeMap<String, String>,
    pub children: Vec<XmlChild>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum XmlChild {
    Element(XmlElement),
    Text(String),
}

impl XmlElement {
    pub fn elements(&self) -> impl Iterator<Item = &XmlElement> {
        self.children.iter().filter_map(|child| match child {
            XmlChild::Element(element) => Some(element),
            XmlChild::Text(_) => None,
        })
    }

    pub fn first(&self, name: &str) -> Option<&XmlElement> {
        self.elements().find(|element| element.tag == name)
    }

    pub fn text(&self) -> String {
        self.children
            .iter()
            .filter_map(|child| match child {
                XmlChild::Text(text) => Some(text.as_str()),
                XmlChild::Element(_) => None,
            })
            .collect::<String>()
    }

    fn has_element_children(&self) -> bool {
        self.children
            .iter()
            .any(|child| matches!(child, XmlChild::Element(_)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportErrorKind {
    InvalidArchive,
    InvalidDesign,
    RockSim,
    MissingRocket,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportError {
    pub kind: ImportErrorKind,
    pub message: String,
}

impl ImportError {
    fn new(kind: ImportErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ImportError {}

fn cmp_strings(a: &str, b: &str) -> Ordering {
    a.cmp(b)
}

fn esc_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\n', "&#10;")
        .replace('\r', "&#13;")
        .replace('\t', "&#9;")
}

fn esc_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#13;")
}

pub fn attrs_canonical(attrs: &BTreeMap<String, String>) -> String {
    let mut entries: Vec<_> = attrs.iter().collect();
    entries.sort_by(|(a, _), (b, _)| cmp_strings(a, b));
    entries
        .iter()
        .map(|(key, value)| format!(" {key}=\"{}\"", esc_attr(value)))
        .collect::<String>()
}

pub fn canonical(element: &XmlElement) -> String {
    let mut output = format!("<{}{}>", element.tag, attrs_canonical(&element.attrs));
    for child in &element.children {
        match child {
            XmlChild::Element(child) => output.push_str(&canonical(child)),
            XmlChild::Text(text) => {
                let blank = text.chars().all(|ch| matches!(ch, ' ' | '\t' | '\n' | '\r'));
                if !(element.has_element_children() && blank) {
                    output.push_str(&esc_text(text));
                }
            }
        }
    }
    output.push_str("</");
    output.push_str(&element.tag);
    output.push('>');
    output
}

fn decode_attribute(event: &BytesStart<'_>) -> Result<BTreeMap<String, String>, ImportError> {
    let mut attrs = BTreeMap::new();
    for attr in event.attributes().with_checks(true) {
        let attr = attr.map_err(|error| {
            ImportError::new(
                ImportErrorKind::InvalidDesign,
                format!("Invalid XML attribute: {error}"),
            )
        })?;
        let name = attr.key.as_ref().to_string();
        let value = quick_xml::escape::unescape(attr.value.as_ref()).map_err(|error| {
                ImportError::new(
                    ImportErrorKind::InvalidDesign,
                    format!("Invalid XML attribute value: {error}"),
                )
            })?;
        let value = value
            .replace("\r\n", " ")
            .replace('\n', " ")
            .replace('\r', " ")
            .replace('\t', " ");
        attrs.insert(name, value);
    }
    Ok(attrs)
}

pub fn parse_xml(xml: &str) -> Result<XmlElement, ImportError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root: Option<XmlElement> = None;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(event)) => {
                let tag = event.name().as_ref().to_string();
                let attrs = decode_attribute(&event)?;
                stack.push(XmlElement {
                    tag,
                    attrs,
                    children: Vec::new(),
                });
            }
            Ok(Event::Empty(event)) => {
                let tag = event.name().as_ref().to_string();
                let attrs = decode_attribute(&event)?;
                let element = XmlElement {
                    tag,
                    attrs,
                    children: Vec::new(),
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::Element(element));
                } else if root.is_none() {
                    root = Some(element);
                } else {
                    return Err(ImportError::new(
                        ImportErrorKind::InvalidDesign,
                        "This XML has multiple root elements.",
                    ));
                }
            }
            Ok(Event::End(_)) => {
                if let Some(element) = stack.pop() {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(XmlChild::Element(element));
                    } else if root.is_none() {
                        root = Some(element);
                    } else {
                        return Err(ImportError::new(
                            ImportErrorKind::InvalidDesign,
                            "This XML has multiple root elements.",
                        ));
                    }
                }
            }
            Ok(Event::Text(event)) => {
                let text = event.as_ref();
                let text = text
                    .replace("\r\n", "\n")
                    .replace('\r', "\n");
                if let Some(parent) = stack.last_mut() {
                    if let Some(XmlChild::Text(previous)) = parent.children.last_mut() {
                        previous.push_str(&text);
                    } else {
                        parent.children.push(XmlChild::Text(text.to_string()));
                    }
                }
            }
            Ok(Event::CData(event)) => {
                let text = event.as_ref().to_string();
                if let Some(parent) = stack.last_mut() {
                    if let Some(XmlChild::Text(previous)) = parent.children.last_mut() {
                        previous.push_str(&text);
                    } else {
                        parent.children.push(XmlChild::Text(text));
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(ImportError::new(
                    ImportErrorKind::InvalidDesign,
                    format!("This is not valid XML: {error}"),
                ));
            }
        }
        buffer.clear();
    }
    if !stack.is_empty() {
        return Err(ImportError::new(
            ImportErrorKind::InvalidDesign,
            "This XML has unclosed elements.",
        ));
    }
    root.ok_or_else(|| {
        ImportError::new(
            ImportErrorKind::InvalidDesign,
            "This XML has no root element.",
        )
    })
}

fn reserved(id: &str) -> bool {
    id == DOC
        || id == SIMS
        || id.starts_with("doc:")
}

fn would_cycle(model: &RocketModel, id: &str, parent: &str) -> bool {
    let mut current = Some(parent);
    let mut guard = 0;
    while let Some(value) = current {
        if guard >= 100_000 {
            break;
        }
        guard += 1;
        if value == id {
            return true;
        }
        current = model.objs.get(value).and_then(|object| object.p.as_deref());
    }
    false
}

fn add_object(
    model: &mut RocketModel,
    element: &XmlElement,
    given_id: Option<&str>,
    parent: Option<&str>,
    position: i64,
    component: bool,
) -> String {
    let existing_id = if component {
        element.first("id").map(|id| id.text().trim().to_string())
    } else {
        None
    };
    let mut id = existing_id
        .filter(|value| !value.is_empty())
        .or_else(|| given_id.map(str::to_string));
    let regenerate = id
        .as_deref()
        .map(|value| model.objs.contains_key(value) || reserved(value))
        .unwrap_or(true);
    if regenerate {
        id = Some(Uuid::new_v4().to_string());
    }
    let id = id.unwrap_or_else(|| Uuid::new_v4().to_string());

    let mut object = RocketObject {
        t: element.tag.clone(),
        p: parent.map(str::to_string),
        o: position,
        k: Vec::new(),
        v: BTreeMap::from([(ATTRS.to_string(), attrs_canonical(&element.attrs))]),
    };

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for child in &element.children {
        let XmlChild::Element(child) = child else {
            continue;
        };
        if component && child.tag == "subcomponents" {
            let mut index = 0i64;
            for grandchild in child.elements() {
                index += 1;
                add_object(model, grandchild, None, Some(&id), index, true);
            }
            continue;
        }
        let config = child.attrs.get("configid");
        let base = match config {
            Some(config) => format!("{}[{config}]", child.tag),
            None => child.tag.clone(),
        };
        let count = counts.entry(base.clone()).or_insert(0);
        *count += 1;
        let key = if *count == 1 {
            base
        } else {
            format!("{base}#{count}")
        };
        let value = if component && child.tag == "id" && regenerate {
            format!("<id>{id}</id>")
        } else {
            canonical(child)
        };
        object.k.push(key.clone());
        object.v.insert(key, value);
    }
    if component && !element.elements().any(|child| child.tag == "id") && regenerate {
        let id_value = format!("<id>{id}</id>");
        let insert_at = object
            .k
            .iter()
            .position(|key| key == "name")
            .map(|position| position + 1)
            .unwrap_or(object.k.len());
        object.k.insert(insert_at, "id".to_string());
        object.v.insert("id".to_string(), id_value);
    }
    model.objs.insert(id.clone(), object);
    id
}

pub fn from_xml(
    xml: &XmlElement,
    attachments: &BTreeMap<String, Vec<u8>>,
    sim_ids: Option<&[String]>,
) -> Result<RocketModel, ImportError> {
    if xml.tag != "openrocket" {
        return Err(ImportError::new(
            ImportErrorKind::InvalidDesign,
            "This is not an OpenRocket design.",
        ));
    }
    let mut model = RocketModel::default();
    model.objs.insert(
        DOC.to_string(),
        RocketObject {
            t: xml.tag.clone(),
            p: None,
            o: 0,
            k: Vec::new(),
            v: BTreeMap::from([(ATTRS.to_string(), attrs_canonical(&xml.attrs))]),
        },
    );

    let mut have_rocket = false;
    let mut have_sims = false;
    let mut index = 0i64;
    let mut raw_count: BTreeMap<String, usize> = BTreeMap::new();
    for child in xml.elements() {
        index += 1;
        if child.tag == "rocket" && !have_rocket {
            have_rocket = true;
            add_object(&mut model, child, None, Some(DOC), index, true);
        } else if child.tag == "simulations" && !have_sims {
            have_sims = true;
            model.objs.insert(
                SIMS.to_string(),
                RocketObject {
                    t: "simulations".to_string(),
                    p: Some(DOC.to_string()),
                    o: index,
                    k: Vec::new(),
                    v: BTreeMap::from([(ATTRS.to_string(), attrs_canonical(&child.attrs))]),
                },
            );
            let mut sim_position = 0i64;
            for (simulation_index, simulation) in child.elements().enumerate() {
                if simulation.tag != "simulation" {
                    continue;
                }
                sim_position += 1;
                let id = sim_ids
                    .and_then(|ids| ids.get(simulation_index))
                    .cloned();
                add_object(
                    &mut model,
                    simulation,
                    id.as_deref(),
                    Some(SIMS),
                    sim_position,
                    false,
                );
            }
        } else {
            let count = raw_count.entry(child.tag.clone()).or_insert(0);
            *count += 1;
            let id = if *count == 1 {
                format!("doc:{}", child.tag)
            } else {
                format!("doc:{}#{count}", child.tag)
            };
            model.objs.insert(
                id,
                RocketObject {
                    t: RAW.to_string(),
                    p: Some(DOC.to_string()),
                    o: index,
                    k: vec!["xml".to_string()],
                    v: BTreeMap::from([
                        (ATTRS.to_string(), String::new()),
                        ("xml".to_string(), canonical(child)),
                    ]),
                },
            );
        }
    }
    if !have_rocket {
        return Err(ImportError::new(
            ImportErrorKind::MissingRocket,
            "The file contains no rocket.",
        ));
    }
    let mut position = 1000i64;
    let mut attachments: Vec<_> = attachments.iter().collect();
    attachments.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (name, data) in attachments {
        let id = format!("att:{name}");
        model.objs.insert(
            id,
            RocketObject {
                t: ATT.to_string(),
                p: Some(DOC.to_string()),
                o: position,
                k: vec!["data".to_string()],
                v: BTreeMap::from([
                    (ATTRS.to_string(), String::new()),
                    ("data".to_string(), BASE64_STANDARD.encode(data)),
                ]),
            },
        );
        position += 1;
    }
    Ok(model)
}

fn child_index(model: &RocketModel) -> BTreeMap<String, Vec<String>> {
    let mut index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, object) in &model.objs {
        if let Some(parent) = &object.p {
            index.entry(parent.clone()).or_default().push(id.clone());
        }
    }
    for children in index.values_mut() {
        children.sort_by(|a, b| {
            let a_object = model.objs.get(a);
            let b_object = model.objs.get(b);
            let a_position = a_object.map(|object| object.o).unwrap_or(0);
            let b_position = b_object.map(|object| object.o).unwrap_or(0);
            a_position
                .cmp(&b_position)
                .then_with(|| cmp_strings(a, b))
        });
    }
    index
}

pub fn to_xml(model: &RocketModel) -> String {
    fn emit(model: &RocketModel, index: &BTreeMap<String, Vec<String>>, id: &str, parts: &mut Vec<String>) {
        let Some(object) = model.objs.get(id) else {
            return;
        };
        if object.t == RAW {
            if let Some(xml) = object
                .v
                .get("xml")
                .or_else(|| object.v.get(RAW))
            {
                parts.push(xml.clone());
            }
            return;
        }
        if object.t == ATT {
            return;
        }
        parts.push(format!(
            "<{}{}>",
            object.t,
            object.v.get(ATTRS).map(String::as_str).unwrap_or("")
        ));
        for key in &object.k {
            if let Some(value) = object.v.get(key) {
                if !key.starts_with('#') {
                    parts.push(value.clone());
                }
            }
        }
        if let Some(children) = index.get(id) {
            if !children.is_empty() {
                let wrap = !(object.t == "openrocket" || object.t == "simulations");
                if wrap {
                    parts.push("<subcomponents>".to_string());
                }
                for child in children {
                    emit(model, index, child, parts);
                }
                if wrap {
                    parts.push("</subcomponents>".to_string());
                }
            }
        }
        parts.push(format!("</{}>", object.t));
    }

    let mut parts = vec!["<?xml version='1.0' encoding='utf-8'?>\n".to_string()];
    let index = child_index(model);
    if model.objs.contains_key(DOC) {
        emit(model, &index, DOC, &mut parts);
    }
    parts.push('\n'.to_string());
    parts.concat()
}

fn same_array(a: &[String], b: &[String]) -> bool {
    a == b
}

fn order(requested: Option<&[String]>, values: &BTreeMap<String, String>, current: &[String]) -> Vec<String> {
    let mut output = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(requested) = requested {
        for key in requested {
            if key != ATTRS && values.contains_key(key) && seen.insert(key.clone()) {
                output.push(key.clone());
            }
        }
    }
    for key in current {
        if values.contains_key(key) && seen.insert(key.clone()) {
            output.push(key.clone());
        }
    }
    let mut keys: Vec<_> = values.keys().filter(|key| key.as_str() != ATTRS).cloned().collect();
    keys.sort();
    for key in keys {
        if seen.insert(key.clone()) {
            output.push(key);
        }
    }
    output
}

pub fn validate_op(op: &ModelOp) -> Result<(), String> {
    if !["put", "set", "move", "del"].contains(&op.op.as_str()) {
        return Err(format!("unknown op {}", op.op));
    }
    if op.id.is_empty() || op.id.len() > 512 {
        return Err("bad id".to_string());
    }
    if op.op == "put" || op.op == "move" {
        if let Some(parent) = op.p.as_deref() {
            if parent.len() > 512 {
                return Err("bad parent".to_string());
            }
        }
        if op.o.is_none() {
            return Err("bad position".to_string());
        }
    }
    if op.op == "put" {
        if op.t.as_deref().map(str::is_empty).unwrap_or(true) || op.t.as_deref().is_some_and(|tag| tag.len() > 128) {
            return Err("bad type".to_string());
        }
    }
    if op.op == "put" || op.op == "set" {
        let values = op.v.as_ref().ok_or_else(|| "bad values".to_string())?;
        if values.len() > 5000 {
            return Err("too many values".to_string());
        }
        for (key, value) in values {
            if key.len() > 512 {
                return Err("bad key".to_string());
            }
            if op.op == "set" && value.is_none() {
                continue;
            }
            if value.is_none() && op.op == "put" {
                return Err("bad value".to_string());
            }
        }
        if let Some(keys) = &op.k {
            if keys.len() > 5000 || keys.iter().any(|key| key.len() > 512) {
                return Err("bad key order".to_string());
            }
        }
    }
    Ok(())
}

pub fn apply_op(model: &mut RocketModel, op: &ModelOp) -> Option<ModelOp> {
    validate_op(op).ok()?;
    match op.op.as_str() {
        "put" => {
            let parent = op.p.clone();
            if let Some(parent) = parent.as_deref() {
                if !model.objs.contains_key(parent) || would_cycle(model, &op.id, parent) {
                    return None;
                }
            } else if op.id != DOC {
                return None;
            }
            let mut values = BTreeMap::new();
            for (key, value) in op.v.as_ref()? {
                if let Some(value) = value {
                    values.insert(key.clone(), value.clone());
                }
            }
            let object = RocketObject {
                t: op.t.clone()?,
                p: parent,
                o: op.o.unwrap_or(0),
                k: order(op.k.as_deref(), &values, &[]),
                v: values,
            };
            let old = model.objs.get(&op.id);
            if old
                .is_some_and(|old| {
                    old.t == object.t
                        && old.p == object.p
                        && old.o == object.o
                        && same_array(&old.k, &object.k)
                        && old.v.len() == object.v.len()
                        && old.v.iter().all(|(key, value)| object.v.get(key) == Some(value))
                })
            {
                return None;
            }
            model.objs.insert(op.id.clone(), object);
            Some(op.clone())
        }
        "set" => {
            let object = model.objs.get_mut(&op.id)?;
            let mut changed = BTreeMap::new();
            let mut any = false;
            for (key, value) in op.v.as_ref()? {
                match value {
                    Some(value) => {
                        if object.v.get(key) == Some(value) {
                            continue;
                        }
                        object.v.insert(key.clone(), value.clone());
                        if key != ATTRS && !object.k.contains(key) {
                            object.k.push(key.clone());
                        }
                        changed.insert(key.clone(), Some(value.clone()));
                    }
                    None => {
                        if !object.v.contains_key(key) {
                            continue;
                        }
                        object.v.remove(key);
                        if let Some(position) = object.k.iter().position(|item| item == key) {
                            object.k.remove(position);
                        }
                        changed.insert(key.clone(), None);
                    }
                }
                any = true;
            }
            let mut reordered = false;
            if let Some(keys) = &op.k {
                let new_keys = order(Some(keys), &object.v, &object.k);
                reordered = !same_array(&new_keys, &object.k);
                object.k = new_keys;
            }
            if !any && !reordered {
                return None;
            }
            let mut output = op.clone();
            output.v = Some(changed);
            Some(output)
        }
        "move" => {
            let parent = op.p.clone()?;
            if op.id == DOC
                || !model.objs.contains_key(&parent)
                || would_cycle(model, &op.id, &parent)
            {
                return None;
            }
            let position = op.o.unwrap_or(0);
            let object = model.objs.get_mut(&op.id)?;
            if object.p.as_deref() == Some(parent.as_str()) && object.o == position {
                return None;
            }
            object.p = Some(parent);
            object.o = position;
            Some(op.clone())
        }
        "del" => {
            if !model.objs.contains_key(&op.id) || op.id == DOC {
                return None;
            }
            let index = child_index(model);
            let mut stack = vec![op.id.clone()];
            while let Some(id) = stack.pop() {
                model.objs.remove(&id);
                if let Some(children) = index.get(&id) {
                    stack.extend(children.iter().cloned());
                }
            }
            Some(op.clone())
        }
        _ => None,
    }
}

pub fn attachments(model: &RocketModel) -> BTreeMap<String, Vec<u8>> {
    let mut output = BTreeMap::new();
    for (id, object) in &model.objs {
        if object.t != ATT || !id.starts_with("att:") {
            continue;
        }
        if let Some(encoded) = object.v.get("data") {
            if let Ok(data) = BASE64_STANDARD.decode(encoded) {
                output.insert(id.trim_start_matches("att:").to_string(), data);
            }
        }
    }
    output
}

pub fn import_ork(bytes: &[u8]) -> Result<RocketModel, ImportError> {
    let mut xml: Vec<u8>;
    let mut atts = BTreeMap::new();
    if bytes.starts_with(&[0x50, 0x4b]) {
        let cursor = Cursor::new(bytes);
        let mut archive = ZipArchive::new(cursor).map_err(|error| {
            ImportError::new(
                ImportErrorKind::InvalidArchive,
                format!("The file is not a valid .ork archive ({error})."),
            )
        })?;
        let mut main = None;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index).map_err(|error| {
                ImportError::new(
                    ImportErrorKind::InvalidArchive,
                    format!("The file is not a valid .ork archive ({error})."),
                )
            })?;
            if file.is_dir() {
                continue;
            }
            let name = file.name().to_string();
            let mut data = Vec::new();
            file.read_to_end(&mut data).map_err(|error| {
                ImportError::new(
                    ImportErrorKind::InvalidArchive,
                    format!("The file is not a valid .ork archive ({error})."),
                )
            })?;
            if main.is_none() && (name.ends_with(".ork") || name.ends_with(".rkt")) {
                main = Some(data);
            } else {
                atts.insert(name, data);
            }
        }
        xml = main.ok_or_else(|| {
            ImportError::new(
                ImportErrorKind::InvalidArchive,
                "No rocket design found inside the archive.",
            )
        })?;
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(bytes);
        xml = Vec::new();
        decoder.read_to_end(&mut xml).map_err(|error| {
            ImportError::new(
                ImportErrorKind::InvalidArchive,
                format!("The gzip file could not be read ({error})."),
            )
        })?;
    } else {
        xml = bytes.to_vec();
    }

    let xml_text = String::from_utf8_lossy(&xml).to_string();
    let root = parse_xml(&xml_text)?;
    if root.tag == "RockSimDocument" {
        return Err(ImportError::new(
            ImportErrorKind::RockSim,
            "RockSim files are not supported here. Open it in OpenRocket, save it as .ork, then upload that.",
        ));
    }
    if root.tag != "openrocket" {
        return Err(ImportError::new(
            ImportErrorKind::InvalidDesign,
            "This is not an OpenRocket design.",
        ));
    }
    let sim_ids: Option<Vec<String>> = root.first("simulations").map(|simulations| {
        simulations
            .elements()
            .enumerate()
            .map(|(index, simulation)| if simulation.tag == "simulation" { format!("sim-{index}") } else { Uuid::new_v4().to_string() })
            .collect()
    });
    from_xml(&root, &atts, sim_ids.as_deref())
}

pub fn model_json(model: &RocketModel) -> Result<String, serde_json::Error> {
    serde_json::to_string(model)
}

pub fn model_from_json(json: &str) -> Result<RocketModel, serde_json::Error> {
    serde_json::from_str(json)
}

pub fn export_ork(model: &RocketModel) -> Result<ExportedOrk, ImportError> {
    let xml = to_xml(model);
    let atts = attachments(model);
    if atts.is_empty() {
        return Ok(ExportedOrk {
            bytes: xml.into_bytes(),
            zip: false,
        });
    }
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default();
        writer
            .start_file("rocket.ork", options)
            .map_err(|error| ImportError::new(ImportErrorKind::InvalidArchive, error.to_string()))?;
        writer.write_all(xml.as_bytes()).map_err(|error| {
            ImportError::new(ImportErrorKind::InvalidArchive, error.to_string())
        })?;
        let mut sorted: Vec<_> = atts.iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (name, data) in sorted {
            writer
                .start_file(name, options)
                .map_err(|error| ImportError::new(ImportErrorKind::InvalidArchive, error.to_string()))?;
            writer.write_all(data).map_err(|error| {
                ImportError::new(ImportErrorKind::InvalidArchive, error.to_string())
            })?;
        }
        writer.finish().map_err(|error| {
            ImportError::new(ImportErrorKind::InvalidArchive, error.to_string())
        })?;
    }
    Ok(ExportedOrk {
        bytes: cursor.into_inner(),
        zip: true,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExportedOrk {
    pub bytes: Vec<u8>,
    pub zip: bool,
}

const PASSWORD_ITERATIONS: u32 = 120_000;
const PASSWORD_HASH_BYTES: usize = 32;

pub fn new_password_salt() -> String {
    URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
}

pub fn hash_password(password: &str, encoded_salt: &str) -> Option<String> {
    let salt = URL_SAFE_NO_PAD.decode(encoded_salt).ok()?;
    let mut output = [0u8; PASSWORD_HASH_BYTES];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        &salt,
        PASSWORD_ITERATIONS,
        &mut output,
    );
    Some(URL_SAFE_NO_PAD.encode(output))
}

pub fn verify_password(password: &str, encoded_salt: &str, expected_hash: &str) -> bool {
    let Some(actual) = hash_password(password, encoded_salt) else {
        return false;
    };
    let actual_bytes = URL_SAFE_NO_PAD.decode(actual).unwrap_or_default();
    let expected_bytes = URL_SAFE_NO_PAD.decode(expected_hash).unwrap_or_default();
    if actual_bytes.len() != expected_bytes.len() {
        return false;
    }
    actual_bytes
        .iter()
        .zip(expected_bytes.iter())
        .fold(0u8, |difference, (actual, expected)| difference | (actual ^ expected))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLANK: &str = include_str!("../../../../server/templates/new-rocket.ork");

    #[test]
    fn blank_template_imports() {
        let model = import_ork(BLANK.as_bytes()).expect("template should import");
        assert!(model.objs.values().any(|object| object.t == "rocket"));
        assert!(model.objs.values().any(|object| object.t == "stage"));
    }

    #[test]
    fn set_operation_changes_a_property() {
        let mut model = import_ork(BLANK.as_bytes()).unwrap();
        let id = model
            .objs
            .iter()
            .find(|(_, object)| object.t == "rocket")
            .map(|(id, _)| id.clone())
            .unwrap();
        let op = ModelOp {
            op: "set".to_string(),
            id,
            p: None,
            o: None,
            t: None,
            v: Some(BTreeMap::from([(
                "name".to_string(),
                Some("<name>Updated rocket</name>".to_string()),
            )])),
            k: None,
        };
        assert!(apply_op(&mut model, &op).is_some());
    }

    #[test]
    fn plain_export_round_trips() {
        let model = import_ork(BLANK.as_bytes()).unwrap();
        let exported = export_ork(&model).unwrap();
        assert!(!exported.zip);
        let again = import_ork(&exported.bytes).unwrap();
        assert_eq!(to_xml(&again), to_xml(&model));
    }

    #[test]
    fn zipped_export_round_trips_with_attachment() {
        let mut model = import_ork(BLANK.as_bytes()).unwrap();
        model.objs.insert(
            "att:decals/a.png".to_string(),
            RocketObject {
                t: ATT.to_string(),
                p: Some(DOC.to_string()),
                o: 1000,
                k: vec!["data".to_string()],
                v: BTreeMap::from([
                    (ATTRS.to_string(), String::new()),
                    ("data".to_string(), BASE64_STANDARD.encode(b"png")),
                ]),
            },
        );
        let exported = export_ork(&model).unwrap();
        assert!(exported.zip);
        let again = import_ork(&exported.bytes).unwrap();
        assert_eq!(attachments(&again).get("decals/a.png"), Some(&b"png".to_vec()));
        assert_eq!(to_xml(&again), to_xml(&model));
    }

    #[test]
    fn reject_rocksims() {
        assert!(matches!(
            import_ork(b"<RockSimDocument/>"),
            Err(ImportError {
                kind: ImportErrorKind::RockSim,
                ..
            })
        ));
    }

    #[test]
    fn password_hash_round_trips() {
        let salt = new_password_salt();
        let hash = hash_password("correct horse battery", &salt).unwrap();
        assert!(verify_password("correct horse battery", &salt, &hash));
        assert!(!verify_password("wrong password", &salt, &hash));
    }
}
