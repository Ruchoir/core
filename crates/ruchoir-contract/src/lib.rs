//! The contract check shared by every Ruchoir service (ADR 0005 of `Ruchoir/.github`).
//!
//! [`breaking_changes`] compares two OpenAPI documents and says what the newer one breaks for a
//! client written against the older one. A service records its contract, then a test of its own
//! fails as soon as this list is not empty: inside a major version, a contract only grows.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// The `type` and `$ref` of a schema node, which an app reads a value as.
fn shape(node: &Value) -> Value {
    serde_json::json!({ "type": node.get("type"), "ref": node.get("$ref"), "items": node.get("items").map(shape) })
}

fn as_object(value: Option<&Value>) -> BTreeMap<String, Value> {
    value
        .and_then(Value::as_object)
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn names(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The schemas sent by apps (request bodies), by name: a field these newly require would be missing
/// from every request an older app makes.
fn request_schemas(doc: &Value) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (_, item) in as_object(doc.get("paths")) {
        for (_, operation) in as_object(Some(&item)) {
            for (_, media) in as_object(operation.pointer("/requestBody/content")) {
                if let Some(name) = media
                    .pointer("/schema/$ref")
                    .and_then(Value::as_str)
                    .and_then(|r| r.rsplit('/').next())
                {
                    found.insert(name.to_owned());
                }
            }
        }
    }
    found
}

/// What `new` breaks for an app written against `old`, both OpenAPI documents; empty when `new`
/// only adds. Reported: a route or method gone, a parameter newly required, a schema or a field
/// gone, a field read as another type, a field no longer always present, a field newly required in
/// what an app sends.
pub fn breaking_changes(old: &Value, new: &Value) -> Vec<String> {
    let mut found = Vec::new();
    let new_paths = as_object(new.get("paths"));
    for (path, item) in as_object(old.get("paths")) {
        let Some(new_item) = new_paths.get(&path) else {
            found.push(format!("route {path} removed"));
            continue;
        };
        for (method, operation) in as_object(Some(&item)) {
            let Some(new_operation) = new_item.get(&method) else {
                found.push(format!("{} {path} removed", method.to_uppercase()));
                continue;
            };
            let before: BTreeSet<String> = operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|p| p.get("name").and_then(Value::as_str).map(str::to_owned))
                .collect();
            for parameter in new_operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let name = parameter.get("name").and_then(Value::as_str).unwrap_or("");
                let required = parameter.get("required").and_then(Value::as_bool) == Some(true);
                let in_path = parameter.get("in").and_then(Value::as_str) == Some("path");
                if required && !in_path && !before.contains(name) {
                    found.push(format!(
                        "{} {path}: parameter {name} newly required",
                        method.to_uppercase()
                    ));
                }
            }
        }
    }

    let sent = request_schemas(new);
    let new_schemas = as_object(new.pointer("/components/schemas"));
    for (name, schema) in as_object(old.pointer("/components/schemas")) {
        let Some(new_schema) = new_schemas.get(&name) else {
            found.push(format!("schema {name} removed"));
            continue;
        };
        let new_properties = as_object(new_schema.get("properties"));
        let old_properties = as_object(schema.get("properties"));
        for (field, node) in &old_properties {
            match new_properties.get(field) {
                None => found.push(format!("{name}.{field} removed")),
                Some(new_node) if shape(new_node) != shape(node) => {
                    found.push(format!("{name}.{field} changed type"))
                }
                Some(_) => {}
            }
        }
        let required_before = names(schema.get("required"));
        let required_now = names(new_schema.get("required"));
        for field in required_before.difference(&required_now) {
            if new_properties.contains_key(field) {
                found.push(format!("{name}.{field} no longer always present"));
            }
        }
        if sent.contains(&name) {
            for field in required_now.difference(&required_before) {
                found.push(format!("{name}.{field} newly required in a request"));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use serde_json::Value;

    use super::breaking_changes;

    /// A small contract: one route that takes `Draft` and answers `Note`.
    fn base() -> Value {
        json!({
            "paths": {
                "/api/v1/notes": {
                    "get": { "parameters": [{ "name": "limit", "in": "query", "required": false }] },
                    "post": {
                        "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Draft" } } } }
                    }
                }
            },
            "components": { "schemas": {
                "Draft": { "type": "object", "required": ["text"], "properties": { "text": { "type": "string" } } },
                "Note": { "type": "object", "required": ["id", "text"], "properties": {
                    "id": { "type": "string" }, "text": { "type": "string" },
                    "tags": { "type": "array", "items": { "type": "string" } }
                } }
            } }
        })
    }

    fn change(edit: impl FnOnce(&mut Value)) -> Vec<String> {
        let mut new = base();
        edit(&mut new);
        breaking_changes(&base(), &new)
    }

    #[test]
    fn the_same_contract_breaks_nothing() {
        assert!(breaking_changes(&base(), &base()).is_empty());
    }

    #[test]
    fn adding_breaks_nothing() {
        let found = change(|doc| {
            doc["paths"]["/api/v1/tags"] = json!({ "get": {} });
            doc["paths"]["/api/v1/notes"]["delete"] = json!({});
            doc["paths"]["/api/v1/notes"]["get"]["parameters"]
                .as_array_mut()
                .unwrap()
                .push(json!({ "name": "before", "in": "query", "required": false }));
            doc["components"]["schemas"]["Tag"] = json!({ "type": "object" });
            // A new field in an answer, even always present; a new optional field in a request.
            doc["components"]["schemas"]["Note"]["properties"]["pinned"] =
                json!({ "type": "boolean" });
            doc["components"]["schemas"]["Note"]["required"] = json!(["id", "text", "pinned"]);
            doc["components"]["schemas"]["Draft"]["properties"]["color"] =
                json!({ "type": "string" });
        });
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn removing_a_route_a_method_a_schema_or_a_field_breaks() {
        assert_eq!(
            change(|doc| {
                doc["paths"]
                    .as_object_mut()
                    .unwrap()
                    .remove("/api/v1/notes");
            }),
            vec!["route /api/v1/notes removed"]
        );
        assert_eq!(
            change(|doc| {
                doc["paths"]["/api/v1/notes"]
                    .as_object_mut()
                    .unwrap()
                    .remove("get");
            }),
            vec!["GET /api/v1/notes removed"]
        );
        assert_eq!(
            change(|doc| {
                doc["components"]["schemas"]["Note"]["properties"]
                    .as_object_mut()
                    .unwrap()
                    .remove("tags");
            }),
            vec!["Note.tags removed"]
        );
        let found = change(|doc| {
            doc["components"]["schemas"]
                .as_object_mut()
                .unwrap()
                .remove("Note");
        });
        assert_eq!(found, vec!["schema Note removed"]);
    }

    #[test]
    fn reading_a_field_as_another_type_breaks() {
        assert_eq!(
            change(
                |doc| doc["components"]["schemas"]["Note"]["properties"]["id"] =
                    json!({ "type": "integer" })
            ),
            vec!["Note.id changed type"]
        );
        // Becoming nullable is a change too: an older app does not expect null there.
        assert_eq!(
            change(
                |doc| doc["components"]["schemas"]["Note"]["properties"]["text"] =
                    json!({ "type": ["string", "null"] })
            ),
            vec!["Note.text changed type"]
        );
        assert_eq!(
            change(
                |doc| doc["components"]["schemas"]["Note"]["properties"]["tags"]["items"] =
                    json!({ "type": "integer" })
            ),
            vec!["Note.tags changed type"]
        );
    }

    #[test]
    fn a_field_that_may_be_missing_now_breaks() {
        assert_eq!(
            change(|doc| doc["components"]["schemas"]["Note"]["required"] = json!(["id"])),
            vec!["Note.text no longer always present"]
        );
    }

    #[test]
    fn asking_more_of_an_older_app_breaks() {
        assert_eq!(
            change(|doc| {
                doc["components"]["schemas"]["Draft"]["properties"]["color"] =
                    json!({ "type": "string" });
                doc["components"]["schemas"]["Draft"]["required"] = json!(["text", "color"]);
            }),
            vec!["Draft.color newly required in a request"]
        );
        assert_eq!(
            change(|doc| {
                doc["paths"]["/api/v1/notes"]["get"]["parameters"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({ "name": "space", "in": "query", "required": true }));
            }),
            vec!["GET /api/v1/notes: parameter space newly required"]
        );
    }
}
