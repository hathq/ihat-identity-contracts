pub(crate) fn strip(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(values) => {
            for key in [
                "authentication",
                "existing_authentication",
                "incoming_authentication",
            ] {
                values.remove(key);
            }
            values.values_mut().for_each(strip);
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(strip),
        _ => {}
    }
}
