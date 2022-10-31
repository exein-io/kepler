table! {
    cves (id) {
        id -> Int4,
        created_at -> Timestamp,
        updated_at -> Nullable<Timestamp>,
        source -> Text,
        vendor -> Text,
        product -> Text,
        cve -> Text,
        summary -> Text,
        score -> Float8,
        severity -> Text,
        vector -> Nullable<Text>,
        references -> Jsonb,
        object_id -> Nullable<Int4>,
    }
}

table! {
    objects (id) {
        id -> Int4,
        created_at -> Timestamp,
        updated_at -> Nullable<Timestamp>,
        cve -> Text,
        data -> Text,
    }
}

joinable!(cves -> objects (object_id));

allow_tables_to_appear_in_same_query!(cves, objects,);
