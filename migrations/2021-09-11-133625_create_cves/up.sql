CREATE TABLE objects (
    id SERIAL PRIMARY KEY,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone,
	cve text NOT NULL,
    data text NOT NULL
);

CREATE INDEX objects_cve ON objects USING btree (cve);

CREATE TABLE cves (
    id SERIAL PRIMARY KEY,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone,
    source text NOT NULL,
    vendor text NOT NULL,
    product text NOT NULL,
    cve text NOT NULL,
    summary text NOT NULL,
    score double precision NOT NULL,
    severity text NOT NULL,
    vector text,
    "references" JSONB NOT NULL,
    object_id integer REFERENCES objects (id)
);

CREATE INDEX cves_object_id ON cves USING btree (object_id);
CREATE INDEX cves_product ON cves USING btree (product);
CREATE INDEX cves_source ON cves USING btree (source);
CREATE INDEX cves_vendor ON cves USING btree (vendor);
CREATE INDEX cves_vendor_product ON cves USING btree (vendor, product);
CREATE INDEX cves_vendor_product_cve ON cves USING btree (vendor, product, cve);
