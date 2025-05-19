-- Add composite unique constraint to objects and cves tables
ALTER TABLE objects ADD CONSTRAINT objects_cve_unique UNIQUE (cve);
ALTER TABLE cves ADD CONSTRAINT cves_cve_vendor_product_unique UNIQUE (cve, vendor, product);