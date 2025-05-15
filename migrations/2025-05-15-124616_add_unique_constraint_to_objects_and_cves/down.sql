-- Remove the composite unique constraints for the objects and cves tables
ALTER TABLE objects DROP CONSTRAINT objects_cve_unique;
ALTER TABLE cves DROP CONSTRAINT cves_cve_vendor_product_unique;