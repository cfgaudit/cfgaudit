// Validates JSON files against a JSON Schema for the schema validation
// workflow. Replaces ajv-cli (#701), whose own dependencies carry advisories
// that no ajv-cli release fixes. Built the way `ajv validate --strict=false`
// built its validator: draft-07 Ajv, strict mode off, the draft-06
// meta-schema added, so what is validated does not change.
//
// Usage: node validate.js <schema.json> <data.json>...
"use strict";

const fs = require("fs");
const Ajv = require("ajv").default;
const draft6 = require("ajv/lib/refs/json-schema-draft-06.json");

const [schemaFile, ...dataFiles] = process.argv.slice(2);
if (!schemaFile || dataFiles.length === 0) {
  console.error("usage: node validate.js <schema.json> <data.json>...");
  process.exit(2);
}

const ajv = new Ajv({ strict: false });
ajv.addMetaSchema(draft6);
const validate = ajv.compile(JSON.parse(fs.readFileSync(schemaFile, "utf8")));

let ok = true;
for (const file of dataFiles) {
  if (validate(JSON.parse(fs.readFileSync(file, "utf8")))) {
    console.log(file, "valid");
  } else {
    console.error(file, "invalid");
    console.error(JSON.stringify(validate.errors, null, 2));
    ok = false;
  }
}
process.exit(ok ? 0 : 1);
