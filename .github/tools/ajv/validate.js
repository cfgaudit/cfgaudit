// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Validates JSON files against a JSON Schema for the schema validation
// workflow. Replaces ajv-cli (#701), whose own dependencies carry advisories
// that no ajv-cli release fixes. Built the way `ajv validate --strict=false`
// built its validator: draft-07 Ajv, strict mode off, the draft-06
// meta-schema added, so what is validated does not change.
//
// Usage: node validate.js [--invalid] <schema.json> <data.json>...
//
// With --invalid every data file must fail the schema: the rejected examples
// of .cfgaudit.yml check that the schema is as strict as the parser (#1106).
"use strict";

const fs = require("fs");
const Ajv = require("ajv").default;
const draft6 = require("ajv/lib/refs/json-schema-draft-06.json");

const args = process.argv.slice(2);
const expectInvalid = args[0] === "--invalid";
if (expectInvalid) {
  args.shift();
}
const [schemaFile, ...dataFiles] = args;
if (!schemaFile || dataFiles.length === 0) {
  console.error("usage: node validate.js [--invalid] <schema.json> <data.json>...");
  process.exit(2);
}

const ajv = new Ajv({ strict: false });
ajv.addMetaSchema(draft6);
const validate = ajv.compile(JSON.parse(fs.readFileSync(schemaFile, "utf8")));

let ok = true;
for (const file of dataFiles) {
  const valid = validate(JSON.parse(fs.readFileSync(file, "utf8")));
  if (valid && !expectInvalid) {
    console.log(file, "valid");
  } else if (!valid && expectInvalid) {
    console.log(file, "rejected, as expected");
  } else if (valid) {
    console.error(file, "valid, but the schema should reject it");
    ok = false;
  } else {
    console.error(file, "invalid");
    console.error(JSON.stringify(validate.errors, null, 2));
    ok = false;
  }
}
process.exit(ok ? 0 : 1);
