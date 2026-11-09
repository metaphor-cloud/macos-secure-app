import { writeFileSync } from "node:fs";
import { serializeVectors, VECTORS_PATH } from "./vectors.ts";

writeFileSync(VECTORS_PATH, serializeVectors());
console.log(`wrote ${VECTORS_PATH.pathname}`);
