// Export the worker URL for use in glue.js
// All actual PoW computation is performed in pow-worker.js
export const workerUrl = new URL("./pow-worker.js", import.meta.url).toString();
