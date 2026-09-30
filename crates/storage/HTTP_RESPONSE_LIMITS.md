# Operator HTTP response limits

Object downloads enforce a 16 MiB limit on the actual bytes received through `Response::chunk()`, including responses without a length header or with chunked or misleading length headers. A declared larger size is rejected before reading the body. The cap accommodates the normal operator's 4 MiB object limit and custom encrypted manifests up to 16 MiB. Objects over the client cap require an explicit protocol/deployment change; they are not partially returned. CID verification still happens after a complete bounded download.

HTTP error bodies are capped at 64 KiB before UTF-8 or JSON decoding. Oversized errors retain their HTTP status and receive a short local error message; the remote body is discarded. Regular structured error messages continue to be decoded.

Recovery discovery pages retain their 3 MiB encoded response limit using the same streaming reader. Their existing aggregate limits remain 64 MiB of decoded records, 10,000 records, and strictly advancing continuation cursors. Exceeding a limit drops the response immediately, closing the remaining body rather than waiting for EOF.

These are per-response limits. Reconstruction can retain multiple objects and plaintext concurrently; aggregate workload memory and process-level concurrency require separate controls. Other small control-plane JSON success responses are unchanged by this patch.
