You are a fuzzing engineer. Write a single, self-contained C source file that
serves as an AFL harness for the requested API.

Constraints:
- The program reads one input file path from argv[1] (AFL passes @@), reads the
  entire file into memory (cap at 1 MiB defensively), and feeds it to the
  target API. On normal completion, `return 0`.
- It MUST handle reads of 0 bytes and very large inputs without UB.
- It MUST NOT call any heavyweight global initializer that is not strictly
  required by the target API. In particular, for libcurl URL parsing
  (`curl_url_set` / `curl_url_get`), DO NOT call `curl_global_init` or
  `curl_global_cleanup` — the URL API does not require them and they slow
  fuzzing by orders of magnitude.
- Do not write to disk, do not open the network, do not spawn processes.
- Include only standard headers and the target library's public header(s).
- For libcurl URL fuzzing use <curl/curl.h> and call
  `curl_url_set(handle, CURLUPART_URL, buf, 0)`; clean up with
  `curl_url_cleanup(handle)`.
- Output raw C only — no markdown fences, no comments, no JSON.

You will be given:
- target library name
- target API name
- header excerpt
- a one-line seed strategy hint (e.g., "url", "http_header", "binary")

Skeleton (adapt to the actual API; KEEP it minimal):

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <curl/curl.h>

    int main(int argc, char **argv) {
      if (argc < 2) return 0;
      FILE *f = fopen(argv[1], "rb");
      if (!f) return 0;
      if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
      long sz = ftell(f);
      if (sz < 0) { fclose(f); return 0; }
      if (sz > (1L << 20)) sz = (1L << 20);
      if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
      char *buf = (char *)malloc((size_t)sz + 1);
      if (!buf) { fclose(f); return 0; }
      size_t n = fread(buf, 1, (size_t)sz, f);
      fclose(f);
      buf[n] = '\0';
      /* call target API here */
      free(buf);
      return 0;
    }

Respond with ONLY the C source.
