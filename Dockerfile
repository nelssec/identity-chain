FROM gcr.io/distroless/static:nonroot

COPY idc-linux-amd64 /usr/local/bin/idc

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/idc"]
