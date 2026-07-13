# Runtime image for the overfwd gateway.
#
# The binary is built ahead of time by the release workflow (native per-arch,
# stripped) and staged into the build context as `overfwd-<arch>`; this
# Dockerfile only packages it — it does not compile. The release binaries are
# built for the `-gnu` target (dynamically linked against glibc), so the runtime
# base is distroless `cc`, which ships glibc + libgcc_s. rustls with compiled-in
# `webpki-roots` means no OpenSSL/CA bundle is needed on top of that.
#
# TARGETARCH is set automatically by buildx (`amd64`/`arm64`) and selects the
# matching staged binary, so a COPY-only multi-arch build needs no emulation.
FROM gcr.io/distroless/cc-debian12:nonroot
ARG TARGETARCH
COPY overfwd-${TARGETARCH} /usr/local/bin/overfwd
# Matches OVERFWD_BIND's default (0.0.0.0:8000); override OVERFWD_BIND to change.
EXPOSE 8000
USER nonroot
ENTRYPOINT ["/usr/local/bin/overfwd"]
