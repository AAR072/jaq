FROM eclipse-temurin:21-jdk-jammy@sha256:ce5767b7222312d42395f5bab033cd91f09e44032a2f21bdfd7b5b912dbe1e77 AS ghidra-download

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl unzip \
    && curl --fail --location --proto '=https' --tlsv1.2 \
       --output /tmp/ghidra.zip \
       https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip \
    && echo "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54  /tmp/ghidra.zip" | sha256sum --check --strict \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_12.1.3_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip

FROM eclipse-temurin:21-jdk-jammy@sha256:ce5767b7222312d42395f5bab033cd91f09e44032a2f21bdfd7b5b912dbe1e77

LABEL org.opencontainers.image.title="JAQ Ghidra static analyzer" \
      org.opencontainers.image.version="12.1.3" \
      org.opencontainers.image.source="https://github.com/NationalSecurityAgency/ghidra" \
      org.opencontainers.image.description="Network-disabled runtime is enforced by the JAQ controller"

RUN groupadd --gid 65532 jaq \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin jaq \
    && install --directory --mode=0555 /input

COPY --from=ghidra-download /opt/ghidra /opt/ghidra
COPY --chmod=0555 entrypoint.sh /opt/jaq/entrypoint.sh
COPY --chmod=0444 ghidra_scripts/ExportEvidence.java /opt/jaq/ghidra_scripts/ExportEvidence.java

ENV GHIDRA_HOME=/opt/ghidra \
    HOME=/tmp/jaq-home \
    JAVA_TOOL_OPTIONS="-Djava.awt.headless=true"

USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["/opt/jaq/entrypoint.sh"]
