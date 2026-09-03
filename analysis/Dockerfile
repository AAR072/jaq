FROM ubuntu:22.04@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc AS build

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential ca-certificates curl file git jq libssl-dev libzip-dev \
        libbz2-dev libffi-dev libgdbm-dev liblzma-dev libncurses-dev \
        libreadline-dev libsqlite3-dev meson ninja-build pkg-config python3 \
        uuid-dev xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/r2 /build \
    && curl --fail --location --proto '=https' --tlsv1.2 \
        --output /tmp/radare2-6.2.0.tar.xz \
        https://github.com/radareorg/radare2/releases/download/6.2.0/radare2-6.2.0.tar.xz \
    && echo "098488a3a0a4c11b893ae9e74496cf65561d17cefd9b7f2661a48b4be97b663a  /tmp/radare2-6.2.0.tar.xz" \
        | sha256sum --check --strict \
    && tar --extract --xz --file /tmp/radare2-6.2.0.tar.xz --strip-components=1 --directory /build \
    && cd /build \
    && cp dist/plugins-cfg/plugins.def.cfg plugins.cfg \
    && sed -i -E '/^(debug\.(bf|evm|rv32ima|bochs|esil|gdb|io|native|qnx|rap|winkd)|io\.(bfdbg|bochs|debug|ebpf|fd|gdb|gprobe|http|isotp|mach|procpid|ptrace|pvm|qnx|r2k|r2pipe|r2web|rap|reg|self|serial|socket|sysgdb|tcpslurp|w32dbg|winedbg|winkd))$/d' plugins.cfg \
    && KEEP_PLUGINS_CFG=1 ./sys/install.sh --install --without-pull --prefix=/opt/r2 \
        --disable-debugger --without-ptrace-wrap --disable-loadlibs \
        --without-qjs \
    && /opt/r2/bin/r2 -L | awk '$2 ~ /^(fd|procpid|pvm|r2k|r2web|reg|self|gdb|http|ptrace|socket|winedbg|winkd)$/ { bad=1 } END { exit bad }' \
    && test "$(/opt/r2/bin/r2 -N -n -q0 -c 'dLq' /bin/true)" = "null" \
    && rm -rf /build /tmp/radare2-6.2.0.tar.xz

ENV PATH=/opt/r2/bin:${PATH} \
    PKG_CONFIG_PATH=/opt/r2/lib/pkgconfig

RUN git clone --branch 1.8.6 --depth 1 \
        https://github.com/radareorg/radare2-mcp.git /build/radare2-mcp \
    && test "$(git -C /build/radare2-mcp rev-parse HEAD)" = "d74b6b9855622c9a7070165b1961262afd686a3f" \
    && cd /build/radare2-mcp \
    && ./configure --prefix=/opt/r2mcp \
    && make -C src all -j2 \
    && LD_LIBRARY_PATH=/opt/r2/lib make test \
    && install -D -m 0755 src/r2mcp /opt/r2mcp/bin/r2mcp \
    && rm -rf /build/radare2-mcp

ARG PYTHON314_VERSION=3.14.7
ARG PYTHON314_SHA256=3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81

RUN mkdir -p /build/python314 \
    && curl --fail --location --proto '=https' --tlsv1.2 \
        --output /tmp/Python-${PYTHON314_VERSION}.tar.xz \
        https://www.python.org/ftp/python/${PYTHON314_VERSION}/Python-${PYTHON314_VERSION}.tar.xz \
    && echo "${PYTHON314_SHA256}  /tmp/Python-${PYTHON314_VERSION}.tar.xz" \
        | sha256sum --check --strict \
    && tar --extract --xz --file /tmp/Python-${PYTHON314_VERSION}.tar.xz \
        --strip-components=1 --directory /build/python314 \
    && cd /build/python314 \
    && ./configure --prefix=/opt/python314 --with-ensurepip=no --disable-test-modules \
    && make -j2 \
    && make install \
    && /opt/python314/bin/python3.14 -c 'import dis, marshal; print(marshal.version)' \
    && rm -rf /build/python314 /tmp/Python-${PYTHON314_VERSION}.tar.xz

FROM ubuntu:22.04@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc

LABEL org.opencontainers.image.title="JAQ Radare2 static sandbox" \
      org.opencontainers.image.description="Rootless, network-disabled Radare2/r2mcp static analysis runtime" \
      org.opencontainers.image.base.name="ubuntu:22.04" \
      org.opencontainers.image.base.digest="sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc" \
      org.opencontainers.image.radare2.version="6.2.0" \
      org.opencontainers.image.radare2.commit="e1fc278734ad62f933fc6f91edb29e4ba732f402" \
      org.opencontainers.image.radare2.archive-sha256="098488a3a0a4c11b893ae9e74496cf65561d17cefd9b7f2661a48b4be97b663a" \
      org.opencontainers.image.r2mcp.version="1.8.6" \
      org.opencontainers.image.r2mcp.commit="d74b6b9855622c9a7070165b1961262afd686a3f" \
      org.opencontainers.image.python314.version="3.14.7" \
      org.opencontainers.image.pyinstxtractor-ng.version="2026.7.3" \
      org.opencontainers.image.capa.version="9.4.0"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        binutils binwalk build-essential bzip2 cabextract file innoextract jq \
        libarchive-tools libimage-exiftool-perl llvm lz4 msitools openssl osslsigncode p7zip-full \
        pev python3 python3-pip ripgrep sqlite3 ssdeep unzip upx-ucl xxd yara \
        xz-utils zstd \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 jaq \
    && useradd --uid 65532 --gid 65532 --no-create-home \
        --home-dir /work --shell /bin/bash jaq \
    && install --directory --owner=65532 --group=65532 --mode=0700 /work \
    && install --directory --owner=65532 --group=65532 --mode=0555 /input

COPY --from=build /opt/r2 /opt/r2
COPY --from=build /opt/r2mcp /opt/r2mcp
COPY --from=build /opt/python314 /opt/python314
COPY requirements-static.txt /opt/jaq/requirements-static.txt
RUN python3 -m pip install --no-cache-dir --disable-pip-version-check pip==26.2.1 \
    && python3 -m pip install --no-cache-dir --disable-pip-version-check \
        --requirement /opt/jaq/requirements-static.txt \
    && python3 -m pip check \
    && python3 -m pip freeze > /opt/jaq/requirements-resolved.txt
COPY --chmod=0555 entrypoint.sh /opt/jaq/entrypoint.sh
COPY --chmod=0444 TOOLS.md /opt/jaq/TOOLS.md
COPY --chmod=0555 jaq-tools /usr/local/bin/jaq-tools
COPY --chmod=0555 pyc-disasm /usr/local/bin/pyc-disasm

RUN rm -f \
        /opt/r2/bin/clang-format-radare2 \
        /opt/r2/bin/r2agent \
        /opt/r2/bin/r2pm \
        /opt/r2/bin/r2r \
        /opt/r2/bin/rarun2 \
        /opt/r2/bin/r2sdb \
        /usr/bin/lli* \
        /usr/bin/bugpoint* \
        /usr/bin/llvm-exegesis* \
        /usr/bin/llvm-jitlink* \
        /usr/bin/llvm-rtdyld* \
        /usr/bin/opt* \
        /usr/lib/llvm-*/bin/lli* \
        /usr/lib/llvm-*/bin/bugpoint* \
        /usr/lib/llvm-*/bin/llvm-exegesis* \
        /usr/lib/llvm-*/bin/llvm-jitlink* \
        /usr/lib/llvm-*/bin/llvm-rtdyld* \
        /usr/lib/llvm-*/bin/opt* \
    && printf '%s\n' /opt/r2/lib > /etc/ld.so.conf.d/jaq-radare2.conf \
    && ldconfig \
    && /opt/r2/bin/r2 -v \
    && /opt/r2mcp/bin/r2mcp -v \
    && /opt/python314/bin/python3.14 --version \
    && python3 -c 'import capstone, dncil, dnfile, malduck, pefile, r2pipe, xdis' \
    && command -v binwalk bsdtar capa innoextract llvm-objdump msiextract \
        pyinstxtractor-ng pydisasm readpe upx yara \
    && pyc-disasm --help >/dev/null \
    && jaq-tools >/dev/null \
    && ldd /opt/r2mcp/bin/r2mcp

ENV PATH=/opt/r2/bin:/opt/r2mcp/bin:${PATH} \
    HOME=/work \
    JAQ_TOOLS_MANIFEST=/opt/jaq/TOOLS.md

USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/opt/jaq/entrypoint.sh"]
