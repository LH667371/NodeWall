FROM golang:1.27.3-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    libc6-dev \
    linux-libc-dev \
    make \
    && case "$(uname -m)" in \
      x86_64) arch="x86_64-linux-gnu" ;; \
      aarch64|arm64) arch="aarch64-linux-gnu" ;; \
      *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac \
    && ln -sf "/usr/include/${arch}/asm" /usr/include/asm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
