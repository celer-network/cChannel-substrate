# Based from https://github.com/paritytech/substrate/blob/master/.maintain/Dockerfile
# ===== FIRST STAGE =====
FROM phusion/baseimage:0.11 as builder
LABEL maintainer="hashimoto19980924@gmail.com"
LABEL description="This is the build stage for Celer Node. Here we create the binary."

ENV DEBIAN_FRONTEND=noninteractive

ARG PROFILE=release
WORKDIR /celer

COPY . /celer

RUN apt-get update && \
	apt-get dist-upgrade -y -o Dpkg::Options::="--force-confold" && \
	apt-get install -y cmake cmake pkg-config libssl-dev git clang libclang-dev

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
	export PATH="$PATH:$HOME/.cargo/bin" && \
	rustup uninstall nightly && \
	rustup install nightly-2020-10-01 && \
	rustup target add wasm32-unknown-unknown --toolchain nightly-2020-10-01 && \
	cargo build "--$PROFILE"
	
# ===== SECOND STAGE ======
FROM phusion/baseimage:0.11
LABEL maintainer="hashimoto19980924@gmail.com"
LABEL description="This is the 2nd stage: a very small image where we copy the Celer Node binary."
ARG PROFILE=release

RUN mv /usr/share/ca* /tmp && \
	rm -rf /usr/share/*  && \
	mv /tmp/ca-certificates /usr/share/ && \
	useradd -m -u 1000 -U -s /bin/sh -d /celer celer

COPY --from=builder /celer/target/$PROFILE/celer-network /usr/local/bin

# checks
RUN ldd /usr/local/bin/celer-network && \
	/usr/local/bin/celer-network --version

# Shrinking
RUN rm -rf /usr/lib/python* && \
	rm -rf /usr/bin /usr/sbin /usr/share/man

USER celer
EXPOSE 30333 9933 9944 9615

RUN mkdir /celer/data

VOLUME ["/celer/data"]

ENTRYPOINT ["/usr/local/bin/celer-network"]
CMD ["--dev", "--tmp", "--rpc-cors=all"]