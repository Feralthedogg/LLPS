# LLPS
### LLAM L4 Proxy Shield

LLPS is a TCP L4 proxy built on LLAM.

## Install LLAM

POSIX auto-detect:

```sh
curl -fsSL https://github.com/Feralthedogg/LLAM/releases/download/v2.0.0/install.sh | sh -s -- --version 2.0.0 --base-url "https://github.com/Feralthedogg/LLAM/releases/download/v2.0.0" --prefix "$HOME/.local"
```

POSIX explicit target:

```sh
curl -fsSL https://github.com/Feralthedogg/LLAM/releases/download/v2.0.0/install.sh | sh -s -- --version 2.0.0 --base-url "https://github.com/Feralthedogg/LLAM/releases/download/v2.0.0" --target macos-aarch64 --prefix "$HOME/.local"
```

Windows x86_64:

```powershell
Invoke-WebRequest "https://github.com/Feralthedogg/LLAM/releases/download/v2.0.0/install.ps1" -OutFile install.ps1; .\install.ps1 -Version 2.0.0 -BaseUrl "https://github.com/Feralthedogg/LLAM/releases/download/v2.0.0" -Prefix "$env:LOCALAPPDATA\LLAM"
```

## Build

```sh
make
```

Equivalent CMake command:

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH="$HOME/.local"
cmake --build build
```

## Configure

Edit `config.yml`.

Common fields:

```yaml
listen_host: 127.0.0.1
listen_port: 25565
target_host: 127.0.0.1
target_port: 25566
```

## Run

```sh
./build/llps -c config.yml
```

## Docker

Docker builds LLAM v2.0.0 from the release installer automatically.

```sh
docker build -t llps:local .
```

Run LLPS and forward to a host backend:

```sh
mkdir -p logs
docker run --rm -p 25565:25565 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=1m,mode=1777 \
  -v "$PWD/logs:/var/log/llps:rw" \
  -e LLPS_TARGET_HOST=host.docker.internal \
  -e LLPS_TARGET_PORT=25566 \
  llps:local
```

Run the Dockerfile-only smoke check:

```sh
python3 tools/run_docker_prod_check.py
```

Run a single-container smoke check with the dummy server, LLPS, and client
inside one container:

```sh
make docker-smoke-one
```

Run one long-lived container with the dummy server and LLPS inside it:

```sh
make docker-run-one
```

## Test

```sh
make test
make audit
```

Run the Docker benchmark:

```sh
make docker-bench
```

## Clean

```sh
make clean
```

Remove logs too:

```sh
make distclean
```
