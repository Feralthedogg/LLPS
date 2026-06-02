BUILD_DIR ?= build
BUILD_TYPE ?= Release
LLAM_PREFIX ?= $(HOME)/.local
CMAKE ?= cmake
CTEST ?= ctest
DOCKER ?= docker
PYTHON ?= python3

.PHONY: all configure build test audit docker-build docker-bench clean distclean

all: build

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DCMAKE_PREFIX_PATH=$(LLAM_PREFIX)

build: configure
	$(CMAKE) --build $(BUILD_DIR)

test:
	$(CMAKE) -S . -B build-test -DCMAKE_PREFIX_PATH=$(LLAM_PREFIX) -DBUILD_TESTING=ON
	$(CMAKE) --build build-test --target test_llps
	$(CTEST) --test-dir build-test --output-on-failure

audit:
	$(PYTHON) tools/run_power_of_ten_audit.py

docker-build:
	$(DOCKER) build -t llps:local .

docker-bench:
	$(PYTHON) tools/run_docker_bench.py --clients 100 --duration 5 --quiet-llps-logs

clean:
	rm -rf build build-* coverage_report htmlcov .pytest_cache .mypy_cache .ruff_cache
	find . \( -name '*.gcda' -o -name '*.gcno' -o -name 'coverage.info' \) -delete
	find . \( -name '__pycache__' -o -name '.pytest_cache' \) -type d -prune -exec rm -rf {} +

distclean: clean
	rm -f logs/*.pxf logs/*.log llps_debug.log benchmark_out.txt
