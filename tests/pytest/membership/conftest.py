import infra.network
import infra.e2e_args

import pytest

CONSTITUTION_ARGS = [
      "--constitution",
      "../src/runtime_config/default/actions.js",
      "--constitution",
      "../src/runtime_config/test/test_actions.js",
      "--constitution",
      "../src/runtime_config/default/validate.js",
      "--constitution",
      "../src/runtime_config/test/resolve.js",
      "--constitution",
      "../src/runtime_config/default/apply.js"
]

LOGGING_PKG = [
    "-p", "samples/apps/logging/liblogging", "-e", "virtual", "--initial-user-count", "0"
]

@pytest.fixture(scope="module")
def network():
    net = infra.network.Network(["local://localhost", "local://localhost"], ".")
    args = infra.e2e_args.cli_args(args_=CONSTITUTION_ARGS + LOGGING_PKG)
    net.start_and_join(args)
    yield net
    net.stop_all_nodes(skip_verification=True)