# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import time
import pprint

from typing import Optional, List

from infra.tx_status import TxStatus
from infra.log_capture import flush_info

from alive_progress import alive_bar


def wait_for_commit(
    client, seqno: int, view: int, timeout: int = 5, log_capture: Optional[list] = None
) -> None:
    """
    Waits for a specific seqno/view pair to be committed by the network,
    as per the node to which client is connected to.

    :param client: Instance of :py:class:`infra.clients.CCFClient`
    :param int seqno: Transaction sequence number.
    :param int view: Consensus view.
    :param str timeout: Maximum time to wait for this seqno/view pair to be committed before giving up.
    :param list log_capture: Rather than emit to default handler, capture log lines to list (optional).

    A TimeoutError exception is raised if the commit index is not committed within the given timeout.
    """
    if view is None or seqno is None:
        raise ValueError(f"{view}.{seqno} is not a valid transaction ID")

    logs: List[str] = []
    end_time = time.time() + timeout
    with alive_bar(5) as bar:
        while time.time() < end_time:
            logs = []
            r = client.get(f"/node/tx?transaction_id={view}.{seqno}", log_capture=logs)

            # May see consistency breaks while polling for commit, depending on the
            # client used. Assume it will reconnect silently, and retry
            if r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                assert r.body.json()["error"]["code"] == "SessionConsistencyLost", r
                continue

            assert (
                r.status_code == http.HTTPStatus.OK
            ), f"tx request returned HTTP status {r.status_code}"
            status = TxStatus(r.body.json()["status"])
            if status == TxStatus.Committed:
                flush_info(logs, log_capture, 1)
                return
            elif status == TxStatus.Invalid:
                raise RuntimeError(
                    f"Transaction ID {view}.{seqno} is marked invalid and will never be committed"
                )
            else:
                time.sleep(0.01)
            bar()
    flush_info(logs, log_capture, 1)
    raise TimeoutError(
        f'Timed out waiting {timeout}s for commit: {pprint.pformat(client.get("/node/commit").body.json())}\n{pprint.pformat(client.get("/node/consensus").body.json())}'
    )
