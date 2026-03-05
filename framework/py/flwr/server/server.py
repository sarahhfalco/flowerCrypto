# Copyright 2025 Flower Labs GmbH. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================
"""Flower server."""


import concurrent.futures
import threading
import io
import os
import timeit
from logging import INFO, WARN
from typing import Callable, Optional, TypeVar, Union

from flwr.common import (
    Code,
    DisconnectRes,
    EvaluateIns,
    EvaluateRes,
    FitIns,
    FitRes,
    Parameters,
    ReconnectIns,
    Scalar,
)


TResult = TypeVar("TResult")


class _ConcurrencyTracker:
    """Track current and peak concurrency for a batch of tasks."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.current = 0
        self.peak = 0

    def increment(self) -> None:
        with self._lock:
            self.current += 1
            if self.current > self.peak:
                self.peak = self.current

    def decrement(self) -> None:
        with self._lock:
            self.current -= 1


def _track_concurrency(
    tracker: _ConcurrencyTracker, func: Callable[..., TResult], *args: object
) -> TResult:
    tracker.increment()
    try:
        return func(*args)
    finally:
        tracker.decrement()


def _wait_for_futures_with_progress(
    submitted_fs: set[concurrent.futures.Future],
    timeout: Optional[float],
    op_name: str,
) -> tuple[set[concurrent.futures.Future], set[concurrent.futures.Future]]:
    """Wait for futures while periodically logging pending work.

    If `timeout` is None, wait indefinitely but emit progress warnings.
    If `timeout` is set, stop waiting after timeout and return unfinished futures.
    """
    poll_interval = 30.0
    started_at = timeit.default_timer()
    remaining = set(submitted_fs)
    finished_total: set[concurrent.futures.Future] = set()

    while remaining:
        elapsed = timeit.default_timer() - started_at
        if timeout is not None:
            remaining_budget = timeout - elapsed
            if remaining_budget <= 0.0:
                break
            current_poll = min(poll_interval, remaining_budget)
        else:
            current_poll = poll_interval

        finished_now, not_done = concurrent.futures.wait(
            fs=remaining,
            timeout=current_poll,
        )
        if finished_now:
            finished_total.update(finished_now)
            remaining = set(not_done)
            continue

        # No completion within poll window: emit diagnostic warning
        if timeout is None:
            log(
                WARN,
                "%s still waiting for %s/%s client(s) after %.1fs (no round_timeout set)",
                op_name,
                len(remaining),
                len(submitted_fs),
                elapsed,
            )
        else:
            log(
                WARN,
                "%s still waiting for %s/%s client(s) after %.1fs (round_timeout=%.1fs)",
                op_name,
                len(remaining),
                len(submitted_fs),
                elapsed,
                timeout,
            )

    return finished_total, remaining
from flwr.common.logger import log
from flwr.common.typing import GetParametersIns
from flwr.server.client_manager import ClientManager, SimpleClientManager
from flwr.server.client_proxy import ClientProxy
from flwr.server.history import History
from flwr.server.strategy import FedAvg, Strategy

from .server_config import ServerConfig
from ..common.crypto import log_file
from ..common.crypto.log_file import log_time

FitResultsAndFailures = tuple[
    list[tuple[ClientProxy, FitRes]],
    list[Union[tuple[ClientProxy, FitRes], BaseException]],
]
EvaluateResultsAndFailures = tuple[
    list[tuple[ClientProxy, EvaluateRes]],
    list[Union[tuple[ClientProxy, EvaluateRes], BaseException]],
]
ReconnectResultsAndFailures = tuple[
    list[tuple[ClientProxy, DisconnectRes]],
    list[Union[tuple[ClientProxy, DisconnectRes], BaseException]],
]


class Server:
    """Flower server."""

    def __init__(
        self,
        *,
        client_manager: ClientManager,
        strategy: Optional[Strategy] = None,
    ) -> None:
        self._client_manager: ClientManager = client_manager
        self.parameters: Parameters = Parameters(
            tensors=[], tensor_type="numpy.ndarray"
        )
        self.strategy: Strategy = strategy if strategy is not None else FedAvg()
        self.max_workers: Optional[int] = None

    def set_max_workers(self, max_workers: Optional[int]) -> None:
        """Set the max_workers used by ThreadPoolExecutor."""
        self.max_workers = max_workers

    def set_strategy(self, strategy: Strategy) -> None:
        """Replace server strategy."""
        self.strategy = strategy

    def client_manager(self) -> ClientManager:
        """Return ClientManager."""
        return self._client_manager

    # pylint: disable=too-many-locals
    def fit(self, num_rounds: int, timeout: Optional[float]) -> tuple[History, float]:
        """Run federated averaging for a number of rounds."""
        log(INFO, "inizio1")
        start_time = timeit.default_timer()
        log_file.reset_crypto_totals()
        history = History()
        if hasattr(self.strategy, "history"):
                self.strategy.history = history
        num_clients = self._client_manager.num_available();
        log_time("Numero totale di client disponibili: %s", num_clients)
        # Initialize parameters
        log(INFO, "[INIT]")
        self.parameters = self._get_initial_parameters(server_round=0, timeout=timeout)
        log(INFO, "Starting evaluation of initial global parameters")
        res = self.strategy.evaluate(0, parameters=self.parameters)
        if res is not None:
            log(
                INFO,
                "initial parameters (loss, other metrics): %s, %s",
                res[0],
                res[1],
            )
            history.add_loss_centralized(server_round=0, loss=res[0])
            history.add_metrics_centralized(server_round=0, metrics=res[1])
        else:
            log(INFO, "Evaluation returned no results (`None`)")

        # Run federated learning for num_rounds
        if timeout is None:
            log(
                WARN,
                "round_timeout is None: the server can wait indefinitely for slow/hung clients",
            )
            log_time(
                "ATTENZIONE: round_timeout=None, il server può restare in attesa indefinita dei client",
            )
        prev_crypto_total, _ = log_file.get_crypto_totals()
        prev_encrypt_total, prev_decrypt_total = log_file.get_encrypt_decrypt_totals()
        prev_integrity_total = log_file.get_integrity_totals()
        prev_auth_total = log_file.get_auth_totals()
        prev_auth_sign_total, prev_auth_verify_total = log_file.get_auth_sign_verify_totals()

        for current_round in range(1, num_rounds + 1):
            if getattr(self.strategy, "stop_triggered", False):
                log(INFO, "Early stopping triggered at round %s, stopping server.", current_round - 1)
                log_time("Early stopping triggered at round %s, stopping server.", current_round - 1)
                break

            round_start = timeit.default_timer()
            log(INFO, "[ROUND %s]", current_round)
            log_time(f"[ROUND {current_round}]")

            # Train model
            round_fit_clients = 0
            round_eval_clients = 0
            res_fit = self.fit_round(server_round=current_round, timeout=timeout)
            round_fit_parallel = 0
            if res_fit is not None:
                (
                    parameters_prime,
                    fit_metrics,
                    (fit_results, _),
                    round_fit_parallel,
                ) = res_fit  # fit_metrics_aggregated
                if parameters_prime:
                    self.parameters = parameters_prime
                history.add_metrics_distributed_fit(
                    server_round=current_round, metrics=fit_metrics
                )
                round_fit_clients = len(fit_results)

            # Evaluate model using strategy implementation
            res_cen = self.strategy.evaluate(current_round, parameters=self.parameters)
            if res_cen is not None:
                loss_cen, metrics_cen = res_cen
                log(INFO, "fit progress: (%s, %s, %s, %s)",
                    current_round, loss_cen, metrics_cen, timeit.default_timer() - round_start)
                log_time(f"fit progress: ({current_round}, {loss_cen}, {metrics_cen}, {timeit.default_timer() - round_start:.5f}s)")
                history.add_loss_centralized(server_round=current_round, loss=loss_cen)
                history.add_metrics_centralized(
                    server_round=current_round, metrics=metrics_cen
                )
                print("metrics_cen",metrics_cen )
                if "accuracy" in metrics_cen:
                    log_time("Round %s Accuracy (centralized): %.4f", current_round, metrics_cen["accuracy"])

            # Evaluate model on a sample of available clients
            res_fed = self.evaluate_round(server_round=current_round, timeout=timeout)
            round_eval_parallel = 0
            if res_fed is not None:
                (
                    loss_fed,
                    evaluate_metrics_fed,
                    (eval_results, _),
                    round_eval_parallel,
                ) = res_fed
                if loss_fed is not None:
                    history.add_loss_distributed(server_round=current_round, loss=loss_fed)
                    history.add_metrics_distributed(server_round=current_round, metrics=evaluate_metrics_fed)
                    if "accuracy" in evaluate_metrics_fed:
                       log_time("Round %s Accuracy (federated): %.4f", current_round, evaluate_metrics_fed["accuracy"])
                round_eval_clients = len(eval_results)
            # Fine round: calcolo e log del tempo
            round_elapsed = timeit.default_timer() - round_start
            current_crypto_total, _ = log_file.get_crypto_totals()
            current_encrypt_total, current_decrypt_total = log_file.get_encrypt_decrypt_totals()
            current_integrity_total = log_file.get_integrity_totals()
            current_auth_total = log_file.get_auth_totals()
            current_auth_sign_total, current_auth_verify_total = log_file.get_auth_sign_verify_totals()
            round_crypto_time = max(current_crypto_total - prev_crypto_total, 0.0)
            round_encrypt_time = max(current_encrypt_total - prev_encrypt_total, 0.0)
            round_decrypt_time = max(current_decrypt_total - prev_decrypt_total, 0.0)
            round_integrity_time = max(current_integrity_total - prev_integrity_total, 0.0)
            round_auth_time = max(current_auth_total - prev_auth_total, 0.0)
            round_auth_sign_time = max(current_auth_sign_total - prev_auth_sign_total, 0.0)
            round_auth_verify_time = max(current_auth_verify_total - prev_auth_verify_total, 0.0)
            prev_crypto_total = current_crypto_total
            prev_encrypt_total = current_encrypt_total
            prev_decrypt_total = current_decrypt_total
            prev_integrity_total = current_integrity_total
            prev_auth_total = current_auth_total
            prev_auth_sign_total = current_auth_sign_total
            prev_auth_verify_total = current_auth_verify_total
            parallel_factor = max(round_fit_parallel, round_eval_parallel, 1)
            parallel_crypto_time = min(
                round_crypto_time / parallel_factor, round_elapsed
            )
            parallel_encrypt_time = min(
                round_encrypt_time / parallel_factor, round_elapsed
            )
            parallel_decrypt_time = min(
                round_decrypt_time / parallel_factor, round_elapsed
            )
            parallel_integrity_time = min(
                round_integrity_time / parallel_factor, round_elapsed
            )
            parallel_auth_time = min(
                round_auth_time / parallel_factor, round_elapsed
            )
            parallel_auth_sign_time = min(
                round_auth_sign_time / parallel_factor, round_elapsed
            )
            parallel_auth_verify_time = min(
                round_auth_verify_time / parallel_factor, round_elapsed
            )
            without_crypto = max(round_elapsed - parallel_crypto_time, 0.0)
            log_file.ROUND_SUMMARIES.append({
                "round": current_round,
                "round_time": round_elapsed,
                "crypto_time": parallel_crypto_time,
                "crypto_cumulative": round_crypto_time,
                "encrypt_time": parallel_encrypt_time,
                "decrypt_time": parallel_decrypt_time,
                "integrity_time": parallel_integrity_time,
                "auth_time": parallel_auth_time,
                "auth_cumulative": round_auth_time,
                "auth_sign_time": parallel_auth_sign_time,
                "auth_verify_time": parallel_auth_verify_time,
                "parallel_fit": float(round_fit_parallel),
                "parallel_eval": float(round_eval_parallel),
                "parallel_factor": float(parallel_factor),
                "without_crypto": without_crypto,
            })

            log_time(
                "Tempo totale round %s: %.2f s | cifratura: %.2f s | decifratura: %.2f s | integrity: %.2f s | firma: %.2f s | verifica: %.2f s",
                current_round,
                round_elapsed,
                parallel_encrypt_time,
                parallel_decrypt_time,
                parallel_integrity_time,
                parallel_auth_sign_time,
                parallel_auth_verify_time,
            )

            history.add_metrics_centralized(
                server_round=current_round,
                metrics={"round_time": round_elapsed}
            )

        # Bookkeeping
       #. if log_file.is_report_requested():
            log_time("=== Report tempi round ===")
            for line in log_file.build_round_time_report():
                log_time(line)
        end_time = timeit.default_timer()

        elapsed= end_time - start_time
        return history, elapsed

    def evaluate_round(
        self,
        server_round: int,
        timeout: Optional[float],
    ) -> Optional[
        tuple[Optional[float], dict[str, Scalar], EvaluateResultsAndFailures, int]
    ]:
        """Validate current global model on a number of clients."""
        # Get clients and their respective instructions from strategy
        client_instructions = self.strategy.configure_evaluate(
            server_round=server_round,
            parameters=self.parameters,
            client_manager=self._client_manager,
        )
        if not client_instructions:
            log(INFO, "configure_evaluate: no clients selected, skipping evaluation")
            return None
        log(
            INFO,
            "configure_evaluate: strategy sampled %s clients (out of %s)",
            len(client_instructions),
            self._client_manager.num_available(),
        )

        # Collect `evaluate` results from all clients participating in this round
        (results, failures), eval_parallel = evaluate_clients(
            client_instructions,
            max_workers=self.max_workers,
            timeout=timeout,
            group_id=server_round,
        )
        log(
            INFO,
            "aggregate_evaluate: received %s results and %s failures",
            len(results),
            len(failures),
        )
        for failure in failures:
            log(WARN, "evaluate failure detail: %s", failure)

        # Aggregate the evaluation results
        aggregated_result: tuple[
            Optional[float],
            dict[str, Scalar],
        ] = self.strategy.aggregate_evaluate(server_round, results, failures)

        loss_aggregated, metrics_aggregated = aggregated_result
        return loss_aggregated, metrics_aggregated, (results, failures), eval_parallel

    def fit_round(
        self,
        server_round: int,
        timeout: Optional[float],
    ) -> Optional[
        tuple[Optional[Parameters], dict[str, Scalar], FitResultsAndFailures, int]
    ]:
        """Perform a single round of federated averaging."""
        # Get clients and their respective instructions from strategy
        client_instructions = self.strategy.configure_fit(
            server_round=server_round,
            parameters=self.parameters,
            client_manager=self._client_manager,
        )

        if not client_instructions:
            log(INFO, "configure_fit: no clients selected, cancel")
            return None
        log(
            INFO,
            "configure_fit: strategy sampled %s clients (out of %s)",
            len(client_instructions),
            self._client_manager.num_available(),
        )

        # Collect `fit` results from all clients participating in this round
        (results, failures), fit_parallel = fit_clients(
            client_instructions=client_instructions,
            max_workers=self.max_workers,
            timeout=timeout,
            group_id=server_round,
        )
        log(
            INFO,
            "aggregate_fit: received %s results and %s failures",
            len(results),
            len(failures),
        )
        for failure in failures:
            log(WARN, "fit failure detail: %s", failure)

        # Aggregate training results
        aggregated_result: tuple[
            Optional[Parameters],
            dict[str, Scalar],
        ] = self.strategy.aggregate_fit(server_round, results, failures)

        parameters_aggregated, metrics_aggregated = aggregated_result
        return parameters_aggregated, metrics_aggregated, (results, failures), fit_parallel

    def disconnect_all_clients(self, timeout: Optional[float]) -> None:
        """Send shutdown signal to all clients."""
        all_clients = self._client_manager.all()
        clients = [all_clients[k] for k in all_clients.keys()]
        instruction = ReconnectIns(seconds=None)
        client_instructions = [(client_proxy, instruction) for client_proxy in clients]
        _ = reconnect_clients(
            client_instructions=client_instructions,
            max_workers=self.max_workers,
            timeout=timeout,
        )

    def _get_initial_parameters(
        self, server_round: int, timeout: Optional[float]
    ) -> Parameters:
        """Get initial parameters from one of the available clients."""
        # Server-side parameter initialization
        parameters: Optional[Parameters] = self.strategy.initialize_parameters(
            client_manager=self._client_manager
        )
        if parameters is not None:
            log(INFO, "Using initial global parameters provided by strategy")
            return parameters

        # Get initial parameters from one of the clients
        log(INFO, "Requesting initial parameters from one random client")
        random_client = self._client_manager.sample(1)[0]
        ins = GetParametersIns(config={})
        get_parameters_res = random_client.get_parameters(
            ins=ins, timeout=timeout, group_id=server_round
        )
        if get_parameters_res.status.code == Code.OK:
            log(INFO, "Received initial parameters from one random client")
        else:
            log(
                WARN,
                "Failed to receive initial parameters from the client."
                " Empty initial parameters will be used.",
            )
        return get_parameters_res.parameters


def reconnect_clients(
    client_instructions: list[tuple[ClientProxy, ReconnectIns]],
    max_workers: Optional[int],
    timeout: Optional[float],
) -> ReconnectResultsAndFailures:
    """Instruct clients to disconnect and never reconnect."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        submitted_fs = {
            executor.submit(reconnect_client, client_proxy, ins, timeout)
            for client_proxy, ins in client_instructions
        }
        finished_fs, unfinished_fs = _wait_for_futures_with_progress(
            submitted_fs,
            timeout,
            "reconnect",
        )
        if unfinished_fs:
            for future in unfinished_fs:
                future.cancel()

    # Gather results
    results: list[tuple[ClientProxy, DisconnectRes]] = []
    failures: list[Union[tuple[ClientProxy, DisconnectRes], BaseException]] = []
    for future in finished_fs:
        failure = future.exception()
        if failure is not None:
            failures.append(failure)
        else:
            result = future.result()
            results.append(result)
    return results, failures


def reconnect_client(
    client: ClientProxy,
    reconnect: ReconnectIns,
    timeout: Optional[float],
) -> tuple[ClientProxy, DisconnectRes]:
    """Instruct client to disconnect and (optionally) reconnect later."""
    disconnect = client.reconnect(
        reconnect,
        timeout=timeout,
        group_id=None,
    )
    return client, disconnect


def fit_clients(
    client_instructions: list[tuple[ClientProxy, FitIns]],
    max_workers: Optional[int],
    timeout: Optional[float],
    group_id: int,
) -> tuple[FitResultsAndFailures, int]:
    """Refine parameters concurrently on all selected clients."""
    tracker = _ConcurrencyTracker()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        submitted_fs = {
            executor.submit(
                _track_concurrency,
                tracker,
                fit_client,
                client_proxy,
                ins,
                timeout,
                group_id,
            )
            for client_proxy, ins in client_instructions
        }
        finished_fs, unfinished_fs = _wait_for_futures_with_progress(
            submitted_fs,
            timeout,
            "fit",
        )
        if unfinished_fs:
            for future in unfinished_fs:
                future.cancel()

    # Gather results
    results: list[tuple[ClientProxy, FitRes]] = []
    failures: list[Union[tuple[ClientProxy, FitRes], BaseException]] = []
    for future in finished_fs:
        _handle_finished_future_after_fit(
            future=future, results=results, failures=failures
        )
    if unfinished_fs:
        failures.extend(
            TimeoutError(
                f"fit timeout waiting for client result (pending={len(unfinished_fs)})"
            )
            for _ in unfinished_fs
        )
    return (results, failures), tracker.peak


def fit_client(
    client: ClientProxy, ins: FitIns, timeout: Optional[float], group_id: int
) -> tuple[ClientProxy, FitRes]:
    """Refine parameters on a single client."""
    fit_res = client.fit(ins, timeout=timeout, group_id=group_id)
    return client, fit_res


def _handle_finished_future_after_fit(
    future: concurrent.futures.Future,  # type: ignore
    results: list[tuple[ClientProxy, FitRes]],
    failures: list[Union[tuple[ClientProxy, FitRes], BaseException]],
) -> None:
    """Convert finished future into either a result or a failure."""
    # Check if there was an exception
    failure = future.exception()
    if failure is not None:
        failures.append(failure)
        return

    # Successfully received a result from a client
    result: tuple[ClientProxy, FitRes] = future.result()
    _, res = result

    # Check result status code
    if res.status.code == Code.OK:
        results.append(result)
        return

    # Not successful, client returned a result where the status code is not OK
    failures.append(result)


def evaluate_clients(
    client_instructions: list[tuple[ClientProxy, EvaluateIns]],
    max_workers: Optional[int],
    timeout: Optional[float],
    group_id: int,
) -> tuple[EvaluateResultsAndFailures, int]:
    """Evaluate parameters concurrently on all selected clients."""
    tracker = _ConcurrencyTracker()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        submitted_fs = {
            executor.submit(
                _track_concurrency,
                tracker,
                evaluate_client,
                client_proxy,
                ins,
                timeout,
                group_id,
            )
            for client_proxy, ins in client_instructions
        }
        finished_fs, unfinished_fs = _wait_for_futures_with_progress(
            submitted_fs,
            timeout,
            "evaluate",
        )
        if unfinished_fs:
            for future in unfinished_fs:
                future.cancel()

    # Gather results
    results: list[tuple[ClientProxy, EvaluateRes]] = []
    failures: list[Union[tuple[ClientProxy, EvaluateRes], BaseException]] = []
    for future in finished_fs:
        _handle_finished_future_after_evaluate(
            future=future, results=results, failures=failures
        )
    if unfinished_fs:
        failures.extend(
            TimeoutError(
                f"evaluate timeout waiting for client result (pending={len(unfinished_fs)})"
            )
            for _ in unfinished_fs
        )
    return (results, failures), tracker.peak


def evaluate_client(
    client: ClientProxy,
    ins: EvaluateIns,
    timeout: Optional[float],
    group_id: int,
) -> tuple[ClientProxy, EvaluateRes]:
    """Evaluate parameters on a single client."""
    evaluate_res = client.evaluate(ins, timeout=timeout, group_id=group_id)
    return client, evaluate_res


def _handle_finished_future_after_evaluate(
    future: concurrent.futures.Future,  # type: ignore
    results: list[tuple[ClientProxy, EvaluateRes]],
    failures: list[Union[tuple[ClientProxy, EvaluateRes], BaseException]],
) -> None:
    """Convert finished future into either a result or a failure."""
    # Check if there was an exception
    failure = future.exception()
    if failure is not None:
        failures.append(failure)
        return

    # Successfully received a result from a client
    result: tuple[ClientProxy, EvaluateRes] = future.result()
    _, res = result

    # Check result status code
    if res.status.code == Code.OK:
        results.append(result)
        return

    # Not successful, client returned a result where the status code is not OK
    failures.append(result)


def init_defaults(
    server: Optional[Server],
    config: Optional[ServerConfig],
    strategy: Optional[Strategy],
    client_manager: Optional[ClientManager],
) -> tuple[Server, ServerConfig]:
    """Create server instance if none was given."""
    if server is None:
        if client_manager is None:
            client_manager = SimpleClientManager()
        if strategy is None:
            strategy = FedAvg()
        server = Server(client_manager=client_manager, strategy=strategy)
    elif strategy is not None:
        log(WARN, "Both server and strategy were provided, ignoring strategy")

    # Set default config values
    if config is None:
        config = ServerConfig()

    return server, config

import requests

BOT_TOKEN = "8440783074:AAGBenk_eeglVRWIIvuNACUBCkhSxVJoAio"
CHAT_ID = 587180276

def send_telegram_file(file_path: str, caption: str = ""):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    try:
        with open(file_path, "rb") as f:
            files = {"document": f}
            data = {"chat_id": CHAT_ID, "caption": caption}
            requests.post(url, data=data, files=files)
    except Exception as e:
        print(f"Errore invio file Telegram: {e}")

def run_fl(
        server: Server,
        config: ServerConfig,
) -> History:
    """Train a model on the given server and return the History object."""
    hist, elapsed_time = server.fit(
        num_rounds=config.num_rounds, timeout=config.round_timeout
    )

    log(INFO, "")
    log(INFO, "[SUMMARY]")
    executed_rounds = len(hist.metrics_centralized.get("round_time", []))
    if executed_rounds == 0:
        executed_rounds = len(hist.losses_centralized)
    if executed_rounds == 0:
        executed_rounds = config.num_rounds

    log(INFO, "Run finished %s round(s) in %.2fs", executed_rounds, elapsed_time)
    log_time(
        "Run finished %s round(s) in %.2fs (tempo wall-clock totale, include training+rete+auth/crypto)",
        executed_rounds,
        elapsed_time,
    )
    total_crypto_time_cumulative, total_serial_time = log_file.get_crypto_totals()
    total_integrity_time = log_file.get_integrity_totals()
    total_auth_time_cumulative = log_file.get_auth_totals()
    total_auth_sign_time_cumulative, total_auth_verify_time_cumulative = log_file.get_auth_sign_verify_totals()

    round_summaries = log_file.get_round_summaries()
    total_crypto_time_parallel = sum(s.get("crypto_time", 0.0) for s in round_summaries)
    total_encrypt_time_parallel = sum(s.get("encrypt_time", 0.0) for s in round_summaries)
    total_decrypt_time_parallel = sum(s.get("decrypt_time", 0.0) for s in round_summaries)
    total_integrity_time_parallel = sum(s.get("integrity_time", 0.0) for s in round_summaries)
    total_auth_time_parallel = sum(s.get("auth_time", 0.0) for s in round_summaries)
    total_auth_sign_time_parallel = sum(s.get("auth_sign_time", 0.0) for s in round_summaries)
    total_auth_verify_time_parallel = sum(s.get("auth_verify_time", 0.0) for s in round_summaries)

    crypto_impact = (
        (total_crypto_time_parallel / elapsed_time * 100.0) if elapsed_time > 0 else 0.0
    )
    auth_impact = (
        (total_auth_time_parallel / elapsed_time * 100.0) if elapsed_time > 0 else 0.0
    )
    log_time(
        "Totale critto (parallel): %.2f s su %.2f s (%.2f%%) | encrypt: %.2f s | decrypt: %.2f s | integrity: %.2f s | auth: %.2f s (%.2f%%) | firma: %.2f s | verifica: %.2f s | serializzazione: %.2f s",
        total_crypto_time_parallel,
        elapsed_time,
        crypto_impact,
        total_encrypt_time_parallel,
        total_decrypt_time_parallel,
        total_integrity_time_parallel,
        total_auth_time_parallel,
        auth_impact,
        total_auth_sign_time_parallel,
        total_auth_verify_time_parallel,
        total_serial_time,
    )
    log_time(
        "Totale critto cumulativo (somma operazioni su tutti i client): %.2f s | auth cumulativo: %.2f s | integrity cumulativo: %.2f s",
        total_crypto_time_cumulative,
        total_auth_time_cumulative,
        total_integrity_time,
    )
    estimated_without_auth_parallel = max(elapsed_time - total_auth_time_parallel, 0.0)
    estimated_without_crypto_auth_parallel = max(
        elapsed_time - total_auth_time_parallel - total_crypto_time_parallel,
        0.0,
    )
    log_time(
        "Tempo totale include auth/crypto. Stima senza auth (parallel): %.2f s | senza auth+crypto (parallel): %.2f s",
        estimated_without_auth_parallel,
        estimated_without_crypto_auth_parallel,
    )
    log_time(
        "Totale firma cumulativo: %.2f s | totale verifica cumulativo: %.2f s",
        total_auth_sign_time_cumulative,
        total_auth_verify_time_cumulative,
    )
    for line in log_file.build_overhead_report():
        log_time(line)

    # 📩 Messaggio Telegram
    #send_telegram_file(null,"Ho finito!!!!")

    # 📄 Invio CSV se esiste


    for line in io.StringIO(str(hist)):
        log_time("\t%s", line.strip("\n"))
        log_time("")

    log_time("")  # riga vuota finale
    if log_file.CSV_PATH is not None:
        abs_path = os.path.abspath(log_file.CSV_PATH)

        if os.path.exists(abs_path):
            send_telegram_file(abs_path, caption="Ecco il log del run")
        else:
            print(f"[run_fl] File non trovato: {abs_path}")
    else:
        print("[run_fl] Nessun CSV_PATH disponibile")
    # Graceful shutdown
    server.disconnect_all_clients(timeout=config.round_timeout)

    return hist
