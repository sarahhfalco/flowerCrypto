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
"""Federated Averaging (FedAvg) [McMahan et al., 2016] strategy.

Paper: arxiv.org/abs/1602.05629
"""
from logging import WARNING
from typing import Callable, Optional, Union
import time

import pandas as pd
import os
from flwr.common import (
    EvaluateIns,
    EvaluateRes,
    FitIns,
    FitRes,
    MetricsAggregationFn,
    NDArrays,
    Parameters,
    Scalar,
    ndarrays_to_parameters,
    parameters_to_ndarrays, context, Context,
)
from flwr.common.logger import log
from flwr.server.client_manager import ClientManager
from flwr.server.client_proxy import ClientProxy
from flwr.common.CriptoLib.configCrypto import (ENCRYPTION_METHOD, ENCRYPTION_ENABLED)
from .aggregate import aggregate, aggregate_inplace, weighted_loss_avg
from .strategy import Strategy


WARNING_MIN_AVAILABLE_CLIENTS_TOO_LOW = """
Setting `min_available_clients` lower than `min_fit_clients` or
`min_evaluate_clients` can cause the server to fail when there are too few clients
connected to the server. `min_available_clients` must be set to a value larger
than or equal to the values of `min_fit_clients` and `min_evaluate_clients`.
"""


# pylint: disable=line-too-long
class FedAvg(Strategy):
    """Federated Averaging strategy.

    Implementation based on https://arxiv.org/abs/1602.05629

    Parameters
    ----------
    fraction_fit : float, optional
        Fraction of clients used during training. In case `min_fit_clients`
        is larger than `fraction_fit * available_clients`, `min_fit_clients`
        will still be sampled. Defaults to 1.0.
    fraction_evaluate : float, optional
        Fraction of clients used during validation. In case `min_evaluate_clients`
        is larger than `fraction_evaluate * available_clients`,
        `min_evaluate_clients` will still be sampled. Defaults to 1.0.
    min_fit_clients : int, optional
        Minimum number of clients used during training. Defaults to 2.
    min_evaluate_clients : int, optional
        Minimum number of clients used during validation. Defaults to 2.
    min_available_clients : int, optional
        Minimum number of total clients in the system. Defaults to 2.
    evaluate_fn : Optional[Callable[[int, NDArrays, Dict[str, Scalar]],Optional[Tuple[float, Dict[str, Scalar]]]]]
        Optional function used for validation. Defaults to None.
    on_fit_config_fn : Callable[[int], Dict[str, Scalar]], optional
        Function used to configure training. Defaults to None.
    on_evaluate_config_fn : Callable[[int], Dict[str, Scalar]], optional
        Function used to configure validation. Defaults to None.
    accept_failures : bool, optional
        Whether or not accept rounds containing failures. Defaults to True.
    initial_parameters : Parameters, optional
        Initial global model parameters.
    fit_metrics_aggregation_fn : Optional[MetricsAggregationFn]
        Metrics aggregation function, optional.
    evaluate_metrics_aggregation_fn : Optional[MetricsAggregationFn]
        Metrics aggregation function, optional.
    inplace : bool (default: True)
        Enable (True) or disable (False) in-place aggregation of model updates.
    """
    def should_continue(self) -> bool:
        """Decide se continuare l'allenamento."""
        if self.should_stop:
            log(WARNING, f"Target accuracy {self.target_accuracy} raggiunta. Stop del server.")
            return False
        return True

    # pylint: disable=too-many-arguments,too-many-instance-attributes, line-too-long
    def __init__(
            self,
            *,
            fraction_fit: float = 1.0,
            fraction_evaluate: float = 1.0,
            min_fit_clients: int = 2,
            min_evaluate_clients: int = 2,
            min_available_clients: int = 2,
            evaluate_fn: Optional[
                Callable[
                    [int, NDArrays, dict[str, Scalar]],
                    Optional[tuple[float, dict[str, Scalar]]],
                ]
            ] = None,
            on_fit_config_fn: Optional[Callable[[int], dict[str, Scalar]]] = None,
            on_evaluate_config_fn: Optional[Callable[[int], dict[str, Scalar]]] = None,
            accept_failures: bool = True,
            initial_parameters: Optional[Parameters] = None,
            fit_metrics_aggregation_fn: Optional[MetricsAggregationFn] = None,
            evaluate_metrics_aggregation_fn: Optional[MetricsAggregationFn] = None,
            inplace: bool = True,
            target_accuracy: float = 0.90,
            context: Optional[Context] = None
    ) -> None:
        super().__init__()

        if (
                min_fit_clients > min_available_clients
                or min_evaluate_clients > min_available_clients
        ):
            log(WARNING, WARNING_MIN_AVAILABLE_CLIENTS_TOO_LOW)

        self.fraction_fit = fraction_fit
        self.fraction_evaluate = fraction_evaluate
        self.min_fit_clients = min_fit_clients
        self.min_evaluate_clients = min_evaluate_clients
        self.min_available_clients = min_available_clients
        self.evaluate_fn = evaluate_fn
        self.on_fit_config_fn = on_fit_config_fn
        self.on_evaluate_config_fn = on_evaluate_config_fn
        self.accept_failures = accept_failures
        self.initial_parameters = initial_parameters
        self.fit_metrics_aggregation_fn = fit_metrics_aggregation_fn
        self.evaluate_metrics_aggregation_fn = evaluate_metrics_aggregation_fn
        self.inplace = inplace
        self.target_accuracy = target_accuracy
        self.should_stop = False
        self.log_data = []
        self.log_file = "fedavg_log.xlsx"
        self.training_start_time = None
        self.training_end_time = None
        self.context = context


    def __repr__(self) -> str:
        """Compute a string representation of the strategy."""
        rep = f"FedAvg(accept_failures={self.accept_failures})"
        return rep

    def log_round_data(self, round_num, fit_time, eval_time, loss, metrics):
        """Salva i dati di un round nel log e scrive su file Excel o CSV."""
        wallclock_now = time.time()
        wallclock_elapsed = (
            wallclock_now - self.training_start_time if self.training_start_time else None
        )
        total_elapsed = None

        # Somma fit + eval se entrambi presenti
        if fit_time is not None and eval_time is not None:
            total_elapsed = fit_time + eval_time

        local_epochs = metrics.get("local_epochs", None) if metrics else None
        batch_size = metrics.get("batch_size", None) if metrics else None
        learning_rate = metrics.get("learning_rate", None) if metrics else None
        n_clients = metrics.get("num_clients", None) if metrics else None

        # 👇 Check se la crittografia è abilitata

        existing = next((item for item in self.log_data if item["Round"] == round_num), None)

        if existing is None:
            # Crea nuovo record per il round
            record = {
                "Round": round_num,
                "BatchSize": batch_size,
                "LearningRate": learning_rate,
                "LocalEpochs": local_epochs,
                "Clients": n_clients,
                "EncryptionMethod": ENCRYPTION_METHOD,
                "FitTime(s)": fit_time,
                "EvalTime(s)": eval_time,
                "Loss": loss,
                "Accuracy": metrics.get("accuracy", None) if metrics else None,
                "TotalTime(s)": total_elapsed,
                "WallClockTime(s)": wallclock_elapsed
            }
            self.log_data.append(record)
        else:
            if batch_size is not None:
                existing["BatchSize"] = batch_size
            if learning_rate is not None:
                existing["LearningRate"] = learning_rate
            if n_clients is not None:
                existing["Clients"] = n_clients
            if ENCRYPTION_METHOD is not None:
                existing["EncryptionMethod"] = ENCRYPTION_METHOD
            # Aggiorna record esistente
            if fit_time is not None:
                existing["FitTime(s)"] = fit_time
            if eval_time is not None:
                existing["EvalTime(s)"] = eval_time
            if loss is not None:
                existing["Loss"] = loss
            if metrics:
                existing["Accuracy"] = metrics.get("accuracy", None)
            if total_elapsed is not None:
                existing["TotalTime(s)"] = total_elapsed
            existing["WallClockTime(s)"] = wallclock_elapsed

        # Salva su file Excel/CSV
        self._save_log_file()


    def log_round_time(self, round_num: int, total_time: float) -> None:
        """Aggiorna il log del round con il tempo totale (fit+eval+overhead)."""
        # Cerca il record del round
        existing = next((item for item in self.log_data if item["Round"] == round_num), None)
        if existing:
            existing["TotalTime(s)"] = total_time
        else:
            # Se non c'è ancora, creane uno minimal
            self.log_data.append({
                "Round": round_num,
                "FitTime(s)": None,
                "EvalTime(s)": None,
                "Loss": None,
                "Accuracy": None,
                "TotalTime(s)": total_time,
                "WallClockTime(s)": None
            })
        # Salva su file
        self._save_log_file()


    def log_training_end(self, total_wallclock_time: Optional[float] = None):
        """Calcola e stampa il tempo totale di allenamento e wallclock."""
        if self.training_start_time and self.training_end_time:
            total_duration = self.training_end_time - self.training_start_time
            print(f"\n⏱️ Tempo totale di allenamento federato: {total_duration:.2f} secondi")
            if total_wallclock_time is not None:
                print(f"🕒 Tempo totale wallclock (simulazione completa): {total_wallclock_time:.2f} secondi")
            else:
                total_wallclock_time = total_duration

            # Aggiungi riga finale al log
            summary = {
                "Round": "TOTAL",
                "FitTime(s)": None,
                "EvalTime(s)": None,
                "Loss": None,
                "Accuracy": None,
                "TotalTime(s)": total_wallclock_time,
            }
            self.log_data.append(summary)

            # Salva su file
            self._save_log_file()


    def _save_log_file(self):
        """Salva log_data su file Excel o CSV."""
        df = pd.DataFrame(self.log_data)
        try:
            if self.log_file.endswith(".csv"):
                df.to_csv(self.log_file, index=False)
            else:
                df.to_excel(self.log_file, index=False)
        except Exception as e:
            print(f"⚠️ Errore nel salvataggio del log: {e}")

    def num_fit_clients(self, num_available_clients: int) -> tuple[int, int]:
        """Return the sample size and the required number of available clients."""
        num_clients = int(num_available_clients * self.fraction_fit)
        return max(num_clients, self.min_fit_clients), self.min_available_clients

    def num_evaluation_clients(self, num_available_clients: int) -> tuple[int, int]:
        """Use a fraction of available clients for evaluation."""
        num_clients = int(num_available_clients * self.fraction_evaluate)
        return max(num_clients, self.min_evaluate_clients), self.min_available_clients

    def initialize_parameters(
            self, client_manager: ClientManager
    ) -> Optional[Parameters]:
        """Initialize global model parameters."""
        initial_parameters = self.initial_parameters
        self.initial_parameters = None  # Don't keep initial parameters in memory
        return initial_parameters

    def evaluate(
            self, server_round: int, parameters: Parameters
    ) -> Optional[tuple[float, dict[str, Scalar]]]:
        """Evaluate model parameters using an evaluation function."""
        if self.evaluate_fn is None:
            # No evaluation function provided
            return None
        parameters_ndarrays = parameters_to_ndarrays(parameters)
        eval_res = self.evaluate_fn(server_round, parameters_ndarrays, {})
        if eval_res is None:
            return None
        loss, metrics = eval_res
        return loss, metrics

    def configure_fit(
            self, server_round: int, parameters: Parameters, client_manager: ClientManager
    ) -> list[tuple[ClientProxy, FitIns]]:
        """Configure the next round of training."""
        config = {}
        if self.on_fit_config_fn is not None:
            # Custom fit config function provided
            config = self.on_fit_config_fn(server_round)
        fit_ins = FitIns(parameters, config)

        # Sample clients
        sample_size, min_num_clients = self.num_fit_clients(
            client_manager.num_available()
        )
        clients = client_manager.sample(
            num_clients=sample_size, min_num_clients=min_num_clients
        )

        # Return client/config pairs
        return [(client, fit_ins) for client in clients]

    def configure_evaluate(
            self, server_round: int, parameters: Parameters, client_manager: ClientManager
    ) -> list[tuple[ClientProxy, EvaluateIns]]:
        """Configure the next round of evaluation."""
        # Do not configure federated evaluation if fraction eval is 0.
        if self.fraction_evaluate == 0.0:
            return []

        # Parameters and config
        config = {}
        if self.on_evaluate_config_fn is not None:
            # Custom evaluation config function provided
            config = self.on_evaluate_config_fn(server_round)
        evaluate_ins = EvaluateIns(parameters, config)

        # Sample clients
        sample_size, min_num_clients = self.num_evaluation_clients(
            client_manager.num_available()
        )
        clients = client_manager.sample(
            num_clients=sample_size, min_num_clients=min_num_clients
        )

        # Return client/config pairs
        return [(client, evaluate_ins) for client in clients]

    def aggregate_fit(
            self,
            server_round: int,
            results: list[tuple[ClientProxy, FitRes]],
            failures: list[Union[tuple[ClientProxy, FitRes], BaseException]],
    ) -> tuple[Optional[Parameters], dict[str, Scalar]]:
        """Aggregate fit results using weighted average and log extra info."""
        if self.training_start_time is None:
            self.training_start_time = time.time()
        start_time = time.time()

        if not results:
            return None, {}
        if not self.accept_failures and failures:
            return None, {}

        # Aggregate model updates
        if self.inplace:
            aggregated_ndarrays = aggregate_inplace(results)
        else:
            weights_results = [
                (parameters_to_ndarrays(fit_res.parameters), fit_res.num_examples)
                for _, fit_res in results
            ]
            aggregated_ndarrays = aggregate(weights_results)

        parameters_aggregated = ndarrays_to_parameters(aggregated_ndarrays)

        # Aggregate custom metrics
        metrics_aggregated = {}
        if self.fit_metrics_aggregation_fn:
            fit_metrics = [(res.num_examples, res.metrics) for _, res in results]
            metrics_aggregated = self.fit_metrics_aggregation_fn(fit_metrics)
        elif server_round == 1:
            log(WARNING, "No fit_metrics_aggregation_fn provided")

        end_time = time.time()
        fit_duration = end_time - start_time
        print(f"[Round {server_round}] Fit aggregation time: {fit_duration:.2f}s")

        # 👇 NEW: get extra params from context.run_config
        batch_size =  self.context.run_config.get("batch-size", None)
        learning_rate = self.context.run_config.get("learning-rate", None)
        n_clients = len(results)
        local_epochs = self.context.run_config.get("local-epochs", None)

        # Add to metrics
        metrics_aggregated["batch_size"] = batch_size
        metrics_aggregated["learning_rate"] = learning_rate
        metrics_aggregated["num_clients"] = n_clients
        metrics_aggregated["local_epochs"] = local_epochs


        # Log round data
        self.log_round_data(server_round, fit_duration, None, None, metrics_aggregated)

        return parameters_aggregated, metrics_aggregated


    def aggregate_evaluate(
            self,
            server_round: int,
            results: list[tuple[ClientProxy, EvaluateRes]],
            failures: list[Union[tuple[ClientProxy, EvaluateRes], BaseException]],
    ) -> tuple[Optional[float], dict[str, Scalar]]:
        """Aggregate evaluation losses using weighted average."""
        start_time = time.time()
        if not results:
            return None, {}
        # Do not aggregate if there are failures and failures are not accepted
        if not self.accept_failures and failures:
            return None, {}

        # Aggregate loss
        loss_aggregated = weighted_loss_avg(
            [
                (evaluate_res.num_examples, evaluate_res.loss)
                for _, evaluate_res in results
            ]
        )

        # Aggregate custom metrics if aggregation fn was provided
        metrics_aggregated = {}
        if self.evaluate_metrics_aggregation_fn:
            eval_metrics = [(res.num_examples, res.metrics) for _, res in results]
            metrics_aggregated = self.evaluate_metrics_aggregation_fn(eval_metrics)
        elif server_round == 1:  # Only log this warning once
            log(WARNING, "No evaluate_metrics_aggregation_fn provided")

        accuracy = metrics_aggregated.get("accuracy", 0.0)
        print(f"[Round {server_round}] Aggregated accuracy: {accuracy:.4f}")
        if accuracy >= self.target_accuracy:
            print(f" Final aggregated accuracy: {accuracy:.4f}\n")
            self.should_stop = True
            self.training_end_time = time.time()
            self.log_training_end()
        end_time = time.time()
        eval_duration = end_time - start_time
        print(f"[Round {server_round}] Evaluation aggregation time: {eval_duration:.2f}s")
        self.log_round_data(server_round, None, eval_duration, loss_aggregated, metrics_aggregated)
        return loss_aggregated, metrics_aggregated


