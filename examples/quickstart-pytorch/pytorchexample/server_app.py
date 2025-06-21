from typing import List, Tuple
from flwr.common import Context, Metrics, ndarrays_to_parameters
from flwr.server import ServerApp, ServerAppComponents, ServerConfig
from flwr.server.strategy import FedAvg
from pytorchexample.task import Net, get_weights
import os
import time

# Funzione per aggregare le metriche (weighted average)
def weighted_average(metrics: List[Tuple[int, Metrics]]) -> Metrics:
    accuracies = [num_examples * m["accuracy"] for num_examples, m in metrics]
    examples = [num_examples for num_examples, _ in metrics]
    return {"accuracy": sum(accuracies) / sum(examples)}

# Strategia custom con early stopping
class EarlyStoppingFedAvg(FedAvg):
    def __init__(self, accuracy_threshold: float, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.accuracy_threshold = accuracy_threshold
        self.start_time = time.time()  # Partenza del training
        self.last_loss = None
        self.last_accuracy = None

    def aggregate_evaluate(self, server_round, results, failures):
        aggregated_result = super().aggregate_evaluate(server_round, results, failures)
        if aggregated_result is not None:
            loss, metrics = aggregated_result
            accuracy = metrics.get("accuracy", 0.0)
            self.last_loss = loss
            self.last_accuracy = accuracy

            print(f"[Server] Round {server_round} - Aggregated loss: {loss:.4f}, accuracy: {accuracy:.4f}")

            if accuracy >= self.accuracy_threshold:
                duration = time.time() - self.start_time
                print(f"\n✅ Target accuracy {self.accuracy_threshold} reached!")
                print(f"🕒 Total training time: {duration:.2f} seconds")
                print(f"📉 Final aggregated loss: {loss:.4f}")
                print(f"🎯 Final aggregated accuracy: {accuracy:.4f}\n")
                os._exit(0)  # Stop immediato
        return aggregated_result

def server_fn(context: Context):
    num_rounds = context.run_config["num-server-rounds"]
    initial_parameters = ndarrays_to_parameters(get_weights(Net()))

    strategy = EarlyStoppingFedAvg(
        accuracy_threshold=0.50,  # Qui la soglia di early stopping
        fraction_fit=1.0,
        fraction_evaluate=context.run_config["fraction-evaluate"],
        min_available_clients=2,
        evaluate_metrics_aggregation_fn=weighted_average,
        initial_parameters=initial_parameters,
    )
    config = ServerConfig(num_rounds=num_rounds)
    return ServerAppComponents(strategy=strategy, config=config)

# ServerApp finale
app = ServerApp(server_fn=server_fn)
