from flwr.server.strategy import FedAvg


class FedAvgWithEarlyStopping(FedAvg):
    def __init__(self, target_accuracy, **kwargs):
        super().__init__(**kwargs)
        self.target_accuracy = target_accuracy

    def evaluate(self, server_round, parameters, client_manager=None):
        # Chiama la evaluate originale
        eval_res = super().evaluate(server_round, parameters, client_manager)

        if eval_res is not None and eval_res.metrics is not None:
            accuracy = eval_res.metrics.get("accuracy", 0)
            print(f"Round {server_round} - Global Accuracy: {accuracy}")
            if accuracy >= self.target_accuracy:
                print(f"Target accuracy {self.target_accuracy} raggiunta. Stop!")
                raise SystemExit("Target accuracy reached")
        return eval_res
