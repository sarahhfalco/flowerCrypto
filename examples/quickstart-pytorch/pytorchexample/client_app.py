"""pytorchexample: A Flower / PyTorch app with Differential Privacy (Opacus)"""

import torch
from flwr.client import ClientApp, NumPyClient
from flwr.common import Context
from opacus import PrivacyEngine

from pytorchexample.task import Net, get_weights, load_data, set_weights, test, train

USE_DP = True

# Define Flower Client
class FlowerClient(NumPyClient):
    def __init__(self, trainloader, valloader, local_epochs, learning_rate):
        self.net = Net()
        self.trainloader = trainloader
        self.valloader = valloader
        self.local_epochs = local_epochs
        self.lr = learning_rate
        self.device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    def fit(self, parameters, config):
        """Train the model with data of this client."""
        set_weights(self.net, parameters)
        self.net.to(self.device)

        # Crea optimizer
        optimizer = torch.optim.SGD(self.net.parameters(), lr=self.lr)

        # Applica Opacus se richiesto
        if USE_DP:
            print("[DP] Differential Privacy ATTIVATA")
            privacy_engine = PrivacyEngine()
            self.net, optimizer, self.trainloader = privacy_engine.make_private(
                module=self.net,
                optimizer=optimizer,
                data_loader=self.trainloader,
                noise_multiplier=1.0,  # più alto = più privacy = meno accuratezza
                max_grad_norm=1.0,
            )
        else:
            print("[DP] Differential Privacy DISATTIVATA")

        # Esegui il training (supporta optimizer esterno)
        results = train(
            self.net,
            self.trainloader,
            self.valloader,
            self.local_epochs,
            self.lr,
            self.device,
            optimizer=optimizer,
        )
        return get_weights(self.net), len(self.trainloader.dataset), results

    def evaluate(self, parameters, config):
        """Evaluate the model on the data this client has."""
        set_weights(self.net, parameters)
        loss, accuracy = test(self.net, self.valloader, self.device)
        return loss, len(self.valloader.dataset), {"accuracy": accuracy}


def client_fn(context: Context):
    """Construct a Client that will be run in a ClientApp."""

    # Read the node_config to fetch data partition associated to this node
    partition_id = context.node_config["partition-id"]
    num_partitions = context.node_config["num-partitions"]

    # Read run_config to fetch hyperparameters relevant to this run
    batch_size = context.run_config["batch-size"]
    trainloader, valloader = load_data(partition_id, num_partitions, batch_size)
    local_epochs = context.run_config["local-epochs"]
    learning_rate = context.run_config["learning-rate"]

    # Return Client instance
    return FlowerClient(trainloader, valloader, local_epochs, learning_rate).to_client()


# Flower ClientApp
app = ClientApp(client_fn)
