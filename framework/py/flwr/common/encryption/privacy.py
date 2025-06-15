from opacus import PrivacyEngine
import torch


def make_optimizer(model, lr, dp: bool = False, trainloader=None, noise_multiplier=1.0, max_grad_norm=1.0):
    """Restituisce un ottimizzatore con o senza DP applicata."""
    optimizer = torch.optim.SGD(model.parameters(), lr=lr)

    if dp:
        print("[DP] Attivo - Wrappiamo con PrivacyEngine")
        if trainloader is None:
            raise ValueError("trainloader richiesto per DP")
        privacy_engine = PrivacyEngine()
        model, optimizer, trainloader = privacy_engine.make_private(
            module=model,
            optimizer=optimizer,
            data_loader=trainloader,
            noise_multiplier=noise_multiplier,
            max_grad_norm=max_grad_norm,
        )
        return model, optimizer, trainloader, privacy_engine
    else:
        print("[DP] Inattivo - Standard optimizer")
        return model, optimizer, trainloader, None
