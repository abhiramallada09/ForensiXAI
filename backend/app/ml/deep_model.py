import torch
import torch.nn as nn
from typing import Dict, Tuple, Any


class ForensicResidualBlock(nn.Module):
    """
    Residual dense block for deep representation learning of forensic telemetry.
    """
    def __init__(self, hidden_dim: int = 64, dropout_rate: float = 0.2):
        super().__init__()
        self.fc1 = nn.Linear(hidden_dim, hidden_dim)
        self.norm1 = nn.LayerNorm(hidden_dim)
        self.act = nn.LeakyReLU(0.1)
        self.drop = nn.Dropout(dropout_rate)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.norm2 = nn.LayerNorm(hidden_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        out = self.fc1(x)
        out = self.norm1(out)
        out = self.act(out)
        out = self.drop(out)
        out = self.fc2(out)
        out = self.norm2(out)
        out = self.act(out + residual)
        return out


class ForensiXDeepNet(nn.Module):
    """
    ForensiX Multi-Task Deep Neural Network for:
    1. Deleted File & Remnant Probability
    2. Timestamp Manipulation & Anti-Forensic Likelihood
    3. Volatile Memory Anomaly & Malware Indicator
    4. Calibrated Model Confidence
    """
    def __init__(self, input_dim: int = 12, hidden_dim: int = 64):
        super().__init__()
        self.input_dim = input_dim

        # Input projection layer
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.LeakyReLU(0.1),
        )

        # Deep representation extraction
        self.res_block1 = ForensicResidualBlock(hidden_dim=hidden_dim, dropout_rate=0.2)
        self.res_block2 = ForensicResidualBlock(hidden_dim=hidden_dim, dropout_rate=0.2)

        # Bottleneck representation
        self.bottleneck = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.LayerNorm(32),
            nn.LeakyReLU(0.1),
        )

        # Multi-task classification heads
        self.head_deleted_file = nn.Sequential(
            nn.Linear(32, 16),
            nn.LeakyReLU(0.1),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

        self.head_manipulation = nn.Sequential(
            nn.Linear(32, 16),
            nn.LeakyReLU(0.1),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

        self.head_malware = nn.Sequential(
            nn.Linear(32, 16),
            nn.LeakyReLU(0.1),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

        self.head_confidence = nn.Sequential(
            nn.Linear(32, 16),
            nn.LeakyReLU(0.1),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> Dict[str, torch.Tensor]:
        feat = self.input_proj(x)
        feat = self.res_block1(feat)
        feat = self.res_block2(feat)
        rep = self.bottleneck(feat)

        p_deleted = self.head_deleted_file(rep).squeeze(-1)
        p_manip = self.head_manipulation(rep).squeeze(-1)
        p_malware = self.head_malware(rep).squeeze(-1)
        p_conf = self.head_confidence(rep).squeeze(-1)

        return {
            "deleted_probability": p_deleted,
            "manipulation_likelihood": p_manip,
            "malware_indicator": p_malware,
            "confidence_score": p_conf,
            "latent_representation": rep,
        }

    def get_layer_summary(self) -> Dict[str, Any]:
        """Returns architecture summary, layer count, and trainable parameter counts."""
        total_params = sum(p.numel() for p in self.parameters())
        trainable_params = sum(p.numel() for p in self.parameters() if p.requires_grad)
        return {
            "model_name": "ForensiXDeepNet",
            "architecture": "Multi-Task Residual Forensic Representation MLP",
            "framework": "PyTorch 2.15+",
            "input_dimension": self.input_dim,
            "hidden_dimension": 64,
            "total_parameters": total_params,
            "trainable_parameters": trainable_params,
            "layers": [
                {"name": "input_proj", "type": "Linear + LayerNorm + LeakyReLU", "dim": f"{self.input_dim} -> 64"},
                {"name": "res_block1", "type": "Residual Dense Block (2x Linear, LayerNorm, Dropout)", "dim": "64 -> 64"},
                {"name": "res_block2", "type": "Residual Dense Block (2x Linear, LayerNorm, Dropout)", "dim": "64 -> 64"},
                {"name": "bottleneck", "type": "Latent Compression Layer", "dim": "64 -> 32"},
                {"name": "head_deleted_file", "type": "Multi-Task Head (Sigmoid)", "dim": "32 -> 16 -> 1"},
                {"name": "head_manipulation", "type": "Multi-Task Head (Sigmoid)", "dim": "32 -> 16 -> 1"},
                {"name": "head_malware", "type": "Multi-Task Head (Sigmoid)", "dim": "32 -> 16 -> 1"},
                {"name": "head_confidence", "type": "Calibrated Confidence Head (Sigmoid)", "dim": "32 -> 16 -> 1"},
            ],
        }
