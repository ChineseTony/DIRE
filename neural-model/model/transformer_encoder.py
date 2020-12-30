import copy
from typing import Optional, Any

import torch
from torch import Tensor
import torch.nn as nn
from model.encoder import *
from utils import nn_util, util
from utils.dataset import Example
from utils.vocab import PAD_ID, Vocab


class TransformerEncoder(Encoder):
    def __init__(self, config):
        super().__init__()
        self.vocab = vocab = Vocab.load(config['vocab_file'])

        self.src_word_embed = nn.Embedding(len(vocab.source_tokens), config['source_embedding_size'])

        dropout = config['dropout']
        self.lstm_encoder = nn.Transformer(input_size=self.src_word_embed.embedding_dim,
                                    hidden_size=config['source_encoding_size'] // 2, num_layers=config['num_layers'],
                                    batch_first=True, bidirectional=True, dropout=dropout)

        self.decoder_cell_init = nn.Linear(config['source_encoding_size'], config['decoder_hidden_size'])

        self.dropout = nn.Dropout(dropout)
        self.config = config

