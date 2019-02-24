"""
Variable renaming

Usage:
    exp.py train [options] CONFIG_FILE

Options:
    -h --help                                   Show this screen
    --cuda                                      Use GPU
    --debug                                     Debug mode
    --seed=<int>                                Seed [default: 0]
    --work-dir=<dir>                            work dir [default: data/exp_runs/]
"""

import time
from typing import List, Tuple, Dict, Iterable
import sys
import numpy as np
import os
import json
from docopt import docopt
from tqdm import tqdm

import torch

from model.decoder import SimpleDecoder
from model.encoder import GraphASTEncoder
from model.gnn import AdjacencyList, GatedGraphNeuralNetwork
from model.model import RenamingModel
from utils import nn_util
from utils.ast import AbstractSyntaxTree
from utils.dataset import Dataset, Example
from utils.vocab import Vocab, VocabEntry


def train(args):
    work_dir = args['--work-dir']
    config = json.load(open(args['CONFIG_FILE']))
    config['work_dir'] = work_dir

    if not os.path.exists(work_dir):
        print(f'creating work dir [{work_dir}]', file=sys.stderr)
        os.makedirs(work_dir)

    json.dump(config, open(os.path.join(work_dir, 'config.json'), 'w'), indent=2)

    # a grammar defines the syntax types of nodes on ASTs
    # a vocabulary defines the collection of all source and target variable names
    vocab = torch.load(config['data']['vocab_file'])
    encoder = GraphASTEncoder(ast_node_encoding_size=128, grammar=vocab.grammar, vocab=vocab)
    decoder = SimpleDecoder(ast_node_encoding_size=128,
                            tgt_name_vocab_size=len(vocab.target))
    model = RenamingModel(encoder, decoder)

    params = [p for p in model.parameters() if p.requires_grad]
    optimizer = torch.optim.Adam(params, lr=0.001)
    nn_util.glorot_init(params)

    # training loop
    train_iter = 0.
    log_every = 10
    cum_loss = cum_examples = 0.
    t1 = time.time()

    while True:
        # load training dataset, which is a collection of ASTs and maps of gold-standard renamings
        train_set_iter: Iterable[Example] = Dataset.batch_iter_from_compressed_file('data/0-trees.tar.gz',
                                                                                    batch_size=32,
                                                                                    shuffle=True)

        for batch_examples in tqdm(train_set_iter, file=sys.stdout):
            train_iter += 1
            optimizer.zero_grad()

            src_asts = [e.ast for e in batch_examples]
            rename_maps = [e.variable_name_map for e in batch_examples]

            tgt_log_probs = model(src_asts, rename_maps)

            loss = -tgt_log_probs.mean()

            cum_loss += loss.item()
            cum_examples += len(batch_examples)

            loss.backward()

            # clip gradient
            grad_norm = torch.nn.utils.clip_grad_norm_(params, 5.)

            optimizer.step()

        if train_iter % log_every == 0:
            print(f'[Learner] train_iter={train_iter} avg. loss={cum_loss / cum_examples}, '
                  f'{cum_examples} batch_examples ({cum_examples / (time.time() - t1)} batch_examples/s)', file=sys.stderr)

            cum_loss = cum_examples = 0.
            t1 = time.time()


if __name__ == '__main__':
    cmd_args = docopt(__doc__)

    # seed the RNG
    seed = int(cmd_args['--seed'])
    print(f'use random seed {seed}', file=sys.stderr)
    torch.manual_seed(seed)

    use_cuda = cmd_args['--cuda']
    if use_cuda:
        torch.cuda.manual_seed(seed)
    np.random.seed(seed * 13 // 7)

    train(cmd_args)