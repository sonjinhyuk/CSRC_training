import argparse
import numpy as np
import os
import random
import torch
import torch.nn as nn


from rnn_model import CharRNN
from MalConv import MalConv
from utils import parse_data, eval_detection, create_sample_benign


def generate_byte(model, base_stream, device, len_to_predict=1000, temperature=0.8):
    hidden_state = model.init_hidden(1).to(device)
    base_input = torch.LongTensor(base_stream).unsqueeze(0).to(device)
    predict = base_stream

    # updating hidden_state before last of base_stream
    for p in range(len(base_stream) - 1):
        _, hidden_state = model(base_input[:, p], hidden_state)

    output_result = []
    model_input = base_input[:, -1]
    for p in range(len_to_predict):
        output, hidden_state = model(model_input, hidden_state)
        output_result.append(output)

        output_dist = output.data.view(-1).div(temperature).exp()
        predict_stream = torch.multinomial(output_dist, 1)[0]

        predict = np.append(predict, predict_stream.detach().cpu())
        model_input = (
            torch.tensor(predict_stream, dtype=torch.long).unsqueeze(0).to(device)
        )

    return predict.tolist(), output_result


def run(args):
    benign_data, critical_data = parse_data(args.data_path, args.chunk_len, 512)

    device = (
        torch.device("cuda:0") if torch.cuda.is_available() else torch.device("cpu")
    )
    print(f"Current device is {device}")

    # Detection model load
    malconv = MalConv(channels=256, window_size=512, embd_size=8)
    nonneg = MalConv(channels=256, window_size=512, embd_size=8)
    malconv_weight = torch.load(args.malconv_path)
    nonneg_weight = torch.load(args.nonneg_path)
    malconv.load_state_dict(malconv_weight)
    nonneg.load_state_dict(nonneg_weight)

    model = CharRNN(
        input_size=256,
        hidden_size=args.hidden_size,
        output_size=256,
        model=args.model_type,
        n_layers=args.number_layers,
    )
    model.to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate)

    loss_record = []
    best_score = -1
    best_loss = -1
    best_model = None

    print("### START TRAINING ###")
    for epoch in range(1, args.epochs + 1):
        print(f"EPOCH {epoch}")

        input_benign, target_benign = create_sample_benign(
            benign_stream=benign_data[random.randrange(0, len(benign_data))],
            chunk_len=args.chunk_len,
            batch_size=args.batch_size,
            device=device,
        )

        hidden_state = model.init_hidden(args.batch_size)
        hidden_state.to(device)

        model.zero_grad()
        loss = 0
        base_stream = critical_data.pop(random.randrange(0, len(critical_data)))[
            : args.max_len
        ]
        predicted, _ = generate_byte(
            model=model, base_stream=base_stream, device=device
        )
        candidate = bytearray(base_stream) + bytearray(predicted[0])
        malconv_result, nonneg_result = eval_detection(malconv, nonneg, candidate)
        for c in range(args.chunk_len):
            output, hidden_state = model(input_benign[:, c], hidden_state.to(device))
            loss += criterion(output.view(args.batch_size, -1), target_benign[:, c])
        loss_record.append(loss)
        loss.backward()
        optimizer.step()
        print(f"Epoch {epoch} loss: {loss.data / args.chunk_len}")
        print(f"Detection Possibility: {malconv_result : 4f}")

        if epoch == 1:
            print("Saving the first model")
            best_model = model
            best_score = malconv_result
            best_loss = loss.data / args.chunk_len
        elif best_score > malconv_result:
            print("Best score updated! Saving...")
            best_model = model
            best_score = malconv_result
            best_loss = loss.data / args.chunk_len
        elif best_score == malconv_result:
            print("Best score updated! Saving...")
            best_model = model
            best_score = malconv_result
            best_loss = loss.data / args.chunk_len

    if not os.path.exists(args.save_path):
        os.mkdir(args.save_path)
    torch.save(best_model, os.path.join(args.save_path, "malRNN_doc.pt"))
    print("Train Finished!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Custom Argument
    parser.add_argument(
        "--data_path",
        type=str,
        default="/home/data1/sangryupark/doc_malware/doc_mal_baejae.csv",
    )
    parser.add_argument("--save_path", type=str, default="./trained_model")

    parser.add_argument("--model_type", type=str, default="gru")
    parser.add_argument("--hidden_size", type=int, default=100)
    parser.add_argument("--number_layers", type=int, default=1)
    parser.add_argument("--batch_size", type=int, default=10)
    parser.add_argument("--max_len", type=int, default=1024)
    parser.add_argument("--chunk_len", type=int, default=200)
    parser.add_argument("--learning_rate", type=float, default=0.01)
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument(
        "--malconv_path", type=str, default="./MalConv/malconv_save/malconv_doc.pth"
    )
    parser.add_argument(
        "--nonneg_path", type=str, default="./MalConv/malconv_save/nonneg_baseline.pth"
    )

    args = parser.parse_args()
    run(args)
