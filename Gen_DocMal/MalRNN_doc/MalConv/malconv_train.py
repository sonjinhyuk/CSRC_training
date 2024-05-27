import argparse
import os
import torch
import torch.nn as nn
import torch.optim as optim

from MalConv import MalConv
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset, DataLoader
from torch.nn.utils.rnn import pad_sequence
from tqdm import tqdm


class StreamDataset(Dataset):
    def __init__(self, stream_list, label):
        super().__init__()
        self.stream_list = stream_list
        self.label = label

    def __len__(self):
        return len(self.label)

    def __getitem__(self, index):
        return self.stream_list[index], self.label[index]


def parse_data(data_path):
    print("### START PARSING DATA ###")
    with open(data_path, "r", encoding="cp949") as data:
        label = []
        stream_data = []
        for idx, line in enumerate(tqdm(data.readlines())):
            try:
                if idx != 0 and len(line) < 100000:
                    look = line.rfind("]")
                    line = line[look + 2 :]
                    line = line.replace("\n", "")
                    if line.startswith(","):
                        line = line[1:]
                    line = line.split(",")
                    line = [int(x, 0) for x in line]

                    if line[1] == 0:
                        label.append(0)
                    else:
                        label.append(1)
                    stream_data.append(line[4:])
            except:
                pass
        data.close()
    print("### PARSING DONE! ###")
    return stream_data[:2000], label[:2000]


def train(model, train_dataloader, loss_fn, optimizer, device):
    model.train()

    cur_loss = 0
    correct = 0
    counts = 0

    for idx, (stream, label) in enumerate(tqdm(train_dataloader)):
        stream = stream.to(device)
        label = label.to(device)
        optimizer.zero_grad()
        output = model(stream)
        loss = loss_fn(output, label)
        loss.backward()
        optimizer.step()
        output = output.argmax(dim=1)

        correct += (output == label).sum().item()
        counts += len(label)

        cur_loss += loss.item()
    print(
        f"Training loss {cur_loss / (idx+1) : .5f}, Traiing accuracy {correct / counts: 5f}"
    )

    total_accuracy = correct / len(train_dataloader.dataset)
    total_train_loss = cur_loss / len(train_dataloader)
    return total_train_loss, total_accuracy


def eval(model, eval_dataloader, loss_fn, device):
    model.eval()

    with torch.no_grad():
        correct = 0
        curr_loss = 0

        for stream, label in tqdm(eval_dataloader):
            stream = stream.to(device)
            label = label.to(device)
            output = model(stream)
            loss = loss_fn(output, label)
            output = output.argmax(dim=1)
            correct += (output == label).sum().item()
            curr_loss += loss.item()

    accuracy = correct / len(eval_dataloader.dataset)
    loss_result = curr_loss / len(eval_dataloader)

    return loss_result, accuracy


def collate_fn(batch, max_len=100000):
    stream_list = []
    label_list = []

    for stream, label in batch:
        if len(stream) < max_len:
            stream += [0] * (max_len - len(stream))
        stream_processed = torch.tensor(stream[:max_len], dtype=torch.long)
        label_processed = torch.tensor(label, dtype=torch.int64)
        stream_list.append(stream_processed)
        label_list.append(label_processed)
    stream_list = pad_sequence(stream_list, batch_first=True, padding_value=0)

    return stream_list, torch.stack(label_list)


def run(args):
    stream, label = parse_data(args.data_path)

    train_stream, valid_stream, train_label, valid_label = train_test_split(
        stream, label, test_size=0.2, shuffle=False
    )

    train_dataset = StreamDataset(train_stream, train_label)
    valid_dataset = StreamDataset(valid_stream, valid_label)

    train_dataloader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=False,
        collate_fn=lambda x: collate_fn(x),
    )
    valid_dataloader = DataLoader(
        valid_dataset,
        batch_size=args.batch_size,
        shuffle=False,
        collate_fn=lambda x: collate_fn(x),
    )
    device = (
        torch.device("cuda:0") if torch.cuda.is_available() else torch.device("cpu")
    )

    print(f"Current device is {device}")

    model = MalConv(channels=256, window_size=512, embd_size=8)
    weight = torch.load("./malconv_base/malconv.checkpoint")
    model.load_state_dict(weight["model_state_dict"])
    model.fc_1 = nn.Linear(in_features=256, out_features=256, bias=True)
    model.fc_2 = nn.Linear(in_features=256, out_features=2, bias=True)

    loss_fn = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=args.learning_rate)
    model.to(device)

    min_loss = 0

    for epoch in range(1, args.num_epochs + 1):
        print(f"### Train Epoch {epoch} ###")
        train_loss, train_accuracy = train(
            model, train_dataloader, loss_fn, optimizer, device
        )
        val_loss, val_accuracy = eval(model, valid_dataloader, loss_fn, device)

        print(
            f"### Epoch {epoch}, train_loss: {train_loss}, train_accuracy: {train_accuracy}, val_loss: {val_loss}, val_accuracy: {val_accuracy} ###"
        )

        if not os.path.exists(args.save_path):
            os.mkdir(args.save_path)

        if epoch == 1:
            print("Saving Initial model")
            min_loss = val_loss
            torch.save(
                model.state_dict(),
                f"{os.path.join(args.save_path, args.model_name)}.pth",
            )
        else:
            if val_loss < min_loss:
                print("Loss has been improved! Save model")
                min_loss = val_loss
                torch.save(
                    model.state_dict(),
                    f"{os.path.join(args.save_path, args.model_name)}.pth",
                )
    print("Training Finish")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data_path",
        type=str,
        default="/home/data1/sangryupark/doc_malware/doc_mal_baejae.csv",
    )
    parser.add_argument("--batch_size", type=int, default=8)
    parser.add_argument("--save_path", type=str, default="./malconv_save")
    parser.add_argument("--learning_rate", type=float, default=0.01)
    parser.add_argument("--model_name", type=str, default="malconv_doc")
    parser.add_argument("--num_epochs", type=int, default=10)

    args = parser.parse_args()
    run(args)
