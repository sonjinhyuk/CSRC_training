import numpy as np
import random
import torch
import torch.nn.functional as F

from tqdm import tqdm


# Parse stream from dataset
def parse_data(data_path, chunk_len, malconv_min_len, len_limit=100000):
    print("### Start Parsing Data ###")
    with open(data_path, "r", encoding="cp949") as data:
        benign_data = []
        critical_data = []

        for idx, line in enumerate(tqdm(data.readlines())):
            try:
                if idx > 2000 and len(line) < len_limit:
                    look = line.rfind("]")
                    line = line[look + 2 :]
                    line = line.replace("\n", "")
                    if line.startswith(","):
                        line = line[1:]
                    line = line.split(",")
                    line = [int(x, 0) for x in line]

                    if line[1] == 0 and len(line[4:]) > chunk_len:
                        benign_data.append(line[4:])
                    elif len(line[4:]) > malconv_min_len:
                        critical_data.append(line[4:])
            except:
                pass
    print("### Data Parsing Done! ###")
    return benign_data, critical_data


# evaluate possibility of detection from detect model
def eval_detection(malconv, nonneg, gen_bytes):
    with torch.no_grad():
        gen_bytes = torch.from_numpy(
            np.frombuffer(gen_bytes, dtype=np.uint8)[np.newaxis, :]
        )
        malconv_output = F.softmax(malconv(gen_bytes), dim=-1)
        nonneg_output = F.softmax(nonneg(gen_bytes), dim=-1)
        malconv_output = malconv_output.detach().numpy()[0, 1]
        nonneg_output = nonneg_output.detach().numpy()[0, 1]
        return malconv_output, nonneg_output


def create_sample_benign(benign_stream, chunk_len, batch_size, device):
    input_stream = torch.LongTensor(batch_size, chunk_len)
    target_stream = torch.LongTensor(batch_size, chunk_len)
    for batch in range(batch_size):
        start_index = random.randrange(0, len(benign_stream) - chunk_len)
        end_index = start_index + chunk_len + 1
        chunk = benign_stream[start_index:end_index]
        input_stream[batch] = torch.as_tensor(chunk[:-1])
        target_stream[batch] = torch.as_tensor(chunk[1:])
    input_stream = torch.LongTensor(input_stream).to(device)
    target_stream = torch.LongTensor(target_stream).to(device)
    return input_stream, target_stream
