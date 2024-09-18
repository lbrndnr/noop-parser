# no-op parser

This is a small example that demonstrates a bug in the linux kernel. The problem arises when a BPF program of type `BPF_SK_SKB_STREAM_VERDICT` does not redirect `__sk_buff`, but instead just returns `SK_PASS`.

## Usage
This will make your system unresponsive until it's unusable. So make sure to run this in a VM.
First, load the BPF programs as follows
```bash
./load.sh
```

Next, spin up a simple HTTP service on port 8000:
```python
python3 -m http.server 8000
```

Finally, make a request to the service
```bash
curl -vvv http://127.0.0.1:8000
```

Alternatively, you can compile the BPF program with the `REDIRECT` flag. This causes the stream verdict to call `bpf_sk_redirect_hash`.
```bash
./unload.sh
./load.sh -DREDIRECT
```